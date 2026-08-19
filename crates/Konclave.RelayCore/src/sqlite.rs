use std::path::Path;
use std::time::Duration;

use KonclaveDomainCore::{
    AcknowledgeRequest, DeliveryClass, EnvelopeId, MAX_RELAY_ENVELOPE_BYTES,
    MAX_RELAY_PAYLOAD_BYTES, MAX_REPLAY_PAGE_BYTES, ProtocolVersion, RelayEnvelope, ReplayPage,
    ReplayRequest, RoutingId, StoredRelayEnvelope,
};
use KonclaveProtocolContracts::v1::{
    decode_relay_envelope, encode_relay_envelope, encode_replay_page_preserving,
};
use async_trait::async_trait;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use sqlx::{Row, SqlitePool};

use crate::{EncodedReplayPage, RelayError, RelayPrincipalId, RelayRepository, SubmitResult};

const SQLITE_SCHEMA_VERSION: u32 = 2;
const REPLAY_PAGE_FIXED_WIRE_BUDGET: usize = 64;
const STORED_ENVELOPE_WIRE_OVERHEAD_BUDGET: usize = 32;

/// SQLite relay repository containing only allowlisted metadata and opaque payloads.
#[derive(Clone)]
pub struct SqliteRelayRepository {
    pool: SqlitePool,
}

impl SqliteRelayRepository {
    /// Opens or creates a relay database.
    ///
    /// # Errors
    ///
    /// Returns a storage error when SQLite cannot connect or initialize the schema.
    pub async fn connect(path: &Path) -> Result<Self, RelayError> {
        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .foreign_keys(true)
            .busy_timeout(Duration::from_secs(5))
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Full);
        let pool = SqlitePoolOptions::new()
            .max_connections(4)
            .connect_with(options)
            .await
            .map_err(|_| storage_failure("SQLite connect"))?;
        initialize_schema(&pool).await?;
        Ok(Self { pool })
    }

    #[cfg(test)]
    async fn connect_memory() -> Result<Self, RelayError> {
        let options = SqliteConnectOptions::new()
            .in_memory(true)
            .foreign_keys(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
            .map_err(|_| storage_failure("SQLite memory connect"))?;
        initialize_schema(&pool).await?;
        Ok(Self { pool })
    }
}

#[async_trait]
impl RelayRepository for SqliteRelayRepository {
    async fn submit_encoded(
        &self,
        envelope: &RelayEnvelope,
        encoded_envelope: &[u8],
        now_unix_seconds: u64,
    ) -> Result<SubmitResult, RelayError> {
        if decode_relay_envelope(encoded_envelope)? != *envelope {
            return Err(RelayError::EnvelopeEncodingMismatch);
        }
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| storage_failure("submission transaction begin"))?;
        sqlx::query(
            "INSERT INTO relay_route (routing_id, next_cursor, current_epoch)
             VALUES (?1, 1, 0)
             ON CONFLICT(routing_id) DO NOTHING",
        )
        .bind(envelope.routing_id().as_bytes().as_slice())
        .execute(&mut *transaction)
        .await
        .map_err(|_| storage_failure("route initialization"))?;

        if let Some(existing) = find_existing(&mut transaction, envelope, encoded_envelope).await? {
            if !existing.identical {
                return Err(RelayError::IdempotencyConflict);
            }
            transaction
                .commit()
                .await
                .map_err(|_| storage_failure("idempotent submission commit"))?;
            return Ok(SubmitResult::new(existing.cursor, true));
        }

        if envelope.expires_at_unix_seconds() <= now_unix_seconds {
            return Err(RelayError::ExpiredEnvelope);
        }

        let cursor = allocate_cursor(&mut transaction, envelope).await?;
        insert_envelope(&mut transaction, envelope, encoded_envelope, cursor).await?;
        transaction
            .commit()
            .await
            .map_err(|_| storage_failure("submission transaction commit"))?;
        Ok(SubmitResult::new(cursor, false))
    }

    async fn replay(&self, request: ReplayRequest) -> Result<ReplayPage, RelayError> {
        let page = self.load_replay_entries(request).await?;
        let envelopes = page
            .entries
            .into_iter()
            .map(|entry| -> Result<StoredRelayEnvelope, RelayError> {
                let envelope = decode_relay_envelope(&entry.encoded_envelope)
                    .map_err(|_| RelayError::InvalidStoredData)?;
                Ok(StoredRelayEnvelope::new(envelope, entry.cursor)?)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ReplayPage::new(envelopes, page.next_cursor, page.has_more)?)
    }

    async fn replay_encoded(
        &self,
        request: ReplayRequest,
    ) -> Result<EncodedReplayPage, RelayError> {
        let page = self.load_replay_entries(request).await?;
        let envelopes = page
            .entries
            .iter()
            .map(|entry| (entry.encoded_envelope.as_slice(), entry.cursor))
            .collect::<Vec<_>>();
        let bytes = encode_replay_page_preserving(&envelopes, page.next_cursor, page.has_more)?;
        EncodedReplayPage::new(
            bytes,
            request.after_cursor(),
            page.next_cursor,
            page.has_more,
            page.entries.len(),
        )
    }

    async fn acknowledge(
        &self,
        principal: RelayPrincipalId,
        request: AcknowledgeRequest,
    ) -> Result<u64, RelayError> {
        let highest: Option<i64> =
            sqlx::query_scalar("SELECT next_cursor - 1 FROM relay_route WHERE routing_id = ?1")
                .bind(request.routing_id().as_bytes().as_slice())
                .fetch_optional(&self.pool)
                .await
                .map_err(|_| storage_failure("acknowledgment route query"))?;
        let highest = highest.map(from_sql_integer).transpose()?.unwrap_or(0);
        if request.cursor() > highest {
            return Err(RelayError::InvalidAcknowledgment);
        }
        let cursor: i64 = sqlx::query_scalar(
            "INSERT INTO relay_acknowledgment (routing_id, principal_id, cursor)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(routing_id, principal_id)
             DO UPDATE SET cursor = MAX(cursor, excluded.cursor)
             RETURNING cursor",
        )
        .bind(request.routing_id().as_bytes().as_slice())
        .bind(principal.as_bytes().as_slice())
        .bind(to_sql_integer(request.cursor())?)
        .fetch_one(&self.pool)
        .await
        .map_err(|_| storage_failure("acknowledgment update"))?;
        from_sql_integer(cursor)
    }
}

impl SqliteRelayRepository {
    async fn load_replay_entries(
        &self,
        request: ReplayRequest,
    ) -> Result<ReplayEntries, RelayError> {
        let limit = usize::try_from(request.limit()).map_err(|_| RelayError::InvalidStoredData)?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| storage_failure("replay transaction begin"))?;
        let size_rows = sqlx::query(
            "SELECT cursor, length(encoded_envelope) AS envelope_length
             FROM relay_envelope
             WHERE routing_id = ?1 AND cursor > ?2
             ORDER BY cursor
             LIMIT ?3",
        )
        .bind(request.routing_id().as_bytes().as_slice())
        .bind(to_sql_integer(request.after_cursor())?)
        .bind(i64::try_from(limit + 1).map_err(|_| RelayError::SequenceExhausted)?)
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| storage_failure("replay sizing query"))?;
        let selection = select_replay_rows(&size_rows, limit)?;

        let Some(last_cursor) = selection.last_cursor else {
            transaction
                .commit()
                .await
                .map_err(|_| storage_failure("empty replay commit"))?;
            return Ok(ReplayEntries {
                entries: Vec::new(),
                next_cursor: request.after_cursor(),
                has_more: false,
            });
        };
        let rows = sqlx::query(
            "SELECT
                cursor,
                CASE WHEN length(routing_id) = 32 THEN routing_id END AS routing_id,
                CASE WHEN length(envelope_id) = 16 THEN envelope_id END AS envelope_id,
                version_major,
                version_minor,
                delivery_class,
                expected_parent_epoch,
                expires_at_unix_seconds,
                encoded_envelope
             FROM relay_envelope
             WHERE routing_id = ?1 AND cursor > ?2 AND cursor <= ?3
             ORDER BY cursor
             LIMIT ?4",
        )
        .bind(request.routing_id().as_bytes().as_slice())
        .bind(to_sql_integer(request.after_cursor())?)
        .bind(to_sql_integer(last_cursor)?)
        .bind(i64::try_from(selection.count).map_err(|_| RelayError::SequenceExhausted)?)
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| storage_failure("replay query"))?;
        let entries = rows
            .into_iter()
            .map(replay_entry_from_row)
            .collect::<Result<Vec<_>, _>>()?;
        transaction
            .commit()
            .await
            .map_err(|_| storage_failure("replay transaction commit"))?;
        let next_cursor = entries
            .last()
            .map_or(request.after_cursor(), |entry| entry.cursor);
        Ok(ReplayEntries {
            entries,
            next_cursor,
            has_more: selection.has_more,
        })
    }
}

struct ReplayEntries {
    entries: Vec<ReplayEntry>,
    next_cursor: u64,
    has_more: bool,
}

struct ReplayEntry {
    encoded_envelope: Vec<u8>,
    cursor: u64,
}

struct ExistingSubmission {
    cursor: u64,
    identical: bool,
}

async fn find_existing(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    envelope: &RelayEnvelope,
    encoded_envelope: &[u8],
) -> Result<Option<ExistingSubmission>, RelayError> {
    let row = sqlx::query(
        "SELECT
            cursor,
            CASE WHEN length(routing_id) = 32 THEN routing_id END AS routing_id,
            CASE WHEN length(envelope_id) = 16 THEN envelope_id END AS envelope_id,
            version_major,
            version_minor,
            delivery_class,
            expected_parent_epoch,
            expires_at_unix_seconds,
            length(encoded_envelope) AS envelope_length
         FROM relay_envelope
         WHERE envelope_id = ?1",
    )
    .bind(envelope.envelope_id().as_bytes().as_slice())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| storage_failure("idempotency query"))?;
    let Some(row) = row else {
        return Ok(None);
    };
    let envelope_length = usize::try_from(
        row.try_get::<i64, _>("envelope_length")
            .map_err(invalid_row)?,
    )
    .map_err(|_| RelayError::InvalidStoredData)?;
    if !(1..=MAX_RELAY_ENVELOPE_BYTES).contains(&envelope_length) {
        return Err(RelayError::InvalidStoredData);
    }
    let stored_encoding: Vec<u8> =
        sqlx::query_scalar("SELECT encoded_envelope FROM relay_envelope WHERE envelope_id = ?1")
            .bind(envelope.envelope_id().as_bytes().as_slice())
            .fetch_one(&mut **transaction)
            .await
            .map_err(|_| storage_failure("idempotency envelope query"))?;
    if stored_encoding.len() != envelope_length {
        return Err(RelayError::InvalidStoredData);
    }
    let stored_envelope =
        decode_relay_envelope(&stored_encoding).map_err(|_| RelayError::InvalidStoredData)?;
    if !row_metadata_matches(&row, &stored_envelope)? {
        return Err(RelayError::InvalidStoredData);
    }
    Ok(Some(ExistingSubmission {
        cursor: from_sql_integer(row.try_get("cursor").map_err(invalid_row)?)?,
        identical: stored_envelope == *envelope && stored_encoding == encoded_envelope,
    }))
}

async fn allocate_cursor(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    envelope: &RelayEnvelope,
) -> Result<u64, RelayError> {
    let expected_epoch = envelope
        .expected_parent_epoch()
        .map(to_sql_integer)
        .transpose()?;
    let cursor: Option<i64> = match envelope.delivery_class() {
        DeliveryClass::GroupCommit => sqlx::query_scalar(
            "UPDATE relay_route
                 SET current_epoch = current_epoch + 1,
                     next_cursor = next_cursor + 1
                 WHERE routing_id = ?1
                   AND current_epoch = ?2
                   AND current_epoch < ?3
                   AND next_cursor < ?3
                 RETURNING next_cursor - 1",
        )
        .bind(envelope.routing_id().as_bytes().as_slice())
        .bind(expected_epoch.ok_or(RelayError::StaleEpoch)?)
        .bind(i64::MAX)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|_| storage_failure("Commit compare-and-set"))?,
        DeliveryClass::GroupProposal => sqlx::query_scalar(
            "UPDATE relay_route
                 SET current_epoch = current_epoch,
                     next_cursor = next_cursor + 1
                 WHERE routing_id = ?1
                   AND current_epoch = ?2
                   AND next_cursor < ?3
                 RETURNING next_cursor - 1",
        )
        .bind(envelope.routing_id().as_bytes().as_slice())
        .bind(expected_epoch.ok_or(RelayError::StaleEpoch)?)
        .bind(i64::MAX)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|_| storage_failure("Proposal compare-and-set"))?,
        DeliveryClass::KeyPackage | DeliveryClass::Welcome | DeliveryClass::GroupApplication => {
            sqlx::query_scalar(
                "UPDATE relay_route
                 SET next_cursor = next_cursor + 1
                 WHERE routing_id = ?1 AND next_cursor < ?2
                 RETURNING next_cursor - 1",
            )
            .bind(envelope.routing_id().as_bytes().as_slice())
            .bind(i64::MAX)
            .fetch_optional(&mut **transaction)
            .await
            .map_err(|_| storage_failure("cursor allocation"))?
        }
    };
    match cursor.map(from_sql_integer).transpose()? {
        Some(cursor) => Ok(cursor),
        None => Err(classify_allocation_failure(transaction, envelope).await?),
    }
}

async fn classify_allocation_failure(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    envelope: &RelayEnvelope,
) -> Result<RelayError, RelayError> {
    let row = sqlx::query(
        "SELECT next_cursor, current_epoch
         FROM relay_route
         WHERE routing_id = ?1",
    )
    .bind(envelope.routing_id().as_bytes().as_slice())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| storage_failure("allocation failure classification"))?
    .ok_or_else(|| storage_failure("missing relay route"))?;
    let next_cursor = from_sql_integer(row.try_get("next_cursor").map_err(invalid_row)?)?;
    let current_epoch = from_sql_integer(row.try_get("current_epoch").map_err(invalid_row)?)?;
    if matches!(
        envelope.delivery_class(),
        DeliveryClass::GroupCommit | DeliveryClass::GroupProposal
    ) && envelope.expected_parent_epoch() != Some(current_epoch)
    {
        return Ok(RelayError::StaleEpoch);
    }
    if next_cursor >= i64::MAX as u64
        || (envelope.delivery_class() == DeliveryClass::GroupCommit
            && current_epoch >= i64::MAX as u64)
    {
        return Ok(RelayError::SequenceExhausted);
    }
    Ok(storage_failure("relay sequence allocation"))
}

async fn insert_envelope(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    envelope: &RelayEnvelope,
    encoded_envelope: &[u8],
    cursor: u64,
) -> Result<(), RelayError> {
    sqlx::query(
        "INSERT INTO relay_envelope (
            routing_id,
            cursor,
            envelope_id,
            version_major,
            version_minor,
            delivery_class,
            expected_parent_epoch,
            expires_at_unix_seconds,
            encoded_envelope
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
    )
    .bind(envelope.routing_id().as_bytes().as_slice())
    .bind(to_sql_integer(cursor)?)
    .bind(envelope.envelope_id().as_bytes().as_slice())
    .bind(i64::from(envelope.version().major()))
    .bind(i64::from(envelope.version().minor()))
    .bind(delivery_class_to_sql(envelope.delivery_class()))
    .bind(
        envelope
            .expected_parent_epoch()
            .map(to_sql_integer)
            .transpose()?,
    )
    .bind(to_sql_integer(envelope.expires_at_unix_seconds())?)
    .bind(encoded_envelope)
    .execute(&mut **transaction)
    .await
    .map(|_| ())
    .map_err(|_| storage_failure("envelope insert"))
}

fn replay_entry_from_row(row: sqlx::sqlite::SqliteRow) -> Result<ReplayEntry, RelayError> {
    let encoded_envelope: Vec<u8> = row.try_get("encoded_envelope").map_err(invalid_row)?;
    if !(1..=MAX_RELAY_ENVELOPE_BYTES).contains(&encoded_envelope.len()) {
        return Err(RelayError::InvalidStoredData);
    }
    let envelope =
        decode_relay_envelope(&encoded_envelope).map_err(|_| RelayError::InvalidStoredData)?;
    if !row_metadata_matches(&row, &envelope)? {
        return Err(RelayError::InvalidStoredData);
    }
    Ok(ReplayEntry {
        encoded_envelope,
        cursor: from_sql_integer(row.try_get("cursor").map_err(invalid_row)?)?,
    })
}

fn row_metadata_matches(
    row: &sqlx::sqlite::SqliteRow,
    envelope: &RelayEnvelope,
) -> Result<bool, RelayError> {
    Ok(RoutingId::from_slice(
        &row.try_get::<Vec<u8>, _>("routing_id")
            .map_err(invalid_row)?,
    )? == envelope.routing_id()
        && EnvelopeId::from_slice(
            &row.try_get::<Vec<u8>, _>("envelope_id")
                .map_err(invalid_row)?,
        )? == envelope.envelope_id()
        && from_sql_u32(row.try_get("version_major").map_err(invalid_row)?)?
            == envelope.version().major()
        && from_sql_u32(row.try_get("version_minor").map_err(invalid_row)?)?
            == envelope.version().minor()
        && delivery_class_from_sql(row.try_get("delivery_class").map_err(invalid_row)?)?
            == envelope.delivery_class()
        && optional_epoch_from_row(row, "expected_parent_epoch")?
            == envelope.expected_parent_epoch()
        && from_sql_integer(
            row.try_get("expires_at_unix_seconds")
                .map_err(invalid_row)?,
        )? == envelope.expires_at_unix_seconds())
}

fn optional_epoch_from_row(
    row: &sqlx::sqlite::SqliteRow,
    column: &str,
) -> Result<Option<u64>, RelayError> {
    row.try_get::<Option<i64>, _>(column)
        .map_err(invalid_row)?
        .map(from_sql_integer)
        .transpose()
}

const fn delivery_class_to_sql(value: DeliveryClass) -> i64 {
    match value {
        DeliveryClass::KeyPackage => 1,
        DeliveryClass::Welcome => 2,
        DeliveryClass::GroupProposal => 3,
        DeliveryClass::GroupCommit => 4,
        DeliveryClass::GroupApplication => 5,
    }
}

fn delivery_class_from_sql(value: i64) -> Result<DeliveryClass, RelayError> {
    match value {
        1 => Ok(DeliveryClass::KeyPackage),
        2 => Ok(DeliveryClass::Welcome),
        3 => Ok(DeliveryClass::GroupProposal),
        4 => Ok(DeliveryClass::GroupCommit),
        5 => Ok(DeliveryClass::GroupApplication),
        _ => Err(RelayError::InvalidStoredData),
    }
}

fn to_sql_integer(value: u64) -> Result<i64, RelayError> {
    i64::try_from(value).map_err(|_| RelayError::SequenceExhausted)
}

fn from_sql_integer(value: i64) -> Result<u64, RelayError> {
    u64::try_from(value).map_err(|_| RelayError::InvalidStoredData)
}

fn from_sql_u32(value: i64) -> Result<u32, RelayError> {
    u32::try_from(value).map_err(|_| RelayError::InvalidStoredData)
}

fn invalid_row(_: sqlx::Error) -> RelayError {
    RelayError::InvalidStoredData
}

const fn storage_failure(operation: &'static str) -> RelayError {
    RelayError::StorageFailure { operation }
}

async fn initialize_schema(pool: &SqlitePool) -> Result<(), RelayError> {
    let mut transaction = pool
        .begin()
        .await
        .map_err(|_| storage_failure("schema transaction begin"))?;
    let raw_version: i64 = sqlx::query_scalar("PRAGMA user_version")
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| storage_failure("schema version read"))?;
    let version = from_sql_u32(raw_version)?;
    if version > SQLITE_SCHEMA_VERSION {
        return Err(RelayError::UnsupportedSchemaVersion { actual: version });
    }
    if version == 0 {
        sqlx::query(
            "CREATE TABLE relay_route (
            routing_id BLOB PRIMARY KEY,
            next_cursor INTEGER NOT NULL CHECK (next_cursor >= 1),
            current_epoch INTEGER NOT NULL CHECK (current_epoch >= 0),
            CHECK (length(routing_id) = 32),
            CHECK (current_epoch < next_cursor)
         ) WITHOUT ROWID",
        )
        .execute(&mut *transaction)
        .await
        .map_err(|_| storage_failure("route schema initialization"))?;
        sqlx::query(
            "CREATE TABLE relay_envelope (
            routing_id BLOB NOT NULL,
            cursor INTEGER NOT NULL CHECK (cursor >= 1),
            envelope_id BLOB NOT NULL,
            version_major INTEGER NOT NULL CHECK (version_major BETWEEN 1 AND 4294967295),
            version_minor INTEGER NOT NULL CHECK (version_minor BETWEEN 0 AND 4294967295),
            delivery_class INTEGER NOT NULL CHECK (delivery_class BETWEEN 1 AND 5),
            expected_parent_epoch INTEGER,
            expires_at_unix_seconds INTEGER NOT NULL CHECK (expires_at_unix_seconds >= 1),
            encoded_envelope BLOB NOT NULL
                CHECK (length(encoded_envelope) BETWEEN 1 AND 1048576),
            PRIMARY KEY (routing_id, cursor),
            UNIQUE (envelope_id),
            FOREIGN KEY (routing_id) REFERENCES relay_route(routing_id) ON DELETE CASCADE,
            CHECK (length(routing_id) = 32),
            CHECK (length(envelope_id) = 16),
            CHECK (
                (delivery_class IN (3, 4) AND expected_parent_epoch IS NOT NULL
                    AND expected_parent_epoch >= 0)
                OR
                (delivery_class NOT IN (3, 4) AND expected_parent_epoch IS NULL)
            )
         ) WITHOUT ROWID",
        )
        .execute(&mut *transaction)
        .await
        .map_err(|_| storage_failure("envelope schema initialization"))?;
        sqlx::query(
            "CREATE TABLE relay_acknowledgment (
            routing_id BLOB NOT NULL,
            principal_id BLOB NOT NULL,
            cursor INTEGER NOT NULL CHECK (cursor >= 1),
            PRIMARY KEY (routing_id, principal_id),
            FOREIGN KEY (routing_id) REFERENCES relay_route(routing_id) ON DELETE CASCADE,
            CHECK (length(routing_id) = 32),
            CHECK (length(principal_id) = 32)
         ) WITHOUT ROWID",
        )
        .execute(&mut *transaction)
        .await
        .map_err(|_| storage_failure("acknowledgment schema initialization"))?;
        sqlx::query("PRAGMA user_version = 2")
            .execute(&mut *transaction)
            .await
            .map_err(|_| storage_failure("schema version write"))?;
    } else if version == 1 {
        migrate_schema_v1_to_v2(&mut transaction).await?;
    }
    validate_schema(&mut transaction).await?;
    transaction
        .commit()
        .await
        .map_err(|_| storage_failure("schema transaction commit"))
}

async fn validate_schema(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
) -> Result<(), RelayError> {
    for query in [
        "SELECT routing_id, next_cursor, current_epoch FROM relay_route LIMIT 0",
        "SELECT routing_id, cursor, envelope_id, version_major, version_minor,
                delivery_class, expected_parent_epoch, expires_at_unix_seconds,
                encoded_envelope
         FROM relay_envelope LIMIT 0",
        "SELECT routing_id, principal_id, cursor FROM relay_acknowledgment LIMIT 0",
    ] {
        sqlx::query(query)
            .execute(&mut **transaction)
            .await
            .map_err(|_| storage_failure("schema validation"))?;
    }
    Ok(())
}

async fn migrate_schema_v1_to_v2(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
) -> Result<(), RelayError> {
    sqlx::query(
        "CREATE TABLE relay_envelope_v2 (
            routing_id BLOB NOT NULL,
            cursor INTEGER NOT NULL CHECK (cursor >= 1),
            envelope_id BLOB NOT NULL,
            version_major INTEGER NOT NULL CHECK (version_major BETWEEN 1 AND 4294967295),
            version_minor INTEGER NOT NULL CHECK (version_minor BETWEEN 0 AND 4294967295),
            delivery_class INTEGER NOT NULL CHECK (delivery_class BETWEEN 1 AND 5),
            expected_parent_epoch INTEGER,
            expires_at_unix_seconds INTEGER NOT NULL CHECK (expires_at_unix_seconds >= 1),
            encoded_envelope BLOB NOT NULL
                CHECK (length(encoded_envelope) BETWEEN 1 AND 1048576),
            PRIMARY KEY (routing_id, cursor),
            UNIQUE (envelope_id),
            FOREIGN KEY (routing_id) REFERENCES relay_route(routing_id) ON DELETE CASCADE,
            CHECK (length(routing_id) = 32),
            CHECK (length(envelope_id) = 16),
            CHECK (
                (delivery_class IN (3, 4) AND expected_parent_epoch IS NOT NULL
                    AND expected_parent_epoch >= 0)
                OR
                (delivery_class NOT IN (3, 4) AND expected_parent_epoch IS NULL)
            )
         ) WITHOUT ROWID",
    )
    .execute(&mut **transaction)
    .await
    .map_err(|_| storage_failure("schema v2 envelope initialization"))?;

    let mut last_envelope_id: Option<Vec<u8>> = None;
    loop {
        let row = sqlx::query(
            "SELECT
                CASE WHEN length(routing_id) = 32 THEN routing_id END AS routing_id,
                cursor,
                CASE WHEN length(envelope_id) = 16 THEN envelope_id END AS envelope_id,
                version_major,
                version_minor,
                delivery_class,
                expected_parent_epoch,
                expires_at_unix_seconds,
                length(payload) AS payload_length
             FROM relay_envelope
             WHERE ?1 IS NULL OR envelope_id > ?1
             ORDER BY envelope_id
             LIMIT 1",
        )
        .bind(last_envelope_id.as_deref())
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|_| storage_failure("schema v1 envelope read"))?;
        let Some(row) = row else {
            break;
        };
        let payload_length = usize::try_from(
            row.try_get::<i64, _>("payload_length")
                .map_err(invalid_row)?,
        )
        .map_err(|_| RelayError::InvalidStoredData)?;
        if !(1..=MAX_RELAY_PAYLOAD_BYTES).contains(&payload_length) {
            return Err(RelayError::InvalidStoredData);
        }
        let envelope_id: Vec<u8> = row.try_get("envelope_id").map_err(invalid_row)?;
        let payload: Vec<u8> =
            sqlx::query_scalar("SELECT payload FROM relay_envelope WHERE envelope_id = ?1")
                .bind(&envelope_id)
                .fetch_one(&mut **transaction)
                .await
                .map_err(|_| storage_failure("schema v1 payload read"))?;
        if payload.len() != payload_length {
            return Err(RelayError::InvalidStoredData);
        }
        let envelope = envelope_from_v1_row(&row, payload)?;
        let encoded_envelope = encode_relay_envelope(&envelope)?;
        let cursor = from_sql_integer(row.try_get("cursor").map_err(invalid_row)?)?;
        sqlx::query(
            "INSERT INTO relay_envelope_v2 (
                routing_id,
                cursor,
                envelope_id,
                version_major,
                version_minor,
                delivery_class,
                expected_parent_epoch,
                expires_at_unix_seconds,
                encoded_envelope
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        )
        .bind(envelope.routing_id().as_bytes().as_slice())
        .bind(to_sql_integer(cursor)?)
        .bind(envelope.envelope_id().as_bytes().as_slice())
        .bind(i64::from(envelope.version().major()))
        .bind(i64::from(envelope.version().minor()))
        .bind(delivery_class_to_sql(envelope.delivery_class()))
        .bind(
            envelope
                .expected_parent_epoch()
                .map(to_sql_integer)
                .transpose()?,
        )
        .bind(to_sql_integer(envelope.expires_at_unix_seconds())?)
        .bind(encoded_envelope)
        .execute(&mut **transaction)
        .await
        .map_err(|_| storage_failure("schema v2 envelope migration"))?;
        last_envelope_id = Some(envelope.envelope_id().as_bytes().to_vec());
    }

    let old_count: i64 = sqlx::query_scalar("SELECT count(*) FROM relay_envelope")
        .fetch_one(&mut **transaction)
        .await
        .map_err(|_| storage_failure("schema v1 envelope count"))?;
    let new_count: i64 = sqlx::query_scalar("SELECT count(*) FROM relay_envelope_v2")
        .fetch_one(&mut **transaction)
        .await
        .map_err(|_| storage_failure("schema v2 envelope count"))?;
    if old_count != new_count {
        return Err(storage_failure("schema envelope migration count"));
    }
    sqlx::query("DROP TABLE relay_envelope")
        .execute(&mut **transaction)
        .await
        .map_err(|_| storage_failure("schema v1 envelope removal"))?;
    sqlx::query("ALTER TABLE relay_envelope_v2 RENAME TO relay_envelope")
        .execute(&mut **transaction)
        .await
        .map_err(|_| storage_failure("schema v2 envelope activation"))?;
    sqlx::query("PRAGMA user_version = 2")
        .execute(&mut **transaction)
        .await
        .map_err(|_| storage_failure("schema v2 version write"))?;
    Ok(())
}

fn envelope_from_v1_row(
    row: &sqlx::sqlite::SqliteRow,
    payload: Vec<u8>,
) -> Result<RelayEnvelope, RelayError> {
    Ok(RelayEnvelope::new(
        ProtocolVersion::new(
            from_sql_u32(row.try_get("version_major").map_err(invalid_row)?)?,
            from_sql_u32(row.try_get("version_minor").map_err(invalid_row)?)?,
        )?,
        RoutingId::from_slice(
            &row.try_get::<Vec<u8>, _>("routing_id")
                .map_err(invalid_row)?,
        )?,
        EnvelopeId::from_slice(
            &row.try_get::<Vec<u8>, _>("envelope_id")
                .map_err(invalid_row)?,
        )?,
        delivery_class_from_sql(row.try_get("delivery_class").map_err(invalid_row)?)?,
        optional_epoch_from_row(row, "expected_parent_epoch")?,
        from_sql_integer(
            row.try_get("expires_at_unix_seconds")
                .map_err(invalid_row)?,
        )?,
        payload,
    )?)
}

struct ReplaySelection {
    last_cursor: Option<u64>,
    count: usize,
    has_more: bool,
}

fn select_replay_rows(
    rows: &[sqlx::sqlite::SqliteRow],
    limit: usize,
) -> Result<ReplaySelection, RelayError> {
    let mut used_bytes = REPLAY_PAGE_FIXED_WIRE_BUDGET;
    let mut last_cursor = None;
    let mut count = 0;
    let mut has_more = false;
    for row in rows {
        let envelope_length = usize::try_from(
            row.try_get::<i64, _>("envelope_length")
                .map_err(invalid_row)?,
        )
        .map_err(|_| RelayError::InvalidStoredData)?;
        if !(1..=MAX_RELAY_ENVELOPE_BYTES).contains(&envelope_length) {
            return Err(RelayError::InvalidStoredData);
        }
        let row_budget = envelope_length
            .checked_add(STORED_ENVELOPE_WIRE_OVERHEAD_BUDGET)
            .ok_or(RelayError::InvalidStoredData)?;
        let next_used_bytes = used_bytes
            .checked_add(row_budget)
            .ok_or(RelayError::InvalidStoredData)?;
        if count == limit || next_used_bytes > MAX_REPLAY_PAGE_BYTES {
            has_more = true;
            break;
        }
        used_bytes = next_used_bytes;
        last_cursor = Some(from_sql_integer(
            row.try_get("cursor").map_err(invalid_row)?,
        )?);
        count += 1;
    }
    if last_cursor.is_none() && !rows.is_empty() {
        return Err(RelayError::InvalidStoredData);
    }
    Ok(ReplaySelection {
        last_cursor,
        count,
        has_more,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::{Arc, Mutex};

    use KonclaveDomainCore::{
        MAX_RELAY_PAYLOAD_BYTES, MAX_REPLAY_PAGE_BYTES, MAX_REPLAY_PAGE_SIZE,
    };
    use KonclaveProtocolContracts::v1::{
        decode_replay_page, encode_relay_envelope, encode_replay_page,
    };

    use super::*;
    use crate::{RelayAuthorizer, RelayClock, RelayPermission, RelayService};

    fn bytes<const N: usize>(value: u8) -> [u8; N] {
        [value; N]
    }

    fn envelope(
        route: u8,
        envelope: u8,
        class: DeliveryClass,
        parent: Option<u64>,
        payload: u8,
    ) -> RelayEnvelope {
        RelayEnvelope::new(
            ProtocolVersion::application_v1(),
            RoutingId::from_bytes(bytes(route)),
            EnvelopeId::from_bytes(bytes(envelope)),
            class,
            parent,
            100,
            vec![payload],
        )
        .unwrap()
    }

    async fn create_v1_pool(path: &Path) -> SqlitePool {
        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .foreign_keys(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
            .unwrap();
        sqlx::query(
            "CREATE TABLE relay_route (
                routing_id BLOB PRIMARY KEY,
                next_cursor INTEGER NOT NULL,
                current_epoch INTEGER NOT NULL
             ) WITHOUT ROWID",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "CREATE TABLE relay_envelope (
                routing_id BLOB NOT NULL,
                cursor INTEGER NOT NULL,
                envelope_id BLOB NOT NULL,
                version_major INTEGER NOT NULL,
                version_minor INTEGER NOT NULL,
                delivery_class INTEGER NOT NULL,
                expected_parent_epoch INTEGER,
                expires_at_unix_seconds INTEGER NOT NULL,
                payload BLOB NOT NULL,
                PRIMARY KEY (routing_id, cursor),
                UNIQUE (envelope_id)
             ) WITHOUT ROWID",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "CREATE TABLE relay_acknowledgment (
                routing_id BLOB NOT NULL,
                principal_id BLOB NOT NULL,
                cursor INTEGER NOT NULL,
                PRIMARY KEY (routing_id, principal_id)
             ) WITHOUT ROWID",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("PRAGMA user_version = 1")
            .execute(&pool)
            .await
            .unwrap();
        pool
    }

    async fn insert_v1_row(
        pool: &SqlitePool,
        envelope: &RelayEnvelope,
        cursor: u64,
        payload: &[u8],
    ) {
        sqlx::query(
            "INSERT INTO relay_route (routing_id, next_cursor, current_epoch)
             VALUES (?1, ?2, 0)
             ON CONFLICT(routing_id)
             DO UPDATE SET next_cursor = MAX(next_cursor, excluded.next_cursor)",
        )
        .bind(envelope.routing_id().as_bytes().as_slice())
        .bind(to_sql_integer(cursor + 1).unwrap())
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO relay_envelope (
                routing_id, cursor, envelope_id, version_major, version_minor,
                delivery_class, expected_parent_epoch, expires_at_unix_seconds, payload
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        )
        .bind(envelope.routing_id().as_bytes().as_slice())
        .bind(to_sql_integer(cursor).unwrap())
        .bind(envelope.envelope_id().as_bytes().as_slice())
        .bind(i64::from(envelope.version().major()))
        .bind(i64::from(envelope.version().minor()))
        .bind(delivery_class_to_sql(envelope.delivery_class()))
        .bind(
            envelope
                .expected_parent_epoch()
                .map(to_sql_integer)
                .transpose()
                .unwrap(),
        )
        .bind(to_sql_integer(envelope.expires_at_unix_seconds()).unwrap())
        .bind(payload)
        .execute(pool)
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn identical_retry_returns_original_cursor_and_conflict_fails() {
        let repository = SqliteRelayRepository::connect_memory().await.unwrap();
        let first = envelope(1, 2, DeliveryClass::GroupApplication, None, 3);
        let accepted = repository.submit(&first, 1).await.unwrap();
        let duplicate = repository.submit(&first, 1).await.unwrap();
        let expired_duplicate = repository.submit(&first, 101).await.unwrap();
        assert_eq!(accepted, SubmitResult::new(1, false));
        assert_eq!(duplicate, SubmitResult::new(1, true));
        assert_eq!(expired_duplicate, SubmitResult::new(1, true));

        let conflict = envelope(1, 2, DeliveryClass::GroupApplication, None, 4);
        assert_eq!(
            repository.submit(&conflict, 1).await.unwrap_err(),
            RelayError::IdempotencyConflict
        );
        let cross_route_conflict = envelope(9, 2, DeliveryClass::GroupApplication, None, 3);
        assert_eq!(
            repository
                .submit(&cross_route_conflict, 1)
                .await
                .unwrap_err(),
            RelayError::IdempotencyConflict
        );
        let cross_route_count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM relay_route WHERE routing_id = ?1")
                .bind(cross_route_conflict.routing_id().as_bytes().as_slice())
                .fetch_one(&repository.pool)
                .await
                .unwrap();
        assert_eq!(cross_route_count, 0);
        assert_eq!(
            repository
                .replay(ReplayRequest::new(first.routing_id(), 0, 100).unwrap())
                .await
                .unwrap()
                .envelopes()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn concurrent_identical_retry_assigns_one_cursor() {
        let directory = tempfile::tempdir().unwrap();
        let repository = SqliteRelayRepository::connect(&directory.path().join("relay.sqlite"))
            .await
            .unwrap();
        let submission = envelope(4, 1, DeliveryClass::GroupApplication, None, 1);
        let (first, second) = tokio::join!(
            repository.submit(&submission, 1),
            repository.submit(&submission, 1)
        );
        let outcomes = [first.unwrap(), second.unwrap()];
        assert_eq!(
            outcomes.iter().filter(|result| !result.duplicate()).count(),
            1
        );
        assert_eq!(
            outcomes.iter().filter(|result| result.duplicate()).count(),
            1
        );
        assert!(outcomes.iter().all(|result| result.cursor() == 1));
    }

    #[tokio::test]
    async fn commit_compare_and_set_selects_one_epoch_winner() {
        let directory = tempfile::tempdir().unwrap();
        let repository = SqliteRelayRepository::connect(&directory.path().join("relay.sqlite"))
            .await
            .unwrap();
        let first = envelope(5, 1, DeliveryClass::GroupCommit, Some(0), 1);
        let second = envelope(5, 2, DeliveryClass::GroupCommit, Some(0), 2);
        let (first, second) =
            tokio::join!(repository.submit(&first, 1), repository.submit(&second, 1));
        let outcomes = [first, second];
        assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            outcomes
                .iter()
                .filter(|result| matches!(result, Err(RelayError::StaleEpoch)))
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn proposals_check_without_advancing_the_epoch() {
        let repository = SqliteRelayRepository::connect_memory().await.unwrap();
        let first = envelope(6, 1, DeliveryClass::GroupProposal, Some(0), 1);
        let second = envelope(6, 2, DeliveryClass::GroupProposal, Some(0), 2);
        let commit = envelope(6, 3, DeliveryClass::GroupCommit, Some(0), 3);
        assert_eq!(
            repository.submit(&first, 1).await.unwrap(),
            SubmitResult::new(1, false)
        );
        assert_eq!(
            repository.submit(&second, 1).await.unwrap(),
            SubmitResult::new(2, false)
        );
        assert_eq!(
            repository.submit(&commit, 1).await.unwrap(),
            SubmitResult::new(3, false)
        );
        assert_eq!(
            repository.submit(&first, 101).await.unwrap(),
            SubmitResult::new(1, true)
        );
        assert_eq!(
            repository
                .submit(&envelope(6, 4, DeliveryClass::GroupProposal, Some(0), 4), 1,)
                .await
                .unwrap_err(),
            RelayError::StaleEpoch
        );
        assert_eq!(
            repository
                .submit(&envelope(6, 5, DeliveryClass::GroupProposal, Some(1), 5), 1,)
                .await
                .unwrap(),
            SubmitResult::new(4, false)
        );
    }

    #[tokio::test]
    async fn replay_is_ordered_bounded_and_acknowledgment_is_monotonic() {
        let repository = SqliteRelayRepository::connect_memory().await.unwrap();
        let route = RoutingId::from_bytes(bytes(7));
        for value in 1..=3 {
            repository
                .submit(
                    &envelope(7, value, DeliveryClass::GroupApplication, None, value),
                    1,
                )
                .await
                .unwrap();
        }
        let first = repository
            .replay(ReplayRequest::new(route, 0, 2).unwrap())
            .await
            .unwrap();
        assert_eq!(
            first
                .envelopes()
                .iter()
                .map(StoredRelayEnvelope::cursor)
                .collect::<Vec<_>>(),
            vec![1, 2]
        );
        assert!(first.has_more());
        let second = repository
            .replay(ReplayRequest::new(route, first.next_cursor(), 2).unwrap())
            .await
            .unwrap();
        assert_eq!(second.envelopes()[0].cursor(), 3);
        assert!(!second.has_more());

        let principal = RelayPrincipalId::from_bytes(bytes(9));
        assert_eq!(
            repository
                .acknowledge(principal, AcknowledgeRequest::new(route, 2).unwrap())
                .await
                .unwrap(),
            2
        );
        assert_eq!(
            repository
                .acknowledge(principal, AcknowledgeRequest::new(route, 1).unwrap())
                .await
                .unwrap(),
            2
        );
        assert_eq!(
            repository
                .acknowledge(principal, AcknowledgeRequest::new(route, 4).unwrap())
                .await
                .unwrap_err(),
            RelayError::InvalidAcknowledgment
        );
    }

    #[tokio::test]
    async fn replay_respects_the_encoded_page_byte_limit_before_loading_payloads() {
        let repository = SqliteRelayRepository::connect_memory().await.unwrap();
        let route = RoutingId::from_bytes(bytes(8));
        for value in 1..=17 {
            let envelope = RelayEnvelope::new(
                ProtocolVersion::application_v1(),
                route,
                EnvelopeId::from_bytes(bytes(value)),
                DeliveryClass::GroupApplication,
                None,
                100,
                vec![value; MAX_RELAY_PAYLOAD_BYTES],
            )
            .unwrap();
            repository.submit(&envelope, 1).await.unwrap();
        }

        let first = repository
            .replay(ReplayRequest::new(route, 0, MAX_REPLAY_PAGE_SIZE as u32).unwrap())
            .await
            .unwrap();
        assert_eq!(first.envelopes().len(), 16);
        assert!(first.has_more());
        assert!(encode_replay_page(&first).unwrap().len() <= MAX_REPLAY_PAGE_BYTES);

        let second = repository
            .replay(
                ReplayRequest::new(route, first.next_cursor(), MAX_REPLAY_PAGE_SIZE as u32)
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(second.envelopes().len(), 1);
        assert!(!second.has_more());
    }

    #[tokio::test]
    async fn replay_preserves_unknown_envelope_fields_exactly() {
        let repository = SqliteRelayRepository::connect_memory().await.unwrap();
        let envelope = envelope(12, 13, DeliveryClass::GroupApplication, None, 14);
        let mut encoded = encode_relay_envelope(&envelope).unwrap();
        encoded.extend_from_slice(&[0xa0, 0x06, 0x07]);
        repository
            .submit_encoded(&envelope, &encoded, 1)
            .await
            .unwrap();

        let replay = repository
            .replay_encoded(ReplayRequest::new(envelope.routing_id(), 0, 100).unwrap())
            .await
            .unwrap();
        assert!(
            replay
                .as_bytes()
                .windows(encoded.len())
                .any(|window| window == encoded)
        );
        assert_eq!(
            decode_replay_page(replay.as_bytes()).unwrap().next_cursor(),
            1
        );
    }

    #[tokio::test]
    async fn sequence_exhaustion_is_distinct_from_a_stale_epoch() {
        let repository = SqliteRelayRepository::connect_memory().await.unwrap();
        let route = RoutingId::from_bytes(bytes(10));
        repository
            .submit(
                &envelope(10, 1, DeliveryClass::GroupApplication, None, 1),
                1,
            )
            .await
            .unwrap();
        sqlx::query(
            "UPDATE relay_route SET next_cursor = ?1, current_epoch = 0 WHERE routing_id = ?2",
        )
        .bind(i64::MAX)
        .bind(route.as_bytes().as_slice())
        .execute(&repository.pool)
        .await
        .unwrap();

        assert_eq!(
            repository
                .submit(&envelope(10, 2, DeliveryClass::GroupCommit, Some(0), 2), 1,)
                .await
                .unwrap_err(),
            RelayError::SequenceExhausted
        );
        assert_eq!(
            repository
                .submit(&envelope(10, 3, DeliveryClass::GroupCommit, Some(1), 3), 1,)
                .await
                .unwrap_err(),
            RelayError::StaleEpoch
        );
    }

    #[tokio::test]
    async fn schema_is_versioned_and_rejects_newer_databases() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("relay.sqlite");
        let repository = SqliteRelayRepository::connect(&path).await.unwrap();
        let version: i64 = sqlx::query_scalar("PRAGMA user_version")
            .fetch_one(&repository.pool)
            .await
            .unwrap();
        assert_eq!(version, i64::from(SQLITE_SCHEMA_VERSION));
        repository.pool.close().await;

        let options = SqliteConnectOptions::new()
            .filename(&path)
            .create_if_missing(false);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
            .unwrap();
        sqlx::query("PRAGMA user_version = 3")
            .execute(&pool)
            .await
            .unwrap();
        pool.close().await;

        assert_eq!(
            SqliteRelayRepository::connect(&path).await.err(),
            Some(RelayError::UnsupportedSchemaVersion { actual: 3 })
        );
    }

    #[tokio::test]
    async fn schema_v1_migrates_existing_payloads_to_exact_envelope_bytes() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("relay.sqlite");
        let pool = create_v1_pool(&path).await;
        let envelope = envelope(15, 16, DeliveryClass::GroupApplication, None, 17);
        insert_v1_row(&pool, &envelope, 1, envelope.payload()).await;
        pool.close().await;

        let repository = SqliteRelayRepository::connect(&path).await.unwrap();
        let version: i64 = sqlx::query_scalar("PRAGMA user_version")
            .fetch_one(&repository.pool)
            .await
            .unwrap();
        assert_eq!(version, 2);
        let replay = repository
            .replay_encoded(ReplayRequest::new(envelope.routing_id(), 0, 100).unwrap())
            .await
            .unwrap();
        assert!(
            replay
                .as_bytes()
                .windows(envelope.payload().len())
                .any(|window| { window == envelope.payload() })
        );
        assert_eq!(
            decode_replay_page(replay.as_bytes()).unwrap().next_cursor(),
            1
        );
    }

    #[tokio::test]
    async fn failed_schema_v1_migration_rolls_back_every_change() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("relay.sqlite");
        let pool = create_v1_pool(&path).await;
        let valid = envelope(18, 1, DeliveryClass::GroupApplication, None, 19);
        let invalid = envelope(18, 2, DeliveryClass::GroupApplication, None, 20);
        insert_v1_row(&pool, &valid, 1, valid.payload()).await;
        insert_v1_row(&pool, &invalid, 2, &[]).await;
        pool.close().await;

        assert!(SqliteRelayRepository::connect(&path).await.is_err());

        let options = SqliteConnectOptions::new()
            .filename(&path)
            .create_if_missing(false);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
            .unwrap();
        let version: i64 = sqlx::query_scalar("PRAGMA user_version")
            .fetch_one(&pool)
            .await
            .unwrap();
        let old_count: i64 = sqlx::query_scalar("SELECT count(*) FROM relay_envelope")
            .fetch_one(&pool)
            .await
            .unwrap();
        let v2_table_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM sqlite_master
             WHERE type = 'table' AND name = 'relay_envelope_v2'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(version, 1);
        assert_eq!(old_count, 2);
        assert_eq!(v2_table_count, 0);
    }

    #[tokio::test]
    async fn database_contains_only_allowlisted_metadata_and_opaque_payloads() {
        let repository = SqliteRelayRepository::connect_memory().await.unwrap();
        let submission = envelope(11, 12, DeliveryClass::GroupApplication, None, 13);
        repository.submit(&submission, 1).await.unwrap();

        let columns = sqlx::query("PRAGMA table_info(relay_envelope)")
            .fetch_all(&repository.pool)
            .await
            .unwrap()
            .into_iter()
            .map(|row| row.try_get::<String, _>("name").unwrap())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            columns,
            [
                "cursor",
                "delivery_class",
                "encoded_envelope",
                "envelope_id",
                "expected_parent_epoch",
                "expires_at_unix_seconds",
                "routing_id",
                "version_major",
                "version_minor",
            ]
            .into_iter()
            .map(str::to_string)
            .collect()
        );
        let encoded: Vec<u8> = sqlx::query_scalar("SELECT encoded_envelope FROM relay_envelope")
            .fetch_one(&repository.pool)
            .await
            .unwrap();
        assert!(decode_relay_envelope(&encoded).unwrap() == submission);
    }

    #[tokio::test]
    async fn service_authorization_and_expiration_fail_before_new_storage() {
        let repository = SqliteRelayRepository::connect_memory().await.unwrap();
        let authorizer = TestAuthorizer::default();
        let service =
            RelayService::with_clock(repository.clone(), authorizer.clone(), FixedClock(5));
        let principal = RelayPrincipalId::from_bytes(bytes(1));
        let route = RoutingId::from_bytes(bytes(2));
        let denied = envelope(2, 1, DeliveryClass::GroupApplication, None, 3);
        assert_eq!(
            service.submit(principal, &denied).await.unwrap_err(),
            RelayError::Unauthorized
        );
        assert_eq!(
            service
                .replay(
                    principal,
                    ReplayRequest::new(route, 0, MAX_REPLAY_PAGE_SIZE as u32).unwrap(),
                )
                .await
                .err(),
            Some(RelayError::Unauthorized)
        );
        assert_eq!(
            service
                .acknowledge(principal, AcknowledgeRequest::new(route, 1).unwrap())
                .await
                .unwrap_err(),
            RelayError::Unauthorized
        );
        authorizer.allow(principal, route, RelayPermission::Send);
        let expired = RelayEnvelope::new(
            ProtocolVersion::application_v1(),
            route,
            EnvelopeId::from_bytes(bytes(2)),
            DeliveryClass::GroupApplication,
            None,
            5,
            vec![1],
        )
        .unwrap();
        assert_eq!(
            service.submit(principal, &expired).await.unwrap_err(),
            RelayError::ExpiredEnvelope
        );
        assert!(
            repository
                .replay(ReplayRequest::new(route, 0, MAX_REPLAY_PAGE_SIZE as u32).unwrap())
                .await
                .unwrap()
                .envelopes()
                .is_empty()
        );
        for table in ["relay_route", "relay_envelope", "relay_acknowledgment"] {
            let count: i64 = sqlx::query_scalar(&format!("SELECT count(*) FROM {table}"))
                .fetch_one(&repository.pool)
                .await
                .unwrap();
            assert_eq!(count, 0);
        }
    }

    #[derive(Clone, Default)]
    struct TestAuthorizer {
        permissions: Arc<Mutex<BTreeSet<(RelayPrincipalId, RoutingId, RelayPermission)>>>,
    }

    impl TestAuthorizer {
        fn allow(
            &self,
            principal: RelayPrincipalId,
            route: RoutingId,
            permission: RelayPermission,
        ) {
            self.permissions
                .lock()
                .unwrap()
                .insert((principal, route, permission));
        }
    }

    #[async_trait]
    impl RelayAuthorizer for TestAuthorizer {
        async fn authorize(
            &self,
            principal: RelayPrincipalId,
            routing_id: RoutingId,
            permission: RelayPermission,
        ) -> Result<(), RelayError> {
            if self
                .permissions
                .lock()
                .unwrap()
                .contains(&(principal, routing_id, permission))
            {
                Ok(())
            } else {
                Err(RelayError::Unauthorized)
            }
        }
    }

    #[derive(Clone, Copy)]
    struct FixedClock(u64);

    impl RelayClock for FixedClock {
        fn now_unix_seconds(&self) -> Result<u64, RelayError> {
            Ok(self.0)
        }
    }
}
