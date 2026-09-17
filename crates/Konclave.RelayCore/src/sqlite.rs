use std::path::Path;
use std::time::Duration;

use KonclaveDomainCore::{
    AcknowledgeRequest, DeliveryClass, EnvelopeId, MAX_RELAY_ENVELOPE_BYTES,
    MAX_RELAY_PAYLOAD_BYTES, MAX_REPLAY_PAGE_BYTES, PairingRendezvousId, PairingRendezvousNonce,
    PairingRendezvousRecord, PairingRendezvousTakeRequest, ProtocolVersion, RelayEnvelope,
    ReplayPage, ReplayRequest, RoutingId, ShortCodeAttemptClaimRequest,
    ShortCodeAttemptMessageRequest, ShortCodeAttemptPublishRequest, ShortCodeAttemptReadRequest,
    ShortCodeAttemptSnapshot, ShortCodeCapabilityTakeId, ShortCodeCapabilityTakeRequest,
    ShortCodePairingAttemptId, ShortCodePairingLocator, ShortCodeRelayMessage, ShortCodeRelayStage,
    StoredRelayEnvelope,
};
use KonclaveProtocolContracts::v1::{
    decode_relay_envelope, encode_relay_envelope, encode_replay_page_preserving,
};
use KonclaveRelayAuthentication::{
    EnrollmentRequestId, RelayEnrollmentOutcome, RelayEnrollmentRequest, RelayEnrollmentResponse,
    RelayPrincipalId,
};
use async_trait::async_trait;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use sqlx::{Row, SqlitePool};

use crate::{
    EncodedReplayPage, PairingRendezvousPublishDecision, PairingRendezvousPublishOutcome,
    PairingRendezvousRepository, RelayError, RelayPrincipalRegistry, RelayRepository,
    ShortCodeAttemptMessageOutcome, ShortCodeAttemptPublishOutcome, ShortCodeClaimDecision,
    ShortCodeMessageDecision, ShortCodePairingRepository, ShortCodePublishDecision,
    StoredPairingRendezvous, StoredShortCodeAttempt, SubmitResult, authorize_short_code_cancel,
    authorize_short_code_read, decide_pairing_rendezvous_publish, decide_pairing_rendezvous_take,
    decide_short_code_capability_take, decide_short_code_claim, decide_short_code_message,
    decide_short_code_publish,
};

const SQLITE_SCHEMA_VERSION: u32 = 7;
const MAX_ACTIVE_DYNAMIC_PRINCIPALS: i64 = 1_024;
const MAX_DYNAMIC_PRINCIPAL_RECORDS: i64 = 4_096;
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

#[async_trait]
impl PairingRendezvousRepository for SqliteRelayRepository {
    async fn publish_pairing_rendezvous(
        &self,
        principal: RelayPrincipalId,
        record: PairingRendezvousRecord,
        now_unix_seconds: u64,
    ) -> Result<PairingRendezvousPublishOutcome, RelayError> {
        if record.expires_at_unix_seconds() <= now_unix_seconds {
            return Err(RelayError::ExpiredPairingRendezvous);
        }
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| storage_failure("pairing rendezvous publish transaction begin"))?;
        cleanup_expired_pairing_rendezvous(
            &mut transaction,
            now_unix_seconds,
            Some(record.lookup_id()),
        )
        .await?;
        let existing = load_pairing_rendezvous(&mut transaction, record.lookup_id()).await?;
        let requires_capacity = existing
            .as_ref()
            .is_none_or(|existing| existing.record().expires_at_unix_seconds() <= now_unix_seconds);
        let (active_global_count, active_principal_count) = if requires_capacity {
            active_pairing_rendezvous_counts(&mut transaction, principal, now_unix_seconds).await?
        } else {
            (0, 0)
        };
        let decision = decide_pairing_rendezvous_publish(
            principal,
            &record,
            existing.as_ref(),
            now_unix_seconds,
            active_global_count,
            active_principal_count,
        )?;
        if decision == PairingRendezvousPublishDecision::Identical {
            transaction
                .commit()
                .await
                .map_err(|_| storage_failure("identical pairing rendezvous publish commit"))?;
            return Ok(PairingRendezvousPublishOutcome::AlreadyPublished);
        }
        if decision == PairingRendezvousPublishDecision::ReplaceExpired {
            sqlx::query("DELETE FROM relay_pairing_rendezvous WHERE lookup_id = ?1")
                .bind(record.lookup_id().as_bytes().as_slice())
                .execute(&mut *transaction)
                .await
                .map_err(|_| storage_failure("expired pairing rendezvous replacement"))?;
        }
        insert_pairing_rendezvous(&mut transaction, principal, &record).await?;
        transaction
            .commit()
            .await
            .map_err(|_| storage_failure("pairing rendezvous publish commit"))?;
        Ok(PairingRendezvousPublishOutcome::Published)
    }

    async fn take_pairing_rendezvous(
        &self,
        request: PairingRendezvousTakeRequest,
        now_unix_seconds: u64,
    ) -> Result<PairingRendezvousRecord, RelayError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| storage_failure("pairing rendezvous take transaction begin"))?;
        cleanup_expired_pairing_rendezvous(
            &mut transaction,
            now_unix_seconds,
            Some(request.lookup_id()),
        )
        .await?;
        let existing = load_pairing_rendezvous(&mut transaction, request.lookup_id()).await?;
        if let Err(error) = decide_pairing_rendezvous_take(existing.as_ref(), now_unix_seconds) {
            if existing.as_ref().is_some_and(|existing| {
                existing.record().expires_at_unix_seconds() <= now_unix_seconds
            }) {
                sqlx::query("DELETE FROM relay_pairing_rendezvous WHERE lookup_id = ?1")
                    .bind(request.lookup_id().as_bytes().as_slice())
                    .execute(&mut *transaction)
                    .await
                    .map_err(|_| storage_failure("expired pairing rendezvous cleanup"))?;
                transaction
                    .commit()
                    .await
                    .map_err(|_| storage_failure("expired pairing rendezvous take commit"))?;
            }
            return Err(error);
        }
        let existing = existing.ok_or(RelayError::PairingRendezvousUnavailable)?;
        let deleted = sqlx::query("DELETE FROM relay_pairing_rendezvous WHERE lookup_id = ?1")
            .bind(request.lookup_id().as_bytes().as_slice())
            .execute(&mut *transaction)
            .await
            .map_err(|_| storage_failure("pairing rendezvous atomic take"))?
            .rows_affected();
        if deleted != 1 {
            return Err(storage_failure("pairing rendezvous atomic take outcome"));
        }
        transaction
            .commit()
            .await
            .map_err(|_| storage_failure("pairing rendezvous take commit"))?;
        Ok(existing.into_record())
    }
}

#[async_trait]
impl ShortCodePairingRepository for SqliteRelayRepository {
    async fn publish_short_code_attempt(
        &self,
        principal: RelayPrincipalId,
        request: ShortCodeAttemptPublishRequest,
        now_unix_seconds: u64,
    ) -> Result<ShortCodeAttemptPublishOutcome, RelayError> {
        if request.deadline_unix_seconds() <= now_unix_seconds {
            return Err(RelayError::ExpiredShortCodeAttempt);
        }
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| storage_failure("short-code publish transaction begin"))?;
        cleanup_short_code_state(&mut transaction, now_unix_seconds).await?;
        let existing = load_short_code_attempt(
            &mut transaction,
            Some(request.locator()),
            Some(request.attempt_id()),
        )
        .await?;
        let counts =
            active_short_code_counts(&mut transaction, principal, now_unix_seconds).await?;
        match decide_short_code_publish(
            principal,
            request,
            existing.as_ref(),
            now_unix_seconds,
            counts.0,
            counts.1,
        )? {
            ShortCodePublishDecision::Identical => {
                transaction
                    .commit()
                    .await
                    .map_err(|_| storage_failure("identical short-code publish commit"))?;
                Ok(ShortCodeAttemptPublishOutcome::AlreadyPublished)
            }
            ShortCodePublishDecision::Insert => {
                insert_short_code_attempt(&mut transaction, principal, request).await?;
                transaction
                    .commit()
                    .await
                    .map_err(|_| storage_failure("short-code publish commit"))?;
                Ok(ShortCodeAttemptPublishOutcome::Published)
            }
        }
    }

    async fn claim_short_code_attempt(
        &self,
        principal: RelayPrincipalId,
        request: ShortCodeAttemptClaimRequest,
        now_unix_seconds: u64,
    ) -> Result<ShortCodeAttemptSnapshot, RelayError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| storage_failure("short-code claim transaction begin"))?;
        cleanup_short_code_state(&mut transaction, now_unix_seconds).await?;
        let existing =
            load_short_code_attempt(&mut transaction, Some(request.locator()), None).await?;
        let counts = short_code_claim_counts(
            &mut transaction,
            principal,
            request.locator(),
            now_unix_seconds,
        )
        .await?;
        let decision = decide_short_code_claim(
            principal,
            &request,
            existing.as_ref(),
            now_unix_seconds,
            counts.0,
            counts.1,
        );
        match decision {
            Ok(ShortCodeClaimDecision::Identical) => {}
            Ok(ShortCodeClaimDecision::Claim) => {
                record_short_code_claim(
                    &mut transaction,
                    principal,
                    request.locator(),
                    now_unix_seconds,
                )
                .await?;
                let attempt = existing
                    .as_ref()
                    .ok_or(RelayError::ShortCodeAttemptUnavailable)?;
                update_short_code_claim(
                    &mut transaction,
                    attempt.publish().attempt_id(),
                    principal,
                    request.payload(),
                )
                .await?;
            }
            Err(error) => {
                if error == RelayError::ShortCodeAttemptUnavailable
                    && counts.0 < crate::MAX_SHORT_CODE_CLAIMS_PER_PRINCIPAL_WINDOW
                    && counts.1 < crate::MAX_SHORT_CODE_CLAIMS_PER_LOCATOR_WINDOW
                {
                    record_short_code_claim(
                        &mut transaction,
                        principal,
                        request.locator(),
                        now_unix_seconds,
                    )
                    .await?;
                    transaction
                        .commit()
                        .await
                        .map_err(|_| storage_failure("unavailable short-code claim commit"))?;
                }
                return Err(error);
            }
        }
        let attempt_id = existing
            .as_ref()
            .ok_or(RelayError::ShortCodeAttemptUnavailable)?
            .publish()
            .attempt_id();
        let stored = load_short_code_attempt(&mut transaction, None, Some(attempt_id))
            .await?
            .ok_or(RelayError::InvalidStoredData)?;
        let snapshot = short_code_snapshot(&stored)?;
        transaction
            .commit()
            .await
            .map_err(|_| storage_failure("short-code claim commit"))?;
        Ok(snapshot)
    }

    async fn publish_short_code_message(
        &self,
        principal: RelayPrincipalId,
        request: ShortCodeAttemptMessageRequest,
        now_unix_seconds: u64,
    ) -> Result<ShortCodeAttemptMessageOutcome, RelayError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| storage_failure("short-code message transaction begin"))?;
        cleanup_short_code_state(&mut transaction, now_unix_seconds).await?;
        let existing = load_short_code_attempt(&mut transaction, None, Some(request.attempt_id()))
            .await?
            .ok_or(RelayError::ShortCodeAttemptUnavailable)?;
        match decide_short_code_message(principal, &request, &existing, now_unix_seconds)? {
            ShortCodeMessageDecision::Identical => {
                transaction
                    .commit()
                    .await
                    .map_err(|_| storage_failure("identical short-code message commit"))?;
                Ok(ShortCodeAttemptMessageOutcome::AlreadyPublished)
            }
            ShortCodeMessageDecision::Insert => {
                insert_short_code_message(&mut transaction, &request).await?;
                transaction
                    .commit()
                    .await
                    .map_err(|_| storage_failure("short-code message commit"))?;
                Ok(ShortCodeAttemptMessageOutcome::Published)
            }
        }
    }

    async fn read_short_code_attempt(
        &self,
        principal: RelayPrincipalId,
        request: ShortCodeAttemptReadRequest,
        now_unix_seconds: u64,
    ) -> Result<ShortCodeAttemptSnapshot, RelayError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| storage_failure("short-code read transaction begin"))?;
        cleanup_short_code_state(&mut transaction, now_unix_seconds).await?;
        let stored = load_short_code_attempt(&mut transaction, None, Some(request.attempt_id()))
            .await?
            .ok_or(RelayError::ShortCodeAttemptUnavailable)?;
        authorize_short_code_read(principal, request, &stored, now_unix_seconds)?;
        let snapshot = short_code_snapshot(&stored)?;
        transaction
            .commit()
            .await
            .map_err(|_| storage_failure("short-code read commit"))?;
        Ok(snapshot)
    }

    async fn cancel_short_code_attempt(
        &self,
        principal: RelayPrincipalId,
        request: ShortCodeAttemptReadRequest,
        now_unix_seconds: u64,
    ) -> Result<(), RelayError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| storage_failure("short-code cancel transaction begin"))?;
        cleanup_short_code_state(&mut transaction, now_unix_seconds).await?;
        let stored = load_short_code_attempt(&mut transaction, None, Some(request.attempt_id()))
            .await?
            .ok_or(RelayError::ShortCodeAttemptUnavailable)?;
        authorize_short_code_cancel(principal, request, &stored)?;
        sqlx::query(
            "UPDATE relay_short_code_attempt
                 SET cancelled = 1
                 WHERE attempt_id = ?1",
        )
        .bind(request.attempt_id().as_bytes().as_slice())
        .execute(&mut *transaction)
        .await
        .map_err(|_| storage_failure("short-code cancellation"))?;
        transaction
            .commit()
            .await
            .map_err(|_| storage_failure("short-code cancel commit"))
    }

    async fn take_short_code_capability(
        &self,
        principal: RelayPrincipalId,
        request: ShortCodeCapabilityTakeRequest,
        now_unix_seconds: u64,
    ) -> Result<Vec<u8>, RelayError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| storage_failure("short-code capability transaction begin"))?;
        cleanup_short_code_state(&mut transaction, now_unix_seconds).await?;
        let stored = load_short_code_attempt(&mut transaction, None, Some(request.attempt_id()))
            .await?
            .ok_or(RelayError::ShortCodeAttemptUnavailable)?;
        let decision =
            decide_short_code_capability_take(principal, request, &stored, now_unix_seconds)?;
        let payload = stored
            .message(ShortCodeRelayStage::Capability)
            .ok_or(RelayError::InvalidStoredData)?
            .to_vec();
        if decision == crate::ShortCodeCapabilityDecision::Consume {
            let updated = sqlx::query(
                "UPDATE relay_short_code_attempt
                 SET capability_consumed = 1,
                     capability_take_id = ?2
                 WHERE attempt_id = ?1
                   AND capability_consumed = 0
                   AND capability_take_id IS NULL",
            )
            .bind(request.attempt_id().as_bytes().as_slice())
            .bind(request.take_id().as_bytes().as_slice())
            .execute(&mut *transaction)
            .await
            .map_err(|_| storage_failure("short-code capability consumption"))?
            .rows_affected();
            if updated != 1 {
                return Err(storage_failure("short-code capability outcome"));
            }
        }
        transaction
            .commit()
            .await
            .map_err(|_| storage_failure("short-code capability commit"))?;
        Ok(payload)
    }
}

#[async_trait]
impl RelayPrincipalRegistry for SqliteRelayRepository {
    async fn register_principal(
        &self,
        request: RelayEnrollmentRequest,
    ) -> Result<RelayEnrollmentResponse, RelayError> {
        if request.version().major() != 1 {
            return Err(RelayError::UnsupportedEnrollmentVersion);
        }
        let inserted = sqlx::query(
            "INSERT INTO relay_dynamic_principal (principal_id, request_id, status)
             SELECT ?1, ?2, 1
             WHERE (SELECT count(*) FROM relay_dynamic_principal WHERE status = 1) < ?3
               AND (SELECT count(*) FROM relay_dynamic_principal) < ?4
             ON CONFLICT DO NOTHING",
        )
        .bind(request.principal_id().as_bytes().as_slice())
        .bind(request.request_id().as_bytes().as_slice())
        .bind(MAX_ACTIVE_DYNAMIC_PRINCIPALS)
        .bind(MAX_DYNAMIC_PRINCIPAL_RECORDS)
        .execute(&self.pool)
        .await
        .map_err(|_| storage_failure("dynamic principal registration"))?
        .rows_affected();
        let outcome = if inserted == 1 {
            RelayEnrollmentOutcome::Registered
        } else {
            self.classify_principal_registration(request).await?
        };
        Ok(RelayEnrollmentResponse::new(
            request.version(),
            request.request_id(),
            request.principal_id(),
            outcome,
        ))
    }

    async fn is_principal_active(&self, principal: RelayPrincipalId) -> Result<bool, RelayError> {
        let status: Option<i64> = sqlx::query_scalar(
            "SELECT status FROM relay_dynamic_principal WHERE principal_id = ?1",
        )
        .bind(principal.as_bytes().as_slice())
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| storage_failure("dynamic principal status query"))?;
        match status {
            None | Some(2) => Ok(false),
            Some(1) => Ok(true),
            Some(_) => Err(RelayError::InvalidStoredData),
        }
    }

    async fn revoke_principal(&self, principal: RelayPrincipalId) -> Result<bool, RelayError> {
        let changed = sqlx::query(
            "UPDATE relay_dynamic_principal
             SET status = 2
             WHERE principal_id = ?1 AND status = 1",
        )
        .bind(principal.as_bytes().as_slice())
        .execute(&self.pool)
        .await
        .map_err(|_| storage_failure("dynamic principal revocation"))?
        .rows_affected();
        Ok(changed == 1)
    }
}

impl SqliteRelayRepository {
    async fn classify_principal_registration(
        &self,
        request: RelayEnrollmentRequest,
    ) -> Result<RelayEnrollmentOutcome, RelayError> {
        let rows = sqlx::query(
            "SELECT
                CASE WHEN length(principal_id) = 32 THEN principal_id END AS principal_id,
                CASE WHEN length(request_id) = 16 THEN request_id END AS request_id,
                status
             FROM relay_dynamic_principal
             WHERE principal_id = ?1 OR request_id = ?2
             LIMIT 2",
        )
        .bind(request.principal_id().as_bytes().as_slice())
        .bind(request.request_id().as_bytes().as_slice())
        .fetch_all(&self.pool)
        .await
        .map_err(|_| storage_failure("dynamic principal conflict classification"))?;
        for row in &rows {
            let principal = RelayPrincipalId::from_slice(
                &row.try_get::<Vec<u8>, _>("principal_id")
                    .map_err(invalid_row)?,
            )
            .map_err(|_| RelayError::InvalidStoredData)?;
            let request_id = EnrollmentRequestId::from_slice(
                &row.try_get::<Vec<u8>, _>("request_id")
                    .map_err(invalid_row)?,
            )
            .map_err(|_| RelayError::InvalidStoredData)?;
            let status: i64 = row.try_get("status").map_err(invalid_row)?;
            if principal == request.principal_id() && request_id == request.request_id() {
                return match status {
                    1 => Ok(RelayEnrollmentOutcome::AlreadyRegistered),
                    2 => Err(RelayError::PrincipalRevoked),
                    _ => Err(RelayError::InvalidStoredData),
                };
            }
        }
        if !rows.is_empty() {
            return Err(RelayError::EnrollmentConflict);
        }
        let counts: (i64, i64) = sqlx::query_as(
            "SELECT
                count(*) FILTER (WHERE status = 1),
                count(*)
             FROM relay_dynamic_principal",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|_| storage_failure("dynamic principal capacity query"))?;
        if counts.0 >= MAX_ACTIVE_DYNAMIC_PRINCIPALS || counts.1 >= MAX_DYNAMIC_PRINCIPAL_RECORDS {
            Err(RelayError::PrincipalCapacityExceeded)
        } else {
            Err(storage_failure("dynamic principal registration outcome"))
        }
    }

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
        DeliveryClass::KeyPackage
        | DeliveryClass::Welcome
        | DeliveryClass::GroupApplication
        | DeliveryClass::Pairing => sqlx::query_scalar(
            "UPDATE relay_route
                 SET next_cursor = next_cursor + 1
                 WHERE routing_id = ?1 AND next_cursor < ?2
                 RETURNING next_cursor - 1",
        )
        .bind(envelope.routing_id().as_bytes().as_slice())
        .bind(i64::MAX)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|_| storage_failure("cursor allocation"))?,
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
        DeliveryClass::Pairing => 6,
    }
}

fn delivery_class_from_sql(value: i64) -> Result<DeliveryClass, RelayError> {
    match value {
        1 => Ok(DeliveryClass::KeyPackage),
        2 => Ok(DeliveryClass::Welcome),
        3 => Ok(DeliveryClass::GroupProposal),
        4 => Ok(DeliveryClass::GroupCommit),
        5 => Ok(DeliveryClass::GroupApplication),
        6 => Ok(DeliveryClass::Pairing),
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

async fn cleanup_expired_pairing_rendezvous(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    now_unix_seconds: u64,
    excluded_lookup_id: Option<PairingRendezvousId>,
) -> Result<(), RelayError> {
    // Callers use this as the first statement so SQLite serializes the following
    // capacity or take decision as a write transaction.
    let excluded_lookup_id = excluded_lookup_id.map(PairingRendezvousId::into_bytes);
    sqlx::query(
        "DELETE FROM relay_pairing_rendezvous
         WHERE expires_at_unix_seconds <= ?1
           AND (?2 IS NULL OR lookup_id <> ?2)",
    )
    .bind(to_sql_integer(now_unix_seconds)?)
    .bind(excluded_lookup_id.as_ref().map(<[u8; 32]>::as_slice))
    .execute(&mut **transaction)
    .await
    .map_err(|_| storage_failure("expired pairing rendezvous cleanup"))?;
    Ok(())
}

async fn active_pairing_rendezvous_counts(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    principal: RelayPrincipalId,
    now_unix_seconds: u64,
) -> Result<(usize, usize), RelayError> {
    let counts: (i64, i64) = sqlx::query_as(
        "SELECT
            count(*),
            count(*) FILTER (WHERE owner_principal_id = ?2)
         FROM relay_pairing_rendezvous
         WHERE expires_at_unix_seconds > ?1",
    )
    .bind(to_sql_integer(now_unix_seconds)?)
    .bind(principal.as_bytes().as_slice())
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| storage_failure("pairing rendezvous capacity query"))?;
    Ok((
        usize::try_from(counts.0).map_err(|_| RelayError::InvalidStoredData)?,
        usize::try_from(counts.1).map_err(|_| RelayError::InvalidStoredData)?,
    ))
}

async fn load_pairing_rendezvous(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    lookup_id: PairingRendezvousId,
) -> Result<Option<StoredPairingRendezvous>, RelayError> {
    let row = sqlx::query(
        "SELECT
            CASE WHEN length(lookup_id) = 32 THEN lookup_id END AS lookup_id,
            CASE WHEN length(owner_principal_id) = 32 THEN owner_principal_id END
                AS owner_principal_id,
            version_major,
            version_minor,
            expires_at_unix_seconds,
            CASE WHEN length(nonce) = 12 THEN nonce END AS nonce,
            ciphertext
         FROM relay_pairing_rendezvous
         WHERE lookup_id = ?1",
    )
    .bind(lookup_id.as_bytes().as_slice())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| storage_failure("pairing rendezvous query"))?;
    let Some(row) = row else {
        return Ok(None);
    };
    let stored_lookup_id = PairingRendezvousId::from_slice(
        &row.try_get::<Vec<u8>, _>("lookup_id")
            .map_err(invalid_row)?,
    )
    .map_err(|_| RelayError::InvalidStoredData)?;
    let owner = RelayPrincipalId::from_slice(
        &row.try_get::<Vec<u8>, _>("owner_principal_id")
            .map_err(invalid_row)?,
    )
    .map_err(|_| RelayError::InvalidStoredData)?;
    let version = ProtocolVersion::new(
        from_sql_u32(row.try_get("version_major").map_err(invalid_row)?)?,
        from_sql_u32(row.try_get("version_minor").map_err(invalid_row)?)?,
    )
    .map_err(|_| RelayError::InvalidStoredData)?;
    let expires_at_unix_seconds = from_sql_integer(
        row.try_get("expires_at_unix_seconds")
            .map_err(invalid_row)?,
    )?;
    let nonce = PairingRendezvousNonce::from_slice(
        &row.try_get::<Vec<u8>, _>("nonce").map_err(invalid_row)?,
    )
    .map_err(|_| RelayError::InvalidStoredData)?;
    let ciphertext = row
        .try_get::<Vec<u8>, _>("ciphertext")
        .map_err(invalid_row)?;
    let record = PairingRendezvousRecord::new(
        version,
        stored_lookup_id,
        expires_at_unix_seconds,
        nonce,
        ciphertext,
    )
    .map_err(|_| RelayError::InvalidStoredData)?;
    Ok(Some(StoredPairingRendezvous::new(owner, record)))
}

async fn insert_pairing_rendezvous(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    principal: RelayPrincipalId,
    record: &PairingRendezvousRecord,
) -> Result<(), RelayError> {
    sqlx::query(
        "INSERT INTO relay_pairing_rendezvous (
            lookup_id,
            owner_principal_id,
            version_major,
            version_minor,
            expires_at_unix_seconds,
            nonce,
            ciphertext
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
    )
    .bind(record.lookup_id().as_bytes().as_slice())
    .bind(principal.as_bytes().as_slice())
    .bind(i64::from(record.version().major()))
    .bind(i64::from(record.version().minor()))
    .bind(to_sql_integer(record.expires_at_unix_seconds())?)
    .bind(record.nonce().as_bytes().as_slice())
    .bind(record.ciphertext())
    .execute(&mut **transaction)
    .await
    .map_err(|_| storage_failure("pairing rendezvous insert"))?;
    Ok(())
}

async fn cleanup_short_code_state(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    now_unix_seconds: u64,
) -> Result<(), RelayError> {
    sqlx::query("DELETE FROM relay_short_code_attempt WHERE deadline_unix_seconds <= ?1")
        .bind(to_sql_integer(now_unix_seconds)?)
        .execute(&mut **transaction)
        .await
        .map_err(|_| storage_failure("expired short-code cleanup"))?;
    let window = short_code_claim_window(now_unix_seconds)?;
    sqlx::query("DELETE FROM relay_short_code_claim_rate WHERE window_start < ?1")
        .bind(window)
        .execute(&mut **transaction)
        .await
        .map_err(|_| storage_failure("short-code rate cleanup"))?;
    Ok(())
}

async fn active_short_code_counts(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    principal: RelayPrincipalId,
    now_unix_seconds: u64,
) -> Result<(usize, usize), RelayError> {
    let counts: (i64, i64) = sqlx::query_as(
        "SELECT
            count(*),
            count(*) FILTER (WHERE owner_principal_id = ?2)
         FROM relay_short_code_attempt
         WHERE deadline_unix_seconds > ?1 AND cancelled = 0",
    )
    .bind(to_sql_integer(now_unix_seconds)?)
    .bind(principal.as_bytes().as_slice())
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| storage_failure("short-code capacity query"))?;
    Ok((
        usize::try_from(counts.0).map_err(|_| RelayError::InvalidStoredData)?,
        usize::try_from(counts.1).map_err(|_| RelayError::InvalidStoredData)?,
    ))
}

async fn short_code_claim_counts(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    principal: RelayPrincipalId,
    locator: ShortCodePairingLocator,
    now_unix_seconds: u64,
) -> Result<(usize, usize), RelayError> {
    let window = short_code_claim_window(now_unix_seconds)?;
    let counts: (i64, i64) = sqlx::query_as(
        "SELECT
            COALESCE(sum(attempts) FILTER (WHERE principal_id = ?1), 0),
            COALESCE(sum(attempts) FILTER (WHERE locator = ?2), 0)
         FROM relay_short_code_claim_rate
         WHERE window_start = ?3",
    )
    .bind(principal.as_bytes().as_slice())
    .bind(locator.as_bytes().as_slice())
    .bind(window)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| storage_failure("short-code claim count"))?;
    Ok((
        usize::try_from(counts.0).map_err(|_| RelayError::InvalidStoredData)?,
        usize::try_from(counts.1).map_err(|_| RelayError::InvalidStoredData)?,
    ))
}

async fn record_short_code_claim(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    principal: RelayPrincipalId,
    locator: ShortCodePairingLocator,
    now_unix_seconds: u64,
) -> Result<(), RelayError> {
    sqlx::query(
        "INSERT INTO relay_short_code_claim_rate (
            locator,
            principal_id,
            window_start,
            attempts
         ) VALUES (?1, ?2, ?3, 1)
         ON CONFLICT(locator, principal_id, window_start)
         DO UPDATE SET attempts = attempts + 1",
    )
    .bind(locator.as_bytes().as_slice())
    .bind(principal.as_bytes().as_slice())
    .bind(short_code_claim_window(now_unix_seconds)?)
    .execute(&mut **transaction)
    .await
    .map_err(|_| storage_failure("short-code claim rate update"))?;
    Ok(())
}

async fn insert_short_code_attempt(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    principal: RelayPrincipalId,
    request: ShortCodeAttemptPublishRequest,
) -> Result<(), RelayError> {
    sqlx::query(
        "INSERT INTO relay_short_code_attempt (
            locator,
            attempt_id,
            owner_principal_id,
            claimant_principal_id,
            version_major,
            version_minor,
            deadline_unix_seconds,
            cancelled,
            capability_consumed
         ) VALUES (?1, ?2, ?3, NULL, ?4, ?5, ?6, 0, 0)",
    )
    .bind(request.locator().as_bytes().as_slice())
    .bind(request.attempt_id().as_bytes().as_slice())
    .bind(principal.as_bytes().as_slice())
    .bind(i64::from(request.version().major()))
    .bind(i64::from(request.version().minor()))
    .bind(to_sql_integer(request.deadline_unix_seconds())?)
    .execute(&mut **transaction)
    .await
    .map_err(|_| storage_failure("short-code attempt insert"))?;
    Ok(())
}

async fn update_short_code_claim(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    attempt_id: ShortCodePairingAttemptId,
    claimant: RelayPrincipalId,
    payload: &[u8],
) -> Result<(), RelayError> {
    let updated = sqlx::query(
        "UPDATE relay_short_code_attempt
         SET claimant_principal_id = ?2
         WHERE attempt_id = ?1 AND claimant_principal_id IS NULL",
    )
    .bind(attempt_id.as_bytes().as_slice())
    .bind(claimant.as_bytes().as_slice())
    .execute(&mut **transaction)
    .await
    .map_err(|_| storage_failure("short-code claimant update"))?
    .rows_affected();
    if updated != 1 {
        return Err(storage_failure("short-code claimant outcome"));
    }
    sqlx::query(
        "INSERT INTO relay_short_code_message (attempt_id, stage, payload)
         VALUES (?1, ?2, ?3)",
    )
    .bind(attempt_id.as_bytes().as_slice())
    .bind(short_code_stage_to_sql(
        ShortCodeRelayStage::CredentialRequest,
    ))
    .bind(payload)
    .execute(&mut **transaction)
    .await
    .map_err(|_| storage_failure("short-code credential request insert"))?;
    Ok(())
}

async fn insert_short_code_message(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    request: &ShortCodeAttemptMessageRequest,
) -> Result<(), RelayError> {
    sqlx::query(
        "INSERT INTO relay_short_code_message (attempt_id, stage, payload)
         VALUES (?1, ?2, ?3)",
    )
    .bind(request.attempt_id().as_bytes().as_slice())
    .bind(short_code_stage_to_sql(request.stage()))
    .bind(request.payload())
    .execute(&mut **transaction)
    .await
    .map_err(|_| storage_failure("short-code message insert"))?;
    Ok(())
}

async fn load_short_code_attempt(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    locator: Option<ShortCodePairingLocator>,
    attempt_id: Option<ShortCodePairingAttemptId>,
) -> Result<Option<StoredShortCodeAttempt>, RelayError> {
    let locator_bytes = locator.map(ShortCodePairingLocator::into_bytes);
    let attempt_bytes = attempt_id.map(ShortCodePairingAttemptId::into_bytes);
    let rows = sqlx::query(
        "SELECT
            CASE WHEN length(locator) = 32 THEN locator END AS locator,
            CASE WHEN length(attempt_id) = 16 THEN attempt_id END AS attempt_id,
            CASE WHEN length(owner_principal_id) = 32 THEN owner_principal_id END
                AS owner_principal_id,
            CASE
                WHEN claimant_principal_id IS NULL THEN NULL
                WHEN length(claimant_principal_id) = 32 THEN claimant_principal_id
            END AS claimant_principal_id,
            version_major,
            version_minor,
            deadline_unix_seconds,
            cancelled,
            capability_consumed,
            typeof(capability_take_id) AS capability_take_id_type,
            length(capability_take_id) AS capability_take_id_length,
            CASE
                WHEN capability_take_id IS NULL THEN NULL
                WHEN length(capability_take_id) = 16 THEN capability_take_id
            END AS capability_take_id
         FROM relay_short_code_attempt
         WHERE (?1 IS NOT NULL AND locator = ?1)
            OR (?2 IS NOT NULL AND attempt_id = ?2)
         LIMIT 2",
    )
    .bind(locator_bytes.as_ref().map(<[u8; 32]>::as_slice))
    .bind(attempt_bytes.as_ref().map(<[u8; 16]>::as_slice))
    .fetch_all(&mut **transaction)
    .await
    .map_err(|_| storage_failure("short-code attempt query"))?;
    if rows.len() > 1 {
        return Err(RelayError::ShortCodeAttemptConflict);
    }
    let Some(row) = rows.first() else {
        return Ok(None);
    };
    let publish = ShortCodeAttemptPublishRequest::new(
        ProtocolVersion::new(
            from_sql_u32(row.try_get("version_major").map_err(invalid_row)?)?,
            from_sql_u32(row.try_get("version_minor").map_err(invalid_row)?)?,
        )?,
        ShortCodePairingLocator::from_slice(
            &row.try_get::<Vec<u8>, _>("locator").map_err(invalid_row)?,
        )?,
        ShortCodePairingAttemptId::from_slice(
            &row.try_get::<Vec<u8>, _>("attempt_id")
                .map_err(invalid_row)?,
        )?,
        from_sql_integer(row.try_get("deadline_unix_seconds").map_err(invalid_row)?)?,
    )?;
    let owner = RelayPrincipalId::from_slice(
        &row.try_get::<Vec<u8>, _>("owner_principal_id")
            .map_err(invalid_row)?,
    )
    .map_err(|_| RelayError::InvalidStoredData)?;
    let claimant = row
        .try_get::<Option<Vec<u8>>, _>("claimant_principal_id")
        .map_err(invalid_row)?
        .map(|bytes| {
            RelayPrincipalId::from_slice(&bytes).map_err(|_| RelayError::InvalidStoredData)
        })
        .transpose()?;
    let cancelled = sql_bool(row.try_get("cancelled").map_err(invalid_row)?)?;
    let capability_consumed = sql_bool(row.try_get("capability_consumed").map_err(invalid_row)?)?;
    let capability_take_id_type = row
        .try_get::<String, _>("capability_take_id_type")
        .map_err(invalid_row)?;
    let capability_take_id_length = row
        .try_get::<Option<i64>, _>("capability_take_id_length")
        .map_err(invalid_row)?;
    let capability_take_id_bytes = row
        .try_get::<Option<Vec<u8>>, _>("capability_take_id")
        .map_err(invalid_row)?;
    let valid_take_id = capability_take_id_type == "null"
        && capability_take_id_length.is_none()
        && capability_take_id_bytes.is_none()
        || capability_take_id_type == "blob"
            && capability_take_id_length == Some(ShortCodeCapabilityTakeId::LENGTH as i64)
            && capability_take_id_bytes.is_some();
    if !valid_take_id {
        return Err(RelayError::InvalidStoredData);
    }
    let capability_take_id = capability_take_id_bytes
        .map(|bytes| {
            ShortCodeCapabilityTakeId::from_slice(&bytes).map_err(|_| RelayError::InvalidStoredData)
        })
        .transpose()?;
    if capability_consumed != capability_take_id.is_some() {
        return Err(RelayError::InvalidStoredData);
    }
    let message_rows = sqlx::query(
        "SELECT stage, payload
         FROM relay_short_code_message
         WHERE attempt_id = ?1
         ORDER BY stage",
    )
    .bind(publish.attempt_id().as_bytes().as_slice())
    .fetch_all(&mut **transaction)
    .await
    .map_err(|_| storage_failure("short-code messages query"))?;
    let mut stored = StoredShortCodeAttempt::new(owner, publish);
    for message in message_rows {
        let stage = short_code_stage_from_sql(message.try_get("stage").map_err(invalid_row)?)?;
        let payload = message
            .try_get::<Vec<u8>, _>("payload")
            .map_err(invalid_row)?;
        ShortCodeRelayMessage::new(stage, payload.clone())
            .map_err(|_| RelayError::InvalidStoredData)?;
        if stage == ShortCodeRelayStage::CredentialRequest {
            stored.set_claim(claimant.ok_or(RelayError::InvalidStoredData)?, payload)?;
        } else {
            stored.insert_message(stage, payload)?;
        }
    }
    if claimant.is_some()
        != stored
            .message(ShortCodeRelayStage::CredentialRequest)
            .is_some()
    {
        return Err(RelayError::InvalidStoredData);
    }
    if cancelled {
        stored.cancel();
    }
    if let Some(take_id) = capability_take_id {
        stored.consume_capability(take_id);
    }
    Ok(Some(stored))
}

fn short_code_snapshot(
    stored: &StoredShortCodeAttempt,
) -> Result<ShortCodeAttemptSnapshot, RelayError> {
    let messages = stored
        .messages()
        .iter()
        .filter(|(stage, _)| **stage != ShortCodeRelayStage::Capability)
        .map(|(stage, payload)| ShortCodeRelayMessage::new(*stage, payload.clone()))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ShortCodeAttemptSnapshot::new(
        stored.publish().version(),
        stored.publish().attempt_id(),
        stored.publish().deadline_unix_seconds(),
        stored.cancelled(),
        stored.capability_consumed(),
        messages,
    )?)
}

fn short_code_claim_window(now_unix_seconds: u64) -> Result<i64, RelayError> {
    to_sql_integer(now_unix_seconds - (now_unix_seconds % crate::SHORT_CODE_CLAIM_WINDOW_SECONDS))
}

const fn short_code_stage_to_sql(stage: ShortCodeRelayStage) -> i64 {
    stage as i64
}

fn short_code_stage_from_sql(value: i64) -> Result<ShortCodeRelayStage, RelayError> {
    match value {
        1 => Ok(ShortCodeRelayStage::CredentialRequest),
        2 => Ok(ShortCodeRelayStage::CredentialResponse),
        3 => Ok(ShortCodeRelayStage::ClaimantFinalization),
        4 => Ok(ShortCodeRelayStage::CreatorIdentity),
        5 => Ok(ShortCodeRelayStage::CreatorConfirmation),
        6 => Ok(ShortCodeRelayStage::ClaimantConfirmation),
        7 => Ok(ShortCodeRelayStage::Capability),
        _ => Err(RelayError::InvalidStoredData),
    }
}

fn sql_bool(value: i64) -> Result<bool, RelayError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(RelayError::InvalidStoredData),
    }
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
            delivery_class INTEGER NOT NULL CHECK (delivery_class BETWEEN 1 AND 6),
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
        initialize_dynamic_principal_schema(&mut transaction).await?;
        initialize_pairing_rendezvous_schema(&mut transaction).await?;
        initialize_short_code_schema(&mut transaction).await?;
        migrate_schema_v6_to_v7(&mut transaction).await?;
    } else if version == 1 {
        migrate_schema_v1_to_v2(&mut transaction).await?;
        migrate_schema_v2_to_v3(&mut transaction).await?;
        migrate_schema_v3_to_v4(&mut transaction).await?;
        migrate_schema_v4_to_v5(&mut transaction).await?;
        migrate_schema_v5_to_v6(&mut transaction).await?;
        migrate_schema_v6_to_v7(&mut transaction).await?;
    } else if version == 2 {
        migrate_schema_v2_to_v3(&mut transaction).await?;
        migrate_schema_v3_to_v4(&mut transaction).await?;
        migrate_schema_v4_to_v5(&mut transaction).await?;
        migrate_schema_v5_to_v6(&mut transaction).await?;
        migrate_schema_v6_to_v7(&mut transaction).await?;
    } else if version == 3 {
        migrate_schema_v3_to_v4(&mut transaction).await?;
        migrate_schema_v4_to_v5(&mut transaction).await?;
        migrate_schema_v5_to_v6(&mut transaction).await?;
        migrate_schema_v6_to_v7(&mut transaction).await?;
    } else if version == 4 {
        migrate_schema_v4_to_v5(&mut transaction).await?;
        migrate_schema_v5_to_v6(&mut transaction).await?;
        migrate_schema_v6_to_v7(&mut transaction).await?;
    } else if version == 5 {
        migrate_schema_v5_to_v6(&mut transaction).await?;
        migrate_schema_v6_to_v7(&mut transaction).await?;
    } else if version == 6 {
        migrate_schema_v6_to_v7(&mut transaction).await?;
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
        "SELECT principal_id, request_id, status FROM relay_dynamic_principal LIMIT 0",
        "SELECT lookup_id, owner_principal_id, version_major, version_minor,
                expires_at_unix_seconds, nonce, ciphertext
         FROM relay_pairing_rendezvous LIMIT 0",
        "SELECT locator, attempt_id, owner_principal_id, claimant_principal_id,
                version_major, version_minor, deadline_unix_seconds, cancelled,
                capability_consumed, capability_take_id
         FROM relay_short_code_attempt LIMIT 0",
        "SELECT attempt_id, stage, payload FROM relay_short_code_message LIMIT 0",
        "SELECT locator, principal_id, window_start, attempts
         FROM relay_short_code_claim_rate LIMIT 0",
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

async fn migrate_schema_v2_to_v3(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
) -> Result<(), RelayError> {
    sqlx::query(
        "CREATE TABLE relay_envelope_v3 (
            routing_id BLOB NOT NULL,
            cursor INTEGER NOT NULL CHECK (cursor >= 1),
            envelope_id BLOB NOT NULL,
            version_major INTEGER NOT NULL CHECK (version_major BETWEEN 1 AND 4294967295),
            version_minor INTEGER NOT NULL CHECK (version_minor BETWEEN 0 AND 4294967295),
            delivery_class INTEGER NOT NULL CHECK (delivery_class BETWEEN 1 AND 6),
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
    .map_err(|_| storage_failure("schema v3 envelope initialization"))?;
    sqlx::query(
        "INSERT INTO relay_envelope_v3 (
            routing_id,
            cursor,
            envelope_id,
            version_major,
            version_minor,
            delivery_class,
            expected_parent_epoch,
            expires_at_unix_seconds,
            encoded_envelope
         )
         SELECT
            routing_id,
            cursor,
            envelope_id,
            version_major,
            version_minor,
            delivery_class,
            expected_parent_epoch,
            expires_at_unix_seconds,
            encoded_envelope
         FROM relay_envelope",
    )
    .execute(&mut **transaction)
    .await
    .map_err(|_| storage_failure("schema v3 envelope migration"))?;
    let old_count: i64 = sqlx::query_scalar("SELECT count(*) FROM relay_envelope")
        .fetch_one(&mut **transaction)
        .await
        .map_err(|_| storage_failure("schema v2 envelope count"))?;
    let new_count: i64 = sqlx::query_scalar("SELECT count(*) FROM relay_envelope_v3")
        .fetch_one(&mut **transaction)
        .await
        .map_err(|_| storage_failure("schema v3 envelope count"))?;
    if old_count != new_count {
        return Err(storage_failure("schema v3 envelope migration count"));
    }
    sqlx::query("DROP TABLE relay_envelope")
        .execute(&mut **transaction)
        .await
        .map_err(|_| storage_failure("schema v2 envelope removal"))?;
    sqlx::query("ALTER TABLE relay_envelope_v3 RENAME TO relay_envelope")
        .execute(&mut **transaction)
        .await
        .map_err(|_| storage_failure("schema v3 envelope activation"))?;
    sqlx::query("PRAGMA user_version = 3")
        .execute(&mut **transaction)
        .await
        .map_err(|_| storage_failure("schema v3 version write"))?;
    Ok(())
}

async fn migrate_schema_v3_to_v4(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
) -> Result<(), RelayError> {
    initialize_dynamic_principal_schema(transaction).await?;
    sqlx::query("PRAGMA user_version = 4")
        .execute(&mut **transaction)
        .await
        .map_err(|_| storage_failure("schema v4 version write"))?;
    Ok(())
}

async fn initialize_dynamic_principal_schema(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
) -> Result<(), RelayError> {
    sqlx::query(
        "CREATE TABLE relay_dynamic_principal (
            principal_id BLOB PRIMARY KEY CHECK (length(principal_id) = 32),
            request_id BLOB NOT NULL UNIQUE CHECK (length(request_id) = 16),
            status INTEGER NOT NULL CHECK (status BETWEEN 1 AND 2)
         ) WITHOUT ROWID",
    )
    .execute(&mut **transaction)
    .await
    .map_err(|_| storage_failure("dynamic principal schema initialization"))?;
    Ok(())
}

async fn migrate_schema_v4_to_v5(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
) -> Result<(), RelayError> {
    initialize_pairing_rendezvous_schema(transaction).await?;
    sqlx::query("PRAGMA user_version = 5")
        .execute(&mut **transaction)
        .await
        .map_err(|_| storage_failure("schema v5 version write"))?;
    Ok(())
}

async fn initialize_pairing_rendezvous_schema(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
) -> Result<(), RelayError> {
    sqlx::query(
        "CREATE TABLE relay_pairing_rendezvous (
            lookup_id BLOB PRIMARY KEY CHECK (length(lookup_id) = 32),
            owner_principal_id BLOB NOT NULL CHECK (length(owner_principal_id) = 32),
            version_major INTEGER NOT NULL CHECK (version_major BETWEEN 1 AND 4294967295),
            version_minor INTEGER NOT NULL CHECK (version_minor BETWEEN 0 AND 4294967295),
            expires_at_unix_seconds INTEGER NOT NULL
                CHECK (expires_at_unix_seconds >= 1),
            nonce BLOB NOT NULL CHECK (length(nonce) = 12),
            ciphertext BLOB NOT NULL CHECK (length(ciphertext) BETWEEN 16 AND 8208)
         ) WITHOUT ROWID",
    )
    .execute(&mut **transaction)
    .await
    .map_err(|_| storage_failure("pairing rendezvous schema initialization"))?;
    sqlx::query(
        "CREATE INDEX relay_pairing_rendezvous_owner_expiry
         ON relay_pairing_rendezvous(owner_principal_id, expires_at_unix_seconds)",
    )
    .execute(&mut **transaction)
    .await
    .map_err(|_| storage_failure("pairing rendezvous owner index initialization"))?;
    sqlx::query(
        "CREATE INDEX relay_pairing_rendezvous_expiry
         ON relay_pairing_rendezvous(expires_at_unix_seconds)",
    )
    .execute(&mut **transaction)
    .await
    .map_err(|_| storage_failure("pairing rendezvous expiry index initialization"))?;
    Ok(())
}

async fn migrate_schema_v5_to_v6(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
) -> Result<(), RelayError> {
    initialize_short_code_schema(transaction).await?;
    sqlx::query("PRAGMA user_version = 6")
        .execute(&mut **transaction)
        .await
        .map_err(|_| storage_failure("schema v6 version write"))?;
    Ok(())
}

async fn migrate_schema_v6_to_v7(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
) -> Result<(), RelayError> {
    sqlx::query("DELETE FROM relay_short_code_attempt WHERE capability_consumed = 1")
        .execute(&mut **transaction)
        .await
        .map_err(|_| storage_failure("consumed short-code attempt migration cleanup"))?;
    sqlx::query(
        "ALTER TABLE relay_short_code_attempt
         ADD COLUMN capability_take_id BLOB
         CHECK (capability_take_id IS NULL OR length(capability_take_id) = 16)",
    )
    .execute(&mut **transaction)
    .await
    .map_err(|_| storage_failure("short-code capability take schema migration"))?;
    sqlx::query("PRAGMA user_version = 7")
        .execute(&mut **transaction)
        .await
        .map_err(|_| storage_failure("schema v7 version write"))?;
    Ok(())
}

async fn initialize_short_code_schema(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
) -> Result<(), RelayError> {
    sqlx::query(
        "CREATE TABLE relay_short_code_attempt (
            locator BLOB PRIMARY KEY CHECK (length(locator) = 32),
            attempt_id BLOB NOT NULL UNIQUE CHECK (length(attempt_id) = 16),
            owner_principal_id BLOB NOT NULL CHECK (length(owner_principal_id) = 32),
            claimant_principal_id BLOB CHECK (
                claimant_principal_id IS NULL OR length(claimant_principal_id) = 32
            ),
            version_major INTEGER NOT NULL CHECK (version_major BETWEEN 1 AND 4294967295),
            version_minor INTEGER NOT NULL CHECK (version_minor BETWEEN 0 AND 4294967295),
            deadline_unix_seconds INTEGER NOT NULL CHECK (deadline_unix_seconds >= 1),
            cancelled INTEGER NOT NULL CHECK (cancelled IN (0, 1)),
            capability_consumed INTEGER NOT NULL CHECK (capability_consumed IN (0, 1))
         ) WITHOUT ROWID",
    )
    .execute(&mut **transaction)
    .await
    .map_err(|_| storage_failure("short-code attempt schema initialization"))?;
    sqlx::query(
        "CREATE INDEX relay_short_code_attempt_owner_deadline
         ON relay_short_code_attempt(owner_principal_id, deadline_unix_seconds)",
    )
    .execute(&mut **transaction)
    .await
    .map_err(|_| storage_failure("short-code owner index initialization"))?;
    sqlx::query(
        "CREATE INDEX relay_short_code_attempt_claimant
         ON relay_short_code_attempt(claimant_principal_id)",
    )
    .execute(&mut **transaction)
    .await
    .map_err(|_| storage_failure("short-code claimant index initialization"))?;
    sqlx::query(
        "CREATE TABLE relay_short_code_message (
            attempt_id BLOB NOT NULL CHECK (length(attempt_id) = 16),
            stage INTEGER NOT NULL CHECK (stage BETWEEN 1 AND 7),
            payload BLOB NOT NULL CHECK (length(payload) BETWEEN 1 AND 9216),
            PRIMARY KEY (attempt_id, stage),
            FOREIGN KEY (attempt_id) REFERENCES relay_short_code_attempt(attempt_id)
                ON DELETE CASCADE
         ) WITHOUT ROWID",
    )
    .execute(&mut **transaction)
    .await
    .map_err(|_| storage_failure("short-code message schema initialization"))?;
    sqlx::query(
        "CREATE TABLE relay_short_code_claim_rate (
            locator BLOB NOT NULL CHECK (length(locator) = 32),
            principal_id BLOB NOT NULL CHECK (length(principal_id) = 32),
            window_start INTEGER NOT NULL CHECK (window_start >= 0),
            attempts INTEGER NOT NULL CHECK (attempts BETWEEN 1 AND 5),
            PRIMARY KEY (locator, principal_id, window_start)
         ) WITHOUT ROWID",
    )
    .execute(&mut **transaction)
    .await
    .map_err(|_| storage_failure("short-code rate schema initialization"))?;
    sqlx::query(
        "CREATE INDEX relay_short_code_claim_rate_principal
         ON relay_short_code_claim_rate(principal_id, window_start)",
    )
    .execute(&mut **transaction)
    .await
    .map_err(|_| storage_failure("short-code rate index initialization"))?;
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
    use crate::{
        DynamicRelayAuthorizer, RelayAuthorizer, RelayClock, RelayPermission,
        RelayPrincipalRegistry, RelayService,
    };

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

    fn enrollment(value: u64) -> RelayEnrollmentRequest {
        let mut request_id = [0_u8; EnrollmentRequestId::LENGTH];
        request_id[..8].copy_from_slice(&value.to_be_bytes());
        let mut principal_id = [0_u8; RelayPrincipalId::LENGTH];
        principal_id[..8].copy_from_slice(&value.to_be_bytes());
        RelayEnrollmentRequest::new(
            ProtocolVersion::application_v1(),
            EnrollmentRequestId::from_bytes(request_id),
            RelayPrincipalId::from_bytes(principal_id),
        )
    }

    fn rendezvous(id: u8, ciphertext: u8, expires_at: u64) -> PairingRendezvousRecord {
        PairingRendezvousRecord::new(
            ProtocolVersion::application_v1(),
            PairingRendezvousId::from_bytes(bytes(id)),
            expires_at,
            PairingRendezvousNonce::from_bytes(bytes(id.wrapping_add(1))),
            vec![ciphertext; 32],
        )
        .unwrap()
    }

    fn rendezvous_take(id: u8) -> PairingRendezvousTakeRequest {
        PairingRendezvousTakeRequest::new(
            ProtocolVersion::application_v1(),
            PairingRendezvousId::from_bytes(bytes(id)),
        )
    }

    fn short_publish(locator: u8, attempt: u8) -> ShortCodeAttemptPublishRequest {
        ShortCodeAttemptPublishRequest::new(
            ProtocolVersion::application_v1(),
            ShortCodePairingLocator::from_bytes(bytes(locator)),
            ShortCodePairingAttemptId::from_bytes(bytes(attempt)),
            100,
        )
        .unwrap()
    }

    fn short_claim(locator: u8, payload: u8) -> ShortCodeAttemptClaimRequest {
        ShortCodeAttemptClaimRequest::new(
            ProtocolVersion::application_v1(),
            ShortCodePairingLocator::from_bytes(bytes(locator)),
            vec![payload],
        )
        .unwrap()
    }

    fn short_message(
        attempt: u8,
        stage: ShortCodeRelayStage,
        payload: u8,
    ) -> ShortCodeAttemptMessageRequest {
        ShortCodeAttemptMessageRequest::new(
            ProtocolVersion::application_v1(),
            ShortCodePairingAttemptId::from_bytes(bytes(attempt)),
            stage,
            vec![payload],
        )
        .unwrap()
    }

    fn short_read(attempt: u8) -> ShortCodeAttemptReadRequest {
        ShortCodeAttemptReadRequest::new(
            ProtocolVersion::application_v1(),
            ShortCodePairingAttemptId::from_bytes(bytes(attempt)),
        )
    }

    fn short_take(attempt: u8, take: u8) -> ShortCodeCapabilityTakeRequest {
        ShortCodeCapabilityTakeRequest::new(
            ProtocolVersion::application_v1(),
            ShortCodePairingAttemptId::from_bytes(bytes(attempt)),
            ShortCodeCapabilityTakeId::from_bytes(bytes(take)),
        )
    }

    #[tokio::test]
    async fn short_code_attempt_is_participant_bound_sequential_and_one_time() {
        let repository = SqliteRelayRepository::connect_memory().await.unwrap();
        let owner = RelayPrincipalId::from_bytes(bytes(1));
        let claimant = RelayPrincipalId::from_bytes(bytes(2));
        let stranger = RelayPrincipalId::from_bytes(bytes(3));
        let publish = short_publish(10, 11);
        assert_eq!(
            repository
                .publish_short_code_attempt(owner, publish, 1)
                .await
                .unwrap(),
            ShortCodeAttemptPublishOutcome::Published
        );
        assert_eq!(
            repository
                .publish_short_code_attempt(owner, publish, 1)
                .await
                .unwrap(),
            ShortCodeAttemptPublishOutcome::AlreadyPublished
        );
        let claim = short_claim(10, 12);
        let claimed = repository
            .claim_short_code_attempt(claimant, claim, 1)
            .await
            .unwrap();
        assert_eq!(
            claimed.message(ShortCodeRelayStage::CredentialRequest),
            Some(&[12][..])
        );
        assert_eq!(
            repository
                .claim_short_code_attempt(claimant, short_claim(10, 12), 1)
                .await
                .unwrap()
                .attempt_id(),
            publish.attempt_id()
        );
        assert_eq!(
            repository
                .claim_short_code_attempt(stranger, short_claim(10, 13), 1)
                .await
                .err(),
            Some(RelayError::ShortCodeAttemptUnavailable)
        );

        for (stage, principal, payload) in [
            (ShortCodeRelayStage::CredentialResponse, owner, 20),
            (ShortCodeRelayStage::ClaimantFinalization, claimant, 21),
            (ShortCodeRelayStage::CreatorIdentity, owner, 22),
            (ShortCodeRelayStage::ClaimantConfirmation, claimant, 23),
            (ShortCodeRelayStage::CreatorConfirmation, owner, 24),
            (ShortCodeRelayStage::Capability, owner, 25),
        ] {
            assert_eq!(
                repository
                    .publish_short_code_message(principal, short_message(11, stage, payload), 1,)
                    .await
                    .unwrap(),
                ShortCodeAttemptMessageOutcome::Published
            );
        }
        let snapshot = repository
            .read_short_code_attempt(owner, short_read(11), 1)
            .await
            .unwrap();
        assert!(snapshot.message(ShortCodeRelayStage::Capability).is_none());
        assert_eq!(
            repository
                .read_short_code_attempt(stranger, short_read(11), 1)
                .await
                .err(),
            Some(RelayError::ShortCodeAttemptUnavailable)
        );
        assert_eq!(
            repository
                .take_short_code_capability(claimant, short_take(11, 30), 1)
                .await
                .unwrap(),
            vec![25]
        );
        assert_eq!(
            repository
                .take_short_code_capability(claimant, short_take(11, 30), 1)
                .await
                .unwrap(),
            vec![25]
        );
        assert_eq!(
            repository
                .take_short_code_capability(claimant, short_take(11, 31), 1)
                .await
                .err(),
            Some(RelayError::ShortCodeAttemptUnavailable)
        );
        assert!(
            repository
                .read_short_code_attempt(owner, short_read(11), 1)
                .await
                .unwrap()
                .capability_consumed()
        );
    }

    #[tokio::test]
    async fn short_code_claims_enforce_principal_and_locator_windows() {
        let repository = SqliteRelayRepository::connect_memory().await.unwrap();
        let principal = RelayPrincipalId::from_bytes(bytes(1));
        for locator in 0..u8::try_from(crate::MAX_SHORT_CODE_CLAIMS_PER_PRINCIPAL_WINDOW).unwrap() {
            assert_eq!(
                repository
                    .claim_short_code_attempt(principal, short_claim(locator, 1), 1)
                    .await
                    .err(),
                Some(RelayError::ShortCodeAttemptUnavailable)
            );
        }
        assert_eq!(
            repository
                .claim_short_code_attempt(principal, short_claim(20, 1), 1)
                .await
                .err(),
            Some(RelayError::ShortCodeClaimRateLimited)
        );

        let locator = ShortCodePairingLocator::from_bytes(bytes(30));
        for value in 10..15 {
            assert_eq!(
                repository
                    .claim_short_code_attempt(
                        RelayPrincipalId::from_bytes(bytes(value)),
                        ShortCodeAttemptClaimRequest::new(
                            ProtocolVersion::application_v1(),
                            locator,
                            vec![1],
                        )
                        .unwrap(),
                        1,
                    )
                    .await
                    .err(),
                Some(RelayError::ShortCodeAttemptUnavailable)
            );
        }
        assert_eq!(
            repository
                .claim_short_code_attempt(
                    RelayPrincipalId::from_bytes(bytes(16)),
                    ShortCodeAttemptClaimRequest::new(
                        ProtocolVersion::application_v1(),
                        locator,
                        vec![1],
                    )
                    .unwrap(),
                    1,
                )
                .await
                .err(),
            Some(RelayError::ShortCodeAttemptUnavailable)
        );
        let attempts: i64 = sqlx::query_scalar(
            "SELECT COALESCE(sum(attempts), 0)
             FROM relay_short_code_claim_rate
             WHERE locator = ?1",
        )
        .bind(locator.as_bytes().as_slice())
        .fetch_one(&repository.pool)
        .await
        .unwrap();
        assert_eq!(attempts, 5);
    }

    #[tokio::test]
    async fn short_code_claim_and_capability_take_are_atomic_under_concurrency() {
        let directory = tempfile::tempdir().unwrap();
        let repository = SqliteRelayRepository::connect(&directory.path().join("relay.sqlite"))
            .await
            .unwrap();
        let owner = RelayPrincipalId::from_bytes(bytes(1));
        let first_claimant = RelayPrincipalId::from_bytes(bytes(2));
        let second_claimant = RelayPrincipalId::from_bytes(bytes(3));
        repository
            .publish_short_code_attempt(owner, short_publish(40, 41), 1)
            .await
            .unwrap();

        let (first, second) = tokio::join!(
            repository.claim_short_code_attempt(first_claimant, short_claim(40, 50), 1),
            repository.claim_short_code_attempt(second_claimant, short_claim(40, 51), 1)
        );
        let claimant = match (first, second) {
            (Ok(_), Err(RelayError::ShortCodeAttemptUnavailable)) => first_claimant,
            (Err(RelayError::ShortCodeAttemptUnavailable), Ok(_)) => second_claimant,
            _ => panic!("exactly one concurrent short-code claimant must win"),
        };
        for (stage, principal, payload) in [
            (ShortCodeRelayStage::CredentialResponse, owner, 60),
            (ShortCodeRelayStage::ClaimantFinalization, claimant, 61),
            (ShortCodeRelayStage::CreatorIdentity, owner, 62),
            (ShortCodeRelayStage::CreatorConfirmation, owner, 63),
            (ShortCodeRelayStage::ClaimantConfirmation, claimant, 64),
            (ShortCodeRelayStage::Capability, owner, 65),
        ] {
            repository
                .publish_short_code_message(principal, short_message(41, stage, payload), 1)
                .await
                .unwrap();
        }

        let (first, second) = tokio::join!(
            repository.take_short_code_capability(claimant, short_take(41, 42), 1),
            repository.take_short_code_capability(claimant, short_take(41, 43), 1)
        );
        let winning_take = match (first, second) {
            (Ok(payload), Err(RelayError::ShortCodeAttemptUnavailable)) if payload == vec![65] => {
                42
            }
            (Err(RelayError::ShortCodeAttemptUnavailable), Ok(payload)) if payload == vec![65] => {
                43
            }
            _ => panic!("exactly one concurrent short-code capability take must win"),
        };
        assert_eq!(
            repository
                .take_short_code_capability(claimant, short_take(41, winning_take), 1)
                .await
                .unwrap(),
            vec![65]
        );
    }

    #[tokio::test]
    async fn short_code_deadline_capacity_and_version_are_enforced_by_storage() {
        let repository = SqliteRelayRepository::connect_memory().await.unwrap();
        let owner = RelayPrincipalId::from_bytes(bytes(1));
        let excessive = ShortCodeAttemptPublishRequest::new(
            ProtocolVersion::application_v1(),
            ShortCodePairingLocator::from_bytes(bytes(70)),
            ShortCodePairingAttemptId::from_bytes(bytes(71)),
            1 + crate::SHORT_CODE_ATTEMPT_LIFETIME_SECONDS + 1,
        )
        .unwrap();
        assert_eq!(
            repository
                .publish_short_code_attempt(owner, excessive, 1)
                .await
                .err(),
            Some(RelayError::InvalidShortCodeDeadline)
        );
        for value in 0..u8::try_from(crate::MAX_ACTIVE_SHORT_CODE_ATTEMPTS_PER_CREATOR).unwrap() {
            repository
                .publish_short_code_attempt(owner, short_publish(80 + value, 90 + value), 1)
                .await
                .unwrap();
        }
        assert_eq!(
            repository
                .publish_short_code_attempt(owner, short_publish(100, 110), 1)
                .await
                .err(),
            Some(RelayError::ShortCodeCreatorCapacityExceeded)
        );
        assert_eq!(
            repository
                .publish_short_code_attempt(
                    RelayPrincipalId::from_bytes(bytes(2)),
                    short_publish(101, 111),
                    1,
                )
                .await
                .unwrap(),
            ShortCodeAttemptPublishOutcome::Published
        );

        let wrong_version_claim = ShortCodeAttemptClaimRequest::new(
            ProtocolVersion::new(1, 1).unwrap(),
            ShortCodePairingLocator::from_bytes(bytes(80)),
            vec![1],
        )
        .unwrap();
        assert_eq!(
            repository
                .claim_short_code_attempt(
                    RelayPrincipalId::from_bytes(bytes(3)),
                    wrong_version_claim,
                    1,
                )
                .await
                .err(),
            Some(RelayError::ShortCodeAttemptUnavailable)
        );
    }

    #[tokio::test]
    async fn pairing_rendezvous_publish_take_and_expiry_are_fail_closed() {
        let repository = SqliteRelayRepository::connect_memory().await.unwrap();
        let owner = RelayPrincipalId::from_bytes(bytes(1));
        let other = RelayPrincipalId::from_bytes(bytes(2));

        assert_eq!(
            repository
                .publish_pairing_rendezvous(owner, rendezvous(3, 4, 100), 1)
                .await
                .unwrap(),
            PairingRendezvousPublishOutcome::Published
        );
        assert_eq!(
            repository
                .publish_pairing_rendezvous(owner, rendezvous(3, 4, 100), 1)
                .await
                .unwrap(),
            PairingRendezvousPublishOutcome::AlreadyPublished
        );
        assert_eq!(
            repository
                .publish_pairing_rendezvous(owner, rendezvous(3, 5, 100), 1)
                .await
                .err(),
            Some(RelayError::PairingRendezvousConflict)
        );
        assert_eq!(
            repository
                .publish_pairing_rendezvous(other, rendezvous(3, 4, 100), 1)
                .await
                .err(),
            Some(RelayError::PairingRendezvousConflict)
        );

        let taken = repository
            .take_pairing_rendezvous(rendezvous_take(3), 1)
            .await
            .unwrap();
        assert_eq!(taken.lookup_id(), PairingRendezvousId::from_bytes(bytes(3)));
        assert_eq!(taken.ciphertext(), &[4; 32]);
        assert_eq!(
            repository
                .take_pairing_rendezvous(rendezvous_take(3), 1)
                .await
                .err(),
            Some(RelayError::PairingRendezvousUnavailable)
        );
        assert_eq!(
            repository
                .publish_pairing_rendezvous(owner, rendezvous(4, 4, 1), 1)
                .await
                .err(),
            Some(RelayError::ExpiredPairingRendezvous)
        );
        repository
            .publish_pairing_rendezvous(owner, rendezvous(7, 7, 10), 1)
            .await
            .unwrap();
        assert_eq!(
            repository
                .publish_pairing_rendezvous(owner, rendezvous(8, 8, 10), 10)
                .await
                .err(),
            Some(RelayError::ExpiredPairingRendezvous)
        );
        let retained: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM relay_pairing_rendezvous WHERE lookup_id = ?1",
        )
        .bind(
            PairingRendezvousId::from_bytes(bytes(7))
                .as_bytes()
                .as_slice(),
        )
        .fetch_one(&repository.pool)
        .await
        .unwrap();
        assert_eq!(retained, 1);

        repository
            .publish_pairing_rendezvous(owner, rendezvous(5, 5, 100), 1)
            .await
            .unwrap();
        assert_eq!(
            repository
                .take_pairing_rendezvous(rendezvous_take(5), 100)
                .await
                .err(),
            Some(RelayError::PairingRendezvousUnavailable)
        );
        assert_eq!(
            repository
                .take_pairing_rendezvous(rendezvous_take(5), 100)
                .await
                .err(),
            Some(RelayError::PairingRendezvousUnavailable)
        );

        repository
            .publish_pairing_rendezvous(owner, rendezvous(6, 6, 100), 1)
            .await
            .unwrap();
        assert_eq!(
            repository
                .publish_pairing_rendezvous(owner, rendezvous(6, 7, 200), 100)
                .await
                .unwrap(),
            PairingRendezvousPublishOutcome::Published
        );
        assert_eq!(
            repository
                .take_pairing_rendezvous(rendezvous_take(6), 100)
                .await
                .unwrap()
                .ciphertext(),
            &[7; 32]
        );
    }

    #[tokio::test]
    async fn pairing_rendezvous_take_is_atomic_under_concurrency() {
        let directory = tempfile::tempdir().unwrap();
        let repository = SqliteRelayRepository::connect(&directory.path().join("relay.sqlite"))
            .await
            .unwrap();
        repository
            .publish_pairing_rendezvous(
                RelayPrincipalId::from_bytes(bytes(1)),
                rendezvous(2, 3, 100),
                1,
            )
            .await
            .unwrap();

        let (first, second) = tokio::join!(
            repository.take_pairing_rendezvous(rendezvous_take(2), 1),
            repository.take_pairing_rendezvous(rendezvous_take(2), 1)
        );
        match (first, second) {
            (Ok(record), Err(RelayError::PairingRendezvousUnavailable))
            | (Err(RelayError::PairingRendezvousUnavailable), Ok(record)) => {
                assert_eq!(record.ciphertext(), &[3; 32]);
            }
            _ => panic!("exactly one concurrent take must consume the record"),
        }
    }

    #[tokio::test]
    async fn pairing_rendezvous_enforces_per_principal_active_capacity() {
        let repository = SqliteRelayRepository::connect_memory().await.unwrap();
        let owner = RelayPrincipalId::from_bytes(bytes(1));
        for id in 0..u8::try_from(crate::MAX_ACTIVE_PAIRING_RENDEZVOUS_PER_PRINCIPAL).unwrap() {
            repository
                .publish_pairing_rendezvous(owner, rendezvous(id, id, 100), 1)
                .await
                .unwrap();
        }
        assert_eq!(
            repository
                .publish_pairing_rendezvous(owner, rendezvous(40, 40, 100), 1)
                .await
                .err(),
            Some(RelayError::PairingRendezvousPrincipalCapacityExceeded)
        );
        assert_eq!(
            repository
                .publish_pairing_rendezvous(
                    RelayPrincipalId::from_bytes(bytes(2)),
                    rendezvous(41, 41, 100),
                    1,
                )
                .await
                .unwrap(),
            PairingRendezvousPublishOutcome::Published
        );
        assert_eq!(
            repository
                .publish_pairing_rendezvous(owner, rendezvous(42, 42, 200), 100)
                .await
                .unwrap(),
            PairingRendezvousPublishOutcome::Published
        );
    }

    #[tokio::test]
    async fn pairing_rendezvous_schema_contains_only_allowlisted_fields() {
        let repository = SqliteRelayRepository::connect_memory().await.unwrap();
        let columns = sqlx::query("PRAGMA table_info(relay_pairing_rendezvous)")
            .fetch_all(&repository.pool)
            .await
            .unwrap()
            .into_iter()
            .map(|row| row.try_get::<String, _>("name").unwrap())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            columns,
            [
                "ciphertext",
                "expires_at_unix_seconds",
                "lookup_id",
                "nonce",
                "owner_principal_id",
                "version_major",
                "version_minor",
            ]
            .into_iter()
            .map(str::to_string)
            .collect()
        );
    }

    #[tokio::test]
    async fn short_code_schema_contains_only_allowlisted_metadata_and_opaque_payloads() {
        let repository = SqliteRelayRepository::connect_memory().await.unwrap();
        for (table, expected) in [
            (
                "relay_short_code_attempt",
                &[
                    "attempt_id",
                    "cancelled",
                    "capability_consumed",
                    "capability_take_id",
                    "claimant_principal_id",
                    "deadline_unix_seconds",
                    "locator",
                    "owner_principal_id",
                    "version_major",
                    "version_minor",
                ][..],
            ),
            (
                "relay_short_code_message",
                &["attempt_id", "payload", "stage"][..],
            ),
            (
                "relay_short_code_claim_rate",
                &["attempts", "locator", "principal_id", "window_start"][..],
            ),
        ] {
            let columns = sqlx::query(&format!("PRAGMA table_info({table})"))
                .fetch_all(&repository.pool)
                .await
                .unwrap()
                .into_iter()
                .map(|row| row.try_get::<String, _>("name").unwrap())
                .collect::<BTreeSet<_>>();
            assert_eq!(
                columns,
                expected
                    .iter()
                    .copied()
                    .map(str::to_string)
                    .collect::<BTreeSet<_>>()
            );
        }
    }

    #[tokio::test]
    async fn dynamic_registration_is_idempotent_authorized_and_revocable() {
        let repository = SqliteRelayRepository::connect_memory().await.unwrap();
        let request = enrollment(1);
        let registered = repository.register_principal(request).await.unwrap();
        assert_eq!(registered.outcome(), RelayEnrollmentOutcome::Registered);
        assert_eq!(
            repository
                .register_principal(request)
                .await
                .unwrap()
                .outcome(),
            RelayEnrollmentOutcome::AlreadyRegistered
        );
        assert_eq!(
            repository
                .register_principal(enrollment(2))
                .await
                .unwrap()
                .outcome(),
            RelayEnrollmentOutcome::Registered
        );
        let conflicting_request = RelayEnrollmentRequest::new(
            request.version(),
            request.request_id(),
            enrollment(3).principal_id(),
        );
        assert_eq!(
            repository.register_principal(conflicting_request).await,
            Err(RelayError::EnrollmentConflict)
        );
        let conflicting_principal = RelayEnrollmentRequest::new(
            request.version(),
            enrollment(3).request_id(),
            request.principal_id(),
        );
        assert_eq!(
            repository.register_principal(conflicting_principal).await,
            Err(RelayError::EnrollmentConflict)
        );

        let authorizer = DynamicRelayAuthorizer::new(repository.clone());
        assert!(
            authorizer
                .authorize(
                    request.principal_id(),
                    RoutingId::from_bytes([9; RoutingId::LENGTH]),
                    RelayPermission::Send,
                )
                .await
                .is_ok()
        );
        assert!(
            repository
                .revoke_principal(request.principal_id())
                .await
                .unwrap()
        );
        assert!(
            !repository
                .revoke_principal(request.principal_id())
                .await
                .unwrap()
        );
        assert!(
            !repository
                .is_principal_active(request.principal_id())
                .await
                .unwrap()
        );
        assert_eq!(
            authorizer
                .authorize(
                    request.principal_id(),
                    RoutingId::from_bytes([9; RoutingId::LENGTH]),
                    RelayPermission::Replay,
                )
                .await,
            Err(RelayError::Unauthorized)
        );
        assert_eq!(
            repository.register_principal(request).await,
            Err(RelayError::PrincipalRevoked)
        );
        assert_eq!(
            repository
                .register_principal(RelayEnrollmentRequest::new(
                    ProtocolVersion::new(2, 0).unwrap(),
                    enrollment(5).request_id(),
                    enrollment(5).principal_id(),
                ))
                .await,
            Err(RelayError::UnsupportedEnrollmentVersion)
        );
    }

    #[tokio::test]
    async fn concurrent_identical_registration_commits_one_principal() {
        let repository = SqliteRelayRepository::connect_memory().await.unwrap();
        let request = enrollment(4);
        let (first, second) = tokio::join!(
            repository.register_principal(request),
            repository.register_principal(request)
        );
        let outcomes = BTreeSet::from([
            first.unwrap().outcome() as u8,
            second.unwrap().outcome() as u8,
        ]);
        assert_eq!(outcomes.len(), 2);
        assert!(
            repository
                .is_principal_active(request.principal_id())
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn active_principal_capacity_is_atomic_and_revocation_releases_it() {
        let repository = SqliteRelayRepository::connect_memory().await.unwrap();
        let capacity = u64::try_from(MAX_ACTIVE_DYNAMIC_PRINCIPALS).unwrap();
        for value in 0..capacity - 1 {
            repository
                .register_principal(enrollment(value))
                .await
                .unwrap();
        }
        let first_request = enrollment(capacity - 1);
        let second_request = enrollment(capacity);
        let (first, second) = tokio::join!(
            repository.register_principal(first_request),
            repository.register_principal(second_request)
        );
        let (accepted, rejected) = match (first, second) {
            (Ok(response), Err(RelayError::PrincipalCapacityExceeded)) => {
                assert_eq!(response.outcome(), RelayEnrollmentOutcome::Registered);
                (first_request, second_request)
            }
            (Err(RelayError::PrincipalCapacityExceeded), Ok(response)) => {
                assert_eq!(response.outcome(), RelayEnrollmentOutcome::Registered);
                (second_request, first_request)
            }
            outcomes => panic!("exactly one registration must win the final slot: {outcomes:?}"),
        };
        assert_eq!(
            repository
                .register_principal(accepted)
                .await
                .unwrap()
                .outcome(),
            RelayEnrollmentOutcome::AlreadyRegistered
        );
        assert!(
            repository
                .revoke_principal(accepted.principal_id())
                .await
                .unwrap()
        );
        assert_eq!(
            repository
                .register_principal(rejected)
                .await
                .unwrap()
                .outcome(),
            RelayEnrollmentOutcome::Registered
        );
    }

    #[tokio::test]
    async fn revoked_principal_history_has_a_hard_total_bound() {
        let repository = SqliteRelayRepository::connect_memory().await.unwrap();
        let mut transaction = repository.pool.begin().await.unwrap();
        for value in 0..u64::try_from(MAX_DYNAMIC_PRINCIPAL_RECORDS).unwrap() {
            let request = enrollment(value);
            sqlx::query(
                "INSERT INTO relay_dynamic_principal (principal_id, request_id, status)
                 VALUES (?1, ?2, 2)",
            )
            .bind(request.principal_id().as_bytes().as_slice())
            .bind(request.request_id().as_bytes().as_slice())
            .execute(&mut *transaction)
            .await
            .unwrap();
        }
        transaction.commit().await.unwrap();
        assert_eq!(
            repository
                .register_principal(enrollment(
                    u64::try_from(MAX_DYNAMIC_PRINCIPAL_RECORDS).unwrap()
                ))
                .await,
            Err(RelayError::PrincipalCapacityExceeded)
        );
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
        let newer_version = SQLITE_SCHEMA_VERSION + 1;
        sqlx::query(&format!("PRAGMA user_version = {newer_version}"))
            .execute(&pool)
            .await
            .unwrap();
        pool.close().await;

        assert_eq!(
            SqliteRelayRepository::connect(&path).await.err(),
            Some(RelayError::UnsupportedSchemaVersion {
                actual: newer_version
            })
        );
    }

    #[tokio::test]
    async fn schema_v4_adds_pairing_rendezvous_without_rewriting_existing_data() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("relay.sqlite");
        let pool = create_v1_pool(&path).await;
        let existing = envelope(44, 45, DeliveryClass::GroupApplication, None, 46);
        insert_v1_row(&pool, &existing, 1, existing.payload()).await;
        let mut transaction = pool.begin().await.unwrap();
        migrate_schema_v1_to_v2(&mut transaction).await.unwrap();
        migrate_schema_v2_to_v3(&mut transaction).await.unwrap();
        migrate_schema_v3_to_v4(&mut transaction).await.unwrap();
        transaction.commit().await.unwrap();
        let version: i64 = sqlx::query_scalar("PRAGMA user_version")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(version, 4);
        pool.close().await;

        let repository = SqliteRelayRepository::connect(&path).await.unwrap();
        let version: i64 = sqlx::query_scalar("PRAGMA user_version")
            .fetch_one(&repository.pool)
            .await
            .unwrap();
        assert_eq!(version, i64::from(SQLITE_SCHEMA_VERSION));
        let replay = repository
            .replay(ReplayRequest::new(existing.routing_id(), 0, 10).unwrap())
            .await
            .unwrap();
        assert!(replay.envelopes()[0].envelope() == &existing);
        repository
            .publish_pairing_rendezvous(
                RelayPrincipalId::from_bytes(bytes(47)),
                rendezvous(48, 49, 100),
                1,
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn schema_v5_adds_short_code_pairing_without_rewriting_existing_data() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("relay.sqlite");
        let pool = create_v1_pool(&path).await;
        let existing = envelope(50, 51, DeliveryClass::GroupApplication, None, 52);
        insert_v1_row(&pool, &existing, 1, existing.payload()).await;
        let mut transaction = pool.begin().await.unwrap();
        migrate_schema_v1_to_v2(&mut transaction).await.unwrap();
        migrate_schema_v2_to_v3(&mut transaction).await.unwrap();
        migrate_schema_v3_to_v4(&mut transaction).await.unwrap();
        migrate_schema_v4_to_v5(&mut transaction).await.unwrap();
        transaction.commit().await.unwrap();
        let version: i64 = sqlx::query_scalar("PRAGMA user_version")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(version, 5);
        pool.close().await;

        let repository = SqliteRelayRepository::connect(&path).await.unwrap();
        let version: i64 = sqlx::query_scalar("PRAGMA user_version")
            .fetch_one(&repository.pool)
            .await
            .unwrap();
        assert_eq!(version, i64::from(SQLITE_SCHEMA_VERSION));
        assert!(
            repository
                .replay(ReplayRequest::new(existing.routing_id(), 0, 10).unwrap())
                .await
                .unwrap()
                .envelopes()[0]
                .envelope()
                == &existing
        );
        repository
            .publish_short_code_attempt(
                RelayPrincipalId::from_bytes(bytes(53)),
                short_publish(54, 55),
                1,
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn schema_v6_adds_retry_identity_and_discards_unrecoverable_consumed_attempts() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("relay.sqlite");
        let pool = create_v1_pool(&path).await;
        let mut transaction = pool.begin().await.unwrap();
        migrate_schema_v1_to_v2(&mut transaction).await.unwrap();
        migrate_schema_v2_to_v3(&mut transaction).await.unwrap();
        migrate_schema_v3_to_v4(&mut transaction).await.unwrap();
        migrate_schema_v4_to_v5(&mut transaction).await.unwrap();
        migrate_schema_v5_to_v6(&mut transaction).await.unwrap();
        let owner = RelayPrincipalId::from_bytes(bytes(56));
        insert_short_code_attempt(&mut transaction, owner, short_publish(57, 58))
            .await
            .unwrap();
        insert_short_code_attempt(&mut transaction, owner, short_publish(59, 60))
            .await
            .unwrap();
        transaction.commit().await.unwrap();
        sqlx::query(
            "UPDATE relay_short_code_attempt
             SET capability_consumed = 1
             WHERE attempt_id = ?1",
        )
        .bind(
            ShortCodePairingAttemptId::from_bytes(bytes(60))
                .as_bytes()
                .as_slice(),
        )
        .execute(&pool)
        .await
        .unwrap();
        pool.close().await;

        let repository = SqliteRelayRepository::connect(&path).await.unwrap();
        let version: i64 = sqlx::query_scalar("PRAGMA user_version")
            .fetch_one(&repository.pool)
            .await
            .unwrap();
        assert_eq!(version, i64::from(SQLITE_SCHEMA_VERSION));
        assert_eq!(
            repository
                .read_short_code_attempt(owner, short_read(58), 1)
                .await
                .unwrap()
                .attempt_id(),
            ShortCodePairingAttemptId::from_bytes(bytes(58))
        );
        assert_eq!(
            repository
                .read_short_code_attempt(owner, short_read(60), 1)
                .await
                .err(),
            Some(RelayError::ShortCodeAttemptUnavailable)
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
        assert_eq!(version, i64::from(SQLITE_SCHEMA_VERSION));
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
    async fn schema_v2_migrates_existing_envelopes_and_accepts_pairing() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("relay.sqlite");
        let pool = create_v1_pool(&path).await;
        let existing = envelope(21, 22, DeliveryClass::GroupApplication, None, 23);
        insert_v1_row(&pool, &existing, 1, existing.payload()).await;
        let mut transaction = pool.begin().await.unwrap();
        migrate_schema_v1_to_v2(&mut transaction).await.unwrap();
        transaction.commit().await.unwrap();
        let version: i64 = sqlx::query_scalar("PRAGMA user_version")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(version, 2);
        pool.close().await;

        let repository = SqliteRelayRepository::connect(&path).await.unwrap();
        let version: i64 = sqlx::query_scalar("PRAGMA user_version")
            .fetch_one(&repository.pool)
            .await
            .unwrap();
        assert_eq!(version, i64::from(SQLITE_SCHEMA_VERSION));
        let replay = repository
            .replay(ReplayRequest::new(existing.routing_id(), 0, 10).unwrap())
            .await
            .unwrap();
        assert!(replay.envelopes()[0].envelope() == &existing);
        let pairing = envelope(24, 25, DeliveryClass::Pairing, None, 26);
        assert_eq!(
            repository.submit(&pairing, 1).await.unwrap(),
            SubmitResult::new(1, false)
        );
        let pairing_replay = repository
            .replay(ReplayRequest::new(pairing.routing_id(), 0, 10).unwrap())
            .await
            .unwrap();
        assert!(pairing_replay.envelopes()[0].envelope() == &pairing);
    }

    #[tokio::test]
    async fn schema_v3_adds_dynamic_registration_without_rewriting_envelopes() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("relay.sqlite");
        let pool = create_v1_pool(&path).await;
        let existing = envelope(30, 31, DeliveryClass::GroupApplication, None, 32);
        insert_v1_row(&pool, &existing, 1, existing.payload()).await;
        let mut transaction = pool.begin().await.unwrap();
        migrate_schema_v1_to_v2(&mut transaction).await.unwrap();
        migrate_schema_v2_to_v3(&mut transaction).await.unwrap();
        transaction.commit().await.unwrap();
        let version: i64 = sqlx::query_scalar("PRAGMA user_version")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(version, 3);
        pool.close().await;

        let repository = SqliteRelayRepository::connect(&path).await.unwrap();
        let replay = repository
            .replay(ReplayRequest::new(existing.routing_id(), 0, 10).unwrap())
            .await
            .unwrap();
        assert!(replay.envelopes()[0].envelope() == &existing);
        assert_eq!(
            repository
                .register_principal(enrollment(33))
                .await
                .unwrap()
                .outcome(),
            RelayEnrollmentOutcome::Registered
        );
    }

    #[tokio::test]
    async fn failed_schema_v3_migration_preserves_the_v3_database() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("relay.sqlite");
        let pool = create_v1_pool(&path).await;
        let existing = envelope(34, 35, DeliveryClass::GroupApplication, None, 36);
        insert_v1_row(&pool, &existing, 1, existing.payload()).await;
        let mut transaction = pool.begin().await.unwrap();
        migrate_schema_v1_to_v2(&mut transaction).await.unwrap();
        migrate_schema_v2_to_v3(&mut transaction).await.unwrap();
        transaction.commit().await.unwrap();
        sqlx::query("CREATE TABLE relay_dynamic_principal (sentinel INTEGER)")
            .execute(&pool)
            .await
            .unwrap();
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
        let original_count: i64 = sqlx::query_scalar("SELECT count(*) FROM relay_envelope")
            .fetch_one(&pool)
            .await
            .unwrap();
        let sentinel_columns: i64 =
            sqlx::query_scalar("SELECT count(*) FROM pragma_table_info('relay_dynamic_principal')")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(version, 3);
        assert_eq!(original_count, 1);
        assert_eq!(sentinel_columns, 1);
    }

    #[tokio::test]
    async fn failed_schema_v2_migration_preserves_the_v2_database() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("relay.sqlite");
        let pool = create_v1_pool(&path).await;
        let existing = envelope(27, 28, DeliveryClass::GroupApplication, None, 29);
        insert_v1_row(&pool, &existing, 1, existing.payload()).await;
        let mut transaction = pool.begin().await.unwrap();
        migrate_schema_v1_to_v2(&mut transaction).await.unwrap();
        transaction.commit().await.unwrap();
        sqlx::query("CREATE TABLE relay_envelope_v3 (sentinel INTEGER)")
            .execute(&pool)
            .await
            .unwrap();
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
        let original_count: i64 = sqlx::query_scalar("SELECT count(*) FROM relay_envelope")
            .fetch_one(&pool)
            .await
            .unwrap();
        let sentinel_columns: i64 =
            sqlx::query_scalar("SELECT count(*) FROM pragma_table_info('relay_envelope_v3')")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(version, 2);
        assert_eq!(original_count, 1);
        assert_eq!(sentinel_columns, 1);
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
