use KonclaveCryptographicCore::DeviceIdentity;
use KonclaveDomainCore::{DeviceId, PairingId, ShortCodePairingAttemptId, ShortCodePairingLocator};
use KonclaveSecretStorage::{SealedBlob, SecretRecordContext, SecretRecordKind};
use rusqlite::{OptionalExtension, params};

use super::{
    PROFILE_SCHEMA_VERSION, ProfileStore, ProfileStoreError, from_sql_integer, to_sql_integer,
};
use crate::short_code_pairing::{
    ShortCodeOperationState, ShortCodePhase, ShortCodeRole, ShortCodeStateError,
};

const MAX_ACTIVE_SHORT_CODE_OPERATIONS: usize = 16;
const MAX_SHORT_CODE_OPERATION_RECORDS: usize = 64;
const SHORT_CODE_RECORD_CONTEXT_VERSION: &[u8] = b"short-code-operation-v1";

/// One authenticated durable short-code operation checkpoint.
pub(crate) struct ShortCodeCheckpoint {
    pub(crate) locator: ShortCodePairingLocator,
    pub(crate) attempt_id: Option<ShortCodePairingAttemptId>,
    pub(crate) pairing_id: Option<PairingId>,
    pub(crate) role: ShortCodeRole,
    pub(crate) phase: ShortCodePhase,
    pub(crate) deadline_unix_seconds: Option<u64>,
    pub(crate) generation: u64,
    pub(crate) state: ShortCodeOperationState,
}

pub(crate) enum ShortCodePeerBinding {
    Unlinked,
    Verified(DeviceId),
    Blocked,
}

impl ProfileStore {
    pub(super) fn initialize_short_code_pairing_schema(&self) -> Result<(), ProfileStoreError> {
        let current_version: u32 = self
            .lock()?
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .map_err(|_| ProfileStoreError::Storage)?;
        let existing_identity = self.read_profile_blob(
            "SELECT length(sealed_device_identity)
             FROM daemon_profile
             WHERE singleton_id = 1",
            "SELECT sealed_device_identity
             FROM daemon_profile
             WHERE singleton_id = 1",
        )?;
        let opened_identity = existing_identity
            .as_ref()
            .map(|blob| {
                DeviceIdentity::open_with_profile_schema_floor(
                    &self.sealer,
                    self.locked_profile.profile_id.as_bytes(),
                    blob,
                )
                .map_err(|_| ProfileStoreError::CorruptData)
            })
            .transpose()?;
        if current_version == PROFILE_SCHEMA_VERSION {
            if let Some((_, floor)) = opened_identity
                && floor != PROFILE_SCHEMA_VERSION
            {
                return Err(ProfileStoreError::CorruptData);
            }
            return Ok(());
        }
        if current_version != 18 {
            return Err(ProfileStoreError::UnsupportedSchema);
        }
        let migrated_identity = match opened_identity {
            Some((identity, 18)) => Some(
                identity
                    .seal_with_profile_schema_floor(
                        &self.sealer,
                        self.locked_profile.profile_id.as_bytes(),
                        PROFILE_SCHEMA_VERSION,
                    )
                    .map_err(|_| ProfileStoreError::Cryptographic)?,
            ),
            Some(_) => return Err(ProfileStoreError::CorruptData),
            None => None,
        };
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction()
            .map_err(|_| ProfileStoreError::Storage)?;
        transaction
            .execute_batch(
                "CREATE TABLE daemon_short_code_pairing (
                    locator BLOB PRIMARY KEY CHECK (length(locator) = 32),
                    attempt_id BLOB UNIQUE CHECK (
                        attempt_id IS NULL OR length(attempt_id) = 16
                    ),
                    pairing_id BLOB UNIQUE CHECK (
                        pairing_id IS NULL OR length(pairing_id) = 16
                    ),
                    local_role INTEGER NOT NULL CHECK (local_role BETWEEN 1 AND 2),
                    phase INTEGER NOT NULL CHECK (phase BETWEEN 1 AND 13),
                    deadline_unix_seconds INTEGER CHECK (
                        deadline_unix_seconds IS NULL OR deadline_unix_seconds >= 1
                    ),
                    generation INTEGER NOT NULL CHECK (generation >= 1),
                    sealed_state BLOB NOT NULL,
                    CHECK (
                        (local_role = 1 AND phase IN (1, 2, 3, 4, 5, 12, 13))
                        OR
                        (local_role = 2 AND phase IN (6, 7, 8, 9, 10, 11, 12, 13))
                    ),
                    CHECK (
                        (phase = 6 AND attempt_id IS NULL AND deadline_unix_seconds IS NULL)
                        OR
                        (phase = 13 AND (
                            attempt_id IS NULL
                            OR
                            (attempt_id IS NOT NULL AND deadline_unix_seconds IS NOT NULL)
                        ))
                        OR
                        (phase NOT IN (6, 13)
                            AND attempt_id IS NOT NULL
                            AND deadline_unix_seconds IS NOT NULL)
                    )
                 ) WITHOUT ROWID;
                 CREATE INDEX daemon_short_code_pairing_active_idx
                    ON daemon_short_code_pairing(phase, locator)
                    WHERE phase NOT IN (5, 11, 13);
                 CREATE INDEX daemon_short_code_pairing_pairing_idx
                    ON daemon_short_code_pairing(pairing_id)
                    WHERE pairing_id IS NOT NULL;",
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        if let Some(identity) = migrated_identity
            && transaction
                .execute(
                    "UPDATE daemon_profile
                     SET sealed_device_identity = ?1
                     WHERE singleton_id = 1 AND sealed_device_identity IS NOT NULL",
                    params![identity.as_bytes()],
                )
                .map_err(|_| ProfileStoreError::Storage)?
                != 1
        {
            return Err(ProfileStoreError::CorruptData);
        }
        transaction
            .pragma_update(None, "user_version", PROFILE_SCHEMA_VERSION)
            .map_err(|_| ProfileStoreError::Storage)?;
        transaction.commit().map_err(|_| ProfileStoreError::Storage)
    }

    pub(super) fn verify_short_code_pairings(&self) -> Result<(), ProfileStoreError> {
        let locators = {
            let connection = self.lock()?;
            let (active, total): (i64, i64) = connection
                .query_row(
                    "SELECT
                    count(*) FILTER (WHERE phase NOT IN (5, 11, 13)),
                    count(*)
                 FROM daemon_short_code_pairing",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .map_err(|_| ProfileStoreError::Storage)?;
            if usize::try_from(active)
                .ok()
                .is_none_or(|value| value > MAX_ACTIVE_SHORT_CODE_OPERATIONS)
                || usize::try_from(total)
                    .ok()
                    .is_none_or(|value| value > MAX_SHORT_CODE_OPERATION_RECORDS)
            {
                return Err(ProfileStoreError::CorruptData);
            }
            let mut statement = connection
                .prepare(
                    "SELECT CASE WHEN length(locator) = 32 THEN locator END
                 FROM daemon_short_code_pairing
                 ORDER BY locator",
                )
                .map_err(|_| ProfileStoreError::Storage)?;
            statement
                .query_map([], |row| row.get::<_, Vec<u8>>(0))
                .map_err(|_| ProfileStoreError::Storage)?
                .map(|value| {
                    ShortCodePairingLocator::from_slice(
                        &value.map_err(|_| ProfileStoreError::Storage)?,
                    )
                    .map_err(|_| ProfileStoreError::CorruptData)
                })
                .collect::<Result<Vec<_>, _>>()?
        };
        for locator in locators {
            self.load_short_code_pairing_by_locator(locator)?;
        }
        Ok(())
    }

    /// Reserves one initial sealed short-code operation.
    ///
    /// # Errors
    ///
    /// Returns a duplicate, capacity, state, sealing, or storage error.
    pub(crate) fn reserve_short_code_pairing(
        &self,
        state: &ShortCodeOperationState,
    ) -> Result<(), ProfileStoreError> {
        if !matches!(
            state.phase,
            ShortCodePhase::CreatorAwaitingClaim | ShortCodePhase::ClaimantClaiming
        ) {
            return Err(ProfileStoreError::InvalidTransition);
        }
        let encoded = state.encode().map_err(short_code_state_error)?;
        let generation = 1;
        let blob = self.seal_short_code_pairing(state, generation, &encoded)?;
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction()
            .map_err(|_| ProfileStoreError::Storage)?;
        transaction
            .execute(
                "DELETE FROM daemon_short_code_pairing
                 WHERE phase IN (5, 11, 13)
                   AND deadline_unix_seconds IS NOT NULL
                   AND deadline_unix_seconds <= ?1",
                params![to_sql_integer(
                    self.clock.now_unix_milliseconds().saturating_div(1_000)
                )?],
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        let inserted = transaction.execute(
            "INSERT INTO daemon_short_code_pairing (
                locator,
                attempt_id,
                pairing_id,
                local_role,
                phase,
                deadline_unix_seconds,
                generation,
                sealed_state
             ) VALUES (?1, ?2, NULL, ?3, ?4, ?5, 1, ?6)",
            params![
                state.locator.as_bytes().as_slice(),
                state.attempt_id.map(ShortCodePairingAttemptId::into_bytes),
                state.role as u8,
                state.phase as u8,
                state
                    .deadline_unix_seconds
                    .map(to_sql_integer)
                    .transpose()?,
                blob.as_bytes(),
            ],
        );
        match inserted {
            Ok(1) => {
                let (active, total): (i64, i64) = transaction
                    .query_row(
                        "SELECT
                            count(*) FILTER (WHERE phase NOT IN (5, 11, 13)),
                            count(*)
                         FROM daemon_short_code_pairing",
                        [],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .map_err(|_| ProfileStoreError::Storage)?;
                if active
                    > i64::try_from(MAX_ACTIVE_SHORT_CODE_OPERATIONS)
                        .map_err(|_| ProfileStoreError::SequenceExhausted)?
                    || total
                        > i64::try_from(MAX_SHORT_CODE_OPERATION_RECORDS)
                            .map_err(|_| ProfileStoreError::SequenceExhausted)?
                {
                    return Err(ProfileStoreError::PairingCapacityExceeded);
                }
                transaction.commit().map_err(|_| ProfileStoreError::Storage)
            }
            Ok(_) => Err(ProfileStoreError::Storage),
            Err(rusqlite::Error::SqliteFailure(ref details, _))
                if details.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                drop(transaction);
                drop(connection);
                let existing = match self.load_short_code_pairing_by_locator(state.locator) {
                    Ok(existing) => existing,
                    Err(ProfileStoreError::OperationNotFound) => {
                        return Err(ProfileStoreError::DuplicateOperation);
                    }
                    Err(error) => return Err(error),
                };
                if existing.generation == generation
                    && existing.role == state.role
                    && existing.phase == state.phase
                    && existing.attempt_id == state.attempt_id
                    && existing.deadline_unix_seconds == state.deadline_unix_seconds
                    && existing
                        .state
                        .encode()
                        .map_err(short_code_state_error)?
                        .as_slice()
                        == encoded.as_slice()
                {
                    Ok(())
                } else {
                    Err(ProfileStoreError::DuplicateOperation)
                }
            }
            Err(_) => Err(ProfileStoreError::Storage),
        }
    }

    /// Loads one authenticated short-code checkpoint by its non-secret locator.
    ///
    /// # Errors
    ///
    /// Returns a missing, malformed, authentication, or storage error.
    pub(crate) fn load_short_code_pairing_by_locator(
        &self,
        locator: ShortCodePairingLocator,
    ) -> Result<ShortCodeCheckpoint, ProfileStoreError> {
        self.load_short_code_pairing_where("locator = ?1", locator.as_bytes())
    }

    /// Loads one authenticated short-code checkpoint by its attempt identifier.
    ///
    /// # Errors
    ///
    /// Returns a missing, malformed, authentication, or storage error.
    pub(crate) fn load_short_code_pairing(
        &self,
        attempt_id: ShortCodePairingAttemptId,
    ) -> Result<ShortCodeCheckpoint, ProfileStoreError> {
        self.load_short_code_pairing_where("attempt_id = ?1", attempt_id.as_bytes())
    }

    fn load_short_code_pairing_where(
        &self,
        predicate: &str,
        identifier: &[u8],
    ) -> Result<ShortCodeCheckpoint, ProfileStoreError> {
        type StoredRow = (
            Vec<u8>,
            Option<Vec<u8>>,
            Option<Vec<u8>>,
            i64,
            i64,
            Option<i64>,
            i64,
            i64,
            Option<Vec<u8>>,
        );
        let query = format!(
            "SELECT
                CASE WHEN length(locator) = 32 THEN locator END,
                CASE
                    WHEN attempt_id IS NULL THEN NULL
                    WHEN length(attempt_id) = 16 THEN attempt_id
                END,
                CASE
                    WHEN pairing_id IS NULL THEN NULL
                    WHEN length(pairing_id) = 16 THEN pairing_id
                END,
                local_role,
                phase,
                deadline_unix_seconds,
                generation,
                length(sealed_state),
                CASE
                    WHEN length(sealed_state) BETWEEN 1 AND ?2 THEN sealed_state
                END
             FROM daemon_short_code_pairing
             WHERE {predicate}"
        );
        let stored: Option<StoredRow> = self
            .lock()?
            .query_row(
                &query,
                params![identifier, super::MAX_SEALED_RECORD_BYTES],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                        row.get(8)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| ProfileStoreError::Storage)?;
        let (
            locator,
            attempt_id,
            pairing_id,
            role,
            phase,
            deadline,
            generation,
            sealed_length,
            sealed_state,
        ) = stored.ok_or(ProfileStoreError::OperationNotFound)?;
        let sealed_state = sealed_state.ok_or(ProfileStoreError::CorruptData)?;
        let locator = ShortCodePairingLocator::from_slice(&locator)
            .map_err(|_| ProfileStoreError::CorruptData)?;
        let attempt_id = attempt_id
            .map(|value| {
                ShortCodePairingAttemptId::from_slice(&value)
                    .map_err(|_| ProfileStoreError::CorruptData)
            })
            .transpose()?;
        let pairing_id = pairing_id
            .map(|value| PairingId::from_slice(&value).map_err(|_| ProfileStoreError::CorruptData))
            .transpose()?;
        let role = short_code_role(role)?;
        let phase = short_code_phase(phase)?;
        let deadline = deadline.map(from_sql_integer).transpose()?;
        let generation = from_sql_integer(generation)?;
        if sealed_length < 1
            || usize::try_from(sealed_length).ok() != Some(sealed_state.len())
            || sealed_state.len() > super::MAX_SEALED_RECORD_BYTES
        {
            return Err(ProfileStoreError::CorruptData);
        }
        let blob =
            SealedBlob::from_bytes(sealed_state).map_err(|_| ProfileStoreError::CorruptData)?;
        let plaintext = self
            .sealer
            .open(
                &short_code_record_context(
                    self.locked_profile.profile_id.as_bytes(),
                    locator,
                    attempt_id,
                    pairing_id,
                    role,
                    phase,
                    deadline,
                    generation,
                )?,
                &blob,
            )
            .map_err(|_| ProfileStoreError::CorruptData)?;
        let state = ShortCodeOperationState::decode(&plaintext).map_err(short_code_state_error)?;
        if state.locator != locator
            || state.attempt_id != attempt_id
            || state.pairing_id != pairing_id
            || state.role != role
            || state.phase != phase
            || state.deadline_unix_seconds != deadline
        {
            return Err(ProfileStoreError::CorruptData);
        }
        Ok(ShortCodeCheckpoint {
            locator,
            attempt_id,
            pairing_id,
            role,
            phase,
            deadline_unix_seconds: deadline,
            generation,
            state,
        })
    }

    /// Atomically replaces one short-code checkpoint under an expected generation.
    ///
    /// # Errors
    ///
    /// Returns a stale generation, invalid transition, state, sealing, or storage error.
    pub(crate) fn checkpoint_short_code_pairing(
        &self,
        locator: ShortCodePairingLocator,
        expected_generation: u64,
        state: &ShortCodeOperationState,
    ) -> Result<u64, ProfileStoreError> {
        if expected_generation == 0 || state.locator != locator {
            return Err(ProfileStoreError::InvalidTransition);
        }
        let current = self.load_short_code_pairing_by_locator(locator)?;
        let encoded = state.encode().map_err(short_code_state_error)?;
        if current.generation != expected_generation {
            return self.match_short_code_retry(&current, expected_generation, state, &encoded);
        }
        if current.role != state.role
            || !valid_short_code_transition(current.phase, state.phase)
            || current.attempt_id.is_some() && current.attempt_id != state.attempt_id
            || current.deadline_unix_seconds.is_some()
                && current.deadline_unix_seconds != state.deadline_unix_seconds
            || current.pairing_id.is_some() && current.pairing_id != state.pairing_id
        {
            return Err(ProfileStoreError::InvalidTransition);
        }
        let next_generation = expected_generation
            .checked_add(1)
            .ok_or(ProfileStoreError::SequenceExhausted)?;
        let blob = self.seal_short_code_pairing(state, next_generation, &encoded)?;
        let changed = self
            .lock()?
            .execute(
                "UPDATE daemon_short_code_pairing
                 SET attempt_id = ?1,
                     pairing_id = ?2,
                     phase = ?3,
                     deadline_unix_seconds = ?4,
                     generation = ?5,
                     sealed_state = ?6
                 WHERE locator = ?7 AND generation = ?8",
                params![
                    state.attempt_id.map(ShortCodePairingAttemptId::into_bytes),
                    state.pairing_id.map(PairingId::into_bytes),
                    state.phase as u8,
                    state
                        .deadline_unix_seconds
                        .map(to_sql_integer)
                        .transpose()?,
                    to_sql_integer(next_generation)?,
                    blob.as_bytes(),
                    locator.as_bytes().as_slice(),
                    to_sql_integer(expected_generation)?,
                ],
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        if changed == 1 {
            return Ok(next_generation);
        }
        let observed = self.load_short_code_pairing_by_locator(locator)?;
        self.match_short_code_retry(&observed, expected_generation, state, &encoded)
    }

    fn match_short_code_retry(
        &self,
        observed: &ShortCodeCheckpoint,
        expected_generation: u64,
        state: &ShortCodeOperationState,
        encoded: &[u8],
    ) -> Result<u64, ProfileStoreError> {
        let retry_generation = expected_generation
            .checked_add(1)
            .ok_or(ProfileStoreError::InvalidTransition)?;
        if observed.generation == retry_generation
            && observed.role == state.role
            && observed.phase == state.phase
            && observed.attempt_id == state.attempt_id
            && observed.deadline_unix_seconds == state.deadline_unix_seconds
            && observed.pairing_id == state.pairing_id
            && observed
                .state
                .encode()
                .map_err(short_code_state_error)?
                .as_slice()
                == encoded
        {
            Ok(observed.generation)
        } else {
            Err(ProfileStoreError::InvalidTransition)
        }
    }

    /// Lists active short-code locators in stable order.
    ///
    /// # Errors
    ///
    /// Returns a bound, malformed-data, or storage error.
    pub(crate) fn active_short_code_pairing_locators(
        &self,
        after: Option<ShortCodePairingLocator>,
        limit: usize,
    ) -> Result<Vec<ShortCodePairingLocator>, ProfileStoreError> {
        if limit == 0 || limit > MAX_ACTIVE_SHORT_CODE_OPERATIONS {
            return Err(ProfileStoreError::InvalidTransition);
        }
        let after = after.map(ShortCodePairingLocator::into_bytes);
        let connection = self.lock()?;
        let mut statement = connection
            .prepare(
                "SELECT locator
                 FROM daemon_short_code_pairing
                 WHERE phase NOT IN (5, 11, 13)
                   AND (?1 IS NULL OR locator > ?1)
                 ORDER BY locator
                 LIMIT ?2",
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        statement
            .query_map(
                params![
                    after.as_ref().map(<[u8; 32]>::as_slice),
                    i64::try_from(limit).map_err(|_| ProfileStoreError::SequenceExhausted)?
                ],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .map_err(|_| ProfileStoreError::Storage)?
            .map(|value| {
                ShortCodePairingLocator::from_slice(&value.map_err(|_| ProfileStoreError::Storage)?)
                    .map_err(|_| ProfileStoreError::CorruptData)
            })
            .collect()
    }

    /// Returns the verified peer identity bound to one resulting pairing.
    ///
    /// # Errors
    ///
    /// Returns malformed-data or storage when a retained binding cannot authenticate.
    pub(crate) fn short_code_peer_binding(
        &self,
        pairing_id: PairingId,
    ) -> Result<ShortCodePeerBinding, ProfileStoreError> {
        let locator: Option<Vec<u8>> = self
            .lock()?
            .query_row(
                "SELECT locator
                 FROM daemon_short_code_pairing
                 WHERE pairing_id = ?1",
                params![pairing_id.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| ProfileStoreError::Storage)?;
        let Some(value) = locator else {
            return Ok(ShortCodePeerBinding::Unlinked);
        };
        let locator = ShortCodePairingLocator::from_slice(&value)
            .map_err(|_| ProfileStoreError::CorruptData)?;
        let checkpoint = self.load_short_code_pairing_by_locator(locator)?;
        if matches!(
            checkpoint.phase,
            ShortCodePhase::CreatorPublishingCapability
                | ShortCodePhase::CreatorCompleted
                | ShortCodePhase::ClaimantTakingCapability
                | ShortCodePhase::ClaimantCompleted
        ) && checkpoint.state.confirmation
            == KonclaveDomainCore::ShortCodeConfirmationState::Confirmed
        {
            return checkpoint
                .state
                .peer_device_id
                .map(ShortCodePeerBinding::Verified)
                .ok_or(ProfileStoreError::CorruptData);
        }
        Ok(ShortCodePeerBinding::Blocked)
    }

    /// Deletes one terminal short-code record.
    ///
    /// # Errors
    ///
    /// Returns invalid-transition, missing, or storage when the record is not terminal.
    pub(crate) fn delete_terminal_short_code_pairing(
        &self,
        locator: ShortCodePairingLocator,
    ) -> Result<(), ProfileStoreError> {
        let changed = self
            .lock()?
            .execute(
                "DELETE FROM daemon_short_code_pairing
                 WHERE locator = ?1 AND phase IN (5, 11, 13)",
                params![locator.as_bytes().as_slice()],
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        if changed == 1 {
            Ok(())
        } else {
            Err(ProfileStoreError::InvalidTransition)
        }
    }

    fn seal_short_code_pairing(
        &self,
        state: &ShortCodeOperationState,
        generation: u64,
        plaintext: &[u8],
    ) -> Result<SealedBlob, ProfileStoreError> {
        self.sealer
            .seal(
                &short_code_record_context(
                    self.locked_profile.profile_id.as_bytes(),
                    state.locator,
                    state.attempt_id,
                    state.pairing_id,
                    state.role,
                    state.phase,
                    state.deadline_unix_seconds,
                    generation,
                )?,
                plaintext,
            )
            .map_err(|_| ProfileStoreError::Storage)
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "every authenticated checkpoint metadata field remains explicit"
)]
fn short_code_record_context(
    profile_id: &[u8],
    locator: ShortCodePairingLocator,
    attempt_id: Option<ShortCodePairingAttemptId>,
    pairing_id: Option<PairingId>,
    role: ShortCodeRole,
    phase: ShortCodePhase,
    deadline: Option<u64>,
    generation: u64,
) -> Result<SecretRecordContext, ProfileStoreError> {
    let attempt = optional_identifier(attempt_id.map(ShortCodePairingAttemptId::into_bytes));
    let pairing = optional_identifier(pairing_id.map(PairingId::into_bytes));
    let deadline = optional_integer(deadline);
    let role_phase = [role as u8, phase as u8];
    SecretRecordContext::derive(
        SecretRecordKind::ShortCodePairingOperation,
        &[
            SHORT_CODE_RECORD_CONTEXT_VERSION,
            profile_id,
            locator.as_bytes(),
            &role_phase,
            &attempt,
            &pairing,
            &deadline,
            &generation.to_be_bytes(),
        ],
    )
    .map_err(|_| ProfileStoreError::Storage)
}

fn optional_identifier<const N: usize>(value: Option<[u8; N]>) -> Vec<u8> {
    let mut output = Vec::with_capacity(N + 1);
    match value {
        Some(value) => {
            output.push(1);
            output.extend_from_slice(&value);
        }
        None => output.push(0),
    }
    output
}

fn optional_integer(value: Option<u64>) -> Vec<u8> {
    let mut output = Vec::with_capacity(9);
    match value {
        Some(value) => {
            output.push(1);
            output.extend_from_slice(&value.to_be_bytes());
        }
        None => output.push(0),
    }
    output
}

fn short_code_role(value: i64) -> Result<ShortCodeRole, ProfileStoreError> {
    match value {
        1 => Ok(ShortCodeRole::Creator),
        2 => Ok(ShortCodeRole::Claimant),
        _ => Err(ProfileStoreError::CorruptData),
    }
}

fn short_code_phase(value: i64) -> Result<ShortCodePhase, ProfileStoreError> {
    match value {
        1 => Ok(ShortCodePhase::CreatorAwaitingClaim),
        2 => Ok(ShortCodePhase::CreatorAwaitingFinalization),
        3 => Ok(ShortCodePhase::CreatorAwaitingConfirmation),
        4 => Ok(ShortCodePhase::CreatorPublishingCapability),
        5 => Ok(ShortCodePhase::CreatorCompleted),
        6 => Ok(ShortCodePhase::ClaimantClaiming),
        7 => Ok(ShortCodePhase::ClaimantAwaitingResponse),
        8 => Ok(ShortCodePhase::ClaimantAwaitingCreatorIdentity),
        9 => Ok(ShortCodePhase::ClaimantAwaitingConfirmation),
        10 => Ok(ShortCodePhase::ClaimantTakingCapability),
        11 => Ok(ShortCodePhase::ClaimantCompleted),
        12 => Ok(ShortCodePhase::Cancelling),
        13 => Ok(ShortCodePhase::Cancelled),
        _ => Err(ProfileStoreError::CorruptData),
    }
}

fn valid_short_code_transition(current: ShortCodePhase, next: ShortCodePhase) -> bool {
    current == next
        || matches!(
            (current, next),
            (
                ShortCodePhase::CreatorAwaitingClaim,
                ShortCodePhase::CreatorAwaitingFinalization
            ) | (
                ShortCodePhase::CreatorAwaitingFinalization,
                ShortCodePhase::CreatorAwaitingConfirmation
            ) | (
                ShortCodePhase::CreatorAwaitingConfirmation,
                ShortCodePhase::CreatorPublishingCapability
            ) | (
                ShortCodePhase::CreatorPublishingCapability,
                ShortCodePhase::CreatorCompleted
            ) | (
                ShortCodePhase::ClaimantClaiming,
                ShortCodePhase::ClaimantAwaitingResponse
            ) | (
                ShortCodePhase::ClaimantAwaitingResponse,
                ShortCodePhase::ClaimantAwaitingCreatorIdentity
            ) | (
                ShortCodePhase::ClaimantAwaitingCreatorIdentity,
                ShortCodePhase::ClaimantAwaitingConfirmation
            ) | (
                ShortCodePhase::ClaimantAwaitingConfirmation,
                ShortCodePhase::ClaimantTakingCapability
            ) | (
                ShortCodePhase::ClaimantTakingCapability,
                ShortCodePhase::ClaimantCompleted
            ) | (
                ShortCodePhase::CreatorAwaitingClaim
                    | ShortCodePhase::CreatorAwaitingFinalization
                    | ShortCodePhase::CreatorAwaitingConfirmation
                    | ShortCodePhase::CreatorPublishingCapability
                    | ShortCodePhase::ClaimantAwaitingResponse
                    | ShortCodePhase::ClaimantAwaitingCreatorIdentity
                    | ShortCodePhase::ClaimantAwaitingConfirmation
                    | ShortCodePhase::ClaimantTakingCapability,
                ShortCodePhase::Cancelling
            ) | (
                ShortCodePhase::Cancelling | ShortCodePhase::ClaimantClaiming,
                ShortCodePhase::Cancelled
            )
        )
}

fn short_code_state_error(_: ShortCodeStateError) -> ProfileStoreError {
    ProfileStoreError::CorruptData
}

#[cfg(test)]
mod tests {
    use KonclaveCryptographicCore::{ShortCodeOpaqueServerRecord, ShortCodePairingCode};
    use KonclaveSecretStorage::{ExternalWrappingKeyProvider, SecretSealer};

    use super::*;
    use crate::persistence::{LockedProfile, ProfileId};

    fn open_store(root: &std::path::Path, profile: &str) -> ProfileStore {
        LockedProfile::acquire(root, ProfileId::parse(profile).unwrap())
            .unwrap()
            .open_store(
                SecretSealer::from_provider(ExternalWrappingKeyProvider::from_bytes([7; 32]))
                    .unwrap(),
            )
            .unwrap()
    }

    #[test]
    fn short_code_state_is_sealed_and_checkpointed_exactly() {
        let root = tempfile::tempdir().unwrap();
        let store = open_store(root.path(), "short-code-persistence");
        let code = ShortCodePairingCode::parse("123456").unwrap();
        let attempt = ShortCodePairingAttemptId::from_bytes([1; 16]);
        let server = ShortCodeOpaqueServerRecord::register(&code, attempt).unwrap();
        let mut server_bytes = Vec::new();
        server.write_to(&mut server_bytes).unwrap();
        let state = ShortCodeOperationState::creator(
            code.locator(),
            attempt,
            100,
            DeviceId::from_bytes([2; 32]),
            server,
        );
        store.reserve_short_code_pairing(&state).unwrap();
        let sealed: Vec<u8> = store
            .lock()
            .unwrap()
            .query_row(
                "SELECT sealed_state FROM daemon_short_code_pairing WHERE locator = ?1",
                params![code.locator().as_bytes().as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            !sealed
                .windows(server_bytes.len())
                .any(|window| window == server_bytes)
        );
        let checkpoint = store.load_short_code_pairing(attempt).unwrap();
        assert_eq!(checkpoint.phase, ShortCodePhase::CreatorAwaitingClaim);

        let mut state = checkpoint.state;
        state.phase = ShortCodePhase::CreatorAwaitingFinalization;
        state.credential_request = Some(vec![3]);
        state.credential_response = Some(vec![4]);
        let generation = store
            .checkpoint_short_code_pairing(checkpoint.locator, checkpoint.generation, &state)
            .unwrap();
        assert_eq!(generation, 2);
        assert_eq!(
            store
                .load_short_code_pairing(attempt)
                .unwrap()
                .state
                .credential_response
                .as_deref(),
            Some(&[4][..])
        );
    }

    #[test]
    fn schema_eighteen_migrates_identity_and_short_code_table_transactionally() {
        let root = tempfile::tempdir().unwrap();
        let profile = "short-code-schema";
        let store = open_store(root.path(), profile);
        let device = store.load_or_create_device().unwrap();
        let database_path = store.locked_profile.profile_database_path();
        let profile_id = store.locked_profile.profile_id.clone();
        let prior_identity = device
            .seal_with_profile_schema_floor(&store.sealer, profile_id.as_bytes(), 18)
            .unwrap();
        {
            let connection = store.lock().unwrap();
            connection
                .execute(
                    "UPDATE daemon_profile SET sealed_device_identity = ?1 WHERE singleton_id = 1",
                    params![prior_identity.as_bytes()],
                )
                .unwrap();
            connection
                .execute_batch(
                    "DROP TABLE daemon_short_code_pairing;
                     PRAGMA user_version = 18;",
                )
                .unwrap();
        }
        drop(store);

        let migrated = LockedProfile::acquire(root.path(), profile_id)
            .unwrap()
            .open_store(
                SecretSealer::from_provider(ExternalWrappingKeyProvider::from_bytes([7; 32]))
                    .unwrap(),
            )
            .unwrap();
        let version: u32 = migrated
            .lock()
            .unwrap()
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, PROFILE_SCHEMA_VERSION);
        assert_eq!(
            migrated.load_or_create_device().unwrap().device_id(),
            device.device_id()
        );
        drop(migrated);
        assert!(database_path.exists());
    }

    #[test]
    fn failed_short_code_schema_migration_preserves_version_eighteen() {
        let root = tempfile::tempdir().unwrap();
        let profile = "short-code-schema-failure";
        let store = open_store(root.path(), profile);
        let device = store.load_or_create_device().unwrap();
        let database_path = store.locked_profile.profile_database_path();
        let profile_id = store.locked_profile.profile_id.clone();
        let prior_identity = device
            .seal_with_profile_schema_floor(&store.sealer, profile_id.as_bytes(), 18)
            .unwrap();
        {
            let connection = store.lock().unwrap();
            connection
                .execute(
                    "UPDATE daemon_profile SET sealed_device_identity = ?1 WHERE singleton_id = 1",
                    params![prior_identity.as_bytes()],
                )
                .unwrap();
            connection
                .execute_batch(
                    "DROP TABLE daemon_short_code_pairing;
                     CREATE TABLE daemon_short_code_pairing (sentinel INTEGER NOT NULL);
                     INSERT INTO daemon_short_code_pairing (sentinel) VALUES (7);
                     PRAGMA user_version = 18;",
                )
                .unwrap();
        }
        drop(store);

        assert_eq!(
            LockedProfile::acquire(root.path(), profile_id)
                .unwrap()
                .open_store(
                    SecretSealer::from_provider(ExternalWrappingKeyProvider::from_bytes([7; 32]),)
                        .unwrap(),
                )
                .err(),
            Some(ProfileStoreError::Storage)
        );
        let connection = rusqlite::Connection::open(database_path).unwrap();
        let version: u32 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        let sentinel: i64 = connection
            .query_row(
                "SELECT sentinel FROM daemon_short_code_pairing",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(version, 18);
        assert_eq!(sentinel, 7);
    }

    #[test]
    fn tampered_short_code_state_fails_profile_startup() {
        let root = tempfile::tempdir().unwrap();
        let profile = "short-code-tamper";
        let store = open_store(root.path(), profile);
        let code = ShortCodePairingCode::parse("123456").unwrap();
        let attempt = ShortCodePairingAttemptId::from_bytes([1; 16]);
        let state = ShortCodeOperationState::creator(
            code.locator(),
            attempt,
            100,
            DeviceId::from_bytes([2; 32]),
            ShortCodeOpaqueServerRecord::register(&code, attempt).unwrap(),
        );
        store.reserve_short_code_pairing(&state).unwrap();
        let profile_id = store.locked_profile.profile_id.clone();
        {
            let connection = store.lock().unwrap();
            let mut sealed: Vec<u8> = connection
                .query_row(
                    "SELECT sealed_state FROM daemon_short_code_pairing WHERE locator = ?1",
                    params![code.locator().as_bytes().as_slice()],
                    |row| row.get(0),
                )
                .unwrap();
            let last = sealed.len() - 1;
            sealed[last] ^= 1;
            connection
                .execute(
                    "UPDATE daemon_short_code_pairing SET sealed_state = ?1 WHERE locator = ?2",
                    params![sealed, code.locator().as_bytes().as_slice()],
                )
                .unwrap();
        }
        drop(store);
        assert_eq!(
            LockedProfile::acquire(root.path(), profile_id)
                .unwrap()
                .open_store(
                    SecretSealer::from_provider(ExternalWrappingKeyProvider::from_bytes([7; 32]),)
                        .unwrap(),
                )
                .err(),
            Some(ProfileStoreError::CorruptData)
        );
    }
}
