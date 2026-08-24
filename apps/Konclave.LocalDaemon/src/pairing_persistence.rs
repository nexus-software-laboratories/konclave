use super::*;

use KonclaveDomainCore::PairingId;

const MAX_ACTIVE_PAIRINGS: usize = 32;
const PAIRING_RECORD_SCOPE: u8 = 1;

/// This profile's role in one pairing exchange.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum PairingRole {
    Joiner = 1,
    Inviter = 2,
}

/// Durable high-level phase for one pairing exchange.
///
/// Detailed record identities and payloads live in the sealed checkpoint. These
/// finite values are duplicated in authenticated metadata so active work can be
/// discovered without opening every secret-bearing record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum PairingPhase {
    JoinerAwaitingInvitation = 1,
    JoinerAwaitingInviterAuthorization = 2,
    JoinerAwaitingWelcome = 3,
    InviterAwaitingAuthorization = 4,
    InviterAwaitingJoinProof = 5,
    InviterAwaitingCompletion = 6,
    Compensating = 7,
    Completed = 8,
    Cancelled = 9,
}

impl PairingPhase {
    pub(crate) const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Cancelled)
    }
}

/// One authenticated durable pairing checkpoint.
///
/// `state` may contain the pairing capability and decrypted operation material, so it
/// is zeroized and this type implements neither `Clone` nor `Debug`.
pub(crate) struct PairingCheckpoint {
    pub pairing_id: PairingId,
    pub routing_id: RoutingId,
    pub role: PairingRole,
    pub phase: PairingPhase,
    pub authorization_deadline_unix_seconds: u64,
    pub completion_deadline_unix_seconds: Option<u64>,
    pub replay_cursor: u64,
    pub generation: u64,
    pub state: Zeroizing<Vec<u8>>,
}

impl ProfileStore {
    /// Reserves the initial sealed checkpoint for one pairing.
    ///
    /// The same pairing and byte-identical checkpoint is idempotent. Reusing a
    /// pairing or route for different state fails closed.
    ///
    /// # Errors
    ///
    /// Returns a validation, duplicate, sealing, or storage error.
    pub(crate) fn reserve_pairing(
        &self,
        pairing_id: PairingId,
        routing_id: RoutingId,
        role: PairingRole,
        authorization_deadline_unix_seconds: u64,
        state: &[u8],
    ) -> Result<(), ProfileStoreError> {
        validate_state(state)?;
        if authorization_deadline_unix_seconds == 0 {
            return Err(ProfileStoreError::InvalidTransition);
        }
        let phase = initial_phase(role);
        let generation = 1;
        let blob = self.seal_pairing_checkpoint(
            pairing_id,
            routing_id,
            role,
            phase,
            authorization_deadline_unix_seconds,
            None,
            0,
            generation,
            state,
        )?;
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction()
            .map_err(|_| ProfileStoreError::Storage)?;
        let inserted = transaction.execute(
            "INSERT INTO daemon_pairing (
                pairing_id,
                routing_id,
                local_role,
                phase,
                authorization_deadline_unix_seconds,
                completion_deadline_unix_seconds,
                replay_cursor,
                generation,
                sealed_state
             ) VALUES (?1, ?2, ?3, ?4, ?5, NULL, 0, ?6, ?7)",
            params![
                pairing_id.as_bytes().as_slice(),
                routing_id.as_bytes().as_slice(),
                role as u8,
                phase as u8,
                to_sql_integer(authorization_deadline_unix_seconds)?,
                to_sql_integer(generation)?,
                blob.as_bytes(),
            ],
        );
        match inserted {
            Ok(1) => {
                let active_count: i64 = transaction
                    .query_row(
                        "SELECT count(*) FROM daemon_pairing WHERE phase NOT IN (8, 9)",
                        [],
                        |row| row.get(0),
                    )
                    .map_err(|_| ProfileStoreError::Storage)?;
                if active_count
                    > i64::try_from(MAX_ACTIVE_PAIRINGS)
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
                let existing = match self.load_pairing(pairing_id) {
                    Ok(existing) => existing,
                    Err(ProfileStoreError::OperationNotFound) => {
                        return Err(ProfileStoreError::DuplicateOperation);
                    }
                    Err(error) => return Err(error),
                };
                if existing.routing_id == routing_id
                    && existing.role == role
                    && existing.phase == phase
                    && existing.authorization_deadline_unix_seconds
                        == authorization_deadline_unix_seconds
                    && existing.completion_deadline_unix_seconds.is_none()
                    && existing.replay_cursor == 0
                    && existing.generation == generation
                    && existing.state.as_slice() == state
                {
                    Ok(())
                } else {
                    Err(ProfileStoreError::DuplicateOperation)
                }
            }
            Err(_) => Err(ProfileStoreError::Storage),
        }
    }

    /// Loads and authenticates one durable pairing checkpoint.
    ///
    /// # Errors
    ///
    /// Returns a missing, malformed, authentication, or storage error.
    pub(crate) fn load_pairing(
        &self,
        pairing_id: PairingId,
    ) -> Result<PairingCheckpoint, ProfileStoreError> {
        type StoredRow = (Vec<u8>, i64, i64, i64, Option<i64>, i64, i64, i64, Vec<u8>);
        let stored: Option<StoredRow> = self
            .lock()?
            .query_row(
                "SELECT
                    CASE WHEN length(routing_id) = 32 THEN routing_id END,
                    local_role,
                    phase,
                    authorization_deadline_unix_seconds,
                    completion_deadline_unix_seconds,
                    replay_cursor,
                    generation,
                    length(sealed_state),
                    sealed_state
                 FROM daemon_pairing
                 WHERE pairing_id = ?1",
                params![pairing_id.as_bytes().as_slice()],
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
            routing_id,
            role,
            phase,
            authorization_deadline,
            completion_deadline,
            replay_cursor,
            generation,
            sealed_length,
            bytes,
        ) = stored.ok_or(ProfileStoreError::OperationNotFound)?;
        validate_blob_length(sealed_length)?;
        let role = pairing_role(role)?;
        let phase = pairing_phase(phase)?;
        let routing_id =
            RoutingId::from_slice(&routing_id).map_err(|_| ProfileStoreError::CorruptData)?;
        let authorization_deadline = from_sql_integer(authorization_deadline)?;
        let completion_deadline = completion_deadline.map(from_sql_integer).transpose()?;
        let replay_cursor = from_sql_integer(replay_cursor)?;
        let generation = from_sql_integer(generation)?;
        validate_metadata(role, phase, authorization_deadline, completion_deadline)?;
        if bytes.len() != usize::try_from(sealed_length).unwrap_or_default() {
            return Err(ProfileStoreError::CorruptData);
        }
        let state = self.open_pairing_checkpoint(
            pairing_id,
            routing_id,
            role,
            phase,
            authorization_deadline,
            completion_deadline,
            replay_cursor,
            generation,
            bytes,
        )?;
        validate_state(&state)?;
        Ok(PairingCheckpoint {
            pairing_id,
            routing_id,
            role,
            phase,
            authorization_deadline_unix_seconds: authorization_deadline,
            completion_deadline_unix_seconds: completion_deadline,
            replay_cursor,
            generation,
            state,
        })
    }

    /// Atomically replaces one pairing checkpoint under an expected generation.
    ///
    /// A byte-identical retry after the update is idempotent. Replay progress may
    /// remain equal or advance but can never move backward.
    ///
    /// # Errors
    ///
    /// Returns a stale-generation, invalid-transition, sealing, or storage error.
    pub(crate) fn checkpoint_pairing(
        &self,
        pairing_id: PairingId,
        expected_generation: u64,
        next_phase: PairingPhase,
        completion_deadline_unix_seconds: Option<u64>,
        replay_cursor: u64,
        state: &[u8],
    ) -> Result<u64, ProfileStoreError> {
        validate_state(state)?;
        if expected_generation == 0 {
            return Err(ProfileStoreError::InvalidTransition);
        }
        let current = self.load_pairing(pairing_id)?;
        if current.generation != expected_generation {
            return self.match_checkpoint_retry(
                &current,
                expected_generation,
                next_phase,
                completion_deadline_unix_seconds,
                replay_cursor,
                state,
            );
        }
        if replay_cursor < current.replay_cursor
            || !valid_transition(current.role, current.phase, next_phase)
            || current.completion_deadline_unix_seconds.is_some()
                && completion_deadline_unix_seconds != current.completion_deadline_unix_seconds
            || current.completion_deadline_unix_seconds.is_none()
                && completion_deadline_unix_seconds.is_some()
                && !matches!(
                    (current.phase, next_phase),
                    (
                        PairingPhase::InviterAwaitingJoinProof,
                        PairingPhase::InviterAwaitingCompletion
                    )
                )
        {
            return Err(ProfileStoreError::InvalidTransition);
        }
        validate_metadata(
            current.role,
            next_phase,
            current.authorization_deadline_unix_seconds,
            completion_deadline_unix_seconds,
        )?;
        let next_generation = expected_generation
            .checked_add(1)
            .ok_or(ProfileStoreError::SequenceExhausted)?;
        let blob = self.seal_pairing_checkpoint(
            pairing_id,
            current.routing_id,
            current.role,
            next_phase,
            current.authorization_deadline_unix_seconds,
            completion_deadline_unix_seconds,
            replay_cursor,
            next_generation,
            state,
        )?;
        let changed = self
            .lock()?
            .execute(
                "UPDATE daemon_pairing
                 SET phase = ?1,
                     completion_deadline_unix_seconds = ?2,
                     replay_cursor = ?3,
                     generation = ?4,
                     sealed_state = ?5
                 WHERE pairing_id = ?6 AND generation = ?7",
                params![
                    next_phase as u8,
                    completion_deadline_unix_seconds
                        .map(to_sql_integer)
                        .transpose()?,
                    to_sql_integer(replay_cursor)?,
                    to_sql_integer(next_generation)?,
                    blob.as_bytes(),
                    pairing_id.as_bytes().as_slice(),
                    to_sql_integer(expected_generation)?,
                ],
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        if changed == 1 {
            return Ok(next_generation);
        }
        let observed = self.load_pairing(pairing_id)?;
        self.match_checkpoint_retry(
            &observed,
            expected_generation,
            next_phase,
            completion_deadline_unix_seconds,
            replay_cursor,
            state,
        )
    }

    /// Lists active pairings in stable identifier order.
    ///
    /// # Errors
    ///
    /// Returns a bounds, malformed-data, or storage error.
    pub(crate) fn active_pairing_ids(
        &self,
        after: Option<PairingId>,
        limit: usize,
    ) -> Result<Vec<PairingId>, ProfileStoreError> {
        if limit == 0 || limit > MAX_ACTIVE_PAIRINGS {
            return Err(ProfileStoreError::InvalidTransition);
        }
        let after = after.map(|value| value.as_bytes().to_vec());
        let connection = self.lock()?;
        let mut statement = connection
            .prepare(
                "SELECT pairing_id
                 FROM daemon_pairing
                 WHERE phase NOT IN (8, 9)
                   AND (?1 IS NULL OR pairing_id > ?1)
                 ORDER BY pairing_id
                 LIMIT ?2",
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        statement
            .query_map(
                params![
                    after.as_deref(),
                    i64::try_from(limit).map_err(|_| ProfileStoreError::SequenceExhausted)?
                ],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .map_err(|_| ProfileStoreError::Storage)?
            .map(|result| {
                let bytes = result.map_err(|_| ProfileStoreError::Storage)?;
                PairingId::from_slice(&bytes).map_err(|_| ProfileStoreError::CorruptData)
            })
            .collect()
    }

    /// Deletes one terminal pairing checkpoint.
    ///
    /// # Errors
    ///
    /// Returns an invalid-transition, missing, or storage error.
    pub(crate) fn delete_terminal_pairing(
        &self,
        pairing_id: PairingId,
    ) -> Result<(), ProfileStoreError> {
        let changed = self
            .lock()?
            .execute(
                "DELETE FROM daemon_pairing
                 WHERE pairing_id = ?1 AND phase IN (8, 9)",
                params![pairing_id.as_bytes().as_slice()],
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        if changed == 1 {
            return Ok(());
        }
        match self.load_pairing(pairing_id) {
            Ok(_) => Err(ProfileStoreError::InvalidTransition),
            Err(ProfileStoreError::OperationNotFound) => Err(ProfileStoreError::OperationNotFound),
            Err(error) => Err(error),
        }
    }

    fn match_checkpoint_retry(
        &self,
        observed: &PairingCheckpoint,
        expected_generation: u64,
        next_phase: PairingPhase,
        completion_deadline_unix_seconds: Option<u64>,
        replay_cursor: u64,
        state: &[u8],
    ) -> Result<u64, ProfileStoreError> {
        let retry_generation = expected_generation
            .checked_add(1)
            .ok_or(ProfileStoreError::InvalidTransition)?;
        if observed.generation == retry_generation
            && observed.phase == next_phase
            && observed.completion_deadline_unix_seconds == completion_deadline_unix_seconds
            && observed.replay_cursor == replay_cursor
            && observed.state.as_slice() == state
        {
            Ok(observed.generation)
        } else {
            Err(ProfileStoreError::InvalidTransition)
        }
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "every authenticated checkpoint metadata field remains explicit"
    )]
    fn seal_pairing_checkpoint(
        &self,
        pairing_id: PairingId,
        routing_id: RoutingId,
        role: PairingRole,
        phase: PairingPhase,
        authorization_deadline: u64,
        completion_deadline: Option<u64>,
        replay_cursor: u64,
        generation: u64,
        state: &[u8],
    ) -> Result<SealedBlob, ProfileStoreError> {
        self.sealer
            .seal(
                &pairing_record_context(
                    &self.locked_profile.profile_id,
                    pairing_id,
                    routing_id,
                    role,
                    phase,
                    authorization_deadline,
                    completion_deadline,
                    replay_cursor,
                    generation,
                )?,
                state,
            )
            .map_err(|_| ProfileStoreError::Storage)
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "every authenticated checkpoint metadata field remains explicit"
    )]
    fn open_pairing_checkpoint(
        &self,
        pairing_id: PairingId,
        routing_id: RoutingId,
        role: PairingRole,
        phase: PairingPhase,
        authorization_deadline: u64,
        completion_deadline: Option<u64>,
        replay_cursor: u64,
        generation: u64,
        bytes: Vec<u8>,
    ) -> Result<Zeroizing<Vec<u8>>, ProfileStoreError> {
        let blob = SealedBlob::from_bytes(bytes).map_err(|_| ProfileStoreError::CorruptData)?;
        self.sealer
            .open(
                &pairing_record_context(
                    &self.locked_profile.profile_id,
                    pairing_id,
                    routing_id,
                    role,
                    phase,
                    authorization_deadline,
                    completion_deadline,
                    replay_cursor,
                    generation,
                )?,
                &blob,
            )
            .map_err(|_| ProfileStoreError::CorruptData)
    }
}

pub(super) fn initialize_pairing_schema(connection: &Connection) -> Result<(), ProfileStoreError> {
    connection
        .execute_batch(
            "BEGIN;
             CREATE TABLE daemon_pairing (
                pairing_id BLOB PRIMARY KEY CHECK (length(pairing_id) = 16),
                routing_id BLOB NOT NULL UNIQUE CHECK (length(routing_id) = 32),
                local_role INTEGER NOT NULL CHECK (local_role BETWEEN 1 AND 2),
                phase INTEGER NOT NULL CHECK (phase BETWEEN 1 AND 9),
                authorization_deadline_unix_seconds INTEGER NOT NULL
                    CHECK (authorization_deadline_unix_seconds >= 1),
                completion_deadline_unix_seconds INTEGER,
                replay_cursor INTEGER NOT NULL CHECK (replay_cursor >= 0),
                generation INTEGER NOT NULL CHECK (generation >= 1),
                sealed_state BLOB NOT NULL,
                CHECK (
                    (local_role = 1 AND phase IN (1, 2, 3, 8, 9))
                    OR
                    (local_role = 2 AND phase IN (4, 5, 6, 7, 8, 9))
                ),
                CHECK (
                    completion_deadline_unix_seconds IS NULL
                    OR completion_deadline_unix_seconds
                        >= authorization_deadline_unix_seconds
                ),
                CHECK (
                    (phase IN (6, 7) AND completion_deadline_unix_seconds IS NOT NULL)
                    OR
                    (phase NOT IN (6, 7))
                )
             ) WITHOUT ROWID;
             CREATE INDEX daemon_pairing_active_idx
                ON daemon_pairing(phase, authorization_deadline_unix_seconds, pairing_id)
                WHERE phase NOT IN (8, 9);
             PRAGMA user_version = 11;
             COMMIT;",
        )
        .map_err(|_| ProfileStoreError::Storage)
}

fn initial_phase(role: PairingRole) -> PairingPhase {
    match role {
        PairingRole::Joiner => PairingPhase::JoinerAwaitingInvitation,
        PairingRole::Inviter => PairingPhase::InviterAwaitingAuthorization,
    }
}

fn valid_transition(role: PairingRole, current: PairingPhase, next: PairingPhase) -> bool {
    if current == next {
        return !current.is_terminal();
    }
    matches!(
        (role, current, next),
        (
            PairingRole::Joiner,
            PairingPhase::JoinerAwaitingInvitation,
            PairingPhase::JoinerAwaitingInviterAuthorization | PairingPhase::Cancelled,
        ) | (
            PairingRole::Joiner,
            PairingPhase::JoinerAwaitingInviterAuthorization,
            PairingPhase::JoinerAwaitingWelcome | PairingPhase::Cancelled,
        ) | (
            PairingRole::Joiner,
            PairingPhase::JoinerAwaitingWelcome,
            PairingPhase::Completed | PairingPhase::Cancelled,
        ) | (
            PairingRole::Inviter,
            PairingPhase::InviterAwaitingAuthorization,
            PairingPhase::InviterAwaitingJoinProof | PairingPhase::Cancelled,
        ) | (
            PairingRole::Inviter,
            PairingPhase::InviterAwaitingJoinProof,
            PairingPhase::InviterAwaitingCompletion | PairingPhase::Cancelled,
        ) | (
            PairingRole::Inviter,
            PairingPhase::InviterAwaitingCompletion,
            PairingPhase::Completed | PairingPhase::Compensating,
        ) | (
            PairingRole::Inviter,
            PairingPhase::Compensating,
            PairingPhase::Cancelled
        )
    )
}

fn validate_metadata(
    role: PairingRole,
    phase: PairingPhase,
    authorization_deadline: u64,
    completion_deadline: Option<u64>,
) -> Result<(), ProfileStoreError> {
    if authorization_deadline == 0
        || completion_deadline.is_some_and(|deadline| deadline < authorization_deadline)
        || matches!(
            (role, phase),
            (
                PairingRole::Joiner,
                PairingPhase::InviterAwaitingAuthorization
                    | PairingPhase::InviterAwaitingJoinProof
                    | PairingPhase::InviterAwaitingCompletion
                    | PairingPhase::Compensating
            ) | (
                PairingRole::Inviter,
                PairingPhase::JoinerAwaitingInvitation
                    | PairingPhase::JoinerAwaitingInviterAuthorization
                    | PairingPhase::JoinerAwaitingWelcome
            )
        )
        || matches!(
            phase,
            PairingPhase::InviterAwaitingCompletion | PairingPhase::Compensating
        ) && completion_deadline.is_none()
        || !matches!(
            phase,
            PairingPhase::InviterAwaitingCompletion
                | PairingPhase::Compensating
                | PairingPhase::Completed
                | PairingPhase::Cancelled
        ) && completion_deadline.is_some()
    {
        return Err(ProfileStoreError::InvalidTransition);
    }
    Ok(())
}

fn pairing_role(value: i64) -> Result<PairingRole, ProfileStoreError> {
    match value {
        1 => Ok(PairingRole::Joiner),
        2 => Ok(PairingRole::Inviter),
        _ => Err(ProfileStoreError::CorruptData),
    }
}

fn pairing_phase(value: i64) -> Result<PairingPhase, ProfileStoreError> {
    match value {
        1 => Ok(PairingPhase::JoinerAwaitingInvitation),
        2 => Ok(PairingPhase::JoinerAwaitingInviterAuthorization),
        3 => Ok(PairingPhase::JoinerAwaitingWelcome),
        4 => Ok(PairingPhase::InviterAwaitingAuthorization),
        5 => Ok(PairingPhase::InviterAwaitingJoinProof),
        6 => Ok(PairingPhase::InviterAwaitingCompletion),
        7 => Ok(PairingPhase::Compensating),
        8 => Ok(PairingPhase::Completed),
        9 => Ok(PairingPhase::Cancelled),
        _ => Err(ProfileStoreError::CorruptData),
    }
}

fn validate_state(state: &[u8]) -> Result<(), ProfileStoreError> {
    if state.is_empty() || state.len() > crate::pairing::MAX_PAIRING_STATE_BYTES {
        return Err(ProfileStoreError::InvalidTransition);
    }
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    reason = "every checkpoint metadata field is part of the authenticated context"
)]
fn pairing_record_context(
    profile_id: &ProfileId,
    pairing_id: PairingId,
    routing_id: RoutingId,
    role: PairingRole,
    phase: PairingPhase,
    authorization_deadline: u64,
    completion_deadline: Option<u64>,
    replay_cursor: u64,
    generation: u64,
) -> Result<SecretRecordContext, ProfileStoreError> {
    let mut identifier = Vec::with_capacity(
        2 + profile_id.as_bytes().len() + PairingId::LENGTH + RoutingId::LENGTH + 2 + 8 * 4,
    );
    identifier.push(
        u8::try_from(profile_id.as_bytes().len())
            .map_err(|_| ProfileStoreError::InvalidProfileId)?,
    );
    identifier.extend_from_slice(profile_id.as_bytes());
    identifier.push(PAIRING_RECORD_SCOPE);
    identifier.extend_from_slice(pairing_id.as_bytes());
    identifier.extend_from_slice(routing_id.as_bytes());
    identifier.push(role as u8);
    identifier.push(phase as u8);
    identifier.extend_from_slice(&authorization_deadline.to_be_bytes());
    identifier.extend_from_slice(&completion_deadline.unwrap_or(0).to_be_bytes());
    identifier.extend_from_slice(&replay_cursor.to_be_bytes());
    identifier.extend_from_slice(&generation.to_be_bytes());
    SecretRecordContext::new(SecretRecordKind::PairingOperation, identifier)
        .map_err(|_| ProfileStoreError::Storage)
}

#[cfg(test)]
mod tests {
    use super::*;
    use KonclaveSecretStorage::{ExternalWrappingKeyProvider, SecretSealer};

    fn store(root: &Path) -> ProfileStore {
        store_for_profile(root, "pairing-test")
    }

    fn store_for_profile(root: &Path, profile_id: &str) -> ProfileStore {
        let locked = LockedProfile::acquire(root, ProfileId::parse(profile_id).unwrap()).unwrap();
        let sealer =
            SecretSealer::from_provider(ExternalWrappingKeyProvider::from_bytes([7; 32])).unwrap();
        locked.open_store(sealer).unwrap()
    }

    fn pairing_id(value: u8) -> PairingId {
        PairingId::from_bytes([value; PairingId::LENGTH])
    }

    fn routing_id(value: u8) -> RoutingId {
        RoutingId::from_bytes([value; RoutingId::LENGTH])
    }

    #[test]
    fn initial_checkpoint_is_sealed_and_idempotent() {
        let root = tempfile::tempdir().unwrap();
        let store = store(root.path());
        let state = b"secret pairing capability";
        store
            .reserve_pairing(
                pairing_id(1),
                routing_id(2),
                PairingRole::Joiner,
                2_000,
                state,
            )
            .unwrap();
        store
            .reserve_pairing(
                pairing_id(1),
                routing_id(2),
                PairingRole::Joiner,
                2_000,
                state,
            )
            .unwrap();
        let loaded = store.load_pairing(pairing_id(1)).unwrap();
        assert_eq!(loaded.role, PairingRole::Joiner);
        assert_eq!(loaded.phase, PairingPhase::JoinerAwaitingInvitation);
        assert_eq!(loaded.generation, 1);
        assert_eq!(loaded.state.as_slice(), state);

        let raw: Vec<u8> = store
            .lock()
            .unwrap()
            .query_row(
                "SELECT sealed_state FROM daemon_pairing WHERE pairing_id = ?1",
                params![pairing_id(1).as_bytes().as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            !raw.windows(state.len()).any(|window| window == state),
            "pairing capability must not cross into SQLite as plaintext"
        );
    }

    #[test]
    fn maximum_profile_identifier_fits_the_authenticated_context() {
        let root = tempfile::tempdir().unwrap();
        let store = store_for_profile(root.path(), &"p".repeat(MAX_PROFILE_ID_BYTES));
        store
            .reserve_pairing(
                pairing_id(1),
                routing_id(2),
                PairingRole::Joiner,
                2_000,
                b"issued",
            )
            .unwrap();
        assert_eq!(
            store.load_pairing(pairing_id(1)).unwrap().state.as_slice(),
            b"issued"
        );
    }

    #[test]
    fn conflicting_reservation_fails_closed() {
        let root = tempfile::tempdir().unwrap();
        let store = store(root.path());
        store
            .reserve_pairing(
                pairing_id(1),
                routing_id(2),
                PairingRole::Inviter,
                2_000,
                b"state",
            )
            .unwrap();
        assert_eq!(
            store.reserve_pairing(
                pairing_id(1),
                routing_id(3),
                PairingRole::Inviter,
                2_000,
                b"state",
            ),
            Err(ProfileStoreError::DuplicateOperation)
        );
        assert_eq!(
            store.reserve_pairing(
                pairing_id(2),
                routing_id(2),
                PairingRole::Inviter,
                2_000,
                b"state",
            ),
            Err(ProfileStoreError::DuplicateOperation)
        );
    }

    #[test]
    fn checkpoint_is_compare_and_swap_idempotent_and_monotonic() {
        let root = tempfile::tempdir().unwrap();
        let store = store(root.path());
        store
            .reserve_pairing(
                pairing_id(1),
                routing_id(2),
                PairingRole::Inviter,
                2_000,
                b"redeemed",
            )
            .unwrap();
        assert_eq!(
            store.checkpoint_pairing(
                pairing_id(1),
                0,
                PairingPhase::InviterAwaitingAuthorization,
                None,
                0,
                b"redeemed",
            ),
            Err(ProfileStoreError::InvalidTransition)
        );
        let generation = store
            .checkpoint_pairing(
                pairing_id(1),
                1,
                PairingPhase::InviterAwaitingJoinProof,
                None,
                3,
                b"invitation ready",
            )
            .unwrap();
        assert_eq!(generation, 2);
        assert_eq!(
            store
                .checkpoint_pairing(
                    pairing_id(1),
                    1,
                    PairingPhase::InviterAwaitingJoinProof,
                    None,
                    3,
                    b"invitation ready",
                )
                .unwrap(),
            2
        );
        assert_eq!(
            store.checkpoint_pairing(
                pairing_id(1),
                1,
                PairingPhase::InviterAwaitingJoinProof,
                None,
                3,
                b"conflicting retry",
            ),
            Err(ProfileStoreError::InvalidTransition)
        );
        assert_eq!(
            store.checkpoint_pairing(
                pairing_id(1),
                2,
                PairingPhase::InviterAwaitingJoinProof,
                None,
                2,
                b"regressed",
            ),
            Err(ProfileStoreError::InvalidTransition)
        );
    }

    #[test]
    fn post_commit_phase_requires_a_separate_completion_deadline() {
        let root = tempfile::tempdir().unwrap();
        let store = store(root.path());
        store
            .reserve_pairing(
                pairing_id(1),
                routing_id(2),
                PairingRole::Inviter,
                2_000,
                b"redeemed",
            )
            .unwrap();
        store
            .checkpoint_pairing(
                pairing_id(1),
                1,
                PairingPhase::InviterAwaitingJoinProof,
                None,
                0,
                b"invitation",
            )
            .unwrap();
        assert_eq!(
            store.checkpoint_pairing(
                pairing_id(1),
                2,
                PairingPhase::InviterAwaitingCompletion,
                None,
                1,
                b"welcome",
            ),
            Err(ProfileStoreError::InvalidTransition)
        );
        assert_eq!(
            store
                .checkpoint_pairing(
                    pairing_id(1),
                    2,
                    PairingPhase::InviterAwaitingCompletion,
                    Some(3_000),
                    1,
                    b"welcome",
                )
                .unwrap(),
            3
        );
        assert_eq!(
            store.checkpoint_pairing(
                pairing_id(1),
                3,
                PairingPhase::InviterAwaitingCompletion,
                Some(4_000),
                1,
                b"extended",
            ),
            Err(ProfileStoreError::InvalidTransition)
        );
        assert_eq!(
            store.checkpoint_pairing(
                pairing_id(1),
                3,
                PairingPhase::Completed,
                None,
                1,
                b"completed",
            ),
            Err(ProfileStoreError::InvalidTransition)
        );
        assert_eq!(
            store
                .checkpoint_pairing(
                    pairing_id(1),
                    3,
                    PairingPhase::Completed,
                    Some(3_000),
                    1,
                    b"completed",
                )
                .unwrap(),
            4
        );
    }

    #[test]
    fn role_phase_and_deadline_mismatches_fail_closed() {
        let root = tempfile::tempdir().unwrap();
        let store = store(root.path());
        store
            .reserve_pairing(
                pairing_id(1),
                routing_id(2),
                PairingRole::Joiner,
                2_000,
                b"issued",
            )
            .unwrap();
        assert_eq!(
            store.checkpoint_pairing(
                pairing_id(1),
                1,
                PairingPhase::InviterAwaitingJoinProof,
                None,
                0,
                b"wrong role",
            ),
            Err(ProfileStoreError::InvalidTransition)
        );

        store
            .reserve_pairing(
                pairing_id(2),
                routing_id(3),
                PairingRole::Inviter,
                2_000,
                b"redeemed",
            )
            .unwrap();
        store
            .checkpoint_pairing(
                pairing_id(2),
                1,
                PairingPhase::InviterAwaitingJoinProof,
                None,
                0,
                b"invitation",
            )
            .unwrap();
        assert_eq!(
            store.checkpoint_pairing(
                pairing_id(2),
                2,
                PairingPhase::InviterAwaitingCompletion,
                Some(1_999),
                1,
                b"deadline regression",
            ),
            Err(ProfileStoreError::InvalidTransition)
        );
    }

    #[test]
    fn terminal_checkpoint_is_not_mutable_and_is_the_only_deletable_state() {
        let root = tempfile::tempdir().unwrap();
        let store = store(root.path());
        store
            .reserve_pairing(
                pairing_id(1),
                routing_id(2),
                PairingRole::Joiner,
                2_000,
                b"issued",
            )
            .unwrap();
        assert_eq!(
            store.delete_terminal_pairing(pairing_id(1)),
            Err(ProfileStoreError::InvalidTransition)
        );
        store
            .checkpoint_pairing(
                pairing_id(1),
                1,
                PairingPhase::Cancelled,
                None,
                0,
                b"cancelled",
            )
            .unwrap();
        assert_eq!(
            store.checkpoint_pairing(
                pairing_id(1),
                2,
                PairingPhase::Cancelled,
                None,
                0,
                b"changed",
            ),
            Err(ProfileStoreError::InvalidTransition)
        );
        store.delete_terminal_pairing(pairing_id(1)).unwrap();
        assert!(matches!(
            store.load_pairing(pairing_id(1)),
            Err(ProfileStoreError::OperationNotFound)
        ));
    }

    #[test]
    fn metadata_tampering_fails_authentication() {
        let root = tempfile::tempdir().unwrap();
        let store = store(root.path());
        store
            .reserve_pairing(
                pairing_id(1),
                routing_id(2),
                PairingRole::Joiner,
                2_000,
                b"issued",
            )
            .unwrap();
        store
            .lock()
            .unwrap()
            .execute(
                "UPDATE daemon_pairing SET replay_cursor = 1 WHERE pairing_id = ?1",
                params![pairing_id(1).as_bytes().as_slice()],
            )
            .unwrap();
        assert!(matches!(
            store.load_pairing(pairing_id(1)),
            Err(ProfileStoreError::CorruptData)
        ));
    }

    #[test]
    fn sealed_checkpoint_tampering_fails_authentication() {
        let root = tempfile::tempdir().unwrap();
        let store = store(root.path());
        store
            .reserve_pairing(
                pairing_id(1),
                routing_id(2),
                PairingRole::Joiner,
                2_000,
                b"issued",
            )
            .unwrap();
        let mut sealed: Vec<u8> = store
            .lock()
            .unwrap()
            .query_row(
                "SELECT sealed_state FROM daemon_pairing WHERE pairing_id = ?1",
                params![pairing_id(1).as_bytes().as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 1;
        store
            .lock()
            .unwrap()
            .execute(
                "UPDATE daemon_pairing SET sealed_state = ?1 WHERE pairing_id = ?2",
                params![sealed, pairing_id(1).as_bytes().as_slice()],
            )
            .unwrap();
        assert!(matches!(
            store.load_pairing(pairing_id(1)),
            Err(ProfileStoreError::CorruptData)
        ));
    }

    #[test]
    fn active_pairing_page_excludes_terminal_records() {
        let root = tempfile::tempdir().unwrap();
        let store = store(root.path());
        for value in 1..=3 {
            store
                .reserve_pairing(
                    pairing_id(value),
                    routing_id(value),
                    PairingRole::Joiner,
                    2_000,
                    b"issued",
                )
                .unwrap();
        }
        store
            .checkpoint_pairing(
                pairing_id(2),
                1,
                PairingPhase::Cancelled,
                None,
                0,
                b"cancelled",
            )
            .unwrap();
        assert_eq!(
            store.active_pairing_ids(None, 10).unwrap(),
            vec![pairing_id(1), pairing_id(3)]
        );
        assert_eq!(
            store.active_pairing_ids(Some(pairing_id(1)), 10).unwrap(),
            vec![pairing_id(3)]
        );
    }

    #[test]
    fn active_pairing_capacity_is_atomic_and_released_by_terminal_state() {
        let root = tempfile::tempdir().unwrap();
        let store = store(root.path());
        for value in 1..=u8::try_from(MAX_ACTIVE_PAIRINGS).unwrap() {
            store
                .reserve_pairing(
                    pairing_id(value),
                    routing_id(value),
                    PairingRole::Joiner,
                    2_000,
                    b"issued",
                )
                .unwrap();
        }
        store
            .reserve_pairing(
                pairing_id(1),
                routing_id(1),
                PairingRole::Joiner,
                2_000,
                b"issued",
            )
            .unwrap();
        assert_eq!(
            store.reserve_pairing(
                pairing_id(33),
                routing_id(33),
                PairingRole::Joiner,
                2_000,
                b"issued",
            ),
            Err(ProfileStoreError::PairingCapacityExceeded)
        );
        store
            .checkpoint_pairing(
                pairing_id(1),
                1,
                PairingPhase::Cancelled,
                None,
                0,
                b"cancelled",
            )
            .unwrap();
        store
            .reserve_pairing(
                pairing_id(33),
                routing_id(33),
                PairingRole::Joiner,
                2_000,
                b"issued",
            )
            .unwrap();
    }

    #[test]
    fn version_ten_profile_migrates_to_current_schema() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("profiles");
        {
            let store = store(&path);
            store
                .lock()
                .unwrap()
                .execute_batch(
                    "DROP TABLE daemon_relay_enrollment;
                     DROP TABLE daemon_pairing;
                     PRAGMA user_version = 10;",
                )
                .unwrap();
        }
        let reopened = store(&path);
        let version: u32 = reopened
            .lock()
            .unwrap()
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, PROFILE_SCHEMA_VERSION);
        assert!(
            reopened
                .reserve_pairing(
                    pairing_id(1),
                    routing_id(2),
                    PairingRole::Joiner,
                    2_000,
                    b"migrated",
                )
                .is_ok()
        );
    }

    #[test]
    fn failed_pairing_migration_preserves_version_ten_schema() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("profiles");
        let database_path = {
            let store = store(&path);
            let database_path = store.locked_profile.profile_database_path();
            store
                .lock()
                .unwrap()
                .execute_batch(
                    "DROP TABLE daemon_pairing;
                     CREATE TABLE daemon_pairing (sentinel INTEGER);
                     PRAGMA user_version = 10;",
                )
                .unwrap();
            database_path
        };

        assert_eq!(
            LockedProfile::acquire(&path, ProfileId::parse("pairing-test").unwrap())
                .unwrap()
                .open_store(
                    SecretSealer::from_provider(ExternalWrappingKeyProvider::from_bytes([7; 32]))
                        .unwrap()
                )
                .err(),
            Some(ProfileStoreError::Storage)
        );
        let connection = Connection::open(database_path).unwrap();
        let version: u32 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        let columns: i64 = connection
            .query_row(
                "SELECT count(*) FROM pragma_table_info('daemon_pairing')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(version, 10);
        assert_eq!(columns, 1);
    }
}
