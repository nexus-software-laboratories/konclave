use KonclaveCryptographicCore::DeviceIdentity;
use KonclaveDomainCore::{
    ApplicationContent, ConversationId, DeviceId, Ed25519PublicKey, PairingId,
    RepeatPairingOperationId, RepeatPairingRequest, RepeatPairingResponse, RoutingId,
};
use KonclaveSecretStorage::{SealedBlob, SecretRecordContext, SecretRecordKind};
use rusqlite::{Connection, OptionalExtension, Transaction, params};

use super::{
    PROFILE_SCHEMA_VERSION, ProfileStore, ProfileStoreError, from_sql_integer, to_sql_integer,
};
use crate::repeat_pairing::{
    MAX_REPEAT_PAIRING_STATE_BYTES, RepeatPairingOperationState, RepeatPairingPhase,
    RepeatPairingRole, RepeatPairingStateError, repeat_pairing_transition_allowed,
};

const PRIOR_PROFILE_SCHEMA_VERSION: u32 = 20;
const MAX_ACTIVE_REPEAT_PAIRINGS: usize = 16;
const MAX_REPEAT_PAIRING_RECORDS: usize = 64;
const MAX_INTERNAL_REPEAT_PAIRING_MESSAGES: usize = MAX_REPEAT_PAIRING_RECORDS * 4;
const MAX_SEALED_REPEAT_PAIRING_STATE_BYTES: usize = MAX_REPEAT_PAIRING_STATE_BYTES + 64;
const REPEAT_PAIRING_COUNT_STATE_VERSION: u8 = 1;
const REPEAT_PAIRING_COUNT_STATE_BYTES: usize = 1 + 8;
const MAX_SEALED_REPEAT_PAIRING_COUNT_STATE_BYTES: usize = REPEAT_PAIRING_COUNT_STATE_BYTES + 64;
const REPEAT_PAIRING_CONTEXT_VERSION: &[u8] = b"repeat-pairing-operation-v1";
const REPEAT_PAIRING_COUNT_CONTEXT_VERSION: &[u8] = b"repeat-pairing-count-v1";
const MAX_REPEAT_PAIRING_WINDOW_SECONDS: u64 = 15 * 60;

pub(crate) struct RepeatPairingCheckpoint {
    pub(crate) generation: u64,
    pub(crate) state: RepeatPairingOperationState,
}

pub(crate) enum RepeatPairingPeerBinding {
    Unlinked,
    Verified {
        peer_device_id: DeviceId,
        conversation_id: ConversationId,
    },
    Blocked,
}

struct RepeatPairingMetadata {
    operation_id: Option<Vec<u8>>,
    role: i64,
    phase: i64,
    bootstrap_conversation_id: Option<Vec<u8>>,
    new_conversation_id: Option<Vec<u8>>,
    peer_device_id: Option<Vec<u8>>,
    deadline_unix_seconds: i64,
    pairing_id: Option<Vec<u8>>,
    generation: i64,
    sealed_state_length: i64,
}

impl ProfileStore {
    pub(super) fn initialize_repeat_pairing_schema(&self) -> Result<(), ProfileStoreError> {
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
        if current_version != PRIOR_PROFILE_SCHEMA_VERSION {
            return Err(ProfileStoreError::UnsupportedSchema);
        }
        let migrated_identity = match opened_identity {
            Some((identity, PRIOR_PROFILE_SCHEMA_VERSION)) => Some(
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
        let sealed_count = self.seal_repeat_pairing_count(0)?;
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction()
            .map_err(|_| ProfileStoreError::Storage)?;
        transaction
            .execute_batch(
                "CREATE TABLE daemon_internal_application_message (
                    conversation_id BLOB NOT NULL CHECK (length(conversation_id) = 32),
                    message_id BLOB NOT NULL CHECK (length(message_id) = 16),
                    PRIMARY KEY (conversation_id, message_id),
                    FOREIGN KEY (conversation_id, message_id)
                        REFERENCES daemon_message_history(conversation_id, message_id)
                        ON DELETE CASCADE
                 ) WITHOUT ROWID;
                 CREATE TABLE daemon_repeat_pairing (
                    operation_id BLOB PRIMARY KEY CHECK (length(operation_id) = 16),
                    local_role INTEGER NOT NULL CHECK (local_role BETWEEN 1 AND 2),
                    phase INTEGER NOT NULL CHECK (phase BETWEEN 1 AND 12),
                    bootstrap_conversation_id BLOB NOT NULL
                        CHECK (length(bootstrap_conversation_id) = 32),
                    new_conversation_id BLOB NOT NULL
                        CHECK (length(new_conversation_id) = 32),
                    peer_device_id BLOB NOT NULL CHECK (length(peer_device_id) = 32),
                    deadline_unix_seconds INTEGER NOT NULL
                        CHECK (deadline_unix_seconds >= 1),
                    pairing_id BLOB UNIQUE CHECK (
                        pairing_id IS NULL OR length(pairing_id) = 16
                    ),
                    generation INTEGER NOT NULL CHECK (generation >= 1),
                    sealed_state BLOB NOT NULL,
                    CHECK (
                        (local_role = 1 AND phase IN (1, 2, 3, 4, 5, 10, 11, 12))
                        OR
                        (local_role = 2 AND phase IN (6, 7, 8, 9, 10, 11, 12))
                    )
                 ) WITHOUT ROWID;
                 CREATE INDEX daemon_repeat_pairing_active_idx
                    ON daemon_repeat_pairing(phase, operation_id)
                    WHERE phase NOT IN (10, 12);
                 CREATE TABLE daemon_repeat_pairing_state (
                    singleton_id INTEGER PRIMARY KEY CHECK (singleton_id = 1),
                    sealed_state BLOB NOT NULL
                 );",
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        if transaction
            .execute(
                "INSERT INTO daemon_repeat_pairing_state (singleton_id, sealed_state)
                 VALUES (1, ?1)",
                params![sealed_count.as_bytes()],
            )
            .map_err(|_| ProfileStoreError::Storage)?
            != 1
        {
            return Err(ProfileStoreError::Storage);
        }
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

    pub(super) fn verify_repeat_pairings(&self) -> Result<(), ProfileStoreError> {
        let connection = self.lock()?;
        self.verify_internal_application_markers(&connection)?;
        let count = repeat_pairing_count(&connection)?;
        let active = active_repeat_pairing_count(&connection)?;
        if count != self.open_repeat_pairing_count(&connection)?
            || count > MAX_REPEAT_PAIRING_RECORDS
            || active > MAX_ACTIVE_REPEAT_PAIRINGS
        {
            return Err(ProfileStoreError::CorruptData);
        }
        let operation_ids =
            repeat_pairing_ids(&connection, false, None, MAX_REPEAT_PAIRING_RECORDS)?;
        for operation_id in operation_ids {
            self.load_repeat_pairing_from(&connection, operation_id)?
                .ok_or(ProfileStoreError::CorruptData)?;
        }
        Ok(())
    }

    fn verify_internal_application_markers(
        &self,
        connection: &Connection,
    ) -> Result<(), ProfileStoreError> {
        let count: i64 = connection
            .query_row(
                "SELECT count(*) FROM daemon_internal_application_message",
                [],
                |row| row.get(0),
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        if usize::try_from(count)
            .ok()
            .is_none_or(|count| count > MAX_INTERNAL_REPEAT_PAIRING_MESSAGES)
        {
            return Err(ProfileStoreError::CorruptData);
        }
        let identifiers = {
            let mut statement = connection
                .prepare(
                    "SELECT
                        CASE WHEN length(conversation_id) = 32 THEN conversation_id END,
                        CASE WHEN length(message_id) = 16 THEN message_id END
                     FROM daemon_internal_application_message
                     ORDER BY conversation_id, message_id",
                )
                .map_err(|_| ProfileStoreError::Storage)?;
            statement
                .query_map([], |row| {
                    Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
                })
                .map_err(|_| ProfileStoreError::Storage)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| ProfileStoreError::Storage)?
        };
        for (conversation_id, message_id) in identifiers {
            let conversation_id = ConversationId::from_slice(&conversation_id)
                .map_err(|_| ProfileStoreError::CorruptData)?;
            let message_id = KonclaveDomainCore::MessageId::from_slice(&message_id)
                .map_err(|_| ProfileStoreError::CorruptData)?;
            let routing_id: Vec<u8> = connection
                .query_row(
                    "SELECT CASE WHEN length(routing_id) = 32 THEN routing_id END
                     FROM daemon_conversation
                     WHERE conversation_id = ?1",
                    params![conversation_id.as_bytes().as_slice()],
                    |row| row.get(0),
                )
                .map_err(|_| ProfileStoreError::Storage)?;
            let routing_id =
                RoutingId::from_slice(&routing_id).map_err(|_| ProfileStoreError::CorruptData)?;
            let history = self
                .load_history_record(connection, conversation_id, routing_id, message_id)?
                .ok_or(ProfileStoreError::CorruptData)?;
            if !history.message.content().is_internal() {
                return Err(ProfileStoreError::CorruptData);
            }
        }
        Ok(())
    }

    pub(crate) fn reserve_repeat_pairing(
        &self,
        state: &RepeatPairingOperationState,
        now_unix_seconds: u64,
    ) -> Result<(), ProfileStoreError> {
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction()
            .map_err(|_| ProfileStoreError::Storage)?;
        self.reserve_repeat_pairing_in(&transaction, state, now_unix_seconds)?;
        transaction.commit().map_err(|_| ProfileStoreError::Storage)
    }

    pub(crate) fn load_repeat_pairing(
        &self,
        operation_id: RepeatPairingOperationId,
    ) -> Result<RepeatPairingCheckpoint, ProfileStoreError> {
        let connection = self.lock()?;
        self.load_repeat_pairing_from(&connection, operation_id)?
            .ok_or(ProfileStoreError::RepeatPairingNotFound)
    }

    pub(crate) fn active_repeat_pairing_ids(
        &self,
        after: Option<RepeatPairingOperationId>,
        limit: usize,
    ) -> Result<Vec<RepeatPairingOperationId>, ProfileStoreError> {
        if limit == 0 || limit > MAX_ACTIVE_REPEAT_PAIRINGS {
            return Err(ProfileStoreError::InvalidTransition);
        }
        let connection = self.lock()?;
        repeat_pairing_ids(&connection, true, after, limit)
    }

    pub(crate) fn checkpoint_repeat_pairing(
        &self,
        operation_id: RepeatPairingOperationId,
        generation: u64,
        state: &RepeatPairingOperationState,
    ) -> Result<u64, ProfileStoreError> {
        let connection = self.lock()?;
        let transaction = connection
            .unchecked_transaction()
            .map_err(|_| ProfileStoreError::Storage)?;
        let existing = self
            .load_repeat_pairing_from(&transaction, operation_id)?
            .ok_or(ProfileStoreError::RepeatPairingNotFound)?;
        if existing.generation != generation
            || !repeat_pairing_transition_allowed(
                existing.state.role,
                existing.state.phase,
                state.phase,
            )
            || !repeat_pairing_identity_equal(&existing.state, state)
        {
            return Err(ProfileStoreError::InvalidTransition);
        }
        let next_generation = generation
            .checked_add(1)
            .ok_or(ProfileStoreError::SequenceExhausted)?;
        let sealed = self.seal_repeat_pairing(state, next_generation)?;
        let pairing_id = state.pairing_id.map(PairingId::into_bytes);
        if transaction
            .execute(
                "UPDATE daemon_repeat_pairing
                 SET phase = ?1,
                     pairing_id = ?2,
                     generation = ?3,
                     sealed_state = ?4
                 WHERE operation_id = ?5 AND generation = ?6",
                params![
                    state.phase as u8,
                    pairing_id.as_ref().map(<[u8; 16]>::as_slice),
                    to_sql_integer(next_generation)?,
                    sealed.as_bytes(),
                    operation_id.as_bytes().as_slice(),
                    to_sql_integer(generation)?,
                ],
            )
            .map_err(|_| ProfileStoreError::Storage)?
            != 1
        {
            return Err(ProfileStoreError::InvalidTransition);
        }
        transaction
            .commit()
            .map_err(|_| ProfileStoreError::Storage)?;
        Ok(next_generation)
    }

    pub(crate) fn repeat_pairing_peer_binding(
        &self,
        pairing_id: PairingId,
    ) -> Result<RepeatPairingPeerBinding, ProfileStoreError> {
        let operation_id: Option<Vec<u8>> = self
            .lock()?
            .query_row(
                "SELECT CASE WHEN length(operation_id) = 16 THEN operation_id END
                 FROM daemon_repeat_pairing
                 WHERE pairing_id = ?1",
                params![pairing_id.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| ProfileStoreError::Storage)?;
        let Some(operation_id) = operation_id else {
            return Ok(RepeatPairingPeerBinding::Unlinked);
        };
        let operation_id = RepeatPairingOperationId::from_slice(&operation_id)
            .map_err(|_| ProfileStoreError::CorruptData)?;
        let checkpoint = self.load_repeat_pairing(operation_id)?;
        if checkpoint.state.pairing_id != Some(pairing_id)
            || matches!(
                checkpoint.state.phase,
                RepeatPairingPhase::Cancelling | RepeatPairingPhase::Cancelled
            )
        {
            return Ok(RepeatPairingPeerBinding::Blocked);
        }
        Ok(RepeatPairingPeerBinding::Verified {
            peer_device_id: checkpoint.state.peer_device_id,
            conversation_id: checkpoint.state.new_conversation_id,
        })
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the authenticated sender, target, conversation, content, and observation time remain explicit"
    )]
    pub(super) fn record_repeat_pairing_content_in(
        &self,
        transaction: &Transaction<'_>,
        conversation_id: ConversationId,
        sender: DeviceId,
        sender_root: Ed25519PublicKey,
        local_device: DeviceId,
        content: &ApplicationContent,
        now_unix_seconds: u64,
    ) -> Result<bool, ProfileStoreError> {
        match content {
            ApplicationContent::RepeatPairingRequest(request) => {
                if sender != local_device && request.target_device_id() == local_device {
                    self.record_repeat_pairing_request_in(
                        transaction,
                        conversation_id,
                        sender,
                        sender_root,
                        request,
                        now_unix_seconds,
                    )?;
                }
                Ok(true)
            }
            ApplicationContent::RepeatPairingResponse(response) => {
                if sender != local_device && response.requester_device_id() == local_device {
                    self.record_repeat_pairing_response_in(
                        transaction,
                        conversation_id,
                        sender,
                        sender_root,
                        response,
                    )?;
                }
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    fn record_repeat_pairing_request_in(
        &self,
        transaction: &Transaction<'_>,
        conversation_id: ConversationId,
        sender: DeviceId,
        sender_root: Ed25519PublicKey,
        request: &RepeatPairingRequest,
        now_unix_seconds: u64,
    ) -> Result<(), ProfileStoreError> {
        if !repeat_pairing_deadline_valid(now_unix_seconds, request.expires_at_unix_seconds()) {
            return Ok(());
        }
        if self
            .load_repeat_pairing_from(transaction, request.operation_id())?
            .is_some()
        {
            return Ok(());
        }
        let state = RepeatPairingOperationState::responder(
            request.operation_id(),
            conversation_id,
            request.new_conversation_id(),
            sender,
            sender_root,
            request.expires_at_unix_seconds(),
        );
        self.reserve_repeat_pairing_in(transaction, &state, now_unix_seconds)
    }

    fn record_repeat_pairing_response_in(
        &self,
        transaction: &Transaction<'_>,
        conversation_id: ConversationId,
        sender: DeviceId,
        sender_root: Ed25519PublicKey,
        response: &RepeatPairingResponse,
    ) -> Result<(), ProfileStoreError> {
        let Some(checkpoint) =
            self.load_repeat_pairing_from(transaction, response.operation_id())?
        else {
            return Ok(());
        };
        let mut state = checkpoint.state;
        if state.role != RepeatPairingRole::Initiator
            || state.bootstrap_conversation_id != conversation_id
            || state.new_conversation_id != response.new_conversation_id()
            || state.peer_device_id != sender
            || state.peer_root_public_key != sender_root
        {
            return Ok(());
        }
        if state.capability.is_some() {
            return Ok(());
        }
        if !matches!(
            state.phase,
            RepeatPairingPhase::InitiatorSendingRequest
                | RepeatPairingPhase::InitiatorAwaitingResponse
        ) {
            return Ok(());
        }
        state.capability = Some(zeroize::Zeroizing::new(response.capability().to_owned()));
        state.phase = RepeatPairingPhase::InitiatorRedeemingCapability;
        self.checkpoint_repeat_pairing_in(transaction, checkpoint.generation, &state)
    }

    fn reserve_repeat_pairing_in(
        &self,
        connection: &Connection,
        state: &RepeatPairingOperationState,
        now_unix_seconds: u64,
    ) -> Result<(), ProfileStoreError> {
        let committed_count = self.open_repeat_pairing_count(connection)?;
        let mut count = repeat_pairing_count(connection)?;
        if committed_count != count {
            return Err(ProfileStoreError::CorruptData);
        }
        if let Some(existing) = self.load_repeat_pairing_from(connection, state.operation_id)? {
            return if existing.generation == 1
                && repeat_pairing_states_equal(&existing.state, state)?
            {
                Ok(())
            } else {
                Err(ProfileStoreError::DuplicateOperation)
            };
        }
        let removed = connection
            .execute(
                "DELETE FROM daemon_repeat_pairing
                 WHERE phase IN (10, 12)
                   AND deadline_unix_seconds < ?1
                   AND operation_id <> ?2",
                params![
                    to_sql_integer(now_unix_seconds)?,
                    state.operation_id.as_bytes().as_slice()
                ],
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        count = count
            .checked_sub(removed)
            .ok_or(ProfileStoreError::CorruptData)?;
        if removed > 0 {
            self.store_repeat_pairing_count(connection, count)?;
        }
        if count >= MAX_REPEAT_PAIRING_RECORDS
            || active_repeat_pairing_count(connection)? >= MAX_ACTIVE_REPEAT_PAIRINGS
        {
            return Err(ProfileStoreError::RepeatPairingCapacityExceeded);
        }
        let generation = 1;
        let sealed = self.seal_repeat_pairing(state, generation)?;
        let pairing_id = state.pairing_id.map(PairingId::into_bytes);
        if connection
            .execute(
                "INSERT INTO daemon_repeat_pairing (
                    operation_id,
                    local_role,
                    phase,
                    bootstrap_conversation_id,
                    new_conversation_id,
                    peer_device_id,
                    deadline_unix_seconds,
                    pairing_id,
                    generation,
                    sealed_state
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    state.operation_id.as_bytes().as_slice(),
                    state.role as u8,
                    state.phase as u8,
                    state.bootstrap_conversation_id.as_bytes().as_slice(),
                    state.new_conversation_id.as_bytes().as_slice(),
                    state.peer_device_id.as_bytes().as_slice(),
                    to_sql_integer(state.deadline_unix_seconds)?,
                    pairing_id.as_ref().map(<[u8; 16]>::as_slice),
                    to_sql_integer(generation)?,
                    sealed.as_bytes(),
                ],
            )
            .map_err(|_| ProfileStoreError::Storage)?
            != 1
        {
            return Err(ProfileStoreError::Storage);
        }
        self.store_repeat_pairing_count(connection, count + 1)
    }

    fn checkpoint_repeat_pairing_in(
        &self,
        connection: &Connection,
        generation: u64,
        state: &RepeatPairingOperationState,
    ) -> Result<(), ProfileStoreError> {
        let existing = self
            .load_repeat_pairing_from(connection, state.operation_id)?
            .ok_or(ProfileStoreError::RepeatPairingNotFound)?;
        if existing.generation != generation
            || !repeat_pairing_transition_allowed(
                existing.state.role,
                existing.state.phase,
                state.phase,
            )
            || !repeat_pairing_identity_equal(&existing.state, state)
        {
            return Err(ProfileStoreError::InvalidTransition);
        }
        let next_generation = generation
            .checked_add(1)
            .ok_or(ProfileStoreError::SequenceExhausted)?;
        let sealed = self.seal_repeat_pairing(state, next_generation)?;
        let pairing_id = state.pairing_id.map(PairingId::into_bytes);
        if connection
            .execute(
                "UPDATE daemon_repeat_pairing
                 SET phase = ?1,
                     pairing_id = ?2,
                     generation = ?3,
                     sealed_state = ?4
                 WHERE operation_id = ?5 AND generation = ?6",
                params![
                    state.phase as u8,
                    pairing_id.as_ref().map(<[u8; 16]>::as_slice),
                    to_sql_integer(next_generation)?,
                    sealed.as_bytes(),
                    state.operation_id.as_bytes().as_slice(),
                    to_sql_integer(generation)?,
                ],
            )
            .map_err(|_| ProfileStoreError::Storage)?
            == 1
        {
            Ok(())
        } else {
            Err(ProfileStoreError::InvalidTransition)
        }
    }

    fn load_repeat_pairing_from(
        &self,
        connection: &Connection,
        operation_id: RepeatPairingOperationId,
    ) -> Result<Option<RepeatPairingCheckpoint>, ProfileStoreError> {
        let metadata = connection
            .query_row(
                "SELECT
                    CASE WHEN length(operation_id) = 16 THEN operation_id END,
                    local_role,
                    phase,
                    CASE WHEN length(bootstrap_conversation_id) = 32
                        THEN bootstrap_conversation_id END,
                    CASE WHEN length(new_conversation_id) = 32
                        THEN new_conversation_id END,
                    CASE WHEN length(peer_device_id) = 32 THEN peer_device_id END,
                    deadline_unix_seconds,
                    CASE
                        WHEN pairing_id IS NULL THEN NULL
                        WHEN length(pairing_id) = 16 THEN pairing_id
                    END,
                    generation,
                    length(sealed_state)
                 FROM daemon_repeat_pairing
                 WHERE operation_id = ?1",
                params![operation_id.as_bytes().as_slice()],
                |row| {
                    Ok(RepeatPairingMetadata {
                        operation_id: row.get(0)?,
                        role: row.get(1)?,
                        phase: row.get(2)?,
                        bootstrap_conversation_id: row.get(3)?,
                        new_conversation_id: row.get(4)?,
                        peer_device_id: row.get(5)?,
                        deadline_unix_seconds: row.get(6)?,
                        pairing_id: row.get(7)?,
                        generation: row.get(8)?,
                        sealed_state_length: row.get(9)?,
                    })
                },
            )
            .optional()
            .map_err(|_| ProfileStoreError::Storage)?;
        metadata
            .map(|metadata| self.open_repeat_pairing(connection, metadata))
            .transpose()
    }

    fn open_repeat_pairing(
        &self,
        connection: &Connection,
        metadata: RepeatPairingMetadata,
    ) -> Result<RepeatPairingCheckpoint, ProfileStoreError> {
        let operation_id = RepeatPairingOperationId::from_slice(
            &metadata
                .operation_id
                .ok_or(ProfileStoreError::CorruptData)?,
        )
        .map_err(|_| ProfileStoreError::CorruptData)?;
        let role = repeat_pairing_role(metadata.role)?;
        let phase = repeat_pairing_phase(metadata.phase)?;
        let bootstrap_conversation_id = ConversationId::from_slice(
            &metadata
                .bootstrap_conversation_id
                .ok_or(ProfileStoreError::CorruptData)?,
        )
        .map_err(|_| ProfileStoreError::CorruptData)?;
        let new_conversation_id = ConversationId::from_slice(
            &metadata
                .new_conversation_id
                .ok_or(ProfileStoreError::CorruptData)?,
        )
        .map_err(|_| ProfileStoreError::CorruptData)?;
        let peer_device_id = DeviceId::from_slice(
            &metadata
                .peer_device_id
                .ok_or(ProfileStoreError::CorruptData)?,
        )
        .map_err(|_| ProfileStoreError::CorruptData)?;
        let deadline_unix_seconds = from_sql_integer(metadata.deadline_unix_seconds)?;
        let pairing_id = metadata
            .pairing_id
            .map(|value| PairingId::from_slice(&value).map_err(|_| ProfileStoreError::CorruptData))
            .transpose()?;
        let generation = from_sql_integer(metadata.generation)?;
        let sealed_length = validate_repeat_pairing_sealed_length(metadata.sealed_state_length)?;
        let sealed: Vec<u8> = connection
            .query_row(
                "SELECT sealed_state FROM daemon_repeat_pairing WHERE operation_id = ?1",
                params![operation_id.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        if sealed.len() != sealed_length {
            return Err(ProfileStoreError::CorruptData);
        }
        let sealed = SealedBlob::from_bytes(sealed).map_err(|_| ProfileStoreError::CorruptData)?;
        let plaintext = self
            .sealer
            .open(
                &repeat_pairing_context(
                    self.locked_profile.profile_id.as_bytes(),
                    operation_id,
                    role,
                    phase,
                    bootstrap_conversation_id,
                    new_conversation_id,
                    peer_device_id,
                    deadline_unix_seconds,
                    pairing_id,
                    generation,
                )?,
                &sealed,
            )
            .map_err(|_| ProfileStoreError::CorruptData)?;
        let state =
            RepeatPairingOperationState::decode(&plaintext).map_err(repeat_pairing_state_error)?;
        if state.operation_id != operation_id
            || state.role != role
            || state.phase != phase
            || state.bootstrap_conversation_id != bootstrap_conversation_id
            || state.new_conversation_id != new_conversation_id
            || state.peer_device_id != peer_device_id
            || state.deadline_unix_seconds != deadline_unix_seconds
            || state.pairing_id != pairing_id
        {
            return Err(ProfileStoreError::CorruptData);
        }
        Ok(RepeatPairingCheckpoint { generation, state })
    }

    fn seal_repeat_pairing(
        &self,
        state: &RepeatPairingOperationState,
        generation: u64,
    ) -> Result<SealedBlob, ProfileStoreError> {
        let plaintext = state.encode().map_err(repeat_pairing_state_error)?;
        self.sealer
            .seal(
                &repeat_pairing_context(
                    self.locked_profile.profile_id.as_bytes(),
                    state.operation_id,
                    state.role,
                    state.phase,
                    state.bootstrap_conversation_id,
                    state.new_conversation_id,
                    state.peer_device_id,
                    state.deadline_unix_seconds,
                    state.pairing_id,
                    generation,
                )?,
                &plaintext,
            )
            .map_err(|_| ProfileStoreError::Storage)
    }

    fn open_repeat_pairing_count(
        &self,
        connection: &Connection,
    ) -> Result<usize, ProfileStoreError> {
        let sealed_length: Option<i64> = connection
            .query_row(
                "SELECT length(sealed_state)
                 FROM daemon_repeat_pairing_state
                 WHERE singleton_id = 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| ProfileStoreError::Storage)?;
        let sealed_length = validate_repeat_pairing_count_sealed_length(
            sealed_length.ok_or(ProfileStoreError::CorruptData)?,
        )?;
        let sealed: Vec<u8> = connection
            .query_row(
                "SELECT sealed_state
                 FROM daemon_repeat_pairing_state
                 WHERE singleton_id = 1",
                [],
                |row| row.get(0),
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        if sealed.len() != sealed_length {
            return Err(ProfileStoreError::CorruptData);
        }
        let sealed = SealedBlob::from_bytes(sealed).map_err(|_| ProfileStoreError::CorruptData)?;
        let plaintext = self
            .sealer
            .open(
                &repeat_pairing_count_context(self.locked_profile.profile_id.as_bytes())?,
                &sealed,
            )
            .map_err(|_| ProfileStoreError::CorruptData)?;
        if plaintext.len() != REPEAT_PAIRING_COUNT_STATE_BYTES
            || plaintext[0] != REPEAT_PAIRING_COUNT_STATE_VERSION
        {
            return Err(ProfileStoreError::CorruptData);
        }
        usize::try_from(u64::from_be_bytes(
            plaintext[1..]
                .try_into()
                .map_err(|_| ProfileStoreError::CorruptData)?,
        ))
        .map_err(|_| ProfileStoreError::CorruptData)
    }

    fn seal_repeat_pairing_count(&self, count: usize) -> Result<SealedBlob, ProfileStoreError> {
        let count = u64::try_from(count).map_err(|_| ProfileStoreError::Storage)?;
        let mut plaintext = [0; REPEAT_PAIRING_COUNT_STATE_BYTES];
        plaintext[0] = REPEAT_PAIRING_COUNT_STATE_VERSION;
        plaintext[1..].copy_from_slice(&count.to_be_bytes());
        self.sealer
            .seal(
                &repeat_pairing_count_context(self.locked_profile.profile_id.as_bytes())?,
                &plaintext,
            )
            .map_err(|_| ProfileStoreError::Storage)
    }

    fn store_repeat_pairing_count(
        &self,
        connection: &Connection,
        count: usize,
    ) -> Result<(), ProfileStoreError> {
        let sealed = self.seal_repeat_pairing_count(count)?;
        if connection
            .execute(
                "UPDATE daemon_repeat_pairing_state
                 SET sealed_state = ?1
                 WHERE singleton_id = 1",
                params![sealed.as_bytes()],
            )
            .map_err(|_| ProfileStoreError::Storage)?
            == 1
        {
            Ok(())
        } else {
            Err(ProfileStoreError::CorruptData)
        }
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "every authenticated repeat-pairing metadata field remains explicit"
)]
fn repeat_pairing_context(
    profile_id: &[u8],
    operation_id: RepeatPairingOperationId,
    role: RepeatPairingRole,
    phase: RepeatPairingPhase,
    bootstrap_conversation_id: ConversationId,
    new_conversation_id: ConversationId,
    peer_device_id: DeviceId,
    deadline_unix_seconds: u64,
    pairing_id: Option<PairingId>,
    generation: u64,
) -> Result<SecretRecordContext, ProfileStoreError> {
    let role_phase = [role as u8, phase as u8];
    let mut checkpoint = Vec::with_capacity(1 + PairingId::LENGTH + 8 + 8);
    match pairing_id {
        Some(pairing_id) => {
            checkpoint.push(1);
            checkpoint.extend_from_slice(pairing_id.as_bytes());
        }
        None => {
            checkpoint.push(0);
            checkpoint.extend_from_slice(&[0; PairingId::LENGTH]);
        }
    }
    checkpoint.extend_from_slice(&deadline_unix_seconds.to_be_bytes());
    checkpoint.extend_from_slice(&generation.to_be_bytes());
    SecretRecordContext::derive(
        SecretRecordKind::RepeatPairingOperation,
        &[
            REPEAT_PAIRING_CONTEXT_VERSION,
            profile_id,
            operation_id.as_bytes(),
            &role_phase,
            bootstrap_conversation_id.as_bytes(),
            new_conversation_id.as_bytes(),
            peer_device_id.as_bytes(),
            &checkpoint,
        ],
    )
    .map_err(|_| ProfileStoreError::Storage)
}

fn repeat_pairing_count_context(
    profile_id: &[u8],
) -> Result<SecretRecordContext, ProfileStoreError> {
    SecretRecordContext::derive(
        SecretRecordKind::RepeatPairingOperationState,
        &[REPEAT_PAIRING_COUNT_CONTEXT_VERSION, profile_id],
    )
    .map_err(|_| ProfileStoreError::Storage)
}

fn repeat_pairing_ids(
    connection: &Connection,
    active_only: bool,
    after: Option<RepeatPairingOperationId>,
    limit: usize,
) -> Result<Vec<RepeatPairingOperationId>, ProfileStoreError> {
    let query = match (active_only, after) {
        (true, Some(_)) => {
            "SELECT CASE WHEN length(operation_id) = 16 THEN operation_id END
             FROM daemon_repeat_pairing
             WHERE phase NOT IN (10, 12) AND operation_id > ?1
             ORDER BY operation_id LIMIT ?2"
        }
        (true, None) => {
            "SELECT CASE WHEN length(operation_id) = 16 THEN operation_id END
             FROM daemon_repeat_pairing
             WHERE phase NOT IN (10, 12)
             ORDER BY operation_id LIMIT ?1"
        }
        (false, Some(_)) => {
            "SELECT CASE WHEN length(operation_id) = 16 THEN operation_id END
             FROM daemon_repeat_pairing
             WHERE operation_id > ?1
             ORDER BY operation_id LIMIT ?2"
        }
        (false, None) => {
            "SELECT CASE WHEN length(operation_id) = 16 THEN operation_id END
             FROM daemon_repeat_pairing
             ORDER BY operation_id LIMIT ?1"
        }
    };
    let values = {
        let mut statement = connection
            .prepare(query)
            .map_err(|_| ProfileStoreError::Storage)?;
        match after {
            Some(after) => statement
                .query_map(params![after.as_bytes().as_slice(), limit], |row| {
                    row.get::<_, Vec<u8>>(0)
                })
                .map_err(|_| ProfileStoreError::Storage)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| ProfileStoreError::Storage)?,
            None => statement
                .query_map(params![limit], |row| row.get::<_, Vec<u8>>(0))
                .map_err(|_| ProfileStoreError::Storage)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| ProfileStoreError::Storage)?,
        }
    };
    values
        .into_iter()
        .map(|value| {
            RepeatPairingOperationId::from_slice(&value).map_err(|_| ProfileStoreError::CorruptData)
        })
        .collect()
}

fn repeat_pairing_count(connection: &Connection) -> Result<usize, ProfileStoreError> {
    let count: i64 = connection
        .query_row("SELECT count(*) FROM daemon_repeat_pairing", [], |row| {
            row.get(0)
        })
        .map_err(|_| ProfileStoreError::Storage)?;
    usize::try_from(count).map_err(|_| ProfileStoreError::CorruptData)
}

fn active_repeat_pairing_count(connection: &Connection) -> Result<usize, ProfileStoreError> {
    let count: i64 = connection
        .query_row(
            "SELECT count(*) FROM daemon_repeat_pairing WHERE phase NOT IN (10, 12)",
            [],
            |row| row.get(0),
        )
        .map_err(|_| ProfileStoreError::Storage)?;
    usize::try_from(count).map_err(|_| ProfileStoreError::CorruptData)
}

fn repeat_pairing_identity_equal(
    left: &RepeatPairingOperationState,
    right: &RepeatPairingOperationState,
) -> bool {
    left.operation_id == right.operation_id
        && left.role == right.role
        && left.bootstrap_conversation_id == right.bootstrap_conversation_id
        && left.new_conversation_id == right.new_conversation_id
        && left.new_routing_id == right.new_routing_id
        && left.peer_device_id == right.peer_device_id
        && left.peer_root_public_key == right.peer_root_public_key
        && left.deadline_unix_seconds == right.deadline_unix_seconds
}

fn repeat_pairing_states_equal(
    left: &RepeatPairingOperationState,
    right: &RepeatPairingOperationState,
) -> Result<bool, ProfileStoreError> {
    Ok(left
        .encode()
        .map_err(repeat_pairing_state_error)?
        .as_slice()
        == right
            .encode()
            .map_err(repeat_pairing_state_error)?
            .as_slice())
}

fn repeat_pairing_deadline_valid(now: u64, deadline: u64) -> bool {
    deadline > now
        && deadline
            .checked_sub(now)
            .is_some_and(|remaining| remaining <= MAX_REPEAT_PAIRING_WINDOW_SECONDS)
}

fn repeat_pairing_role(value: i64) -> Result<RepeatPairingRole, ProfileStoreError> {
    match value {
        1 => Ok(RepeatPairingRole::Initiator),
        2 => Ok(RepeatPairingRole::Responder),
        _ => Err(ProfileStoreError::CorruptData),
    }
}

fn repeat_pairing_phase(value: i64) -> Result<RepeatPairingPhase, ProfileStoreError> {
    match value {
        1 => Ok(RepeatPairingPhase::InitiatorSendingRequest),
        2 => Ok(RepeatPairingPhase::InitiatorAwaitingResponse),
        3 => Ok(RepeatPairingPhase::InitiatorRedeemingCapability),
        4 => Ok(RepeatPairingPhase::InitiatorCreatingConversation),
        5 => Ok(RepeatPairingPhase::InitiatorPairing),
        6 => Ok(RepeatPairingPhase::ResponderIssuingCapability),
        7 => Ok(RepeatPairingPhase::ResponderReservingPairing),
        8 => Ok(RepeatPairingPhase::ResponderSendingResponse),
        9 => Ok(RepeatPairingPhase::ResponderPairing),
        10 => Ok(RepeatPairingPhase::Completed),
        11 => Ok(RepeatPairingPhase::Cancelling),
        12 => Ok(RepeatPairingPhase::Cancelled),
        _ => Err(ProfileStoreError::CorruptData),
    }
}

fn repeat_pairing_state_error(_: RepeatPairingStateError) -> ProfileStoreError {
    ProfileStoreError::CorruptData
}

fn validate_repeat_pairing_sealed_length(length: i64) -> Result<usize, ProfileStoreError> {
    validate_sealed_length(length, MAX_SEALED_REPEAT_PAIRING_STATE_BYTES)
}

fn validate_repeat_pairing_count_sealed_length(length: i64) -> Result<usize, ProfileStoreError> {
    validate_sealed_length(length, MAX_SEALED_REPEAT_PAIRING_COUNT_STATE_BYTES)
}

fn validate_sealed_length(length: i64, maximum: usize) -> Result<usize, ProfileStoreError> {
    let length = usize::try_from(length).map_err(|_| ProfileStoreError::CorruptData)?;
    if length == 0 || length > maximum {
        return Err(ProfileStoreError::CorruptData);
    }
    Ok(length)
}

#[cfg(test)]
mod tests {
    use KonclaveDomainCore::RoutingId;
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

    fn initiator(operation: u8) -> RepeatPairingOperationState {
        RepeatPairingOperationState::initiator(
            RepeatPairingOperationId::from_bytes([operation; 16]),
            ConversationId::from_bytes([2; 32]),
            ConversationId::from_bytes([3; 32]),
            RoutingId::from_bytes([4; 32]),
            DeviceId::from_bytes([5; 32]),
            Ed25519PublicKey::from_bytes([6; 32]),
            u64::MAX / 2,
        )
    }

    #[test]
    fn repeat_pairing_checkpoints_are_sealed_and_generation_bound() {
        let root = tempfile::tempdir().unwrap();
        let store = open_store(root.path(), "repeat-pairing-store");
        let state = initiator(1);
        store.reserve_repeat_pairing(&state, 0).unwrap();
        let sealed: Vec<u8> = store
            .lock()
            .unwrap()
            .query_row(
                "SELECT sealed_state FROM daemon_repeat_pairing",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!sealed.windows(16).any(|window| window == [1; 16]));
        let mut checkpoint = store.load_repeat_pairing(state.operation_id).unwrap();
        checkpoint.state.phase = RepeatPairingPhase::InitiatorAwaitingResponse;
        assert_eq!(
            store
                .checkpoint_repeat_pairing(
                    state.operation_id,
                    checkpoint.generation,
                    &checkpoint.state,
                )
                .unwrap(),
            2
        );
        assert_eq!(
            store
                .load_repeat_pairing(state.operation_id)
                .unwrap()
                .state
                .phase,
            RepeatPairingPhase::InitiatorAwaitingResponse
        );
    }

    #[test]
    fn inbound_repeat_pairing_content_is_targeted_and_idempotent() {
        let root = tempfile::tempdir().unwrap();
        let store = open_store(root.path(), "repeat-pairing-content");
        let local = DeviceId::from_bytes([9; 32]);
        let peer = DeviceId::from_bytes([5; 32]);
        let peer_root = Ed25519PublicKey::from_bytes([6; 32]);
        let operation_id = RepeatPairingOperationId::from_bytes([8; 16]);
        let deadline = store.clock.now_unix_milliseconds() / 1_000 + 300;
        let request = ApplicationContent::repeat_pairing_request(
            RepeatPairingRequest::new(
                operation_id,
                local,
                ConversationId::from_bytes([3; 32]),
                deadline,
            )
            .unwrap(),
        );
        {
            let connection = store.lock().unwrap();
            let transaction = connection.unchecked_transaction().unwrap();
            assert!(
                store
                    .record_repeat_pairing_content_in(
                        &transaction,
                        ConversationId::from_bytes([2; 32]),
                        peer,
                        peer_root,
                        local,
                        &request,
                        deadline - 300,
                    )
                    .unwrap()
            );
            transaction.commit().unwrap();
        }
        let responder = store.load_repeat_pairing(operation_id).unwrap();
        assert_eq!(responder.state.role, RepeatPairingRole::Responder);
        assert_eq!(responder.state.peer_device_id, peer);

        let initiator = initiator(10);
        let initiator_id = initiator.operation_id;
        store.reserve_repeat_pairing(&initiator, 0).unwrap();
        let mut awaiting = store.load_repeat_pairing(initiator_id).unwrap();
        awaiting.state.phase = RepeatPairingPhase::InitiatorAwaitingResponse;
        store
            .checkpoint_repeat_pairing(initiator_id, awaiting.generation, &awaiting.state)
            .unwrap();
        let response = ApplicationContent::repeat_pairing_response(
            RepeatPairingResponse::new(
                initiator_id,
                local,
                ConversationId::from_bytes([3; 32]),
                "sealed-capability",
            )
            .unwrap(),
        );
        {
            let connection = store.lock().unwrap();
            let transaction = connection.unchecked_transaction().unwrap();
            store
                .record_repeat_pairing_content_in(
                    &transaction,
                    ConversationId::from_bytes([2; 32]),
                    peer,
                    peer_root,
                    local,
                    &response,
                    deadline - 300,
                )
                .unwrap();
            transaction.commit().unwrap();
        }
        let received = store.load_repeat_pairing(initiator_id).unwrap();
        assert_eq!(
            received.state.phase,
            RepeatPairingPhase::InitiatorRedeemingCapability
        );
        assert_eq!(
            received.state.capability.as_deref().map(String::as_str),
            Some("sealed-capability")
        );
    }

    #[test]
    fn schema_twenty_migrates_identity_and_repeat_pairing_tables() {
        let root = tempfile::tempdir().unwrap();
        let profile = "repeat-pairing-schema";
        let store = open_store(root.path(), profile);
        let device = store.load_or_create_device().unwrap();
        let profile_id = store.locked_profile.profile_id.clone();
        let prior_identity = device
            .seal_with_profile_schema_floor(
                &store.sealer,
                profile_id.as_bytes(),
                PRIOR_PROFILE_SCHEMA_VERSION,
            )
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
                    "DROP TABLE daemon_repeat_pairing_state;
                     DROP TABLE daemon_repeat_pairing;
                     DROP TABLE daemon_internal_application_message;
                     PRAGMA user_version = 20;",
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
    }

    #[test]
    fn deleted_repeat_pairing_checkpoint_fails_profile_startup() {
        let root = tempfile::tempdir().unwrap();
        let profile = "repeat-pairing-delete";
        let store = open_store(root.path(), profile);
        store.reserve_repeat_pairing(&initiator(1), 0).unwrap();
        let profile_id = store.locked_profile.profile_id.clone();
        store
            .lock()
            .unwrap()
            .execute("DELETE FROM daemon_repeat_pairing", [])
            .unwrap();
        drop(store);
        assert_eq!(
            LockedProfile::acquire(root.path(), profile_id)
                .unwrap()
                .open_store(
                    SecretSealer::from_provider(ExternalWrappingKeyProvider::from_bytes([7; 32]))
                        .unwrap(),
                )
                .err(),
            Some(ProfileStoreError::CorruptData)
        );
    }

    #[test]
    fn expired_terminal_repeat_pairings_are_pruned_before_new_reservations() {
        let root = tempfile::tempdir().unwrap();
        let store = open_store(root.path(), "repeat-pairing-pruning");
        let mut first = initiator(1);
        first.deadline_unix_seconds = 100;
        let first_id = first.operation_id;
        store.reserve_repeat_pairing(&first, 1).unwrap();
        let mut checkpoint = store.load_repeat_pairing(first_id).unwrap();
        checkpoint.state.phase = RepeatPairingPhase::Cancelling;
        let generation = store
            .checkpoint_repeat_pairing(first_id, checkpoint.generation, &checkpoint.state)
            .unwrap();
        checkpoint.state.phase = RepeatPairingPhase::Cancelled;
        store
            .checkpoint_repeat_pairing(first_id, generation, &checkpoint.state)
            .unwrap();

        store.reserve_repeat_pairing(&initiator(2), 101).unwrap();
        assert_eq!(
            store.load_repeat_pairing(first_id).err(),
            Some(ProfileStoreError::RepeatPairingNotFound)
        );
        assert_eq!(
            store
                .open_repeat_pairing_count(&store.lock().unwrap())
                .unwrap(),
            1
        );
    }

    #[test]
    fn transitional_pairing_identifier_is_bound_before_ordinary_reservation() {
        let root = tempfile::tempdir().unwrap();
        let store = open_store(root.path(), "repeat-pairing-binding");
        let mut state = initiator(1);
        let operation_id = state.operation_id;
        let pairing_id = PairingId::from_bytes([9; PairingId::LENGTH]);
        store.reserve_repeat_pairing(&state, 0).unwrap();
        let mut generation = 1;
        state.phase = RepeatPairingPhase::InitiatorAwaitingResponse;
        generation = store
            .checkpoint_repeat_pairing(operation_id, generation, &state)
            .unwrap();
        state.capability = Some(zeroize::Zeroizing::new("capability".to_owned()));
        state.phase = RepeatPairingPhase::InitiatorRedeemingCapability;
        generation = store
            .checkpoint_repeat_pairing(operation_id, generation, &state)
            .unwrap();
        state.pairing_id = Some(pairing_id);
        state.phase = RepeatPairingPhase::InitiatorCreatingConversation;
        store
            .checkpoint_repeat_pairing(operation_id, generation, &state)
            .unwrap();

        assert!(matches!(
            store.repeat_pairing_peer_binding(pairing_id).unwrap(),
            RepeatPairingPeerBinding::Verified {
                peer_device_id,
                conversation_id,
            } if peer_device_id == state.peer_device_id
                && conversation_id == state.new_conversation_id
        ));
        assert_eq!(
            store.load_pairing(pairing_id).err(),
            Some(ProfileStoreError::OperationNotFound)
        );
    }
}
