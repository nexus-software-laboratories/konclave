use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use KonclaveClientLibrary::{RelayAccessCredential, RelayEndpoint};
use KonclaveCryptographicCore::{
    ConversationSigningMaterial, DeviceIdentity, VerifiedDeviceCredentialBinding,
    verify_device_credential_binding,
};
use KonclaveDomainCore::{
    ApplicationMessage, ConversationId, ConversationState, DeliveryClass, DeviceCredentialBinding,
    DeviceId, EnvelopeId, MAX_MEMBERS, MessageId, RelayEnvelope, RoutingId, StoredRelayEnvelope,
};
use KonclaveProtocolContracts::v1::{
    decode_application_message, decode_conversation_state, decode_device_credential_binding,
    decode_relay_envelope, encode_application_message, encode_conversation_state,
    encode_device_credential_binding, encode_relay_envelope,
};
use KonclaveSecretStorage::{
    MAX_SECRET_PLAINTEXT_BYTES, SealedBlob, SecretRecordContext, SecretRecordKind, SecretSealer,
};
use fs4::{FileExt, TryLockError};
use rusqlite::{Connection, OptionalExtension, params};
use thiserror::Error;
use zeroize::Zeroizing;

const PROFILE_SCHEMA_VERSION: u32 = 3;
const MAX_PROFILE_ID_BYTES: usize = 32;
const MAX_SEALED_RECORD_BYTES: usize = MAX_SECRET_PLAINTEXT_BYTES + 64;
const MAX_LOCAL_BINDINGS: usize = MAX_MEMBERS + 1;
pub(crate) const MAX_CONVERSATION_PAGE_SIZE: usize = 100;
const MAX_PENDING_OUTBOX: usize = 32;
const MAX_MESSAGE_PAGE_SIZE: usize = 100;
const LOCAL_RECORD_VERSION: u8 = 1;
const OUTBOX_RECORD_SCOPE: u8 = 1;
const INBOX_ENVELOPE_RECORD_SCOPE: u8 = 2;
const INBOX_MESSAGE_RECORD_SCOPE: u8 = 3;
const CURSOR_OBSERVATION_RECORD_SCOPE: u8 = 4;
const SENDER_COUNTER_RECORD_SCOPE: u8 = 5;
const MESSAGE_HISTORY_RECORD_SCOPE: u8 = 6;

type InboxMessageMetadata = (Vec<u8>, Vec<u8>, Vec<u8>, i64, i64, Vec<u8>, i64);
type HistoryMetadata = (Vec<u8>, Option<i64>, i64, i64, Vec<u8>, i64, i64, i64);

/// Portable, filesystem-safe local profile identifier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ProfileId(String);

impl ProfileId {
    /// Parses a non-empty ASCII profile identifier.
    ///
    /// # Errors
    ///
    /// Returns a validation error for unsafe characters or excessive length.
    pub(crate) fn parse(value: impl Into<String>) -> Result<Self, ProfileStoreError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_PROFILE_ID_BYTES
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(ProfileStoreError::InvalidProfileId);
        }

        Ok(Self(value))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }

    fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

/// Exclusive profile directory and its deterministic database paths.
pub(crate) struct LockedProfile {
    profile_id: ProfileId,
    directory: PathBuf,
    _lock: File,
}

impl LockedProfile {
    /// Creates the profile directory and acquires its non-blocking exclusive lock.
    ///
    /// # Errors
    ///
    /// Returns a typed I/O or lock-conflict error.
    pub(crate) fn acquire(root: &Path, profile_id: ProfileId) -> Result<Self, ProfileStoreError> {
        let directory = root.join(profile_id.as_str());
        std::fs::create_dir_all(&directory).map_err(|_| ProfileStoreError::Io)?;
        let lock_path = directory.join("profile.lock");
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(lock_path)
            .map_err(|_| ProfileStoreError::Io)?;
        match FileExt::try_lock(&lock) {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => return Err(ProfileStoreError::ProfileLocked),
            Err(TryLockError::Error(_)) => return Err(ProfileStoreError::Io),
        }
        Ok(Self {
            profile_id,
            directory,
            _lock: lock,
        })
    }

    #[must_use]
    pub(crate) fn profile_id(&self) -> &ProfileId {
        &self.profile_id
    }

    #[must_use]
    pub(crate) fn mls_database_path(&self) -> PathBuf {
        self.directory.join("mls.sqlite")
    }

    fn profile_database_path(&self) -> PathBuf {
        self.directory.join("profile.sqlite")
    }

    /// Opens the sealed application store while retaining this profile lock.
    ///
    /// # Errors
    ///
    /// Returns a typed SQLite, schema, or profile-identity error.
    pub(crate) fn open_store(
        self,
        sealer: SecretSealer,
    ) -> Result<ProfileStore, ProfileStoreError> {
        let connection =
            Connection::open(self.profile_database_path()).map_err(|_| ProfileStoreError::Io)?;
        initialize_schema(&connection)?;
        connection
            .busy_timeout(Duration::from_secs(5))
            .map_err(|_| ProfileStoreError::Storage)?;
        let existing: Option<String> = connection
            .query_row(
                "SELECT profile_id FROM daemon_profile WHERE singleton_id = 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| ProfileStoreError::Storage)?;
        match existing {
            Some(existing) if existing != self.profile_id.as_str() => {
                return Err(ProfileStoreError::ProfileMismatch);
            }
            Some(_) => {}
            None => {
                connection
                    .execute(
                        "INSERT INTO daemon_profile (singleton_id, profile_id)
                         VALUES (1, ?1)",
                        params![self.profile_id.as_str()],
                    )
                    .map_err(|_| ProfileStoreError::Storage)?;
            }
        }
        let store = ProfileStore {
            connection: Mutex::new(connection),
            sealer: Arc::new(sealer),
            locked_profile: self,
        };
        store.migrate_legacy_history()?;
        Ok(store)
    }
}

/// Sealed profile, relay, conversation-policy, and credential persistence.
pub(crate) struct ProfileStore {
    connection: Mutex<Connection>,
    sealer: Arc<SecretSealer>,
    locked_profile: LockedProfile,
}

impl ProfileStore {
    /// Returns the path owned by the sealed MLS storage adapter.
    #[must_use]
    pub(crate) fn mls_database_path(&self) -> PathBuf {
        self.locked_profile.mls_database_path()
    }

    fn migrate_legacy_history(&self) -> Result<(), ProfileStoreError> {
        let missing_outbound: i64 = self
            .lock()?
            .query_row(
                "SELECT count(*)
                 FROM daemon_outbox o
                 LEFT JOIN daemon_message_history h
                   ON h.conversation_id = o.conversation_id
                  AND h.message_id = o.message_id
                 WHERE o.status IN (2, 3) AND h.message_id IS NULL",
                [],
                |row| row.get(0),
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        if missing_outbound != 0 {
            return Err(ProfileStoreError::LegacyOutboundRecoveryUnsupported);
        }
        let missing_inbound = {
            let connection = self.lock()?;
            let mut statement = connection
                .prepare(
                    "SELECT
                        CASE WHEN length(i.conversation_id) = 32
                            THEN i.conversation_id
                        END,
                        i.cursor,
                        CASE WHEN length(i.envelope_id) = 16 THEN i.envelope_id END,
                        i.status
                     FROM daemon_inbox i
                     LEFT JOIN daemon_message_history h
                       ON h.conversation_id = i.conversation_id
                      AND h.message_id = i.message_id
                     WHERE i.status IN (2, 3) AND h.message_id IS NULL
                     ORDER BY i.conversation_id, i.cursor",
                )
                .map_err(|_| ProfileStoreError::Storage)?;
            statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                })
                .map_err(|_| ProfileStoreError::Storage)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| ProfileStoreError::Storage)?
        };
        for (conversation_id, cursor, envelope_id, status) in missing_inbound {
            let conversation_id = ConversationId::from_slice(&conversation_id)
                .map_err(|_| ProfileStoreError::CorruptData)?;
            let cursor = from_sql_integer(cursor)?;
            let envelope_id =
                EnvelopeId::from_slice(&envelope_id).map_err(|_| ProfileStoreError::CorruptData)?;
            let routing_id = self.conversation_routing_id(conversation_id)?;
            let message = self.load_message_at(conversation_id, cursor)?;
            if message.envelope_id != envelope_id {
                return Err(ProfileStoreError::CorruptData);
            }
            let mut connection = self.lock()?;
            let transaction = connection
                .transaction()
                .map_err(|_| ProfileStoreError::Storage)?;
            self.insert_or_verify_history(
                &transaction,
                conversation_id,
                routing_id,
                envelope_id,
                Some(cursor),
                MessageDirection::Inbound,
                message.sender,
                message.epoch,
                &message.message,
            )?;
            if status == 3
                && !self.complete_history(
                    &transaction,
                    conversation_id,
                    routing_id,
                    message.message.message_id(),
                    envelope_id,
                    cursor,
                )?
            {
                return Err(ProfileStoreError::CorruptData);
            }
            transaction
                .commit()
                .map_err(|_| ProfileStoreError::Storage)?;
        }
        Ok(())
    }

    /// Reopens the profile device root or generates and seals it exactly once.
    ///
    /// # Errors
    ///
    /// Returns a typed storage or cryptographic error.
    pub(crate) fn load_or_create_device(&self) -> Result<DeviceIdentity, ProfileStoreError> {
        let existing = self.read_profile_blob(
            "SELECT length(sealed_device_identity) FROM daemon_profile WHERE singleton_id = 1",
            "SELECT sealed_device_identity FROM daemon_profile WHERE singleton_id = 1",
        )?;
        if let Some(blob) = existing {
            return DeviceIdentity::open(
                &self.sealer,
                self.locked_profile.profile_id.as_bytes(),
                &blob,
            )
            .map_err(|_| ProfileStoreError::Cryptographic);
        }

        let identity = DeviceIdentity::generate().map_err(|_| ProfileStoreError::Cryptographic)?;
        let blob = identity
            .seal(&self.sealer, self.locked_profile.profile_id.as_bytes())
            .map_err(|_| ProfileStoreError::Cryptographic)?;
        let changed = self
            .lock()?
            .execute(
                "UPDATE daemon_profile
                 SET sealed_device_identity = ?1
                 WHERE singleton_id = 1 AND sealed_device_identity IS NULL",
                params![blob.as_bytes()],
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        if changed != 1 {
            return Err(ProfileStoreError::Storage);
        }
        Ok(identity)
    }

    /// Stores one normalized relay endpoint and sealed bearer credential.
    ///
    /// # Errors
    ///
    /// Returns a typed sealing or storage error.
    pub(crate) fn configure_relay(
        &self,
        endpoint: &RelayEndpoint,
        credential: &RelayAccessCredential,
    ) -> Result<(), ProfileStoreError> {
        let blob = credential
            .seal(
                &self.sealer,
                self.locked_profile.profile_id.as_bytes(),
                endpoint,
            )
            .map_err(|_| ProfileStoreError::Credential)?;
        self.lock()?
            .execute(
                "UPDATE daemon_profile
                 SET relay_endpoint = ?1, sealed_relay_credential = ?2
                 WHERE singleton_id = 1",
                params![endpoint.as_str(), blob.as_bytes()],
            )
            .map(|_| ())
            .map_err(|_| ProfileStoreError::Storage)
    }

    /// Loads the configured relay endpoint and bearer credential.
    ///
    /// # Errors
    ///
    /// Returns a missing, malformed, authentication, or storage error.
    pub(crate) fn relay_configuration(
        &self,
    ) -> Result<(RelayEndpoint, RelayAccessCredential), ProfileStoreError> {
        let connection = self.lock()?;
        let (endpoint, length): (Option<String>, Option<i64>) = connection
            .query_row(
                "SELECT relay_endpoint, length(sealed_relay_credential)
                 FROM daemon_profile WHERE singleton_id = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        let endpoint = endpoint.ok_or(ProfileStoreError::RelayNotConfigured)?;
        let length = length.ok_or(ProfileStoreError::RelayNotConfigured)?;
        validate_blob_length(length)?;
        let bytes: Vec<u8> = connection
            .query_row(
                "SELECT sealed_relay_credential
                 FROM daemon_profile WHERE singleton_id = 1",
                [],
                |row| row.get(0),
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        if bytes.len() != usize::try_from(length).unwrap_or_default() {
            return Err(ProfileStoreError::CorruptData);
        }
        drop(connection);
        let blob = SealedBlob::from_bytes(bytes).map_err(|_| ProfileStoreError::CorruptData)?;
        let endpoint =
            RelayEndpoint::parse(&endpoint).map_err(|_| ProfileStoreError::CorruptData)?;
        let credential = RelayAccessCredential::open(
            &self.sealer,
            self.locked_profile.profile_id.as_bytes(),
            &endpoint,
            &blob,
        )
        .map_err(|_| ProfileStoreError::Credential)?;
        Ok((endpoint, credential))
    }

    /// Inserts one conversation's sealed signing material and authenticated policy.
    ///
    /// # Errors
    ///
    /// Returns a typed validation, sealing, duplicate, or storage error.
    pub(crate) fn insert_conversation(
        &self,
        routing_id: RoutingId,
        signing_material: &ConversationSigningMaterial,
        state: &ConversationState,
        bindings: &[DeviceCredentialBinding],
    ) -> Result<(), ProfileStoreError> {
        let conversation_id = signing_material.binding().conversation_id();
        if state.conversation_id() != conversation_id {
            return Err(ProfileStoreError::ConversationMismatch);
        }
        validate_bindings(state, signing_material.binding(), bindings)?;
        let signing_blob = signing_material
            .seal(&self.sealer, self.locked_profile.profile_id.as_bytes())
            .map_err(|_| ProfileStoreError::Cryptographic)?;
        let state_bytes =
            encode_conversation_state(state).map_err(|_| ProfileStoreError::Protocol)?;
        let state_blob = self.seal_conversation_record(
            SecretRecordKind::ConversationPolicyState,
            conversation_id,
            Some(routing_id),
            None,
            &state_bytes,
        )?;
        let mut sealed_bindings = Vec::with_capacity(bindings.len());
        for binding in bindings {
            let bytes = encode_device_credential_binding(binding)
                .map_err(|_| ProfileStoreError::Protocol)?;
            let blob = self.seal_conversation_record(
                SecretRecordKind::ConversationCredentialBinding,
                conversation_id,
                None,
                Some(binding.device_id()),
                &bytes,
            )?;
            sealed_bindings.push((binding.device_id(), blob));
        }

        let mut connection = self.lock()?;
        let transaction = connection
            .transaction()
            .map_err(|_| ProfileStoreError::Storage)?;
        transaction
            .execute(
                "INSERT INTO daemon_conversation (
                    conversation_id,
                    routing_id,
                    sealed_signing_material,
                    sealed_policy_state,
                    sender_counter,
                    replay_cursor
                 ) VALUES (?1, ?2, ?3, ?4, 0, 0)",
                params![
                    conversation_id.as_bytes().as_slice(),
                    routing_id.as_bytes().as_slice(),
                    signing_blob.as_bytes(),
                    state_blob.as_bytes()
                ],
            )
            .map_err(|error| match error {
                rusqlite::Error::SqliteFailure(ref details, _)
                    if details.code == rusqlite::ErrorCode::ConstraintViolation =>
                {
                    ProfileStoreError::ConversationExists
                }
                _ => ProfileStoreError::Storage,
            })?;
        for (device_id, blob) in sealed_bindings {
            transaction
                .execute(
                    "INSERT INTO daemon_conversation_binding (
                        conversation_id, device_id, sealed_binding
                     ) VALUES (?1, ?2, ?3)",
                    params![
                        conversation_id.as_bytes().as_slice(),
                        device_id.as_bytes().as_slice(),
                        blob.as_bytes()
                    ],
                )
                .map_err(|_| ProfileStoreError::Storage)?;
        }
        transaction.commit().map_err(|_| ProfileStoreError::Storage)
    }

    /// Loads and verifies one complete local conversation record.
    ///
    /// # Errors
    ///
    /// Returns a typed missing, malformed, authentication, credential, or storage
    /// error.
    pub(crate) fn load_conversation(
        &self,
        conversation_id: ConversationId,
    ) -> Result<StoredConversation, ProfileStoreError> {
        let metadata: Option<(Vec<u8>, i64, i64, i64, i64)> = self
            .lock()?
            .query_row(
                "SELECT
                    CASE WHEN length(routing_id) = 32 THEN routing_id END,
                    length(sealed_signing_material),
                    length(sealed_policy_state),
                    sender_counter,
                    replay_cursor
                 FROM daemon_conversation
                 WHERE conversation_id = ?1",
                params![conversation_id.as_bytes().as_slice()],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| ProfileStoreError::Storage)?;
        let (routing_id, signing_length, state_length, sender_counter, replay_cursor) =
            metadata.ok_or(ProfileStoreError::ConversationNotFound)?;
        let routing_id =
            RoutingId::from_slice(&routing_id).map_err(|_| ProfileStoreError::CorruptData)?;
        validate_blob_length(signing_length)?;
        validate_blob_length(state_length)?;
        let (signing_bytes, state_bytes): (Vec<u8>, Vec<u8>) = self
            .lock()?
            .query_row(
                "SELECT sealed_signing_material, sealed_policy_state
                 FROM daemon_conversation
                 WHERE conversation_id = ?1",
                params![conversation_id.as_bytes().as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        if signing_bytes.len() != usize::try_from(signing_length).unwrap_or_default()
            || state_bytes.len() != usize::try_from(state_length).unwrap_or_default()
        {
            return Err(ProfileStoreError::CorruptData);
        }
        let signing_blob =
            SealedBlob::from_bytes(signing_bytes).map_err(|_| ProfileStoreError::CorruptData)?;
        let signing_material = ConversationSigningMaterial::open(
            &self.sealer,
            self.locked_profile.profile_id.as_bytes(),
            conversation_id,
            &signing_blob,
        )
        .map_err(|_| ProfileStoreError::Cryptographic)?;
        let state_blob =
            SealedBlob::from_bytes(state_bytes).map_err(|_| ProfileStoreError::CorruptData)?;
        let state_plaintext = self
            .sealer
            .open(
                &conversation_record_context(
                    &self.locked_profile.profile_id,
                    SecretRecordKind::ConversationPolicyState,
                    conversation_id,
                    Some(routing_id),
                    None,
                )?,
                &state_blob,
            )
            .map_err(|_| ProfileStoreError::CorruptData)?;
        let state =
            decode_conversation_state(&state_plaintext).map_err(|_| ProfileStoreError::Protocol)?;
        if state.conversation_id() != conversation_id {
            return Err(ProfileStoreError::ConversationMismatch);
        }
        let bindings = self.load_bindings(conversation_id)?;
        let binding_values = bindings
            .iter()
            .map(VerifiedDeviceCredentialBinding::binding)
            .cloned()
            .collect::<Vec<_>>();
        validate_bindings(&state, signing_material.binding(), &binding_values)?;
        Ok(StoredConversation {
            routing_id,
            signing_material,
            state,
            bindings,
            sender_counter: from_sql_integer(sender_counter)?,
            replay_cursor: from_sql_integer(replay_cursor)?,
        })
    }

    /// Lists one bounded page of local conversation identifiers.
    ///
    /// # Errors
    ///
    /// Returns a bounds, malformed-row, or storage error.
    pub(crate) fn conversation_ids(
        &self,
        after: Option<ConversationId>,
        limit: usize,
    ) -> Result<Vec<ConversationId>, ProfileStoreError> {
        if !(1..=MAX_CONVERSATION_PAGE_SIZE).contains(&limit) {
            return Err(ProfileStoreError::InvalidTransition);
        }
        let limit = i64::try_from(limit).map_err(|_| ProfileStoreError::SequenceExhausted)?;
        let identifiers = {
            let connection = self.lock()?;
            match after {
                Some(after) => {
                    let mut statement = connection
                        .prepare(
                            "SELECT
                                CASE WHEN length(conversation_id) = 32
                                    THEN conversation_id
                                END
                             FROM daemon_conversation
                             WHERE conversation_id > ?1
                             ORDER BY conversation_id
                             LIMIT ?2",
                        )
                        .map_err(|_| ProfileStoreError::Storage)?;
                    statement
                        .query_map(params![after.as_bytes().as_slice(), limit], |row| {
                            row.get::<_, Vec<u8>>(0)
                        })
                        .map_err(|_| ProfileStoreError::Storage)?
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(|_| ProfileStoreError::Storage)?
                }
                None => {
                    let mut statement = connection
                        .prepare(
                            "SELECT
                                CASE WHEN length(conversation_id) = 32
                                    THEN conversation_id
                                END
                             FROM daemon_conversation
                             ORDER BY conversation_id
                             LIMIT ?1",
                        )
                        .map_err(|_| ProfileStoreError::Storage)?;
                    statement
                        .query_map(params![limit], |row| row.get::<_, Vec<u8>>(0))
                        .map_err(|_| ProfileStoreError::Storage)?
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(|_| ProfileStoreError::Storage)?
                }
            }
        };
        identifiers
            .into_iter()
            .map(|identifier| {
                ConversationId::from_slice(&identifier).map_err(|_| ProfileStoreError::CorruptData)
            })
            .collect()
    }

    /// Atomically reserves one sender counter and idempotency identifiers.
    ///
    /// # Errors
    ///
    /// Returns a missing-conversation, duplicate, sequence, or storage error.
    pub(crate) fn reserve_outbound_application(
        &self,
        conversation_id: ConversationId,
        message_id: MessageId,
        envelope_id: EnvelopeId,
    ) -> Result<OutboundReservation, ProfileStoreError> {
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction()
            .map_err(|_| ProfileStoreError::Storage)?;
        let existing = {
            let mut statement = transaction
                .prepare(
                    "SELECT
                        CASE WHEN length(conversation_id) = 32 THEN conversation_id END,
                        CASE WHEN length(message_id) = 16 THEN message_id END,
                        CASE WHEN length(envelope_id) = 16 THEN envelope_id END,
                        sender_counter,
                        status
                     FROM daemon_outbox
                     WHERE envelope_id = ?1
                        OR (conversation_id = ?2 AND message_id = ?3)
                     LIMIT 2",
                )
                .map_err(|_| ProfileStoreError::Storage)?;
            statement
                .query_map(
                    params![
                        envelope_id.as_bytes().as_slice(),
                        conversation_id.as_bytes().as_slice(),
                        message_id.as_bytes().as_slice()
                    ],
                    |row| {
                        Ok((
                            row.get::<_, Vec<u8>>(0)?,
                            row.get::<_, Vec<u8>>(1)?,
                            row.get::<_, Vec<u8>>(2)?,
                            row.get::<_, i64>(3)?,
                            row.get::<_, i64>(4)?,
                        ))
                    },
                )
                .map_err(|_| ProfileStoreError::Storage)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| ProfileStoreError::Storage)?
        };
        if !existing.is_empty() {
            if existing.len() != 1
                || ConversationId::from_slice(&existing[0].0).ok() != Some(conversation_id)
                || MessageId::from_slice(&existing[0].1).ok() != Some(message_id)
                || EnvelopeId::from_slice(&existing[0].2).ok() != Some(envelope_id)
            {
                return Err(ProfileStoreError::DuplicateOperation);
            }
            if existing[0].4 == 4 {
                return Err(ProfileStoreError::InvalidTransition);
            }
            return Ok(OutboundReservation {
                conversation_id,
                message_id,
                envelope_id,
                sender_counter: from_sql_integer(existing[0].3)?,
            });
        }
        let pending: i64 = transaction
            .query_row(
                "SELECT count(*) FROM daemon_outbox WHERE status < 3",
                [],
                |row| row.get(0),
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        if usize::try_from(pending)
            .ok()
            .is_none_or(|pending| pending >= MAX_PENDING_OUTBOX)
        {
            return Err(ProfileStoreError::OutboxCapacityExceeded);
        }
        let current: i64 = transaction
            .query_row(
                "SELECT sender_counter FROM daemon_conversation
                 WHERE conversation_id = ?1",
                params![conversation_id.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| ProfileStoreError::Storage)?
            .ok_or(ProfileStoreError::ConversationNotFound)?;
        let sender_counter = from_sql_integer(current)?
            .checked_add(1)
            .ok_or(ProfileStoreError::SequenceExhausted)?;
        transaction
            .execute(
                "UPDATE daemon_conversation SET sender_counter = ?1
                 WHERE conversation_id = ?2",
                params![
                    to_sql_integer(sender_counter)?,
                    conversation_id.as_bytes().as_slice()
                ],
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        transaction
            .execute(
                "INSERT INTO daemon_outbox (
                    envelope_id, conversation_id, message_id, sender_counter, status
                 ) VALUES (?1, ?2, ?3, ?4, 1)",
                params![
                    envelope_id.as_bytes().as_slice(),
                    conversation_id.as_bytes().as_slice(),
                    message_id.as_bytes().as_slice(),
                    to_sql_integer(sender_counter)?
                ],
            )
            .map_err(map_operation_insert_error)?;
        transaction
            .commit()
            .map_err(|_| ProfileStoreError::Storage)?;
        Ok(OutboundReservation {
            conversation_id,
            message_id,
            envelope_id,
            sender_counter,
        })
    }

    /// Attaches one encrypted relay envelope to its reserved outbox operation.
    ///
    /// # Errors
    ///
    /// Returns a mismatch, transition, sealing, protocol, or storage error.
    pub(crate) fn store_outbound_envelope(
        &self,
        reservation: OutboundReservation,
        envelope: &RelayEnvelope,
    ) -> Result<(), ProfileStoreError> {
        let routing_id: Vec<u8> = self
            .lock()?
            .query_row(
                "SELECT routing_id FROM daemon_conversation WHERE conversation_id = ?1",
                params![reservation.conversation_id.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| ProfileStoreError::Storage)?
            .ok_or(ProfileStoreError::ConversationNotFound)?;
        if envelope.delivery_class() != DeliveryClass::GroupApplication {
            return Err(ProfileStoreError::InvalidTransition);
        }
        if envelope.envelope_id() != reservation.envelope_id
            || envelope.routing_id()
                != RoutingId::from_slice(&routing_id).map_err(|_| ProfileStoreError::CorruptData)?
        {
            return Err(ProfileStoreError::ConversationMismatch);
        }
        let encoded = encode_outbox_record(reservation, envelope)?;
        let blob = self.seal_operation_record(
            SecretRecordKind::LocalOperation,
            reservation.conversation_id,
            envelope.routing_id(),
            OUTBOX_RECORD_SCOPE,
            reservation.envelope_id.as_bytes(),
            &encoded,
        )?;
        let changed = self
            .lock()?
            .execute(
                "UPDATE daemon_outbox
                 SET sealed_envelope = ?1, status = 2
                 WHERE envelope_id = ?2
                   AND conversation_id = ?3
                   AND message_id = ?4
                   AND sender_counter = ?5
                   AND status = 1",
                params![
                    blob.as_bytes(),
                    reservation.envelope_id.as_bytes().as_slice(),
                    reservation.conversation_id.as_bytes().as_slice(),
                    reservation.message_id.as_bytes().as_slice(),
                    to_sql_integer(reservation.sender_counter)?
                ],
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        if changed == 1 {
            return Ok(());
        }
        let existing = self.load_outbox_record(reservation.envelope_id)?;
        if existing.reservation == reservation && existing.envelope == *envelope {
            Ok(())
        } else {
            Err(ProfileStoreError::InvalidTransition)
        }
    }

    /// Stores one sealed outbound plaintext record before its envelope becomes ready.
    ///
    /// # Errors
    ///
    /// Returns a mismatch, duplicate, transition, sealing, protocol, or storage error.
    pub(crate) fn store_outbound_message(
        &self,
        reservation: OutboundReservation,
        routing_id: RoutingId,
        sender: DeviceId,
        epoch: u64,
        message: &ApplicationMessage,
    ) -> Result<(), ProfileStoreError> {
        if message.message_id() != reservation.message_id
            || message.sender_counter() != reservation.sender_counter
        {
            return Err(ProfileStoreError::ConversationMismatch);
        }
        let stored_routing_id = self.conversation_routing_id(reservation.conversation_id)?;
        if stored_routing_id != routing_id {
            return Err(ProfileStoreError::ConversationMismatch);
        }
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction()
            .map_err(|_| ProfileStoreError::Storage)?;
        let status: Option<i64> = transaction
            .query_row(
                "SELECT status FROM daemon_outbox
                 WHERE envelope_id = ?1
                   AND conversation_id = ?2
                   AND message_id = ?3
                   AND sender_counter = ?4",
                params![
                    reservation.envelope_id.as_bytes().as_slice(),
                    reservation.conversation_id.as_bytes().as_slice(),
                    reservation.message_id.as_bytes().as_slice(),
                    to_sql_integer(reservation.sender_counter)?
                ],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| ProfileStoreError::Storage)?;
        if status != Some(1) {
            return Err(ProfileStoreError::InvalidTransition);
        }
        self.insert_or_verify_history(
            &transaction,
            reservation.conversation_id,
            routing_id,
            reservation.envelope_id,
            None,
            MessageDirection::Outbound,
            sender,
            epoch,
            message,
        )?;
        transaction.commit().map_err(|_| ProfileStoreError::Storage)
    }

    /// Loads every bounded ready outbox envelope for retry.
    ///
    /// # Errors
    ///
    /// Returns a malformed, authentication, protocol, count, or storage error.
    pub(crate) fn ready_outbox(&self) -> Result<Vec<PendingOutbox>, ProfileStoreError> {
        let count: i64 = self
            .lock()?
            .query_row(
                "SELECT count(*) FROM daemon_outbox WHERE status = 2",
                [],
                |row| row.get(0),
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        if count < 0
            || usize::try_from(count)
                .ok()
                .is_none_or(|count| count > MAX_PENDING_OUTBOX)
        {
            return Err(ProfileStoreError::OutboxCapacityExceeded);
        }
        let metadata = {
            let connection = self.lock()?;
            let mut statement = connection
                .prepare(
                    "SELECT
                        CASE WHEN length(o.conversation_id) = 32 THEN o.conversation_id END,
                        CASE WHEN length(o.message_id) = 16 THEN o.message_id END,
                        CASE WHEN length(o.envelope_id) = 16 THEN o.envelope_id END,
                        o.sender_counter,
                        CASE WHEN length(c.routing_id) = 32 THEN c.routing_id END,
                        length(o.sealed_envelope)
                     FROM daemon_outbox o
                     JOIN daemon_conversation c
                       ON c.conversation_id = o.conversation_id
                     WHERE o.status = 2
                     ORDER BY o.conversation_id, o.sender_counter",
                )
                .map_err(|_| ProfileStoreError::Storage)?;
            statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, Vec<u8>>(4)?,
                        row.get::<_, i64>(5)?,
                    ))
                })
                .map_err(|_| ProfileStoreError::Storage)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| ProfileStoreError::Storage)?
        };
        let mut pending = Vec::with_capacity(metadata.len());
        for (conversation_id, message_id, envelope_id, sender_counter, routing_id, length) in
            metadata
        {
            validate_blob_length(length)?;
            let bytes: Vec<u8> = self
                .lock()?
                .query_row(
                    "SELECT sealed_envelope FROM daemon_outbox WHERE envelope_id = ?1",
                    params![&envelope_id],
                    |row| row.get(0),
                )
                .map_err(|_| ProfileStoreError::Storage)?;
            if bytes.len() != usize::try_from(length).unwrap_or_default() {
                return Err(ProfileStoreError::CorruptData);
            }
            let conversation_id = ConversationId::from_slice(&conversation_id)
                .map_err(|_| ProfileStoreError::CorruptData)?;
            let envelope_id =
                EnvelopeId::from_slice(&envelope_id).map_err(|_| ProfileStoreError::CorruptData)?;
            let message_id =
                MessageId::from_slice(&message_id).map_err(|_| ProfileStoreError::CorruptData)?;
            let routing_id =
                RoutingId::from_slice(&routing_id).map_err(|_| ProfileStoreError::CorruptData)?;
            let sender_counter = from_sql_integer(sender_counter)?;
            let record =
                self.open_outbox_record(conversation_id, routing_id, envelope_id, bytes)?;
            if record.reservation
                != (OutboundReservation {
                    conversation_id,
                    message_id,
                    envelope_id,
                    sender_counter,
                })
                || record.envelope.envelope_id() != envelope_id
                || record.envelope.routing_id() != routing_id
            {
                return Err(ProfileStoreError::CorruptData);
            }
            pending.push(PendingOutbox {
                conversation_id,
                envelope: record.envelope,
            });
        }
        Ok(pending)
    }

    /// Loads one ready or accepted outbound application by its stable message ID.
    ///
    /// # Errors
    ///
    /// Returns a malformed, authentication, protocol, transition, or storage error.
    pub(crate) fn outbound_application(
        &self,
        conversation_id: ConversationId,
        message_id: MessageId,
    ) -> Result<Option<StoredOutboundApplication>, ProfileStoreError> {
        let metadata: Option<(Vec<u8>, i64, Option<i64>)> = self
            .lock()?
            .query_row(
                "SELECT
                    CASE WHEN length(envelope_id) = 16 THEN envelope_id END,
                    status,
                    accepted_cursor
                 FROM daemon_outbox
                 WHERE conversation_id = ?1 AND message_id = ?2",
                params![
                    conversation_id.as_bytes().as_slice(),
                    message_id.as_bytes().as_slice()
                ],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(|_| ProfileStoreError::Storage)?;
        let Some((envelope_id, status, accepted_cursor)) = metadata else {
            return Ok(None);
        };
        if !matches!(status, 2 | 3) {
            return Err(ProfileStoreError::InvalidTransition);
        }
        let envelope_id =
            EnvelopeId::from_slice(&envelope_id).map_err(|_| ProfileStoreError::CorruptData)?;
        let outbox = self.load_outbox_record(envelope_id)?;
        if outbox.reservation.conversation_id != conversation_id
            || outbox.reservation.message_id != message_id
        {
            return Err(ProfileStoreError::CorruptData);
        }
        let routing_id = outbox.envelope.routing_id();
        let connection = self.lock()?;
        let history = self
            .load_history_record(&connection, conversation_id, routing_id, message_id)?
            .ok_or(ProfileStoreError::CorruptData)?;
        drop(connection);
        if history.direction != MessageDirection::Outbound || history.envelope_id != envelope_id {
            return Err(ProfileStoreError::CorruptData);
        }
        let cursor = accepted_cursor.map(from_sql_integer).transpose()?;
        if status == 2 && (cursor.is_some() || history.cursor.is_some())
            || status == 3 && (cursor.is_none() || history.cursor != cursor)
        {
            return Err(ProfileStoreError::CorruptData);
        }
        Ok(Some(StoredOutboundApplication {
            conversation_id,
            message: history.message,
            envelope: outbox.envelope,
            cursor,
        }))
    }

    /// Converts unsealed reservations into durable counter-gap tombstones.
    ///
    /// This recovery transition is valid only before new outbound work begins.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the transition cannot be persisted.
    pub(crate) fn abandon_unsealed_outbox(&self) -> Result<usize, ProfileStoreError> {
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction()
            .map_err(|_| ProfileStoreError::Storage)?;
        let changed = transaction
            .execute("UPDATE daemon_outbox SET status = 4 WHERE status = 1", [])
            .map_err(|_| ProfileStoreError::Storage)?;
        transaction
            .execute(
                "DELETE FROM daemon_message_history
                 WHERE direction = 1
                   AND status = 1
                   AND cursor IS NULL
                   AND envelope_id IN (
                        SELECT envelope_id FROM daemon_outbox WHERE status = 4
                   )",
                [],
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        transaction
            .commit()
            .map_err(|_| ProfileStoreError::Storage)?;
        Ok(changed)
    }

    /// Converts one exact unsealed reservation into a durable counter-gap tombstone.
    ///
    /// # Errors
    ///
    /// Returns a mismatch, invalid transition, sequence, or storage error.
    pub(crate) fn abandon_outbound_application(
        &self,
        reservation: OutboundReservation,
    ) -> Result<(), ProfileStoreError> {
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction()
            .map_err(|_| ProfileStoreError::Storage)?;
        let changed = transaction
            .execute(
                "UPDATE daemon_outbox SET status = 4
                 WHERE envelope_id = ?1
                   AND conversation_id = ?2
                   AND message_id = ?3
                   AND sender_counter = ?4
                   AND status = 1",
                params![
                    reservation.envelope_id.as_bytes().as_slice(),
                    reservation.conversation_id.as_bytes().as_slice(),
                    reservation.message_id.as_bytes().as_slice(),
                    to_sql_integer(reservation.sender_counter)?
                ],
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        if changed == 1 {
            transaction
                .execute(
                    "DELETE FROM daemon_message_history
                     WHERE conversation_id = ?1
                       AND message_id = ?2
                       AND envelope_id = ?3
                       AND direction = 1
                       AND status = 1
                       AND cursor IS NULL",
                    params![
                        reservation.conversation_id.as_bytes().as_slice(),
                        reservation.message_id.as_bytes().as_slice(),
                        reservation.envelope_id.as_bytes().as_slice()
                    ],
                )
                .map_err(|_| ProfileStoreError::Storage)?;
            transaction
                .commit()
                .map_err(|_| ProfileStoreError::Storage)?;
            return Ok(());
        }
        let state: Option<(Vec<u8>, Vec<u8>, i64, i64)> = transaction
            .query_row(
                "SELECT
                    CASE WHEN length(conversation_id) = 32 THEN conversation_id END,
                    CASE WHEN length(message_id) = 16 THEN message_id END,
                    sender_counter,
                    status
                 FROM daemon_outbox
                 WHERE envelope_id = ?1",
                params![reservation.envelope_id.as_bytes().as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .map_err(|_| ProfileStoreError::Storage)?;
        if state.is_some_and(|(conversation_id, message_id, sender_counter, status)| {
            ConversationId::from_slice(&conversation_id).ok() == Some(reservation.conversation_id)
                && MessageId::from_slice(&message_id).ok() == Some(reservation.message_id)
                && from_sql_integer(sender_counter).ok() == Some(reservation.sender_counter)
                && status == 4
        }) {
            transaction
                .commit()
                .map_err(|_| ProfileStoreError::Storage)?;
            Ok(())
        } else {
            Err(ProfileStoreError::InvalidTransition)
        }
    }

    /// Marks a ready outbox operation accepted at one durable relay cursor.
    ///
    /// # Errors
    ///
    /// Returns a cursor conflict, invalid transition, sequence, or storage error.
    pub(crate) fn mark_outbox_accepted(
        &self,
        stored: &StoredRelayEnvelope,
    ) -> Result<(), ProfileStoreError> {
        let envelope_id = stored.envelope().envelope_id();
        let cursor = stored.cursor();
        let record = self.load_outbox_record(envelope_id)?;
        if record.envelope != *stored.envelope() {
            return Err(ProfileStoreError::CursorConflict);
        }
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction()
            .map_err(|_| ProfileStoreError::Storage)?;
        let state: Option<(i64, Option<i64>)> = transaction
            .query_row(
                "SELECT status, accepted_cursor FROM daemon_outbox
                 WHERE envelope_id = ?1",
                params![envelope_id.as_bytes().as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|_| ProfileStoreError::Storage)?;
        match state {
            Some((2, None)) => {
                self.insert_or_verify_cursor_observation(
                    &transaction,
                    record.reservation.conversation_id,
                    record.envelope.routing_id(),
                    cursor,
                    &record.envelope,
                )?;
                let changed = transaction
                    .execute(
                        "UPDATE daemon_outbox
                         SET status = 3, accepted_cursor = ?1
                         WHERE envelope_id = ?2 AND status = 2",
                        params![to_sql_integer(cursor)?, envelope_id.as_bytes().as_slice()],
                    )
                    .map_err(|_| ProfileStoreError::Storage)?;
                if changed != 1 {
                    return Err(ProfileStoreError::InvalidTransition);
                }
            }
            Some((3, Some(accepted))) if from_sql_integer(accepted)? == cursor => {
                self.verify_cursor_observation(
                    &transaction,
                    record.reservation.conversation_id,
                    record.envelope.routing_id(),
                    cursor,
                    &record.envelope,
                )?;
            }
            _ => return Err(ProfileStoreError::InvalidTransition),
        }
        if !self.assign_history_cursor(
            &transaction,
            record.reservation.conversation_id,
            record.envelope.routing_id(),
            record.reservation.message_id,
            envelope_id,
            cursor,
        )? {
            return Err(ProfileStoreError::CorruptData);
        }
        transaction.commit().map_err(|_| ProfileStoreError::Storage)
    }

    /// Journals one received relay envelope before cryptographic processing.
    ///
    /// An exact duplicate is idempotent; any conflicting identifier or cursor fails.
    ///
    /// # Errors
    ///
    /// Returns a route, cursor conflict, duplicate, sealing, protocol, or storage
    /// error.
    pub(crate) fn record_inbox_envelope(
        &self,
        stored: &StoredRelayEnvelope,
    ) -> Result<ConversationId, ProfileStoreError> {
        let envelope = stored.envelope();
        if envelope.delivery_class() != DeliveryClass::GroupApplication {
            return Err(ProfileStoreError::InvalidTransition);
        }
        let conversation_id: Vec<u8> = self
            .lock()?
            .query_row(
                "SELECT conversation_id FROM daemon_conversation WHERE routing_id = ?1",
                params![envelope.routing_id().as_bytes().as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| ProfileStoreError::Storage)?
            .ok_or(ProfileStoreError::ConversationNotFound)?;
        let conversation_id = ConversationId::from_slice(&conversation_id)
            .map_err(|_| ProfileStoreError::CorruptData)?;
        let encoded = encode_inbox_envelope_record(stored)?;
        let blob = self.seal_operation_record(
            SecretRecordKind::LocalOperation,
            conversation_id,
            envelope.routing_id(),
            INBOX_ENVELOPE_RECORD_SCOPE,
            envelope.envelope_id().as_bytes(),
            &encoded,
        )?;
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction()
            .map_err(|_| ProfileStoreError::Storage)?;
        let observation_inserted = self.insert_or_verify_cursor_observation(
            &transaction,
            conversation_id,
            envelope.routing_id(),
            stored.cursor(),
            envelope,
        )?;
        let insert = transaction.execute(
            "INSERT INTO daemon_inbox (
                conversation_id, cursor, envelope_id, status, sealed_envelope
             ) VALUES (?1, ?2, ?3, 1, ?4)",
            params![
                conversation_id.as_bytes().as_slice(),
                to_sql_integer(stored.cursor())?,
                envelope.envelope_id().as_bytes().as_slice(),
                blob.as_bytes()
            ],
        );
        match insert {
            Ok(_) => {
                let replay_cursor: i64 = transaction
                    .query_row(
                        "SELECT replay_cursor FROM daemon_conversation
                         WHERE conversation_id = ?1",
                        params![conversation_id.as_bytes().as_slice()],
                        |row| row.get(0),
                    )
                    .map_err(|_| ProfileStoreError::Storage)?;
                let replay_cursor = from_sql_integer(replay_cursor)?;
                let cursor_window = u64::try_from(MAX_MESSAGE_PAGE_SIZE)
                    .map_err(|_| ProfileStoreError::SequenceExhausted)?;
                if stored.cursor() > replay_cursor.saturating_add(cursor_window) {
                    return Err(ProfileStoreError::InboxCapacityExceeded);
                }
                let count: i64 = transaction
                    .query_row(
                        "SELECT count(*) FROM daemon_inbox
                         WHERE conversation_id = ?1 AND status < 3",
                        params![conversation_id.as_bytes().as_slice()],
                        |row| row.get(0),
                    )
                    .map_err(|_| ProfileStoreError::Storage)?;
                if usize::try_from(count)
                    .ok()
                    .is_none_or(|count| count > MAX_MESSAGE_PAGE_SIZE)
                {
                    return Err(ProfileStoreError::InboxCapacityExceeded);
                }
                transaction
                    .commit()
                    .map_err(|_| ProfileStoreError::Storage)?;
                Ok(conversation_id)
            }
            Err(rusqlite::Error::SqliteFailure(ref details, _))
                if details.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                if observation_inserted {
                    return Err(ProfileStoreError::CorruptData);
                }
                drop(transaction);
                drop(connection);
                let existing = self.load_conflicting_inbox(
                    conversation_id,
                    stored.cursor(),
                    envelope.envelope_id(),
                )?;
                if &existing == stored {
                    Ok(conversation_id)
                } else {
                    Err(ProfileStoreError::DuplicateOperation)
                }
            }
            Err(_) => Err(ProfileStoreError::Storage),
        }
    }

    /// Stores a decoded application message plus its authenticated MLS sender and
    /// epoch before ratchet persistence.
    ///
    /// # Errors
    ///
    /// Returns a duplicate, transition, sealing, protocol, or storage error.
    pub(crate) fn save_inbox_message(
        &self,
        conversation_id: ConversationId,
        cursor: u64,
        sender: DeviceId,
        sender_epoch: u64,
        message: &ApplicationMessage,
    ) -> Result<(), ProfileStoreError> {
        let envelope_id: Option<Vec<u8>> = self
            .lock()?
            .query_row(
                "SELECT CASE WHEN length(envelope_id) = 16 THEN envelope_id END
                 FROM daemon_inbox
                 WHERE conversation_id = ?1 AND cursor = ?2",
                params![
                    conversation_id.as_bytes().as_slice(),
                    to_sql_integer(cursor)?
                ],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| ProfileStoreError::Storage)?;
        let envelope_id =
            EnvelopeId::from_slice(&envelope_id.ok_or(ProfileStoreError::InvalidTransition)?)
                .map_err(|_| ProfileStoreError::CorruptData)?;
        let stored_envelope = self.load_inbox_envelope(envelope_id)?;
        if stored_envelope.cursor() != cursor {
            return Err(ProfileStoreError::CorruptData);
        }
        let routing_id = stored_envelope.envelope().routing_id();
        let plaintext =
            encode_inbox_message_record(cursor, envelope_id, sender, sender_epoch, message)?;
        let blob = self.seal_operation_record(
            SecretRecordKind::LocalApplicationMessage,
            conversation_id,
            routing_id,
            INBOX_MESSAGE_RECORD_SCOPE,
            message.message_id().as_bytes(),
            &plaintext,
        )?;
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction()
            .map_err(|_| ProfileStoreError::Storage)?;
        let update = transaction.execute(
            "UPDATE daemon_inbox
             SET sender_device_id = ?1,
                 sender_epoch = ?2,
                 message_id = ?3,
                 sender_counter = ?4,
                 sealed_message = ?5,
                 status = 2
             WHERE conversation_id = ?6 AND cursor = ?7 AND status = 1",
            params![
                sender.as_bytes().as_slice(),
                to_sql_integer(sender_epoch)?,
                message.message_id().as_bytes().as_slice(),
                to_sql_integer(message.sender_counter())?,
                blob.as_bytes(),
                conversation_id.as_bytes().as_slice(),
                to_sql_integer(cursor)?
            ],
        );
        match update {
            Ok(1) => {
                self.insert_or_verify_history(
                    &transaction,
                    conversation_id,
                    routing_id,
                    envelope_id,
                    Some(cursor),
                    MessageDirection::Inbound,
                    sender,
                    sender_epoch,
                    message,
                )?;
                transaction.commit().map_err(|_| ProfileStoreError::Storage)
            }
            Ok(_) => {
                drop(transaction);
                drop(connection);
                let existing = self.load_message_at(conversation_id, cursor)?;
                if existing.sender == sender
                    && existing.epoch == sender_epoch
                    && application_messages_equal(&existing.message, message)?
                {
                    let mut connection = self.lock()?;
                    let transaction = connection
                        .transaction()
                        .map_err(|_| ProfileStoreError::Storage)?;
                    self.insert_or_verify_history(
                        &transaction,
                        conversation_id,
                        routing_id,
                        envelope_id,
                        Some(cursor),
                        MessageDirection::Inbound,
                        sender,
                        sender_epoch,
                        message,
                    )?;
                    transaction
                        .commit()
                        .map_err(|_| ProfileStoreError::Storage)?;
                    Ok(())
                } else {
                    Err(ProfileStoreError::InvalidTransition)
                }
            }
            Err(rusqlite::Error::SqliteFailure(ref details, _))
                if details.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                drop(transaction);
                drop(connection);
                Err(ProfileStoreError::DuplicateOperation)
            }
            Err(_) => Err(ProfileStoreError::Storage),
        }
    }

    /// Loads one exact inbox operation for recovery or idempotent replay.
    ///
    /// # Errors
    ///
    /// Returns a missing, malformed, authentication, protocol, or storage error.
    pub(crate) fn inbox_operation(
        &self,
        conversation_id: ConversationId,
        cursor: u64,
    ) -> Result<InboxOperation, ProfileStoreError> {
        let metadata: Option<(Vec<u8>, i64)> = self
            .lock()?
            .query_row(
                "SELECT
                    CASE WHEN length(envelope_id) = 16 THEN envelope_id END,
                    status
                 FROM daemon_inbox
                 WHERE conversation_id = ?1 AND cursor = ?2",
                params![
                    conversation_id.as_bytes().as_slice(),
                    to_sql_integer(cursor)?
                ],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|_| ProfileStoreError::Storage)?;
        let (envelope_id, status) = metadata.ok_or(ProfileStoreError::InvalidTransition)?;
        let envelope_id =
            EnvelopeId::from_slice(&envelope_id).map_err(|_| ProfileStoreError::CorruptData)?;
        let stored = self.load_inbox_envelope(envelope_id)?;
        if stored.cursor() != cursor {
            return Err(ProfileStoreError::CorruptData);
        }
        match status {
            1 => Ok(InboxOperation::Received { stored }),
            2 => Ok(InboxOperation::MessageSaved {
                stored,
                message: self.load_message_at(conversation_id, cursor)?,
            }),
            3 => Ok(InboxOperation::Complete {
                stored,
                message: self.load_message_at(conversation_id, cursor)?,
            }),
            _ => Err(ProfileStoreError::CorruptData),
        }
    }

    /// Loads and cursor-binds one locally sent message echoed by the relay.
    ///
    /// # Errors
    ///
    /// Returns a cursor conflict, malformed, authentication, protocol, or storage
    /// error.
    pub(crate) fn outbound_history_message(
        &self,
        conversation_id: ConversationId,
        envelope_id: EnvelopeId,
        cursor: u64,
    ) -> Result<Option<StoredHistoryMessage>, ProfileStoreError> {
        let routing_id = self.conversation_routing_id(conversation_id)?;
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction()
            .map_err(|_| ProfileStoreError::Storage)?;
        let message_id: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT CASE WHEN length(message_id) = 16 THEN message_id END
                 FROM daemon_message_history
                 WHERE conversation_id = ?1
                   AND envelope_id = ?2
                   AND direction = 1",
                params![
                    conversation_id.as_bytes().as_slice(),
                    envelope_id.as_bytes().as_slice()
                ],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| ProfileStoreError::Storage)?;
        let Some(message_id) = message_id else {
            return Ok(None);
        };
        let message_id =
            MessageId::from_slice(&message_id).map_err(|_| ProfileStoreError::CorruptData)?;
        if !self.assign_history_cursor(
            &transaction,
            conversation_id,
            routing_id,
            message_id,
            envelope_id,
            cursor,
        )? {
            return Err(ProfileStoreError::CorruptData);
        }
        let history = self
            .load_history_record(&transaction, conversation_id, routing_id, message_id)?
            .ok_or(ProfileStoreError::CorruptData)?;
        transaction
            .commit()
            .map_err(|_| ProfileStoreError::Storage)?;
        Ok(Some(StoredHistoryMessage {
            cursor,
            direction: history.direction,
            envelope_id: history.envelope_id,
            sender: history.sender,
            epoch: history.epoch,
            message: history.message,
        }))
    }

    /// Loads bounded incomplete inbox operations in durable cursor order.
    ///
    /// # Errors
    ///
    /// Returns a malformed, authentication, protocol, count, or storage error.
    pub(crate) fn incomplete_inbox(
        &self,
        conversation_id: ConversationId,
    ) -> Result<Vec<PendingInbox>, ProfileStoreError> {
        self.conversation_routing_id(conversation_id)?;
        let metadata = {
            let connection = self.lock()?;
            let mut statement = connection
                .prepare(
                    "SELECT
                        cursor,
                        CASE WHEN length(envelope_id) = 16 THEN envelope_id END,
                        status
                     FROM daemon_inbox
                     WHERE conversation_id = ?1 AND status < 3
                     ORDER BY cursor
                     LIMIT ?2",
                )
                .map_err(|_| ProfileStoreError::Storage)?;
            statement
                .query_map(
                    params![
                        conversation_id.as_bytes().as_slice(),
                        i64::try_from(MAX_MESSAGE_PAGE_SIZE + 1)
                            .map_err(|_| ProfileStoreError::SequenceExhausted)?
                    ],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, Vec<u8>>(1)?,
                            row.get::<_, i64>(2)?,
                        ))
                    },
                )
                .map_err(|_| ProfileStoreError::Storage)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| ProfileStoreError::Storage)?
        };
        if metadata.len() > MAX_MESSAGE_PAGE_SIZE {
            return Err(ProfileStoreError::InboxCapacityExceeded);
        }
        let mut pending = Vec::with_capacity(metadata.len());
        for (cursor, envelope_id, status) in metadata {
            let cursor = from_sql_integer(cursor)?;
            let envelope_id =
                EnvelopeId::from_slice(&envelope_id).map_err(|_| ProfileStoreError::CorruptData)?;
            let stored = self.load_inbox_envelope(envelope_id)?;
            if stored.cursor() != cursor {
                return Err(ProfileStoreError::CorruptData);
            }
            pending.push(match status {
                1 => PendingInbox::Received {
                    conversation_id,
                    stored,
                },
                2 => PendingInbox::MessageSaved {
                    conversation_id,
                    stored,
                    message: self.load_message_at(conversation_id, cursor)?,
                },
                _ => return Err(ProfileStoreError::CorruptData),
            });
        }
        Ok(pending)
    }

    /// Marks one saved inbox message complete and advances only the next contiguous
    /// durable cursor.
    ///
    /// # Errors
    ///
    /// Returns a cursor or sender-counter gap, sender-counter regression,
    /// transition, sequence, or storage error.
    pub(crate) fn complete_inbox(
        &self,
        conversation_id: ConversationId,
        cursor: u64,
    ) -> Result<u64, ProfileStoreError> {
        let message = self.load_message_at(conversation_id, cursor)?;
        let envelope = self.load_inbox_envelope(message.envelope_id)?;
        if envelope.cursor() != cursor {
            return Err(ProfileStoreError::CorruptData);
        }
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction()
            .map_err(|_| ProfileStoreError::Storage)?;
        self.verify_cursor_observation(
            &transaction,
            conversation_id,
            envelope.envelope().routing_id(),
            cursor,
            envelope.envelope(),
        )?;
        let current: i64 = transaction
            .query_row(
                "SELECT replay_cursor FROM daemon_conversation WHERE conversation_id = ?1",
                params![conversation_id.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| ProfileStoreError::Storage)?
            .ok_or(ProfileStoreError::ConversationNotFound)?;
        let current = from_sql_integer(current)?;
        let high_water = self.load_sender_high_water(
            &transaction,
            conversation_id,
            message.sender,
            message.epoch,
        )?;
        if cursor <= current {
            let status: Option<i64> = transaction
                .query_row(
                    "SELECT status FROM daemon_inbox
                     WHERE conversation_id = ?1 AND cursor = ?2",
                    params![
                        conversation_id.as_bytes().as_slice(),
                        to_sql_integer(cursor)?
                    ],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|_| ProfileStoreError::Storage)?;
            return if status == Some(3)
                && high_water.is_some_and(|counter| counter >= message.message.sender_counter())
            {
                Ok(current)
            } else {
                Err(ProfileStoreError::CorruptData)
            };
        }
        if current.checked_add(1) != Some(cursor) {
            return Err(ProfileStoreError::CursorGap);
        }
        if let Some(high_water) = high_water {
            let sender_counter = message.message.sender_counter();
            if sender_counter <= high_water {
                return Err(ProfileStoreError::SenderCounterRegression);
            }
            if high_water.checked_add(1) != Some(sender_counter) {
                return Err(ProfileStoreError::SenderCounterGap);
            }
        }
        self.store_sender_high_water(
            &transaction,
            conversation_id,
            message.sender,
            message.epoch,
            message.message.sender_counter(),
        )?;
        if !self.complete_history(
            &transaction,
            conversation_id,
            envelope.envelope().routing_id(),
            message.message.message_id(),
            message.envelope_id,
            cursor,
        )? {
            return Err(ProfileStoreError::CorruptData);
        }
        let changed = transaction
            .execute(
                "UPDATE daemon_inbox SET status = 3
                 WHERE conversation_id = ?1 AND cursor = ?2 AND status = 2",
                params![
                    conversation_id.as_bytes().as_slice(),
                    to_sql_integer(cursor)?
                ],
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        if changed != 1 {
            return Err(ProfileStoreError::InvalidTransition);
        }
        transaction
            .execute(
                "UPDATE daemon_conversation SET replay_cursor = ?1
                 WHERE conversation_id = ?2",
                params![
                    to_sql_integer(cursor)?,
                    conversation_id.as_bytes().as_slice()
                ],
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        transaction
            .commit()
            .map_err(|_| ProfileStoreError::Storage)?;
        Ok(cursor)
    }

    /// Loads a bounded page of completed local application messages.
    ///
    /// # Errors
    ///
    /// Returns a bounds, malformed, authentication, protocol, or storage error.
    pub(crate) fn load_messages(
        &self,
        conversation_id: ConversationId,
        after_cursor: u64,
        limit: usize,
    ) -> Result<Vec<StoredApplicationMessage>, ProfileStoreError> {
        if !(1..=MAX_MESSAGE_PAGE_SIZE).contains(&limit) {
            return Err(ProfileStoreError::InvalidTransition);
        }
        self.conversation_routing_id(conversation_id)?;
        let metadata = {
            let connection = self.lock()?;
            let mut statement = connection
                .prepare(
                    "SELECT cursor
                     FROM daemon_inbox
                     WHERE conversation_id = ?1 AND cursor > ?2 AND status = 3
                     ORDER BY cursor
                     LIMIT ?3",
                )
                .map_err(|_| ProfileStoreError::Storage)?;
            statement
                .query_map(
                    params![
                        conversation_id.as_bytes().as_slice(),
                        to_sql_integer(after_cursor)?,
                        i64::try_from(limit).map_err(|_| ProfileStoreError::SequenceExhausted)?
                    ],
                    |row| row.get::<_, i64>(0),
                )
                .map_err(|_| ProfileStoreError::Storage)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| ProfileStoreError::Storage)?
        };
        let mut messages = Vec::with_capacity(metadata.len());
        for cursor in metadata {
            messages.push(self.load_message_at(conversation_id, from_sql_integer(cursor)?)?);
        }
        Ok(messages)
    }

    /// Loads one bounded cursor-ordered page of completed sent and received messages.
    ///
    /// # Errors
    ///
    /// Returns a bounds, malformed, authentication, protocol, or storage error.
    pub(crate) fn load_history(
        &self,
        conversation_id: ConversationId,
        after_cursor: u64,
        limit: usize,
    ) -> Result<HistoryPage, ProfileStoreError> {
        if !(1..=MAX_MESSAGE_PAGE_SIZE).contains(&limit) {
            return Err(ProfileStoreError::InvalidTransition);
        }
        let conversation = self.load_conversation(conversation_id)?;
        let routing_id = conversation.routing_id;
        let message_ids = {
            let connection = self.lock()?;
            let mut statement = connection
                .prepare(
                    "SELECT CASE WHEN length(message_id) = 16 THEN message_id END
                     FROM daemon_message_history
                     WHERE conversation_id = ?1
                       AND status = 2
                       AND cursor > ?2
                       AND cursor <= ?3
                     ORDER BY cursor
                     LIMIT ?4",
                )
                .map_err(|_| ProfileStoreError::Storage)?;
            statement
                .query_map(
                    params![
                        conversation_id.as_bytes().as_slice(),
                        to_sql_integer(after_cursor)?,
                        to_sql_integer(conversation.replay_cursor)?,
                        i64::try_from(limit + 1)
                            .map_err(|_| ProfileStoreError::SequenceExhausted)?
                    ],
                    |row| row.get::<_, Vec<u8>>(0),
                )
                .map_err(|_| ProfileStoreError::Storage)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| ProfileStoreError::Storage)?
        };
        let has_more = message_ids.len() > limit;
        let mut messages = Vec::with_capacity(message_ids.len().min(limit));
        for message_id in message_ids.into_iter().take(limit) {
            let message_id =
                MessageId::from_slice(&message_id).map_err(|_| ProfileStoreError::CorruptData)?;
            let connection = self.lock()?;
            let history = self
                .load_history_record(&connection, conversation_id, routing_id, message_id)?
                .ok_or(ProfileStoreError::CorruptData)?;
            drop(connection);
            let cursor = history.cursor.ok_or(ProfileStoreError::CorruptData)?;
            match history.direction {
                MessageDirection::Outbound => {
                    let outbox = self.load_outbox_record(history.envelope_id)?;
                    if outbox.reservation.conversation_id != conversation_id {
                        return Err(ProfileStoreError::CorruptData);
                    }
                    let connection = self.lock()?;
                    self.verify_cursor_observation(
                        &connection,
                        conversation_id,
                        routing_id,
                        cursor,
                        &outbox.envelope,
                    )?;
                }
                MessageDirection::Inbound => {
                    let inbox = self.load_inbox_envelope(history.envelope_id)?;
                    if inbox.cursor() != cursor {
                        return Err(ProfileStoreError::CorruptData);
                    }
                }
            }
            messages.push(stored_history_message(history).ok_or(ProfileStoreError::CorruptData)?);
        }
        Ok(HistoryPage { messages, has_more })
    }

    fn insert_or_verify_cursor_observation(
        &self,
        transaction: &rusqlite::Transaction<'_>,
        conversation_id: ConversationId,
        routing_id: RoutingId,
        cursor: u64,
        envelope: &RelayEnvelope,
    ) -> Result<bool, ProfileStoreError> {
        let envelope_id = envelope.envelope_id();
        let plaintext = encode_cursor_observation(cursor, envelope)?;
        let blob = self.seal_operation_record(
            SecretRecordKind::LocalOperation,
            conversation_id,
            routing_id,
            CURSOR_OBSERVATION_RECORD_SCOPE,
            envelope_id.as_bytes(),
            &plaintext,
        )?;
        match transaction.execute(
            "INSERT INTO daemon_cursor_observation (
                conversation_id, cursor, envelope_id, sealed_observation
             ) VALUES (?1, ?2, ?3, ?4)",
            params![
                conversation_id.as_bytes().as_slice(),
                to_sql_integer(cursor)?,
                envelope_id.as_bytes().as_slice(),
                blob.as_bytes()
            ],
        ) {
            Ok(1) => Ok(true),
            Ok(_) => Err(ProfileStoreError::Storage),
            Err(rusqlite::Error::SqliteFailure(ref details, _))
                if details.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                self.verify_cursor_observation(
                    transaction,
                    conversation_id,
                    routing_id,
                    cursor,
                    envelope,
                )?;
                Ok(false)
            }
            Err(_) => Err(ProfileStoreError::Storage),
        }
    }

    fn verify_cursor_observation(
        &self,
        connection: &Connection,
        conversation_id: ConversationId,
        routing_id: RoutingId,
        cursor: u64,
        envelope: &RelayEnvelope,
    ) -> Result<(), ProfileStoreError> {
        let envelope_id = envelope.envelope_id();
        let metadata = {
            let mut statement = connection
                .prepare(
                    "SELECT
                        CASE WHEN length(conversation_id) = 32 THEN conversation_id END,
                        cursor,
                        CASE WHEN length(envelope_id) = 16 THEN envelope_id END,
                        length(sealed_observation)
                     FROM daemon_cursor_observation
                     WHERE (conversation_id = ?1 AND cursor = ?2)
                        OR envelope_id = ?3
                     LIMIT 2",
                )
                .map_err(|_| ProfileStoreError::Storage)?;
            statement
                .query_map(
                    params![
                        conversation_id.as_bytes().as_slice(),
                        to_sql_integer(cursor)?,
                        envelope_id.as_bytes().as_slice()
                    ],
                    |row| {
                        Ok((
                            row.get::<_, Vec<u8>>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, Vec<u8>>(2)?,
                            row.get::<_, i64>(3)?,
                        ))
                    },
                )
                .map_err(|_| ProfileStoreError::Storage)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| ProfileStoreError::Storage)?
        };
        if metadata.len() != 1
            || ConversationId::from_slice(&metadata[0].0).ok() != Some(conversation_id)
            || from_sql_integer(metadata[0].1).ok() != Some(cursor)
            || EnvelopeId::from_slice(&metadata[0].2).ok() != Some(envelope_id)
        {
            return Err(ProfileStoreError::CursorConflict);
        }
        validate_blob_length(metadata[0].3)?;
        let bytes: Vec<u8> = connection
            .query_row(
                "SELECT sealed_observation
                 FROM daemon_cursor_observation
                 WHERE conversation_id = ?1 AND cursor = ?2",
                params![
                    conversation_id.as_bytes().as_slice(),
                    to_sql_integer(cursor)?
                ],
                |row| row.get(0),
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        if bytes.len() != usize::try_from(metadata[0].3).unwrap_or_default() {
            return Err(ProfileStoreError::CorruptData);
        }
        let plaintext = self.open_operation_record(
            SecretRecordKind::LocalOperation,
            conversation_id,
            routing_id,
            CURSOR_OBSERVATION_RECORD_SCOPE,
            envelope_id.as_bytes(),
            bytes,
        )?;
        let observed = decode_cursor_observation(&plaintext)?;
        if observed.cursor() != cursor || observed.envelope() != envelope {
            return Err(ProfileStoreError::CursorConflict);
        }
        Ok(())
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "history identity and authenticated message fields remain explicit"
    )]
    fn insert_or_verify_history(
        &self,
        connection: &Connection,
        conversation_id: ConversationId,
        routing_id: RoutingId,
        envelope_id: EnvelopeId,
        cursor: Option<u64>,
        direction: MessageDirection,
        sender: DeviceId,
        epoch: u64,
        message: &ApplicationMessage,
    ) -> Result<(), ProfileStoreError> {
        let plaintext =
            encode_history_message_record(direction, envelope_id, sender, epoch, message)?;
        let blob = self.seal_operation_record(
            SecretRecordKind::LocalApplicationMessage,
            conversation_id,
            routing_id,
            MESSAGE_HISTORY_RECORD_SCOPE,
            message.message_id().as_bytes(),
            &plaintext,
        )?;
        let insert = connection.execute(
            "INSERT INTO daemon_message_history (
                conversation_id,
                message_id,
                envelope_id,
                cursor,
                direction,
                status,
                sender_device_id,
                sender_epoch,
                sender_counter,
                sealed_message
             ) VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6, ?7, ?8, ?9)",
            params![
                conversation_id.as_bytes().as_slice(),
                message.message_id().as_bytes().as_slice(),
                envelope_id.as_bytes().as_slice(),
                cursor.map(to_sql_integer).transpose()?,
                direction as i64,
                sender.as_bytes().as_slice(),
                to_sql_integer(epoch)?,
                to_sql_integer(message.sender_counter())?,
                blob.as_bytes()
            ],
        );
        match insert {
            Ok(1) => return Ok(()),
            Ok(_) => return Err(ProfileStoreError::Storage),
            Err(rusqlite::Error::SqliteFailure(ref details, _))
                if details.code == rusqlite::ErrorCode::ConstraintViolation => {}
            Err(_) => return Err(ProfileStoreError::Storage),
        }
        let existing = self
            .load_history_record(
                connection,
                conversation_id,
                routing_id,
                message.message_id(),
            )?
            .ok_or(ProfileStoreError::DuplicateOperation)?;
        if existing.envelope_id != envelope_id
            || existing.sender != sender
            || existing.epoch != epoch
            || !application_messages_equal(&existing.message, message)?
        {
            return Err(ProfileStoreError::DuplicateOperation);
        }
        match (existing.cursor, cursor) {
            (Some(existing), Some(candidate)) if existing != candidate => {
                return Err(ProfileStoreError::CursorConflict);
            }
            (None, Some(cursor)) => {
                connection
                    .execute(
                        "UPDATE daemon_message_history SET cursor = ?1
                         WHERE conversation_id = ?2
                           AND message_id = ?3
                           AND cursor IS NULL",
                        params![
                            to_sql_integer(cursor)?,
                            conversation_id.as_bytes().as_slice(),
                            message.message_id().as_bytes().as_slice()
                        ],
                    )
                    .map_err(map_history_update_error)?;
            }
            _ => {}
        }
        Ok(())
    }

    fn load_history_record(
        &self,
        connection: &Connection,
        conversation_id: ConversationId,
        routing_id: RoutingId,
        message_id: MessageId,
    ) -> Result<Option<HistoryRecord>, ProfileStoreError> {
        let metadata: Option<HistoryMetadata> = connection
            .query_row(
                "SELECT
                    CASE WHEN length(envelope_id) = 16 THEN envelope_id END,
                    cursor,
                    direction,
                    status,
                    CASE WHEN length(sender_device_id) = 32
                        THEN sender_device_id
                    END,
                    sender_epoch,
                    sender_counter,
                    length(sealed_message)
                 FROM daemon_message_history
                 WHERE conversation_id = ?1 AND message_id = ?2",
                params![
                    conversation_id.as_bytes().as_slice(),
                    message_id.as_bytes().as_slice()
                ],
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
                    ))
                },
            )
            .optional()
            .map_err(|_| ProfileStoreError::Storage)?;
        let Some((envelope_id, cursor, direction, status, sender, epoch, sender_counter, length)) =
            metadata
        else {
            return Ok(None);
        };
        validate_blob_length(length)?;
        let bytes: Vec<u8> = connection
            .query_row(
                "SELECT sealed_message
                 FROM daemon_message_history
                 WHERE conversation_id = ?1 AND message_id = ?2",
                params![
                    conversation_id.as_bytes().as_slice(),
                    message_id.as_bytes().as_slice()
                ],
                |row| row.get(0),
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        if bytes.len() != usize::try_from(length).unwrap_or_default() {
            return Err(ProfileStoreError::CorruptData);
        }
        let blob = SealedBlob::from_bytes(bytes).map_err(|_| ProfileStoreError::CorruptData)?;
        let plaintext = self
            .sealer
            .open(
                &operation_record_context(
                    &self.locked_profile.profile_id,
                    SecretRecordKind::LocalApplicationMessage,
                    conversation_id,
                    routing_id,
                    MESSAGE_HISTORY_RECORD_SCOPE,
                    message_id.as_bytes(),
                )?,
                &blob,
            )
            .map_err(|_| ProfileStoreError::CorruptData)?;
        let (stored_direction, stored_envelope, stored_sender, stored_epoch, message) =
            decode_history_message_record(&plaintext)?;
        let envelope_id =
            EnvelopeId::from_slice(&envelope_id).map_err(|_| ProfileStoreError::CorruptData)?;
        let sender = DeviceId::from_slice(&sender).map_err(|_| ProfileStoreError::CorruptData)?;
        let epoch = from_sql_integer(epoch)?;
        if stored_envelope != envelope_id
            || stored_sender != sender
            || stored_epoch != epoch
            || message.message_id() != message_id
            || message.sender_counter() != from_sql_integer(sender_counter)?
        {
            return Err(ProfileStoreError::CorruptData);
        }
        let direction = match direction {
            1 => MessageDirection::Outbound,
            2 => MessageDirection::Inbound,
            _ => return Err(ProfileStoreError::CorruptData),
        };
        if stored_direction != direction {
            return Err(ProfileStoreError::CorruptData);
        }
        let complete = match status {
            1 => false,
            2 => true,
            _ => return Err(ProfileStoreError::CorruptData),
        };
        Ok(Some(HistoryRecord {
            cursor: cursor.map(from_sql_integer).transpose()?,
            direction,
            envelope_id,
            sender,
            epoch,
            message,
            complete,
        }))
    }

    fn assign_history_cursor(
        &self,
        connection: &Connection,
        conversation_id: ConversationId,
        routing_id: RoutingId,
        message_id: MessageId,
        envelope_id: EnvelopeId,
        cursor: u64,
    ) -> Result<bool, ProfileStoreError> {
        let Some(history) =
            self.load_history_record(connection, conversation_id, routing_id, message_id)?
        else {
            return Ok(false);
        };
        if history.envelope_id != envelope_id
            || history.cursor.is_some_and(|existing| existing != cursor)
        {
            return Err(ProfileStoreError::CursorConflict);
        }
        if history.cursor == Some(cursor) {
            return Ok(true);
        }
        let changed = connection
            .execute(
                "UPDATE daemon_message_history
                 SET cursor = ?1
                 WHERE conversation_id = ?2
                   AND message_id = ?3
                   AND cursor IS NULL",
                params![
                    to_sql_integer(cursor)?,
                    conversation_id.as_bytes().as_slice(),
                    message_id.as_bytes().as_slice()
                ],
            )
            .map_err(map_history_update_error)?;
        if changed == 1 {
            Ok(true)
        } else {
            Err(ProfileStoreError::InvalidTransition)
        }
    }

    fn complete_history(
        &self,
        connection: &Connection,
        conversation_id: ConversationId,
        routing_id: RoutingId,
        message_id: MessageId,
        envelope_id: EnvelopeId,
        cursor: u64,
    ) -> Result<bool, ProfileStoreError> {
        let Some(history) =
            self.load_history_record(connection, conversation_id, routing_id, message_id)?
        else {
            return Ok(false);
        };
        if history.envelope_id != envelope_id
            || history.cursor.is_some_and(|existing| existing != cursor)
        {
            return Err(ProfileStoreError::CursorConflict);
        }
        if history.complete && history.cursor == Some(cursor) {
            return Ok(true);
        }
        let changed = connection
            .execute(
                "UPDATE daemon_message_history
                 SET cursor = ?1, status = 2
                 WHERE conversation_id = ?2
                   AND message_id = ?3
                   AND status = 1",
                params![
                    to_sql_integer(cursor)?,
                    conversation_id.as_bytes().as_slice(),
                    message_id.as_bytes().as_slice()
                ],
            )
            .map_err(map_history_update_error)?;
        if changed == 1 {
            Ok(true)
        } else {
            Err(ProfileStoreError::InvalidTransition)
        }
    }

    fn load_sender_high_water(
        &self,
        connection: &Connection,
        conversation_id: ConversationId,
        sender: DeviceId,
        epoch: u64,
    ) -> Result<Option<u64>, ProfileStoreError> {
        let metadata: Option<(i64, i64)> = connection
            .query_row(
                "SELECT highest_counter, length(sealed_state)
                 FROM daemon_sender_counter
                 WHERE conversation_id = ?1
                   AND sender_device_id = ?2
                   AND sender_epoch = ?3",
                params![
                    conversation_id.as_bytes().as_slice(),
                    sender.as_bytes().as_slice(),
                    to_sql_integer(epoch)?
                ],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|_| ProfileStoreError::Storage)?;
        let Some((highest_counter, length)) = metadata else {
            return Ok(None);
        };
        validate_blob_length(length)?;
        let bytes: Vec<u8> = connection
            .query_row(
                "SELECT sealed_state
                 FROM daemon_sender_counter
                 WHERE conversation_id = ?1
                   AND sender_device_id = ?2
                   AND sender_epoch = ?3",
                params![
                    conversation_id.as_bytes().as_slice(),
                    sender.as_bytes().as_slice(),
                    to_sql_integer(epoch)?
                ],
                |row| row.get(0),
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        if bytes.len() != usize::try_from(length).unwrap_or_default() {
            return Err(ProfileStoreError::CorruptData);
        }
        let blob = SealedBlob::from_bytes(bytes).map_err(|_| ProfileStoreError::CorruptData)?;
        let plaintext = self
            .sealer
            .open(
                &sender_counter_record_context(
                    &self.locked_profile.profile_id,
                    conversation_id,
                    sender,
                    epoch,
                )?,
                &blob,
            )
            .map_err(|_| ProfileStoreError::CorruptData)?;
        let (stored_sender, stored_epoch, stored_counter) =
            decode_sender_counter_state(&plaintext)?;
        let highest_counter = from_sql_integer(highest_counter)?;
        if stored_sender != sender || stored_epoch != epoch || stored_counter != highest_counter {
            return Err(ProfileStoreError::CorruptData);
        }
        Ok(Some(highest_counter))
    }

    fn store_sender_high_water(
        &self,
        connection: &Connection,
        conversation_id: ConversationId,
        sender: DeviceId,
        epoch: u64,
        highest_counter: u64,
    ) -> Result<(), ProfileStoreError> {
        let plaintext = encode_sender_counter_state(sender, epoch, highest_counter)?;
        let blob = self
            .sealer
            .seal(
                &sender_counter_record_context(
                    &self.locked_profile.profile_id,
                    conversation_id,
                    sender,
                    epoch,
                )?,
                &plaintext,
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        connection
            .execute(
                "INSERT INTO daemon_sender_counter (
                    conversation_id,
                    sender_device_id,
                    sender_epoch,
                    highest_counter,
                    sealed_state
                 ) VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT (conversation_id, sender_device_id, sender_epoch)
                 DO UPDATE SET
                    highest_counter = excluded.highest_counter,
                    sealed_state = excluded.sealed_state",
                params![
                    conversation_id.as_bytes().as_slice(),
                    sender.as_bytes().as_slice(),
                    to_sql_integer(epoch)?,
                    to_sql_integer(highest_counter)?,
                    blob.as_bytes()
                ],
            )
            .map(|_| ())
            .map_err(|_| ProfileStoreError::Storage)
    }

    fn seal_operation_record(
        &self,
        kind: SecretRecordKind,
        conversation_id: ConversationId,
        routing_id: RoutingId,
        scope: u8,
        record_id: &[u8],
        plaintext: &[u8],
    ) -> Result<SealedBlob, ProfileStoreError> {
        self.sealer
            .seal(
                &operation_record_context(
                    &self.locked_profile.profile_id,
                    kind,
                    conversation_id,
                    routing_id,
                    scope,
                    record_id,
                )?,
                plaintext,
            )
            .map_err(|_| ProfileStoreError::Storage)
    }

    fn open_operation_record(
        &self,
        kind: SecretRecordKind,
        conversation_id: ConversationId,
        routing_id: RoutingId,
        scope: u8,
        record_id: &[u8],
        bytes: Vec<u8>,
    ) -> Result<Zeroizing<Vec<u8>>, ProfileStoreError> {
        let blob = SealedBlob::from_bytes(bytes).map_err(|_| ProfileStoreError::CorruptData)?;
        self.sealer
            .open(
                &operation_record_context(
                    &self.locked_profile.profile_id,
                    kind,
                    conversation_id,
                    routing_id,
                    scope,
                    record_id,
                )?,
                &blob,
            )
            .map_err(|_| ProfileStoreError::CorruptData)
    }

    fn open_outbox_record(
        &self,
        conversation_id: ConversationId,
        routing_id: RoutingId,
        envelope_id: EnvelopeId,
        bytes: Vec<u8>,
    ) -> Result<OutboxRecord, ProfileStoreError> {
        let plaintext = self.open_operation_record(
            SecretRecordKind::LocalOperation,
            conversation_id,
            routing_id,
            OUTBOX_RECORD_SCOPE,
            envelope_id.as_bytes(),
            bytes,
        )?;
        decode_outbox_record(conversation_id, envelope_id, &plaintext)
    }

    fn load_outbox_record(
        &self,
        envelope_id: EnvelopeId,
    ) -> Result<OutboxRecord, ProfileStoreError> {
        let metadata: Option<(Vec<u8>, Vec<u8>, Option<i64>)> = self
            .lock()?
            .query_row(
                "SELECT
                    CASE WHEN length(conversation_id) = 32 THEN conversation_id END,
                    CASE WHEN length(routing_id) = 32 THEN routing_id END,
                    length(sealed_envelope)
                 FROM daemon_outbox
                 JOIN daemon_conversation USING (conversation_id)
                 WHERE envelope_id = ?1",
                params![envelope_id.as_bytes().as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(|_| ProfileStoreError::Storage)?;
        let (conversation_id, routing_id, length) =
            metadata.ok_or(ProfileStoreError::InvalidTransition)?;
        let length = length.ok_or(ProfileStoreError::InvalidTransition)?;
        validate_blob_length(length)?;
        let bytes: Vec<u8> = self
            .lock()?
            .query_row(
                "SELECT sealed_envelope FROM daemon_outbox WHERE envelope_id = ?1",
                params![envelope_id.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        if bytes.len() != usize::try_from(length).unwrap_or_default() {
            return Err(ProfileStoreError::CorruptData);
        }
        self.open_outbox_record(
            ConversationId::from_slice(&conversation_id)
                .map_err(|_| ProfileStoreError::CorruptData)?,
            RoutingId::from_slice(&routing_id).map_err(|_| ProfileStoreError::CorruptData)?,
            envelope_id,
            bytes,
        )
    }

    fn load_inbox_envelope(
        &self,
        envelope_id: EnvelopeId,
    ) -> Result<StoredRelayEnvelope, ProfileStoreError> {
        let metadata: Option<(Vec<u8>, Vec<u8>, i64, i64)> = self
            .lock()?
            .query_row(
                "SELECT
                    CASE WHEN length(conversation_id) = 32 THEN conversation_id END,
                    CASE WHEN length(routing_id) = 32 THEN routing_id END,
                    cursor,
                    length(sealed_envelope)
                 FROM daemon_inbox
                 JOIN daemon_conversation USING (conversation_id)
                 WHERE envelope_id = ?1",
                params![envelope_id.as_bytes().as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .map_err(|_| ProfileStoreError::Storage)?;
        let (conversation_id, routing_id, cursor, length) =
            metadata.ok_or(ProfileStoreError::InvalidTransition)?;
        validate_blob_length(length)?;
        let bytes: Vec<u8> = self
            .lock()?
            .query_row(
                "SELECT sealed_envelope FROM daemon_inbox WHERE envelope_id = ?1",
                params![envelope_id.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        if bytes.len() != usize::try_from(length).unwrap_or_default() {
            return Err(ProfileStoreError::CorruptData);
        }
        let conversation_id = ConversationId::from_slice(&conversation_id)
            .map_err(|_| ProfileStoreError::CorruptData)?;
        let routing_id =
            RoutingId::from_slice(&routing_id).map_err(|_| ProfileStoreError::CorruptData)?;
        let plaintext = self.open_operation_record(
            SecretRecordKind::LocalOperation,
            conversation_id,
            routing_id,
            INBOX_ENVELOPE_RECORD_SCOPE,
            envelope_id.as_bytes(),
            bytes,
        )?;
        let stored = decode_inbox_envelope_record(&plaintext)?;
        if stored.cursor() != from_sql_integer(cursor)?
            || stored.envelope().envelope_id() != envelope_id
            || stored.envelope().routing_id() != routing_id
        {
            return Err(ProfileStoreError::CorruptData);
        }
        {
            let connection = self.lock()?;
            self.verify_cursor_observation(
                &connection,
                conversation_id,
                routing_id,
                stored.cursor(),
                stored.envelope(),
            )?;
        }
        Ok(stored)
    }

    fn load_conflicting_inbox(
        &self,
        conversation_id: ConversationId,
        cursor: u64,
        envelope_id: EnvelopeId,
    ) -> Result<StoredRelayEnvelope, ProfileStoreError> {
        let envelope_ids = {
            let connection = self.lock()?;
            let mut statement = connection
                .prepare(
                    "SELECT CASE WHEN length(envelope_id) = 16 THEN envelope_id END
                     FROM daemon_inbox
                     WHERE envelope_id = ?1
                        OR (conversation_id = ?2 AND cursor = ?3)
                     LIMIT 2",
                )
                .map_err(|_| ProfileStoreError::Storage)?;
            statement
                .query_map(
                    params![
                        envelope_id.as_bytes().as_slice(),
                        conversation_id.as_bytes().as_slice(),
                        to_sql_integer(cursor)?
                    ],
                    |row| row.get::<_, Vec<u8>>(0),
                )
                .map_err(|_| ProfileStoreError::Storage)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| ProfileStoreError::Storage)?
        };
        if envelope_ids.len() != 1
            || EnvelopeId::from_slice(&envelope_ids[0]).ok() != Some(envelope_id)
        {
            return Err(ProfileStoreError::DuplicateOperation);
        }
        self.load_inbox_envelope(envelope_id)
    }

    fn load_message_at(
        &self,
        conversation_id: ConversationId,
        cursor: u64,
    ) -> Result<StoredApplicationMessage, ProfileStoreError> {
        let metadata: Option<InboxMessageMetadata> = self
            .lock()?
            .query_row(
                "SELECT
                    CASE WHEN length(c.routing_id) = 32 THEN c.routing_id END,
                    CASE WHEN length(i.envelope_id) = 16 THEN i.envelope_id END,
                    CASE WHEN length(i.sender_device_id) = 32 THEN i.sender_device_id END,
                    i.sender_epoch,
                    i.sender_counter,
                    CASE WHEN length(i.message_id) = 16 THEN i.message_id END,
                    length(i.sealed_message)
                 FROM daemon_inbox i
                 JOIN daemon_conversation c
                   ON c.conversation_id = i.conversation_id
                 WHERE i.conversation_id = ?1 AND i.cursor = ?2 AND i.status >= 2",
                params![
                    conversation_id.as_bytes().as_slice(),
                    to_sql_integer(cursor)?
                ],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| ProfileStoreError::Storage)?;
        let (routing_id, envelope_id, sender, sender_epoch, sender_counter, message_id, length) =
            metadata.ok_or(ProfileStoreError::InvalidTransition)?;
        validate_blob_length(length)?;
        let bytes: Vec<u8> = self
            .lock()?
            .query_row(
                "SELECT sealed_message FROM daemon_inbox
                 WHERE conversation_id = ?1 AND cursor = ?2",
                params![
                    conversation_id.as_bytes().as_slice(),
                    to_sql_integer(cursor)?
                ],
                |row| row.get(0),
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        if bytes.len() != usize::try_from(length).unwrap_or_default() {
            return Err(ProfileStoreError::CorruptData);
        }
        let routing_id =
            RoutingId::from_slice(&routing_id).map_err(|_| ProfileStoreError::CorruptData)?;
        let sender = DeviceId::from_slice(&sender).map_err(|_| ProfileStoreError::CorruptData)?;
        let envelope_id =
            EnvelopeId::from_slice(&envelope_id).map_err(|_| ProfileStoreError::CorruptData)?;
        let message_id =
            MessageId::from_slice(&message_id).map_err(|_| ProfileStoreError::CorruptData)?;
        let plaintext = self.open_operation_record(
            SecretRecordKind::LocalApplicationMessage,
            conversation_id,
            routing_id,
            INBOX_MESSAGE_RECORD_SCOPE,
            message_id.as_bytes(),
            bytes,
        )?;
        let stored = decode_inbox_message_record(&plaintext)?;
        if stored.cursor != cursor
            || stored.envelope_id != envelope_id
            || stored.sender != sender
            || stored.epoch != from_sql_integer(sender_epoch)?
            || stored.message.message_id() != message_id
            || stored.message.sender_counter() != from_sql_integer(sender_counter)?
        {
            return Err(ProfileStoreError::CorruptData);
        }
        Ok(stored)
    }

    fn conversation_routing_id(
        &self,
        conversation_id: ConversationId,
    ) -> Result<RoutingId, ProfileStoreError> {
        let routing_id: Option<Vec<u8>> = self
            .lock()?
            .query_row(
                "SELECT CASE WHEN length(routing_id) = 32 THEN routing_id END
                 FROM daemon_conversation WHERE conversation_id = ?1",
                params![conversation_id.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| ProfileStoreError::Storage)?;
        RoutingId::from_slice(&routing_id.ok_or(ProfileStoreError::ConversationNotFound)?)
            .map_err(|_| ProfileStoreError::CorruptData)
    }

    fn load_bindings(
        &self,
        conversation_id: ConversationId,
    ) -> Result<Vec<VerifiedDeviceCredentialBinding>, ProfileStoreError> {
        let count: i64 = self
            .lock()?
            .query_row(
                "SELECT count(*) FROM daemon_conversation_binding
                 WHERE conversation_id = ?1",
                params![conversation_id.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        if count < 1
            || usize::try_from(count)
                .ok()
                .is_none_or(|count| count > MAX_LOCAL_BINDINGS)
        {
            return Err(ProfileStoreError::CorruptData);
        }
        let metadata = {
            let connection = self.lock()?;
            let mut statement = connection
                .prepare(
                    "SELECT
                        CASE WHEN length(device_id) = 32 THEN device_id END,
                        length(sealed_binding)
                     FROM daemon_conversation_binding
                     WHERE conversation_id = ?1
                     ORDER BY device_id",
                )
                .map_err(|_| ProfileStoreError::Storage)?;
            statement
                .query_map(params![conversation_id.as_bytes().as_slice()], |row| {
                    Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?))
                })
                .map_err(|_| ProfileStoreError::Storage)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| ProfileStoreError::Storage)?
        };
        let mut bindings = Vec::with_capacity(metadata.len());
        for (device_id, length) in metadata {
            validate_blob_length(length)?;
            let bytes: Vec<u8> = self
                .lock()?
                .query_row(
                    "SELECT sealed_binding
                     FROM daemon_conversation_binding
                     WHERE conversation_id = ?1 AND device_id = ?2",
                    params![conversation_id.as_bytes().as_slice(), &device_id],
                    |row| row.get(0),
                )
                .map_err(|_| ProfileStoreError::Storage)?;
            if bytes.len() != usize::try_from(length).unwrap_or_default() {
                return Err(ProfileStoreError::CorruptData);
            }
            let device_id =
                DeviceId::from_slice(&device_id).map_err(|_| ProfileStoreError::CorruptData)?;
            let blob = SealedBlob::from_bytes(bytes).map_err(|_| ProfileStoreError::CorruptData)?;
            let plaintext = self
                .sealer
                .open(
                    &conversation_record_context(
                        &self.locked_profile.profile_id,
                        SecretRecordKind::ConversationCredentialBinding,
                        conversation_id,
                        None,
                        Some(device_id),
                    )?,
                    &blob,
                )
                .map_err(|_| ProfileStoreError::CorruptData)?;
            let binding = decode_device_credential_binding(&plaintext)
                .map_err(|_| ProfileStoreError::Protocol)?;
            if binding.conversation_id() != conversation_id || binding.device_id() != device_id {
                return Err(ProfileStoreError::ConversationMismatch);
            }
            bindings.push(
                verify_device_credential_binding(&binding)
                    .map_err(|_| ProfileStoreError::Cryptographic)?,
            );
        }
        Ok(bindings)
    }

    fn seal_conversation_record(
        &self,
        kind: SecretRecordKind,
        conversation_id: ConversationId,
        routing_id: Option<RoutingId>,
        device_id: Option<DeviceId>,
        plaintext: &[u8],
    ) -> Result<SealedBlob, ProfileStoreError> {
        let context = conversation_record_context(
            &self.locked_profile.profile_id,
            kind,
            conversation_id,
            routing_id,
            device_id,
        )?;
        self.sealer
            .seal(&context, plaintext)
            .map_err(|_| ProfileStoreError::Storage)
    }

    fn read_profile_blob(
        &self,
        length_query: &str,
        value_query: &str,
    ) -> Result<Option<SealedBlob>, ProfileStoreError> {
        let length: Option<i64> = self
            .lock()?
            .query_row(length_query, [], |row| row.get(0))
            .map_err(|_| ProfileStoreError::Storage)?;
        let Some(length) = length else {
            return Ok(None);
        };
        validate_blob_length(length)?;
        let bytes: Vec<u8> = self
            .lock()?
            .query_row(value_query, [], |row| row.get(0))
            .map_err(|_| ProfileStoreError::Storage)?;
        if bytes.len() != usize::try_from(length).unwrap_or_default() {
            return Err(ProfileStoreError::CorruptData);
        }
        SealedBlob::from_bytes(bytes)
            .map(Some)
            .map_err(|_| ProfileStoreError::CorruptData)
    }

    fn lock(&self) -> Result<MutexGuard<'_, Connection>, ProfileStoreError> {
        self.connection
            .lock()
            .map_err(|_| ProfileStoreError::Storage)
    }
}

/// Reopened conversation inputs for the cryptographic client and relay transport.
pub(crate) struct StoredConversation {
    pub routing_id: RoutingId,
    pub signing_material: ConversationSigningMaterial,
    pub state: ConversationState,
    pub bindings: Vec<VerifiedDeviceCredentialBinding>,
    pub sender_counter: u64,
    pub replay_cursor: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct OutboundReservation {
    pub conversation_id: ConversationId,
    pub message_id: MessageId,
    pub envelope_id: EnvelopeId,
    pub sender_counter: u64,
}

pub(crate) struct PendingOutbox {
    pub conversation_id: ConversationId,
    pub envelope: RelayEnvelope,
}

pub(crate) struct StoredOutboundApplication {
    pub conversation_id: ConversationId,
    pub message: ApplicationMessage,
    pub envelope: RelayEnvelope,
    pub cursor: Option<u64>,
}

struct OutboxRecord {
    reservation: OutboundReservation,
    envelope: RelayEnvelope,
}

struct HistoryRecord {
    cursor: Option<u64>,
    direction: MessageDirection,
    envelope_id: EnvelopeId,
    sender: DeviceId,
    epoch: u64,
    message: ApplicationMessage,
    complete: bool,
}

pub(crate) struct StoredApplicationMessage {
    pub cursor: u64,
    pub envelope_id: EnvelopeId,
    pub sender: DeviceId,
    pub epoch: u64,
    pub message: ApplicationMessage,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MessageDirection {
    Outbound = 1,
    Inbound = 2,
}

pub(crate) struct StoredHistoryMessage {
    pub(crate) cursor: u64,
    pub(crate) direction: MessageDirection,
    pub(crate) envelope_id: EnvelopeId,
    pub(crate) sender: DeviceId,
    pub(crate) epoch: u64,
    pub(crate) message: ApplicationMessage,
}

pub(crate) struct HistoryPage {
    pub(crate) messages: Vec<StoredHistoryMessage>,
    pub(crate) has_more: bool,
}

pub(crate) enum PendingInbox {
    Received {
        conversation_id: ConversationId,
        stored: StoredRelayEnvelope,
    },
    MessageSaved {
        conversation_id: ConversationId,
        stored: StoredRelayEnvelope,
        message: StoredApplicationMessage,
    },
}

pub(crate) enum InboxOperation {
    Received {
        stored: StoredRelayEnvelope,
    },
    MessageSaved {
        stored: StoredRelayEnvelope,
        message: StoredApplicationMessage,
    },
    Complete {
        stored: StoredRelayEnvelope,
        message: StoredApplicationMessage,
    },
}

/// Stable profile locking, sealing, schema, and validation failures.
#[non_exhaustive]
#[derive(Debug, Error, PartialEq, Eq)]
pub(crate) enum ProfileStoreError {
    #[error("profile identifier is invalid")]
    InvalidProfileId,
    #[error("profile is already locked by another daemon")]
    ProfileLocked,
    #[error("profile filesystem operation failed")]
    Io,
    #[error("profile storage operation failed")]
    Storage,
    #[error("profile database schema is unsupported")]
    UnsupportedSchema,
    #[error("profile database belongs to another profile")]
    ProfileMismatch,
    #[error("profile data is malformed or unauthenticated")]
    CorruptData,
    #[error("profile relay is not configured")]
    RelayNotConfigured,
    #[error("profile relay credential is unavailable")]
    Credential,
    #[error("conversation already exists")]
    ConversationExists,
    #[error("conversation does not exist")]
    ConversationNotFound,
    #[error("conversation data does not agree")]
    ConversationMismatch,
    #[error("conversation protocol encoding failed")]
    Protocol,
    #[error("conversation cryptographic operation failed")]
    Cryptographic,
    #[error("local operation identifier or counter already exists")]
    DuplicateOperation,
    #[error("legacy outbound operation has no recoverable sealed plaintext")]
    LegacyOutboundRecoveryUnsupported,
    #[error("local operation state transition is invalid")]
    InvalidTransition,
    #[error("local cursor sequence contains a gap")]
    CursorGap,
    #[error("relay cursor maps to a conflicting envelope")]
    CursorConflict,
    #[error("authenticated sender counter regressed")]
    SenderCounterRegression,
    #[error("authenticated sender counter contains a gap")]
    SenderCounterGap,
    #[error("local sequence exhausted its supported range")]
    SequenceExhausted,
    #[error("local outbox reached its pending-operation limit")]
    OutboxCapacityExceeded,
    #[error("local inbox reached its incomplete-operation limit")]
    InboxCapacityExceeded,
}

fn initialize_schema(connection: &Connection) -> Result<(), ProfileStoreError> {
    connection
        .pragma_update(None, "foreign_keys", "ON")
        .map_err(|_| ProfileStoreError::Storage)?;
    connection
        .pragma_update(None, "journal_mode", "WAL")
        .map_err(|_| ProfileStoreError::Storage)?;
    connection
        .pragma_update(None, "synchronous", "FULL")
        .map_err(|_| ProfileStoreError::Storage)?;
    let version: u32 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|_| ProfileStoreError::Storage)?;
    match version {
        PROFILE_SCHEMA_VERSION => return Ok(()),
        2 => return initialize_message_history_schema(connection),
        0 => connection
            .execute_batch(
                "BEGIN;
             CREATE TABLE daemon_profile (
                singleton_id INTEGER PRIMARY KEY CHECK (singleton_id = 1),
                profile_id TEXT NOT NULL UNIQUE,
                sealed_device_identity BLOB,
                relay_endpoint TEXT,
                sealed_relay_credential BLOB,
                CHECK (
                    (relay_endpoint IS NULL AND sealed_relay_credential IS NULL)
                    OR
                    (relay_endpoint IS NOT NULL AND sealed_relay_credential IS NOT NULL)
                )
             );
             CREATE TABLE daemon_conversation (
                conversation_id BLOB PRIMARY KEY CHECK (length(conversation_id) = 32),
                routing_id BLOB NOT NULL UNIQUE CHECK (length(routing_id) = 32),
                sealed_signing_material BLOB NOT NULL,
                sealed_policy_state BLOB NOT NULL,
                sender_counter INTEGER NOT NULL CHECK (sender_counter >= 0),
                replay_cursor INTEGER NOT NULL CHECK (replay_cursor >= 0)
             ) WITHOUT ROWID;
             CREATE TABLE daemon_conversation_binding (
                conversation_id BLOB NOT NULL,
                device_id BLOB NOT NULL CHECK (length(device_id) = 32),
                sealed_binding BLOB NOT NULL,
                PRIMARY KEY (conversation_id, device_id),
                FOREIGN KEY (conversation_id)
                    REFERENCES daemon_conversation(conversation_id)
                    ON DELETE CASCADE
             ) WITHOUT ROWID;
             PRAGMA user_version = 1;
             COMMIT;",
            )
            .map_err(|_| ProfileStoreError::Storage)?,
        1 => {}
        _ => return Err(ProfileStoreError::UnsupportedSchema),
    }
    connection
        .execute_batch(
            "BEGIN;
             CREATE TABLE daemon_outbox (
                envelope_id BLOB PRIMARY KEY CHECK (length(envelope_id) = 16),
                conversation_id BLOB NOT NULL,
                message_id BLOB NOT NULL CHECK (length(message_id) = 16),
                sender_counter INTEGER NOT NULL CHECK (sender_counter >= 1),
                status INTEGER NOT NULL CHECK (status BETWEEN 1 AND 4),
                sealed_envelope BLOB,
                accepted_cursor INTEGER,
                FOREIGN KEY (conversation_id)
                    REFERENCES daemon_conversation(conversation_id)
                    ON DELETE CASCADE,
                UNIQUE (conversation_id, message_id),
                UNIQUE (conversation_id, sender_counter),
                CHECK (
                    (status = 1 AND sealed_envelope IS NULL AND accepted_cursor IS NULL)
                    OR
                    (status = 2 AND sealed_envelope IS NOT NULL AND accepted_cursor IS NULL)
                    OR
                    (status = 3 AND sealed_envelope IS NOT NULL
                        AND accepted_cursor IS NOT NULL AND accepted_cursor >= 1)
                    OR
                    (status = 4 AND sealed_envelope IS NULL AND accepted_cursor IS NULL)
                )
             ) WITHOUT ROWID;
             CREATE INDEX daemon_outbox_status_idx
                ON daemon_outbox(status, conversation_id, sender_counter);
             CREATE TABLE daemon_cursor_observation (
                conversation_id BLOB NOT NULL,
                cursor INTEGER NOT NULL CHECK (cursor >= 1),
                envelope_id BLOB NOT NULL UNIQUE CHECK (length(envelope_id) = 16),
                sealed_observation BLOB NOT NULL,
                PRIMARY KEY (conversation_id, cursor),
                FOREIGN KEY (conversation_id)
                    REFERENCES daemon_conversation(conversation_id)
                    ON DELETE CASCADE
             ) WITHOUT ROWID;
             CREATE TABLE daemon_inbox (
                conversation_id BLOB NOT NULL,
                cursor INTEGER NOT NULL CHECK (cursor >= 1),
                envelope_id BLOB NOT NULL UNIQUE CHECK (length(envelope_id) = 16),
                status INTEGER NOT NULL CHECK (status BETWEEN 1 AND 3),
                sealed_envelope BLOB NOT NULL,
                sender_device_id BLOB,
                sender_epoch INTEGER,
                message_id BLOB,
                sender_counter INTEGER,
                sealed_message BLOB,
                PRIMARY KEY (conversation_id, cursor),
                FOREIGN KEY (conversation_id)
                    REFERENCES daemon_conversation(conversation_id)
                    ON DELETE CASCADE,
                UNIQUE (conversation_id, message_id),
                UNIQUE (
                    conversation_id,
                    sender_device_id,
                    sender_epoch,
                    sender_counter
                ),
                CHECK (
                    (status = 1
                        AND sender_device_id IS NULL
                        AND sender_epoch IS NULL
                        AND message_id IS NULL
                        AND sender_counter IS NULL
                        AND sealed_message IS NULL)
                    OR
                    (status BETWEEN 2 AND 3
                        AND sender_device_id IS NOT NULL
                        AND length(sender_device_id) = 32
                        AND sender_epoch IS NOT NULL
                        AND sender_epoch >= 0
                        AND message_id IS NOT NULL
                        AND length(message_id) = 16
                        AND sender_counter IS NOT NULL
                        AND sender_counter >= 1
                        AND sealed_message IS NOT NULL)
                )
             ) WITHOUT ROWID;
             CREATE INDEX daemon_inbox_pending_idx
                ON daemon_inbox(conversation_id, cursor)
                WHERE status < 3;
             CREATE TABLE daemon_sender_counter (
                conversation_id BLOB NOT NULL,
                sender_device_id BLOB NOT NULL CHECK (length(sender_device_id) = 32),
                sender_epoch INTEGER NOT NULL CHECK (sender_epoch >= 0),
                highest_counter INTEGER NOT NULL CHECK (highest_counter >= 1),
                sealed_state BLOB NOT NULL,
                PRIMARY KEY (conversation_id, sender_device_id, sender_epoch),
                FOREIGN KEY (conversation_id)
                    REFERENCES daemon_conversation(conversation_id)
                    ON DELETE CASCADE
             ) WITHOUT ROWID;
             PRAGMA user_version = 2;
             COMMIT;",
        )
        .map_err(|_| ProfileStoreError::Storage)?;
    initialize_message_history_schema(connection)
}

fn initialize_message_history_schema(connection: &Connection) -> Result<(), ProfileStoreError> {
    connection
        .execute_batch(
            "BEGIN;
             CREATE TABLE daemon_message_history (
                conversation_id BLOB NOT NULL,
                message_id BLOB NOT NULL CHECK (length(message_id) = 16),
                envelope_id BLOB NOT NULL UNIQUE CHECK (length(envelope_id) = 16),
                cursor INTEGER,
                direction INTEGER NOT NULL CHECK (direction BETWEEN 1 AND 2),
                status INTEGER NOT NULL CHECK (status BETWEEN 1 AND 2),
                sender_device_id BLOB NOT NULL CHECK (length(sender_device_id) = 32),
                sender_epoch INTEGER NOT NULL CHECK (sender_epoch >= 0),
                sender_counter INTEGER NOT NULL CHECK (sender_counter >= 1),
                sealed_message BLOB NOT NULL,
                PRIMARY KEY (conversation_id, message_id),
                FOREIGN KEY (conversation_id)
                    REFERENCES daemon_conversation(conversation_id)
                    ON DELETE CASCADE,
                UNIQUE (
                    conversation_id,
                    sender_device_id,
                    sender_epoch,
                    sender_counter
                ),
                CHECK (
                    (direction = 1 AND (cursor IS NULL OR cursor >= 1))
                    OR
                    (direction = 2 AND cursor IS NOT NULL AND cursor >= 1)
                ),
                CHECK (
                    (status = 1)
                    OR
                    (status = 2 AND cursor IS NOT NULL AND cursor >= 1)
                )
             ) WITHOUT ROWID;
             CREATE UNIQUE INDEX daemon_message_history_cursor_idx
                ON daemon_message_history(conversation_id, cursor)
                WHERE cursor IS NOT NULL;
             CREATE INDEX daemon_message_history_page_idx
                ON daemon_message_history(conversation_id, cursor)
                WHERE status = 2;
             PRAGMA user_version = 3;
             COMMIT;",
        )
        .map_err(|_| ProfileStoreError::Storage)
}

fn validate_bindings(
    state: &ConversationState,
    self_binding: &DeviceCredentialBinding,
    bindings: &[DeviceCredentialBinding],
) -> Result<(), ProfileStoreError> {
    if bindings.is_empty() || bindings.len() > MAX_LOCAL_BINDINGS {
        return Err(ProfileStoreError::ConversationMismatch);
    }
    let mut device_ids = BTreeSet::new();
    for binding in bindings {
        if binding.conversation_id() != state.conversation_id()
            || !device_ids.insert(binding.device_id())
            || verify_device_credential_binding(binding).is_err()
        {
            return Err(ProfileStoreError::ConversationMismatch);
        }
    }
    if bindings
        .iter()
        .find(|binding| binding.device_id() == self_binding.device_id())
        != Some(self_binding)
        || !device_ids.contains(&self_binding.device_id())
        || state
            .members()
            .iter()
            .any(|member| !device_ids.contains(&member.device_id()))
    {
        return Err(ProfileStoreError::ConversationMismatch);
    }
    Ok(())
}

fn encode_outbox_record(
    reservation: OutboundReservation,
    envelope: &RelayEnvelope,
) -> Result<Vec<u8>, ProfileStoreError> {
    let envelope = encode_relay_envelope(envelope).map_err(|_| ProfileStoreError::Protocol)?;
    let mut record = Vec::with_capacity(1 + MessageId::LENGTH + 8 + envelope.len());
    record.push(LOCAL_RECORD_VERSION);
    record.extend_from_slice(reservation.message_id.as_bytes());
    record.extend_from_slice(&reservation.sender_counter.to_be_bytes());
    record.extend_from_slice(&envelope);
    Ok(record)
}

fn decode_outbox_record(
    conversation_id: ConversationId,
    envelope_id: EnvelopeId,
    record: &[u8],
) -> Result<OutboxRecord, ProfileStoreError> {
    const HEADER_LENGTH: usize = 1 + MessageId::LENGTH + 8;
    if record.len() <= HEADER_LENGTH || record[0] != LOCAL_RECORD_VERSION {
        return Err(ProfileStoreError::CorruptData);
    }
    let message_id = MessageId::from_slice(&record[1..1 + MessageId::LENGTH])
        .map_err(|_| ProfileStoreError::CorruptData)?;
    let sender_counter = decode_positive_u64(&record[1 + MessageId::LENGTH..HEADER_LENGTH])?;
    let envelope =
        decode_relay_envelope(&record[HEADER_LENGTH..]).map_err(|_| ProfileStoreError::Protocol)?;
    if envelope.envelope_id() != envelope_id {
        return Err(ProfileStoreError::CorruptData);
    }
    Ok(OutboxRecord {
        reservation: OutboundReservation {
            conversation_id,
            message_id,
            envelope_id,
            sender_counter,
        },
        envelope,
    })
}

fn encode_cursor_observation(
    cursor: u64,
    envelope: &RelayEnvelope,
) -> Result<Vec<u8>, ProfileStoreError> {
    if cursor == 0 {
        return Err(ProfileStoreError::InvalidTransition);
    }
    let envelope = encode_relay_envelope(envelope).map_err(|_| ProfileStoreError::Protocol)?;
    let mut record = Vec::with_capacity(1 + 8 + envelope.len());
    record.push(LOCAL_RECORD_VERSION);
    record.extend_from_slice(&cursor.to_be_bytes());
    record.extend_from_slice(&envelope);
    Ok(record)
}

fn decode_cursor_observation(record: &[u8]) -> Result<StoredRelayEnvelope, ProfileStoreError> {
    const HEADER_LENGTH: usize = 1 + 8;
    if record.len() <= HEADER_LENGTH || record[0] != LOCAL_RECORD_VERSION {
        return Err(ProfileStoreError::CorruptData);
    }
    let cursor = decode_positive_u64(&record[1..9])?;
    let envelope =
        decode_relay_envelope(&record[HEADER_LENGTH..]).map_err(|_| ProfileStoreError::Protocol)?;
    StoredRelayEnvelope::new(envelope, cursor).map_err(|_| ProfileStoreError::CorruptData)
}

fn encode_sender_counter_state(
    sender: DeviceId,
    epoch: u64,
    highest_counter: u64,
) -> Result<Vec<u8>, ProfileStoreError> {
    if highest_counter == 0 {
        return Err(ProfileStoreError::CorruptData);
    }
    let mut record = Vec::with_capacity(1 + DeviceId::LENGTH + 8 + 8);
    record.push(LOCAL_RECORD_VERSION);
    record.extend_from_slice(sender.as_bytes());
    record.extend_from_slice(&epoch.to_be_bytes());
    record.extend_from_slice(&highest_counter.to_be_bytes());
    Ok(record)
}

fn decode_sender_counter_state(record: &[u8]) -> Result<(DeviceId, u64, u64), ProfileStoreError> {
    const EPOCH_START: usize = 1 + DeviceId::LENGTH;
    const COUNTER_START: usize = EPOCH_START + 8;
    const RECORD_LENGTH: usize = COUNTER_START + 8;
    if record.len() != RECORD_LENGTH || record[0] != LOCAL_RECORD_VERSION {
        return Err(ProfileStoreError::CorruptData);
    }
    let sender = DeviceId::from_slice(&record[1..EPOCH_START])
        .map_err(|_| ProfileStoreError::CorruptData)?;
    let epoch = u64::from_be_bytes(
        record[EPOCH_START..COUNTER_START]
            .try_into()
            .map_err(|_| ProfileStoreError::CorruptData)?,
    );
    let highest_counter = decode_positive_u64(&record[COUNTER_START..])?;
    Ok((sender, epoch, highest_counter))
}

fn encode_inbox_envelope_record(
    stored: &StoredRelayEnvelope,
) -> Result<Vec<u8>, ProfileStoreError> {
    let envelope =
        encode_relay_envelope(stored.envelope()).map_err(|_| ProfileStoreError::Protocol)?;
    let mut record = Vec::with_capacity(1 + 8 + envelope.len());
    record.push(LOCAL_RECORD_VERSION);
    record.extend_from_slice(&stored.cursor().to_be_bytes());
    record.extend_from_slice(&envelope);
    Ok(record)
}

fn decode_inbox_envelope_record(record: &[u8]) -> Result<StoredRelayEnvelope, ProfileStoreError> {
    const HEADER_LENGTH: usize = 1 + 8;
    if record.len() <= HEADER_LENGTH || record[0] != LOCAL_RECORD_VERSION {
        return Err(ProfileStoreError::CorruptData);
    }
    let cursor = decode_positive_u64(&record[1..HEADER_LENGTH])?;
    let envelope =
        decode_relay_envelope(&record[HEADER_LENGTH..]).map_err(|_| ProfileStoreError::Protocol)?;
    StoredRelayEnvelope::new(envelope, cursor).map_err(|_| ProfileStoreError::CorruptData)
}

fn encode_inbox_message_record(
    cursor: u64,
    envelope_id: EnvelopeId,
    sender: DeviceId,
    sender_epoch: u64,
    message: &ApplicationMessage,
) -> Result<Zeroizing<Vec<u8>>, ProfileStoreError> {
    if cursor == 0 {
        return Err(ProfileStoreError::InvalidTransition);
    }
    let message = Zeroizing::new(
        encode_application_message(message).map_err(|_| ProfileStoreError::Protocol)?,
    );
    let mut record = Zeroizing::new(Vec::with_capacity(
        1 + 8 + EnvelopeId::LENGTH + DeviceId::LENGTH + 8 + message.len(),
    ));
    record.push(LOCAL_RECORD_VERSION);
    record.extend_from_slice(&cursor.to_be_bytes());
    record.extend_from_slice(envelope_id.as_bytes());
    record.extend_from_slice(sender.as_bytes());
    record.extend_from_slice(&sender_epoch.to_be_bytes());
    record.extend_from_slice(&message);
    Ok(record)
}

fn decode_inbox_message_record(
    record: &[u8],
) -> Result<StoredApplicationMessage, ProfileStoreError> {
    const ENVELOPE_ID_START: usize = 1 + 8;
    const SENDER_START: usize = ENVELOPE_ID_START + EnvelopeId::LENGTH;
    const EPOCH_START: usize = SENDER_START + DeviceId::LENGTH;
    const HEADER_LENGTH: usize = EPOCH_START + 8;
    if record.len() <= HEADER_LENGTH || record[0] != LOCAL_RECORD_VERSION {
        return Err(ProfileStoreError::CorruptData);
    }
    let cursor = decode_positive_u64(&record[1..9])?;
    let envelope_id = EnvelopeId::from_slice(&record[ENVELOPE_ID_START..SENDER_START])
        .map_err(|_| ProfileStoreError::CorruptData)?;
    let sender = DeviceId::from_slice(&record[SENDER_START..EPOCH_START])
        .map_err(|_| ProfileStoreError::CorruptData)?;
    let epoch = u64::from_be_bytes(
        record[EPOCH_START..HEADER_LENGTH]
            .try_into()
            .map_err(|_| ProfileStoreError::CorruptData)?,
    );
    let message = decode_application_message(&record[HEADER_LENGTH..])
        .map_err(|_| ProfileStoreError::Protocol)?;
    Ok(StoredApplicationMessage {
        cursor,
        envelope_id,
        sender,
        epoch,
        message,
    })
}

fn encode_history_message_record(
    direction: MessageDirection,
    envelope_id: EnvelopeId,
    sender: DeviceId,
    epoch: u64,
    message: &ApplicationMessage,
) -> Result<Zeroizing<Vec<u8>>, ProfileStoreError> {
    let message = Zeroizing::new(
        encode_application_message(message).map_err(|_| ProfileStoreError::Protocol)?,
    );
    let mut record = Zeroizing::new(Vec::with_capacity(
        2 + EnvelopeId::LENGTH + DeviceId::LENGTH + 8 + message.len(),
    ));
    record.push(LOCAL_RECORD_VERSION);
    record.push(direction as u8);
    record.extend_from_slice(envelope_id.as_bytes());
    record.extend_from_slice(sender.as_bytes());
    record.extend_from_slice(&epoch.to_be_bytes());
    record.extend_from_slice(&message);
    Ok(record)
}

fn decode_history_message_record(
    record: &[u8],
) -> Result<
    (
        MessageDirection,
        EnvelopeId,
        DeviceId,
        u64,
        ApplicationMessage,
    ),
    ProfileStoreError,
> {
    const ENVELOPE_START: usize = 2;
    const SENDER_START: usize = ENVELOPE_START + EnvelopeId::LENGTH;
    const EPOCH_START: usize = SENDER_START + DeviceId::LENGTH;
    const HEADER_LENGTH: usize = EPOCH_START + 8;
    if record.len() <= HEADER_LENGTH || record[0] != LOCAL_RECORD_VERSION {
        return Err(ProfileStoreError::CorruptData);
    }
    let direction = match record[1] {
        1 => MessageDirection::Outbound,
        2 => MessageDirection::Inbound,
        _ => return Err(ProfileStoreError::CorruptData),
    };
    let envelope_id = EnvelopeId::from_slice(&record[ENVELOPE_START..SENDER_START])
        .map_err(|_| ProfileStoreError::CorruptData)?;
    let sender = DeviceId::from_slice(&record[SENDER_START..EPOCH_START])
        .map_err(|_| ProfileStoreError::CorruptData)?;
    let epoch = u64::from_be_bytes(
        record[EPOCH_START..HEADER_LENGTH]
            .try_into()
            .map_err(|_| ProfileStoreError::CorruptData)?,
    );
    let message = decode_application_message(&record[HEADER_LENGTH..])
        .map_err(|_| ProfileStoreError::Protocol)?;
    Ok((direction, envelope_id, sender, epoch, message))
}

fn decode_positive_u64(bytes: &[u8]) -> Result<u64, ProfileStoreError> {
    let bytes: [u8; 8] = bytes
        .try_into()
        .map_err(|_| ProfileStoreError::CorruptData)?;
    let value = u64::from_be_bytes(bytes);
    if value == 0 {
        Err(ProfileStoreError::CorruptData)
    } else {
        Ok(value)
    }
}

fn application_messages_equal(
    left: &ApplicationMessage,
    right: &ApplicationMessage,
) -> Result<bool, ProfileStoreError> {
    let left =
        Zeroizing::new(encode_application_message(left).map_err(|_| ProfileStoreError::Protocol)?);
    let right =
        Zeroizing::new(encode_application_message(right).map_err(|_| ProfileStoreError::Protocol)?);
    Ok(left == right)
}

fn stored_history_message(history: HistoryRecord) -> Option<StoredHistoryMessage> {
    if !history.complete {
        return None;
    }
    Some(StoredHistoryMessage {
        cursor: history.cursor?,
        direction: history.direction,
        envelope_id: history.envelope_id,
        sender: history.sender,
        epoch: history.epoch,
        message: history.message,
    })
}

fn conversation_record_context(
    profile_id: &ProfileId,
    kind: SecretRecordKind,
    conversation_id: ConversationId,
    routing_id: Option<RoutingId>,
    device_id: Option<DeviceId>,
) -> Result<SecretRecordContext, ProfileStoreError> {
    let mut identifier = Vec::with_capacity(
        1 + profile_id.as_bytes().len()
            + ConversationId::LENGTH
            + routing_id.map_or(0, |_| RoutingId::LENGTH)
            + device_id.map_or(0, |_| DeviceId::LENGTH),
    );
    identifier.push(
        u8::try_from(profile_id.as_bytes().len())
            .map_err(|_| ProfileStoreError::InvalidProfileId)?,
    );
    identifier.extend_from_slice(profile_id.as_bytes());
    identifier.extend_from_slice(conversation_id.as_bytes());
    if let Some(routing_id) = routing_id {
        identifier.extend_from_slice(routing_id.as_bytes());
    }
    if let Some(device_id) = device_id {
        identifier.extend_from_slice(device_id.as_bytes());
    }
    SecretRecordContext::new(kind, identifier).map_err(|_| ProfileStoreError::Storage)
}

fn operation_record_context(
    profile_id: &ProfileId,
    kind: SecretRecordKind,
    conversation_id: ConversationId,
    routing_id: RoutingId,
    scope: u8,
    record_id: &[u8],
) -> Result<SecretRecordContext, ProfileStoreError> {
    if scope == 0 || record_id.len() != EnvelopeId::LENGTH {
        return Err(ProfileStoreError::CorruptData);
    }
    let mut identifier = Vec::with_capacity(
        2 + profile_id.as_bytes().len()
            + ConversationId::LENGTH
            + RoutingId::LENGTH
            + record_id.len(),
    );
    identifier.push(
        u8::try_from(profile_id.as_bytes().len())
            .map_err(|_| ProfileStoreError::InvalidProfileId)?,
    );
    identifier.extend_from_slice(profile_id.as_bytes());
    identifier.extend_from_slice(conversation_id.as_bytes());
    identifier.extend_from_slice(routing_id.as_bytes());
    identifier.push(scope);
    identifier.extend_from_slice(record_id);
    SecretRecordContext::new(kind, identifier).map_err(|_| ProfileStoreError::Storage)
}

fn sender_counter_record_context(
    profile_id: &ProfileId,
    conversation_id: ConversationId,
    sender: DeviceId,
    epoch: u64,
) -> Result<SecretRecordContext, ProfileStoreError> {
    let mut identifier = Vec::with_capacity(
        2 + profile_id.as_bytes().len() + ConversationId::LENGTH + DeviceId::LENGTH + 8,
    );
    identifier.push(
        u8::try_from(profile_id.as_bytes().len())
            .map_err(|_| ProfileStoreError::InvalidProfileId)?,
    );
    identifier.extend_from_slice(profile_id.as_bytes());
    identifier.extend_from_slice(conversation_id.as_bytes());
    identifier.push(SENDER_COUNTER_RECORD_SCOPE);
    identifier.extend_from_slice(sender.as_bytes());
    identifier.extend_from_slice(&epoch.to_be_bytes());
    SecretRecordContext::new(SecretRecordKind::LocalOperation, identifier)
        .map_err(|_| ProfileStoreError::Storage)
}

fn validate_blob_length(length: i64) -> Result<(), ProfileStoreError> {
    if length <= 0
        || usize::try_from(length)
            .ok()
            .is_none_or(|length| length > MAX_SEALED_RECORD_BYTES)
    {
        return Err(ProfileStoreError::CorruptData);
    }
    Ok(())
}

fn from_sql_integer(value: i64) -> Result<u64, ProfileStoreError> {
    u64::try_from(value).map_err(|_| ProfileStoreError::CorruptData)
}

fn to_sql_integer(value: u64) -> Result<i64, ProfileStoreError> {
    i64::try_from(value).map_err(|_| ProfileStoreError::SequenceExhausted)
}

fn map_operation_insert_error(error: rusqlite::Error) -> ProfileStoreError {
    match error {
        rusqlite::Error::SqliteFailure(ref details, _)
            if details.code == rusqlite::ErrorCode::ConstraintViolation =>
        {
            ProfileStoreError::DuplicateOperation
        }
        _ => ProfileStoreError::Storage,
    }
}

fn map_history_update_error(error: rusqlite::Error) -> ProfileStoreError {
    match error {
        rusqlite::Error::SqliteFailure(ref details, _)
            if details.code == rusqlite::ErrorCode::ConstraintViolation =>
        {
            ProfileStoreError::CursorConflict
        }
        _ => ProfileStoreError::Storage,
    }
}

#[cfg(test)]
mod tests {
    use std::process::Command;

    use KonclaveDomainCore::{ApplicationContent, ConversationRole, Member, ProtocolVersion};
    use KonclaveSecretStorage::{ExternalWrappingKeyProvider, SecretSealer};

    use super::*;

    fn sealer() -> SecretSealer {
        SecretSealer::from_provider(ExternalWrappingKeyProvider::from_bytes([7; 32])).unwrap()
    }

    struct ConversationFixture {
        root: tempfile::TempDir,
        profile_id: ProfileId,
        store: ProfileStore,
        conversation_id: ConversationId,
        routing_id: RoutingId,
        device_id: DeviceId,
    }

    fn conversation_fixture(name: &str) -> ConversationFixture {
        let root = tempfile::tempdir().unwrap();
        let profile_id = ProfileId::parse(name).unwrap();
        let store = LockedProfile::acquire(root.path(), profile_id.clone())
            .unwrap()
            .open_store(sealer())
            .unwrap();
        let identity = store.load_or_create_device().unwrap();
        let conversation_id = identity.generate_conversation_id().unwrap();
        let material = identity
            .create_conversation_signing_material(conversation_id)
            .unwrap();
        let state = ConversationState::new(
            ProtocolVersion::application_v1(),
            conversation_id,
            0,
            vec![Member::new(
                identity.device_id(),
                ConversationRole::Administrator,
                0,
            )],
            vec![],
        )
        .unwrap();
        let routing_id = RoutingId::from_bytes([9; RoutingId::LENGTH]);
        store
            .insert_conversation(routing_id, &material, &state, &[material.binding().clone()])
            .unwrap();
        ConversationFixture {
            root,
            profile_id,
            store,
            conversation_id,
            routing_id,
            device_id: identity.device_id(),
        }
    }

    fn application_message(id: u8, sender_counter: u64, text: &str) -> ApplicationMessage {
        ApplicationMessage::new(
            ProtocolVersion::application_v1(),
            MessageId::from_bytes([id; MessageId::LENGTH]),
            sender_counter,
            1_700_000_000_000,
            None,
            ApplicationContent::text(text).unwrap(),
        )
        .unwrap()
    }

    fn relay_envelope(routing_id: RoutingId, id: u8, payload: &[u8]) -> RelayEnvelope {
        RelayEnvelope::new(
            ProtocolVersion::application_v1(),
            routing_id,
            EnvelopeId::from_bytes([id; EnvelopeId::LENGTH]),
            DeliveryClass::GroupApplication,
            None,
            1_900_000_000,
            payload.to_vec(),
        )
        .unwrap()
    }

    fn stage_inbox_message(
        fixture: &ConversationFixture,
        cursor: u64,
        identifier: u8,
        sender_epoch: u64,
        sender_counter: u64,
    ) {
        let envelope = StoredRelayEnvelope::new(
            relay_envelope(fixture.routing_id, identifier, &[identifier]),
            cursor,
        )
        .unwrap();
        fixture.store.record_inbox_envelope(&envelope).unwrap();
        fixture
            .store
            .save_inbox_message(
                fixture.conversation_id,
                cursor,
                fixture.device_id,
                sender_epoch,
                &application_message(
                    identifier.wrapping_add(100),
                    sender_counter,
                    &format!("message-{identifier}"),
                ),
            )
            .unwrap();
    }

    fn create_v1_profile_database(path: &Path) {
        let connection = Connection::open(path).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE daemon_profile (
                    singleton_id INTEGER PRIMARY KEY CHECK (singleton_id = 1),
                    profile_id TEXT NOT NULL UNIQUE,
                    sealed_device_identity BLOB,
                    relay_endpoint TEXT,
                    sealed_relay_credential BLOB,
                    CHECK (
                        (relay_endpoint IS NULL AND sealed_relay_credential IS NULL)
                        OR
                        (relay_endpoint IS NOT NULL AND sealed_relay_credential IS NOT NULL)
                    )
                 );
                 CREATE TABLE daemon_conversation (
                    conversation_id BLOB PRIMARY KEY CHECK (length(conversation_id) = 32),
                    routing_id BLOB NOT NULL UNIQUE CHECK (length(routing_id) = 32),
                    sealed_signing_material BLOB NOT NULL,
                    sealed_policy_state BLOB NOT NULL,
                    sender_counter INTEGER NOT NULL CHECK (sender_counter >= 0),
                    replay_cursor INTEGER NOT NULL CHECK (replay_cursor >= 0)
                 ) WITHOUT ROWID;
                 CREATE TABLE daemon_conversation_binding (
                    conversation_id BLOB NOT NULL,
                    device_id BLOB NOT NULL CHECK (length(device_id) = 32),
                    sealed_binding BLOB NOT NULL,
                    PRIMARY KEY (conversation_id, device_id),
                    FOREIGN KEY (conversation_id)
                        REFERENCES daemon_conversation(conversation_id)
                        ON DELETE CASCADE
                 ) WITHOUT ROWID;
                 PRAGMA user_version = 1;",
            )
            .unwrap();
    }

    #[test]
    fn outbox_reservations_and_transitions_are_durable_and_idempotent() {
        let fixture = conversation_fixture("outbox-test");
        let message_id = MessageId::from_bytes([1; MessageId::LENGTH]);
        let envelope_id = EnvelopeId::from_bytes([2; EnvelopeId::LENGTH]);
        let reservation = fixture
            .store
            .reserve_outbound_application(fixture.conversation_id, message_id, envelope_id)
            .unwrap();
        assert_eq!(reservation.sender_counter, 1);
        assert_eq!(
            fixture
                .store
                .reserve_outbound_application(fixture.conversation_id, message_id, envelope_id)
                .unwrap(),
            reservation
        );
        assert!(fixture.store.ready_outbox().unwrap().is_empty());

        let envelope = relay_envelope(fixture.routing_id, 2, b"opaque-outbox-ciphertext");
        fixture
            .store
            .store_outbound_message(
                reservation,
                fixture.routing_id,
                fixture.device_id,
                0,
                &application_message(1, 1, "outbox message"),
            )
            .unwrap();
        fixture
            .store
            .store_outbound_envelope(reservation, &envelope)
            .unwrap();
        fixture
            .store
            .store_outbound_envelope(reservation, &envelope)
            .unwrap();
        let ready = fixture.store.ready_outbox().unwrap();
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].conversation_id, fixture.conversation_id);
        assert!(ready[0].envelope == envelope);

        let ConversationFixture {
            root,
            profile_id,
            store,
            conversation_id,
            ..
        } = fixture;
        drop(store);
        let reopened = LockedProfile::acquire(root.path(), profile_id)
            .unwrap()
            .open_store(sealer())
            .unwrap();
        let ready = reopened.ready_outbox().unwrap();
        assert_eq!(ready.len(), 1);
        assert!(ready[0].envelope == envelope);
        let accepted = StoredRelayEnvelope::new(envelope.clone(), 7).unwrap();
        reopened.mark_outbox_accepted(&accepted).unwrap();
        reopened.mark_outbox_accepted(&accepted).unwrap();
        assert_eq!(
            reopened.mark_outbox_accepted(&StoredRelayEnvelope::new(envelope.clone(), 8).unwrap()),
            Err(ProfileStoreError::InvalidTransition)
        );
        assert!(reopened.ready_outbox().unwrap().is_empty());

        let second = reopened
            .reserve_outbound_application(
                conversation_id,
                MessageId::from_bytes([3; MessageId::LENGTH]),
                EnvelopeId::from_bytes([4; EnvelopeId::LENGTH]),
            )
            .unwrap();
        assert_eq!(second.sender_counter, 2);
        reopened.abandon_outbound_application(second).unwrap();
        reopened.abandon_outbound_application(second).unwrap();
        assert_eq!(
            reopened.reserve_outbound_application(
                conversation_id,
                second.message_id,
                second.envelope_id,
            ),
            Err(ProfileStoreError::InvalidTransition)
        );
        assert_eq!(
            reopened.reserve_outbound_application(
                conversation_id,
                MessageId::from_bytes([5; MessageId::LENGTH]),
                envelope_id,
            ),
            Err(ProfileStoreError::DuplicateOperation)
        );
        assert_eq!(
            reopened
                .load_conversation(conversation_id)
                .unwrap()
                .sender_counter,
            2
        );
    }

    #[test]
    fn cursor_observations_reject_relay_equivocation_in_both_directions() {
        let fixture = conversation_fixture("cursor-observation-test");
        let first_reservation = fixture
            .store
            .reserve_outbound_application(
                fixture.conversation_id,
                MessageId::from_bytes([1; MessageId::LENGTH]),
                EnvelopeId::from_bytes([1; EnvelopeId::LENGTH]),
            )
            .unwrap();
        let first = relay_envelope(fixture.routing_id, 1, b"first");
        fixture
            .store
            .store_outbound_message(
                first_reservation,
                fixture.routing_id,
                fixture.device_id,
                0,
                &application_message(1, 1, "first outbound"),
            )
            .unwrap();
        fixture
            .store
            .store_outbound_envelope(first_reservation, &first)
            .unwrap();
        let altered_response = RelayEnvelope::new(
            first.version(),
            first.routing_id(),
            first.envelope_id(),
            first.delivery_class(),
            first.expected_parent_epoch(),
            first.expires_at_unix_seconds(),
            b"altered-response".to_vec(),
        )
        .unwrap();
        assert_eq!(
            fixture
                .store
                .mark_outbox_accepted(&StoredRelayEnvelope::new(altered_response, 1).unwrap()),
            Err(ProfileStoreError::CursorConflict)
        );
        fixture
            .store
            .mark_outbox_accepted(&StoredRelayEnvelope::new(first.clone(), 1).unwrap())
            .unwrap();
        let sealed_observation: Vec<u8> = fixture
            .store
            .lock()
            .unwrap()
            .query_row(
                "SELECT sealed_observation FROM daemon_cursor_observation
                 WHERE conversation_id = ?1 AND cursor = 1",
                params![fixture.conversation_id.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        fixture
            .store
            .lock()
            .unwrap()
            .execute(
                "UPDATE daemon_outbox SET accepted_cursor = 2
                 WHERE envelope_id = ?1",
                params![first.envelope_id().as_bytes().as_slice()],
            )
            .unwrap();
        assert_eq!(
            fixture
                .store
                .mark_outbox_accepted(&StoredRelayEnvelope::new(first.clone(), 2).unwrap()),
            Err(ProfileStoreError::CursorConflict)
        );
        fixture
            .store
            .lock()
            .unwrap()
            .execute(
                "UPDATE daemon_outbox SET accepted_cursor = 1
                 WHERE envelope_id = ?1",
                params![first.envelope_id().as_bytes().as_slice()],
            )
            .unwrap();
        fixture
            .store
            .lock()
            .unwrap()
            .execute(
                "UPDATE daemon_cursor_observation
                 SET sealed_observation = (
                    SELECT sealed_envelope FROM daemon_outbox WHERE envelope_id = ?1
                 )
                 WHERE conversation_id = ?2 AND cursor = 1",
                params![
                    first.envelope_id().as_bytes().as_slice(),
                    fixture.conversation_id.as_bytes().as_slice()
                ],
            )
            .unwrap();
        assert_eq!(
            fixture
                .store
                .mark_outbox_accepted(&StoredRelayEnvelope::new(first.clone(), 1).unwrap()),
            Err(ProfileStoreError::CorruptData)
        );
        fixture
            .store
            .lock()
            .unwrap()
            .execute(
                "UPDATE daemon_cursor_observation SET sealed_observation = ?1
                 WHERE conversation_id = ?2 AND cursor = 1",
                params![
                    sealed_observation,
                    fixture.conversation_id.as_bytes().as_slice()
                ],
            )
            .unwrap();
        let altered_first = RelayEnvelope::new(
            first.version(),
            first.routing_id(),
            first.envelope_id(),
            first.delivery_class(),
            first.expected_parent_epoch(),
            first.expires_at_unix_seconds(),
            b"altered-first".to_vec(),
        )
        .unwrap();
        assert_eq!(
            fixture
                .store
                .record_inbox_envelope(&StoredRelayEnvelope::new(altered_first, 1).unwrap()),
            Err(ProfileStoreError::CursorConflict)
        );
        let conflicting_first = StoredRelayEnvelope::new(
            relay_envelope(fixture.routing_id, 2, b"conflicting-first"),
            1,
        )
        .unwrap();
        assert_eq!(
            fixture.store.record_inbox_envelope(&conflicting_first),
            Err(ProfileStoreError::CursorConflict)
        );
        fixture
            .store
            .record_inbox_envelope(&StoredRelayEnvelope::new(first.clone(), 1).unwrap())
            .unwrap();

        let second =
            StoredRelayEnvelope::new(relay_envelope(fixture.routing_id, 3, b"second"), 2).unwrap();
        fixture.store.record_inbox_envelope(&second).unwrap();
        let conflicting_reservation = fixture
            .store
            .reserve_outbound_application(
                fixture.conversation_id,
                MessageId::from_bytes([4; MessageId::LENGTH]),
                EnvelopeId::from_bytes([4; EnvelopeId::LENGTH]),
            )
            .unwrap();
        let conflicting_second = relay_envelope(fixture.routing_id, 4, b"conflicting-second");
        fixture
            .store
            .store_outbound_envelope(conflicting_reservation, &conflicting_second)
            .unwrap();
        assert_eq!(
            fixture.store.mark_outbox_accepted(
                &StoredRelayEnvelope::new(conflicting_second.clone(), 2).unwrap()
            ),
            Err(ProfileStoreError::CursorConflict)
        );
        assert_eq!(fixture.store.ready_outbox().unwrap().len(), 1);
    }

    #[test]
    fn inbox_transitions_enforce_deduplication_and_contiguous_completion() {
        let fixture = conversation_fixture("inbox-test");
        let envelope = relay_envelope(fixture.routing_id, 1, b"opaque-inbox-ciphertext");
        let stored = StoredRelayEnvelope::new(envelope.clone(), 1).unwrap();
        assert_eq!(
            fixture.store.record_inbox_envelope(&stored).unwrap(),
            fixture.conversation_id
        );
        assert_eq!(
            fixture.store.record_inbox_envelope(&stored).unwrap(),
            fixture.conversation_id
        );
        let conflict =
            StoredRelayEnvelope::new(relay_envelope(fixture.routing_id, 2, b"different"), 1)
                .unwrap();
        assert_eq!(
            fixture.store.record_inbox_envelope(&conflict),
            Err(ProfileStoreError::CursorConflict)
        );
        let moved_duplicate = StoredRelayEnvelope::new(envelope, 2).unwrap();
        assert_eq!(
            fixture.store.record_inbox_envelope(&moved_duplicate),
            Err(ProfileStoreError::CursorConflict)
        );

        let pending = fixture
            .store
            .incomplete_inbox(fixture.conversation_id)
            .unwrap();
        assert!(matches!(
            pending.as_slice(),
            [PendingInbox::Received {
                conversation_id,
                stored
            }] if *conversation_id == fixture.conversation_id && stored.cursor() == 1
        ));

        let message = application_message(3, 1, "sealed-inbox-plaintext");
        fixture
            .store
            .save_inbox_message(fixture.conversation_id, 1, fixture.device_id, 0, &message)
            .unwrap();
        fixture
            .store
            .save_inbox_message(fixture.conversation_id, 1, fixture.device_id, 0, &message)
            .unwrap();
        let pending = fixture
            .store
            .incomplete_inbox(fixture.conversation_id)
            .unwrap();
        assert!(matches!(
            pending.as_slice(),
            [PendingInbox::MessageSaved {
                conversation_id,
                stored,
                message
            }] if *conversation_id == fixture.conversation_id
                && stored.cursor() == 1
                && message.cursor == 1
                && message.sender == fixture.device_id
                && message.epoch == 0
                && message.message.message_id() == MessageId::from_bytes([3; MessageId::LENGTH])
        ));

        assert_eq!(
            fixture
                .store
                .complete_inbox(fixture.conversation_id, 1)
                .unwrap(),
            1
        );
        assert_eq!(
            fixture
                .store
                .complete_inbox(fixture.conversation_id, 1)
                .unwrap(),
            1
        );
        assert!(
            fixture
                .store
                .incomplete_inbox(fixture.conversation_id)
                .unwrap()
                .is_empty()
        );
        let messages = fixture
            .store
            .load_messages(fixture.conversation_id, 0, 10)
            .unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].cursor, 1);
        assert_eq!(messages[0].envelope_id, stored.envelope().envelope_id());
        assert_eq!(messages[0].sender, fixture.device_id);
        assert!(application_messages_equal(&messages[0].message, &message).unwrap());

        let gap_envelope =
            StoredRelayEnvelope::new(relay_envelope(fixture.routing_id, 4, b"gap"), 3).unwrap();
        fixture.store.record_inbox_envelope(&gap_envelope).unwrap();
        fixture
            .store
            .save_inbox_message(
                fixture.conversation_id,
                3,
                fixture.device_id,
                0,
                &application_message(4, 2, "gap"),
            )
            .unwrap();
        assert_eq!(
            fixture.store.complete_inbox(fixture.conversation_id, 3),
            Err(ProfileStoreError::CursorGap)
        );
    }

    #[test]
    fn inbox_window_preserves_capacity_for_missing_head_cursor() {
        let fixture = conversation_fixture("inbox-window");
        for cursor in 2_u64..=100 {
            stage_inbox_message(&fixture, cursor, u8::try_from(cursor).unwrap(), 0, cursor);
        }
        let cursor_101 =
            StoredRelayEnvelope::new(relay_envelope(fixture.routing_id, 101, b"cursor-101"), 101)
                .unwrap();
        assert_eq!(
            fixture.store.record_inbox_envelope(&cursor_101),
            Err(ProfileStoreError::InboxCapacityExceeded)
        );

        stage_inbox_message(&fixture, 1, 1, 0, 1);
        assert_eq!(
            fixture
                .store
                .complete_inbox(fixture.conversation_id, 1)
                .unwrap(),
            1
        );
        stage_inbox_message(&fixture, 101, 101, 0, 101);
        for cursor in 2_u64..=101 {
            assert_eq!(
                fixture
                    .store
                    .complete_inbox(fixture.conversation_id, cursor)
                    .unwrap(),
                cursor
            );
        }
        assert_eq!(
            fixture
                .store
                .load_conversation(fixture.conversation_id)
                .unwrap()
                .replay_cursor,
            101
        );
    }

    #[test]
    fn completed_inbox_rejects_sender_counter_regressions_per_epoch() {
        let fixture = conversation_fixture("sender-counter-regression-test");
        stage_inbox_message(&fixture, 1, 1, 4, 10);
        assert_eq!(
            fixture
                .store
                .complete_inbox(fixture.conversation_id, 1)
                .unwrap(),
            1
        );
        let sealed_high_water: Vec<u8> = fixture
            .store
            .lock()
            .unwrap()
            .query_row(
                "SELECT sealed_state FROM daemon_sender_counter
                 WHERE conversation_id = ?1
                   AND sender_device_id = ?2
                   AND sender_epoch = 4",
                params![
                    fixture.conversation_id.as_bytes().as_slice(),
                    fixture.device_id.as_bytes().as_slice()
                ],
                |row| row.get(0),
            )
            .unwrap();
        fixture
            .store
            .lock()
            .unwrap()
            .execute(
                "UPDATE daemon_sender_counter SET highest_counter = 9
                 WHERE conversation_id = ?1
                   AND sender_device_id = ?2
                   AND sender_epoch = 4",
                params![
                    fixture.conversation_id.as_bytes().as_slice(),
                    fixture.device_id.as_bytes().as_slice()
                ],
            )
            .unwrap();
        assert_eq!(
            fixture.store.complete_inbox(fixture.conversation_id, 1),
            Err(ProfileStoreError::CorruptData)
        );
        fixture
            .store
            .lock()
            .unwrap()
            .execute(
                "UPDATE daemon_sender_counter
                 SET highest_counter = 10,
                     sealed_state = (
                        SELECT sealed_observation
                        FROM daemon_cursor_observation
                        WHERE conversation_id = ?1 AND cursor = 1
                     )
                 WHERE conversation_id = ?1
                   AND sender_device_id = ?2
                   AND sender_epoch = 4",
                params![
                    fixture.conversation_id.as_bytes().as_slice(),
                    fixture.device_id.as_bytes().as_slice()
                ],
            )
            .unwrap();
        assert_eq!(
            fixture.store.complete_inbox(fixture.conversation_id, 1),
            Err(ProfileStoreError::CorruptData)
        );
        fixture
            .store
            .lock()
            .unwrap()
            .execute(
                "UPDATE daemon_sender_counter SET sealed_state = ?1
                 WHERE conversation_id = ?2
                   AND sender_device_id = ?3
                   AND sender_epoch = 4",
                params![
                    sealed_high_water,
                    fixture.conversation_id.as_bytes().as_slice(),
                    fixture.device_id.as_bytes().as_slice()
                ],
            )
            .unwrap();
        stage_inbox_message(&fixture, 2, 2, 5, 1);
        assert_eq!(
            fixture
                .store
                .complete_inbox(fixture.conversation_id, 2)
                .unwrap(),
            2
        );
        stage_inbox_message(&fixture, 3, 3, 4, 9);
        assert_eq!(
            fixture.store.complete_inbox(fixture.conversation_id, 3),
            Err(ProfileStoreError::SenderCounterRegression)
        );
        assert_eq!(
            fixture
                .store
                .load_conversation(fixture.conversation_id)
                .unwrap()
                .replay_cursor,
            2
        );
        assert_eq!(
            fixture
                .store
                .incomplete_inbox(fixture.conversation_id)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn completed_inbox_keeps_sender_counter_gaps_visible() {
        let fixture = conversation_fixture("sender-counter-gap-test");
        stage_inbox_message(&fixture, 1, 1, 7, 10);
        fixture
            .store
            .complete_inbox(fixture.conversation_id, 1)
            .unwrap();
        stage_inbox_message(&fixture, 2, 2, 7, 12);
        assert_eq!(
            fixture.store.complete_inbox(fixture.conversation_id, 2),
            Err(ProfileStoreError::SenderCounterGap)
        );
        assert_eq!(
            fixture
                .store
                .load_conversation(fixture.conversation_id)
                .unwrap()
                .replay_cursor,
            1
        );
    }

    #[test]
    fn application_journal_rejects_other_delivery_classes() {
        let fixture = conversation_fixture("journal-class-test");
        let envelope_id = EnvelopeId::from_bytes([2; EnvelopeId::LENGTH]);
        let reservation = fixture
            .store
            .reserve_outbound_application(
                fixture.conversation_id,
                MessageId::from_bytes([1; MessageId::LENGTH]),
                envelope_id,
            )
            .unwrap();
        let commit = RelayEnvelope::new(
            ProtocolVersion::application_v1(),
            fixture.routing_id,
            envelope_id,
            DeliveryClass::GroupCommit,
            Some(0),
            1_900_000_000,
            vec![1],
        )
        .unwrap();
        assert_eq!(
            fixture.store.store_outbound_envelope(reservation, &commit),
            Err(ProfileStoreError::InvalidTransition)
        );
        assert_eq!(
            fixture
                .store
                .record_inbox_envelope(&StoredRelayEnvelope::new(commit, 1).unwrap()),
            Err(ProfileStoreError::InvalidTransition)
        );
    }

    #[test]
    fn incomplete_inbox_reopens_received_and_message_saved_states() {
        let fixture = conversation_fixture("inbox-recovery-test");
        let first = StoredRelayEnvelope::new(relay_envelope(fixture.routing_id, 1, b"received"), 1)
            .unwrap();
        let second =
            StoredRelayEnvelope::new(relay_envelope(fixture.routing_id, 2, b"message-saved"), 2)
                .unwrap();
        fixture.store.record_inbox_envelope(&first).unwrap();
        fixture.store.record_inbox_envelope(&second).unwrap();
        fixture
            .store
            .save_inbox_message(
                fixture.conversation_id,
                2,
                fixture.device_id,
                0,
                &application_message(3, 1, "saved"),
            )
            .unwrap();

        let ConversationFixture {
            root,
            profile_id,
            store,
            conversation_id,
            device_id,
            ..
        } = fixture;
        drop(store);
        let reopened = LockedProfile::acquire(root.path(), profile_id)
            .unwrap()
            .open_store(sealer())
            .unwrap();
        let pending = reopened.incomplete_inbox(conversation_id).unwrap();
        assert!(matches!(
            pending.as_slice(),
            [
                PendingInbox::Received { stored: first, .. },
                PendingInbox::MessageSaved {
                    stored: second,
                    message,
                    ..
                }
            ] if first.cursor() == 1
                && second.cursor() == 2
                && message.cursor == 2
                && message.sender == device_id
                && message.epoch == 0
        ));
    }

    #[test]
    fn journal_reads_reject_unknown_conversations_and_invalid_page_bounds() {
        let fixture = conversation_fixture("journal-read-validation-test");
        let unknown = ConversationId::from_bytes([8; ConversationId::LENGTH]);
        assert_eq!(
            fixture.store.incomplete_inbox(unknown).err(),
            Some(ProfileStoreError::ConversationNotFound)
        );
        assert_eq!(
            fixture.store.load_messages(unknown, 0, 10).err(),
            Some(ProfileStoreError::ConversationNotFound)
        );
        assert_eq!(
            fixture
                .store
                .load_messages(fixture.conversation_id, 0, 0)
                .err(),
            Some(ProfileStoreError::InvalidTransition)
        );
        assert_eq!(
            fixture
                .store
                .load_messages(fixture.conversation_id, 0, MAX_MESSAGE_PAGE_SIZE + 1)
                .err(),
            Some(ProfileStoreError::InvalidTransition)
        );
    }

    #[test]
    fn journal_sealing_hides_payload_and_message_sentinels() {
        let fixture = conversation_fixture("sealed-journal-test");
        let reservation = fixture
            .store
            .reserve_outbound_application(
                fixture.conversation_id,
                MessageId::from_bytes([1; MessageId::LENGTH]),
                EnvelopeId::from_bytes([2; EnvelopeId::LENGTH]),
            )
            .unwrap();
        fixture
            .store
            .store_outbound_envelope(
                reservation,
                &relay_envelope(fixture.routing_id, 2, b"OUTBOX-CIPHERTEXT-SENTINEL"),
            )
            .unwrap();
        let stored = StoredRelayEnvelope::new(
            relay_envelope(fixture.routing_id, 3, b"INBOX-CIPHERTEXT-SENTINEL"),
            1,
        )
        .unwrap();
        fixture.store.record_inbox_envelope(&stored).unwrap();
        fixture
            .store
            .save_inbox_message(
                fixture.conversation_id,
                1,
                fixture.device_id,
                0,
                &application_message(4, 1, "PLAINTEXT-MESSAGE-SENTINEL"),
            )
            .unwrap();
        let sealed_records: Vec<Vec<u8>> = fixture
            .store
            .lock()
            .unwrap()
            .query_row(
                "SELECT
                    (SELECT sealed_envelope FROM daemon_outbox LIMIT 1),
                    (SELECT sealed_observation FROM daemon_cursor_observation LIMIT 1),
                    (SELECT sealed_message FROM daemon_message_history LIMIT 1),
                    sealed_envelope,
                    sealed_message
                 FROM daemon_inbox LIMIT 1",
                [],
                |row| {
                    Ok(vec![
                        row.get(0)?,
                        row.get(1)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(2)?,
                    ])
                },
            )
            .unwrap();
        for (sealed, sentinel) in sealed_records.iter().zip([
            b"OUTBOX-CIPHERTEXT-SENTINEL".as_slice(),
            b"INBOX-CIPHERTEXT-SENTINEL".as_slice(),
            b"INBOX-CIPHERTEXT-SENTINEL".as_slice(),
            b"PLAINTEXT-MESSAGE-SENTINEL".as_slice(),
            b"PLAINTEXT-MESSAGE-SENTINEL".as_slice(),
        ]) {
            assert!(
                !sealed
                    .windows(sentinel.len())
                    .any(|window| window == sentinel)
            );
        }
    }

    #[test]
    fn journal_metadata_and_record_scope_tampering_fails_closed() {
        let fixture = conversation_fixture("journal-tamper-test");
        let reservation = fixture
            .store
            .reserve_outbound_application(
                fixture.conversation_id,
                MessageId::from_bytes([1; MessageId::LENGTH]),
                EnvelopeId::from_bytes([2; EnvelopeId::LENGTH]),
            )
            .unwrap();
        fixture
            .store
            .store_outbound_envelope(
                reservation,
                &relay_envelope(fixture.routing_id, 2, b"outbound"),
            )
            .unwrap();
        fixture
            .store
            .lock()
            .unwrap()
            .execute(
                "UPDATE daemon_outbox SET message_id = ?1",
                params![
                    MessageId::from_bytes([8; MessageId::LENGTH])
                        .as_bytes()
                        .as_slice()
                ],
            )
            .unwrap();
        assert_eq!(
            fixture.store.ready_outbox().err(),
            Some(ProfileStoreError::CorruptData)
        );
        fixture
            .store
            .lock()
            .unwrap()
            .execute(
                "UPDATE daemon_outbox SET message_id = ?1, sender_counter = 2",
                params![reservation.message_id.as_bytes().as_slice()],
            )
            .unwrap();
        assert_eq!(
            fixture.store.ready_outbox().err(),
            Some(ProfileStoreError::CorruptData)
        );
        fixture
            .store
            .lock()
            .unwrap()
            .execute("UPDATE daemon_outbox SET sender_counter = 1", [])
            .unwrap();
        fixture
            .store
            .lock()
            .unwrap()
            .execute(
                "UPDATE daemon_conversation SET routing_id = ?1",
                params![
                    RoutingId::from_bytes([8; RoutingId::LENGTH])
                        .as_bytes()
                        .as_slice()
                ],
            )
            .unwrap();
        assert_eq!(
            fixture.store.ready_outbox().err(),
            Some(ProfileStoreError::CorruptData)
        );
        fixture
            .store
            .lock()
            .unwrap()
            .execute(
                "UPDATE daemon_conversation SET routing_id = ?1",
                params![fixture.routing_id.as_bytes().as_slice()],
            )
            .unwrap();

        let stored =
            StoredRelayEnvelope::new(relay_envelope(fixture.routing_id, 3, b"inbound"), 1).unwrap();
        fixture.store.record_inbox_envelope(&stored).unwrap();
        let message = application_message(4, 1, "message");
        fixture
            .store
            .save_inbox_message(fixture.conversation_id, 1, fixture.device_id, 0, &message)
            .unwrap();
        fixture
            .store
            .lock()
            .unwrap()
            .execute("UPDATE daemon_inbox SET cursor = 2", [])
            .unwrap();
        assert_eq!(
            fixture
                .store
                .load_inbox_envelope(stored.envelope().envelope_id())
                .err(),
            Some(ProfileStoreError::CorruptData)
        );
        fixture
            .store
            .lock()
            .unwrap()
            .execute(
                "UPDATE daemon_inbox
                 SET cursor = 1, sender_device_id = ?1",
                params![
                    DeviceId::from_bytes([8; DeviceId::LENGTH])
                        .as_bytes()
                        .as_slice()
                ],
            )
            .unwrap();
        assert_eq!(
            fixture
                .store
                .load_message_at(fixture.conversation_id, 1)
                .err(),
            Some(ProfileStoreError::CorruptData)
        );
        fixture
            .store
            .lock()
            .unwrap()
            .execute(
                "UPDATE daemon_inbox
                 SET sender_device_id = ?1, sender_counter = 2",
                params![fixture.device_id.as_bytes().as_slice()],
            )
            .unwrap();
        assert_eq!(
            fixture
                .store
                .load_message_at(fixture.conversation_id, 1)
                .err(),
            Some(ProfileStoreError::CorruptData)
        );
        fixture
            .store
            .lock()
            .unwrap()
            .execute(
                "UPDATE daemon_inbox
                 SET sender_counter = 1, sender_epoch = 1",
                [],
            )
            .unwrap();
        assert_eq!(
            fixture
                .store
                .load_message_at(fixture.conversation_id, 1)
                .err(),
            Some(ProfileStoreError::CorruptData)
        );
        fixture
            .store
            .lock()
            .unwrap()
            .execute(
                "UPDATE daemon_inbox
                 SET sender_epoch = 0, envelope_id = ?1",
                params![
                    EnvelopeId::from_bytes([7; EnvelopeId::LENGTH])
                        .as_bytes()
                        .as_slice()
                ],
            )
            .unwrap();
        assert_eq!(
            fixture
                .store
                .load_message_at(fixture.conversation_id, 1)
                .err(),
            Some(ProfileStoreError::CorruptData)
        );
        fixture
            .store
            .lock()
            .unwrap()
            .execute(
                "UPDATE daemon_inbox
                 SET envelope_id = ?1,
                     sealed_envelope = (SELECT sealed_envelope FROM daemon_outbox LIMIT 1)",
                params![stored.envelope().envelope_id().as_bytes().as_slice()],
            )
            .unwrap();
        assert_eq!(
            fixture
                .store
                .load_inbox_envelope(stored.envelope().envelope_id())
                .err(),
            Some(ProfileStoreError::CorruptData)
        );
    }

    #[test]
    fn history_hides_accepted_outbound_until_contiguous_echo_completion() {
        let fixture = conversation_fixture("history-contiguous-frontier");
        let message_id = MessageId::from_bytes([71; MessageId::LENGTH]);
        let envelope_id = EnvelopeId::from_bytes([72; EnvelopeId::LENGTH]);
        let reservation = fixture
            .store
            .reserve_outbound_application(fixture.conversation_id, message_id, envelope_id)
            .unwrap();
        let outbound_message = application_message(71, 1, "outbound-at-two");
        let outbound_envelope = relay_envelope(fixture.routing_id, 72, b"outbound-ciphertext");
        fixture
            .store
            .store_outbound_message(
                reservation,
                fixture.routing_id,
                fixture.device_id,
                0,
                &outbound_message,
            )
            .unwrap();
        fixture
            .store
            .store_outbound_envelope(reservation, &outbound_envelope)
            .unwrap();
        fixture
            .store
            .mark_outbox_accepted(&StoredRelayEnvelope::new(outbound_envelope.clone(), 2).unwrap())
            .unwrap();
        assert!(
            fixture
                .store
                .load_history(fixture.conversation_id, 0, 10)
                .unwrap()
                .messages
                .is_empty()
        );

        let inbound = StoredRelayEnvelope::new(
            relay_envelope(fixture.routing_id, 73, b"inbound-ciphertext"),
            1,
        )
        .unwrap();
        fixture.store.record_inbox_envelope(&inbound).unwrap();
        fixture
            .store
            .save_inbox_message(
                fixture.conversation_id,
                1,
                DeviceId::from_bytes([74; DeviceId::LENGTH]),
                0,
                &application_message(74, 1, "inbound-at-one"),
            )
            .unwrap();
        fixture
            .store
            .complete_inbox(fixture.conversation_id, 1)
            .unwrap();
        let first_page = fixture
            .store
            .load_history(fixture.conversation_id, 0, 10)
            .unwrap();
        assert_eq!(first_page.messages.len(), 1);
        assert_eq!(first_page.messages[0].cursor, 1);

        let echo = StoredRelayEnvelope::new(outbound_envelope, 2).unwrap();
        fixture.store.record_inbox_envelope(&echo).unwrap();
        let outbound = fixture
            .store
            .outbound_history_message(fixture.conversation_id, envelope_id, 2)
            .unwrap()
            .unwrap();
        fixture
            .store
            .save_inbox_message(
                fixture.conversation_id,
                2,
                outbound.sender,
                outbound.epoch,
                &outbound.message,
            )
            .unwrap();
        fixture
            .store
            .complete_inbox(fixture.conversation_id, 2)
            .unwrap();
        let complete = fixture
            .store
            .load_history(fixture.conversation_id, 0, 10)
            .unwrap();
        assert_eq!(
            complete
                .messages
                .iter()
                .map(|message| message.cursor)
                .collect::<Vec<_>>(),
            vec![1, 2]
        );
    }

    #[test]
    fn outbox_capacity_and_sequence_failures_do_not_consume_counters() {
        let fixture = conversation_fixture("outbox-capacity-test");
        for value in 1..=MAX_PENDING_OUTBOX {
            let value = u8::try_from(value).unwrap();
            let reservation = fixture
                .store
                .reserve_outbound_application(
                    fixture.conversation_id,
                    MessageId::from_bytes([value; MessageId::LENGTH]),
                    EnvelopeId::from_bytes([value; EnvelopeId::LENGTH]),
                )
                .unwrap();
            assert_eq!(reservation.sender_counter, u64::from(value));
        }
        assert_eq!(
            fixture.store.reserve_outbound_application(
                fixture.conversation_id,
                MessageId::from_bytes([100; MessageId::LENGTH]),
                EnvelopeId::from_bytes([100; EnvelopeId::LENGTH]),
            ),
            Err(ProfileStoreError::OutboxCapacityExceeded)
        );
        assert_eq!(
            fixture
                .store
                .load_conversation(fixture.conversation_id)
                .unwrap()
                .sender_counter,
            MAX_PENDING_OUTBOX as u64
        );
        assert_eq!(
            fixture.store.abandon_unsealed_outbox().unwrap(),
            MAX_PENDING_OUTBOX
        );
        assert_eq!(
            fixture.store.reserve_outbound_application(
                fixture.conversation_id,
                MessageId::from_bytes([1; MessageId::LENGTH]),
                EnvelopeId::from_bytes([1; EnvelopeId::LENGTH]),
            ),
            Err(ProfileStoreError::InvalidTransition)
        );
        assert_eq!(
            fixture
                .store
                .reserve_outbound_application(
                    fixture.conversation_id,
                    MessageId::from_bytes([100; MessageId::LENGTH]),
                    EnvelopeId::from_bytes([100; EnvelopeId::LENGTH]),
                )
                .unwrap()
                .sender_counter,
            (MAX_PENDING_OUTBOX + 1) as u64
        );

        fixture
            .store
            .lock()
            .unwrap()
            .execute("DELETE FROM daemon_outbox", [])
            .unwrap();
        fixture
            .store
            .lock()
            .unwrap()
            .execute(
                "UPDATE daemon_conversation SET sender_counter = ?1",
                params![i64::MAX],
            )
            .unwrap();
        assert_eq!(
            fixture.store.reserve_outbound_application(
                fixture.conversation_id,
                MessageId::from_bytes([101; MessageId::LENGTH]),
                EnvelopeId::from_bytes([101; EnvelopeId::LENGTH]),
            ),
            Err(ProfileStoreError::SequenceExhausted)
        );
        let (counter, outbox_count): (i64, i64) = fixture
            .store
            .lock()
            .unwrap()
            .query_row(
                "SELECT
                    sender_counter,
                    (SELECT count(*) FROM daemon_outbox)
                 FROM daemon_conversation",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(counter, i64::MAX);
        assert_eq!(outbox_count, 0);
    }

    #[test]
    fn concurrent_outbox_reservations_allocate_unique_monotonic_counters() {
        let fixture = conversation_fixture("outbox-concurrency-test");
        let ConversationFixture {
            root: _root,
            store,
            conversation_id,
            ..
        } = fixture;
        let store = Arc::new(store);
        let mut workers = Vec::new();
        for value in 1..=16 {
            let store = Arc::clone(&store);
            workers.push(std::thread::spawn(move || {
                store
                    .reserve_outbound_application(
                        conversation_id,
                        MessageId::from_bytes([value; MessageId::LENGTH]),
                        EnvelopeId::from_bytes([value; EnvelopeId::LENGTH]),
                    )
                    .unwrap()
                    .sender_counter
            }));
        }
        let mut counters = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect::<Vec<_>>();
        counters.sort_unstable();
        assert_eq!(counters, (1..=16).collect::<Vec<_>>());
        assert_eq!(
            store
                .load_conversation(conversation_id)
                .unwrap()
                .sender_counter,
            16
        );
    }

    #[test]
    fn profile_lock_identity_and_relay_configuration_reopen() {
        let root = tempfile::tempdir().unwrap();
        let profile_id = ProfileId::parse("default").unwrap();
        let locked = LockedProfile::acquire(root.path(), profile_id.clone()).unwrap();
        assert_eq!(
            LockedProfile::acquire(root.path(), profile_id.clone()).err(),
            Some(ProfileStoreError::ProfileLocked)
        );
        let store = locked.open_store(sealer()).unwrap();
        let first_device = store.load_or_create_device().unwrap();
        let endpoint = RelayEndpoint::parse("https://relay.example.com/base").unwrap();
        let credential = RelayAccessCredential::from_bytes([8; RelayAccessCredential::LENGTH]);
        store.configure_relay(&endpoint, &credential).unwrap();
        drop(store);

        let store = LockedProfile::acquire(root.path(), profile_id)
            .unwrap()
            .open_store(sealer())
            .unwrap();
        assert_eq!(
            store.load_or_create_device().unwrap().device_id(),
            first_device.device_id()
        );
        let (reopened_endpoint, reopened_credential) = store.relay_configuration().unwrap();
        assert_eq!(reopened_endpoint.as_str(), endpoint.as_str());
        assert!(RelayClient::new(reopened_endpoint, reopened_credential).is_ok());
        store
            .lock()
            .unwrap()
            .execute(
                "UPDATE daemon_profile
                 SET relay_endpoint = 'https://other.example.com/'
                 WHERE singleton_id = 1",
                [],
            )
            .unwrap();
        assert_eq!(
            store.relay_configuration().err(),
            Some(ProfileStoreError::Credential)
        );
    }

    #[test]
    fn profile_lock_is_exclusive_across_processes() {
        if let Ok(root) = std::env::var("KONCLAVE_PROFILE_LOCK_CHILD_ROOT") {
            assert_eq!(
                LockedProfile::acquire(
                    Path::new(&root),
                    ProfileId::parse("cross-process").unwrap(),
                )
                .err(),
                Some(ProfileStoreError::ProfileLocked)
            );
            return;
        }

        let root = tempfile::tempdir().unwrap();
        let _locked =
            LockedProfile::acquire(root.path(), ProfileId::parse("cross-process").unwrap())
                .unwrap();
        let status = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "persistence::tests::profile_lock_is_exclusive_across_processes",
                "--nocapture",
            ])
            .env("KONCLAVE_PROFILE_LOCK_CHILD_ROOT", root.path())
            .status()
            .unwrap();
        assert!(status.success());
    }

    #[test]
    fn profile_store_rejects_unknown_schema_versions() {
        let root = tempfile::tempdir().unwrap();
        let locked =
            LockedProfile::acquire(root.path(), ProfileId::parse("schema-test").unwrap()).unwrap();
        let connection = Connection::open(locked.profile_database_path()).unwrap();
        connection.pragma_update(None, "user_version", 4).unwrap();
        drop(connection);
        assert_eq!(
            locked.open_store(sealer()).err(),
            Some(ProfileStoreError::UnsupportedSchema)
        );
    }

    #[test]
    fn profile_schema_migrates_v1_to_v3_transactionally() {
        let root = tempfile::tempdir().unwrap();
        let profile_id = ProfileId::parse("migration-test").unwrap();
        let locked = LockedProfile::acquire(root.path(), profile_id).unwrap();
        let database_path = locked.profile_database_path();
        create_v1_profile_database(&database_path);
        let store = locked.open_store(sealer()).unwrap();
        let version: u32 = store
            .lock()
            .unwrap()
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, PROFILE_SCHEMA_VERSION);
        for table in [
            "daemon_outbox",
            "daemon_cursor_observation",
            "daemon_inbox",
            "daemon_sender_counter",
            "daemon_message_history",
        ] {
            let exists: i64 = store
                .lock()
                .unwrap()
                .query_row(
                    "SELECT count(*) FROM sqlite_schema
                     WHERE type = 'table' AND name = ?1",
                    params![table],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(exists, 1);
        }
    }

    #[test]
    fn profile_schema_migrates_v2_to_v3_message_history() {
        let root = tempfile::tempdir().unwrap();
        let profile_id = ProfileId::parse("message-history-migration").unwrap();
        let database_path = {
            let store = LockedProfile::acquire(root.path(), profile_id.clone())
                .unwrap()
                .open_store(sealer())
                .unwrap();
            store.locked_profile.profile_database_path()
        };
        let connection = Connection::open(&database_path).unwrap();
        connection
            .execute("DROP TABLE daemon_message_history", [])
            .unwrap();
        connection.pragma_update(None, "user_version", 2).unwrap();
        drop(connection);

        let store = LockedProfile::acquire(root.path(), profile_id)
            .unwrap()
            .open_store(sealer())
            .unwrap();
        let version: u32 = store
            .lock()
            .unwrap()
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        let history_exists: i64 = store
            .lock()
            .unwrap()
            .query_row(
                "SELECT count(*) FROM sqlite_schema
                 WHERE type = 'table' AND name = 'daemon_message_history'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(version, PROFILE_SCHEMA_VERSION);
        assert_eq!(history_exists, 1);
    }

    #[test]
    fn legacy_history_rehydrates_completed_and_pending_inbox_rows() {
        let fixture = conversation_fixture("legacy-inbox-history");
        stage_inbox_message(&fixture, 1, 81, 0, 1);
        fixture
            .store
            .complete_inbox(fixture.conversation_id, 1)
            .unwrap();
        stage_inbox_message(&fixture, 2, 82, 0, 2);
        fixture
            .store
            .lock()
            .unwrap()
            .execute("DELETE FROM daemon_message_history", [])
            .unwrap();
        let root = fixture.root.path().to_path_buf();
        let profile_id = fixture.profile_id.clone();
        let conversation_id = fixture.conversation_id;
        drop(fixture.store);

        let reopened = LockedProfile::acquire(&root, profile_id)
            .unwrap()
            .open_store(sealer())
            .unwrap();

        let history = reopened.load_history(conversation_id, 0, 10).unwrap();
        assert_eq!(history.messages.len(), 1);
        assert_eq!(history.messages[0].cursor, 1);
        let rows = {
            let connection = reopened.lock().unwrap();
            let mut statement = connection
                .prepare(
                    "SELECT cursor, status
                     FROM daemon_message_history
                     WHERE conversation_id = ?1
                     ORDER BY cursor",
                )
                .unwrap();
            statement
                .query_map(params![conversation_id.as_bytes().as_slice()], |row| {
                    Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
                })
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap()
        };
        assert_eq!(rows, vec![(1, 2), (2, 1)]);
        let pending = reopened.incomplete_inbox(conversation_id).unwrap();
        assert_eq!(pending.len(), 1);
        assert!(matches!(
            &pending[0],
            PendingInbox::MessageSaved { stored, .. } if stored.cursor() == 2
        ));
    }

    #[test]
    fn legacy_history_rejects_unrecoverable_ready_and_accepted_outbox_rows() {
        for (profile, accepted) in [
            ("legacy-ready-outbox", false),
            ("legacy-accepted-outbox", true),
        ] {
            let fixture = conversation_fixture(profile);
            let reservation = fixture
                .store
                .reserve_outbound_application(
                    fixture.conversation_id,
                    MessageId::from_bytes([82; MessageId::LENGTH]),
                    EnvelopeId::from_bytes([83; EnvelopeId::LENGTH]),
                )
                .unwrap();
            let message = application_message(82, 1, "legacy outbound");
            let envelope = relay_envelope(fixture.routing_id, 83, b"legacy-outbound-ciphertext");
            fixture
                .store
                .store_outbound_message(
                    reservation,
                    fixture.routing_id,
                    fixture.device_id,
                    0,
                    &message,
                )
                .unwrap();
            fixture
                .store
                .store_outbound_envelope(reservation, &envelope)
                .unwrap();
            if accepted {
                fixture
                    .store
                    .mark_outbox_accepted(&StoredRelayEnvelope::new(envelope, 1).unwrap())
                    .unwrap();
            }
            fixture
                .store
                .lock()
                .unwrap()
                .execute("DELETE FROM daemon_message_history", [])
                .unwrap();
            let root = fixture.root.path().to_path_buf();
            let profile_id = fixture.profile_id.clone();
            drop(fixture.store);

            assert_eq!(
                LockedProfile::acquire(&root, profile_id)
                    .unwrap()
                    .open_store(sealer())
                    .err(),
                Some(ProfileStoreError::LegacyOutboundRecoveryUnsupported)
            );
        }
    }

    #[test]
    fn failed_v3_history_migration_preserves_v2_schema() {
        let root = tempfile::tempdir().unwrap();
        let profile_id = ProfileId::parse("message-history-rollback").unwrap();
        let database_path = {
            let store = LockedProfile::acquire(root.path(), profile_id.clone())
                .unwrap()
                .open_store(sealer())
                .unwrap();
            store.locked_profile.profile_database_path()
        };
        let connection = Connection::open(&database_path).unwrap();
        connection
            .execute("DROP TABLE daemon_message_history", [])
            .unwrap();
        connection
            .execute("CREATE TABLE daemon_message_history (sentinel INTEGER)", [])
            .unwrap();
        connection.pragma_update(None, "user_version", 2).unwrap();
        drop(connection);

        assert_eq!(
            LockedProfile::acquire(root.path(), profile_id)
                .unwrap()
                .open_store(sealer())
                .err(),
            Some(ProfileStoreError::Storage)
        );
        let connection = Connection::open(database_path).unwrap();
        let version: u32 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        let history_columns: i64 = connection
            .query_row(
                "SELECT count(*) FROM pragma_table_info('daemon_message_history')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(version, 2);
        assert_eq!(history_columns, 1);
    }

    #[test]
    fn failed_profile_schema_migration_preserves_v1() {
        let root = tempfile::tempdir().unwrap();
        let profile_id = ProfileId::parse("migration-rollback-test").unwrap();
        let locked = LockedProfile::acquire(root.path(), profile_id).unwrap();
        let database_path = locked.profile_database_path();
        create_v1_profile_database(&database_path);
        Connection::open(&database_path)
            .unwrap()
            .execute("CREATE TABLE daemon_outbox (sentinel INTEGER)", [])
            .unwrap();
        assert_eq!(
            locked.open_store(sealer()).err(),
            Some(ProfileStoreError::Storage)
        );
        let connection = Connection::open(database_path).unwrap();
        let version: u32 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, 1);
        let inbox_exists: i64 = connection
            .query_row(
                "SELECT count(*) FROM sqlite_schema
                 WHERE type = 'table' AND name = 'daemon_inbox'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let outbox_columns: i64 = connection
            .query_row(
                "SELECT count(*) FROM pragma_table_info('daemon_outbox')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(inbox_exists, 0);
        assert_eq!(outbox_columns, 1);
    }

    #[test]
    fn conversation_records_reopen_with_verified_sealed_state() {
        let root = tempfile::tempdir().unwrap();
        let store =
            LockedProfile::acquire(root.path(), ProfileId::parse("conversation-test").unwrap())
                .unwrap()
                .open_store(sealer())
                .unwrap();
        let identity = store.load_or_create_device().unwrap();
        let conversation_id = identity.generate_conversation_id().unwrap();
        let material = identity
            .create_conversation_signing_material(conversation_id)
            .unwrap();
        let binding = material.binding().clone();
        let state = ConversationState::new(
            ProtocolVersion::application_v1(),
            conversation_id,
            0,
            vec![Member::new(
                identity.device_id(),
                ConversationRole::Administrator,
                0,
            )],
            vec![],
        )
        .unwrap();
        let routing_id = RoutingId::from_bytes([9; RoutingId::LENGTH]);
        store
            .insert_conversation(routing_id, &material, &state, &[binding])
            .unwrap();
        assert_eq!(
            store.conversation_ids(None, 10).unwrap(),
            vec![conversation_id]
        );
        let encoded_state = encode_conversation_state(&state).unwrap();
        let encoded_binding = encode_device_credential_binding(material.binding()).unwrap();
        let (sealed_state, sealed_binding): (Vec<u8>, Vec<u8>) = store
            .lock()
            .unwrap()
            .query_row(
                "SELECT c.sealed_policy_state, b.sealed_binding
                 FROM daemon_conversation c
                 JOIN daemon_conversation_binding b
                   ON b.conversation_id = c.conversation_id
                 WHERE c.conversation_id = ?1",
                params![conversation_id.as_bytes().as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert!(
            !sealed_state
                .windows(encoded_state.len())
                .any(|window| window == encoded_state)
        );
        assert!(
            !sealed_binding
                .windows(encoded_binding.len())
                .any(|window| window == encoded_binding)
        );

        let reopened = store.load_conversation(conversation_id).unwrap();
        assert_eq!(reopened.routing_id, routing_id);
        assert_eq!(reopened.state, state);
        assert_eq!(reopened.bindings.len(), 1);
        assert_eq!(reopened.sender_counter, 0);
        assert_eq!(reopened.replay_cursor, 0);
        assert_eq!(
            reopened.signing_material.binding().device_id(),
            identity.device_id()
        );
        assert_eq!(
            store
                .insert_conversation(
                    routing_id,
                    &reopened.signing_material,
                    &reopened.state,
                    &[reopened.bindings[0].binding().clone()],
                )
                .unwrap_err(),
            ProfileStoreError::ConversationExists
        );
        store
            .lock()
            .unwrap()
            .execute(
                "UPDATE daemon_conversation
                 SET routing_id = ?1
                 WHERE conversation_id = ?2",
                params![
                    RoutingId::from_bytes([10; RoutingId::LENGTH])
                        .as_bytes()
                        .as_slice(),
                    conversation_id.as_bytes().as_slice()
                ],
            )
            .unwrap();
        assert_eq!(
            store.load_conversation(conversation_id).err(),
            Some(ProfileStoreError::CorruptData)
        );
    }

    use KonclaveClientLibrary::RelayClient;
}
