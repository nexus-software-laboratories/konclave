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
    ConversationId, ConversationState, DeviceCredentialBinding, DeviceId, MAX_MEMBERS, RoutingId,
};
use KonclaveProtocolContracts::v1::{
    decode_conversation_state, decode_device_credential_binding, encode_conversation_state,
    encode_device_credential_binding,
};
use KonclaveSecretStorage::{
    MAX_SECRET_PLAINTEXT_BYTES, SealedBlob, SecretRecordContext, SecretRecordKind, SecretSealer,
};
use fs4::{FileExt, TryLockError};
use rusqlite::{Connection, OptionalExtension, params};
use thiserror::Error;

const PROFILE_SCHEMA_VERSION: u32 = 1;
const MAX_PROFILE_ID_BYTES: usize = 32;
const MAX_SEALED_RECORD_BYTES: usize = MAX_SECRET_PLAINTEXT_BYTES + 64;
const MAX_LOCAL_BINDINGS: usize = MAX_MEMBERS + 1;

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
        Ok(ProfileStore {
            connection: Mutex::new(connection),
            sealer: Arc::new(sealer),
            locked_profile: self,
        })
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
    if version == PROFILE_SCHEMA_VERSION {
        return Ok(());
    }
    if version != 0 {
        return Err(ProfileStoreError::UnsupportedSchema);
    }
    connection
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

#[cfg(test)]
mod tests {
    use std::process::Command;

    use KonclaveDomainCore::{ConversationRole, Member, ProtocolVersion};
    use KonclaveSecretStorage::{ExternalWrappingKeyProvider, SecretSealer};

    use super::*;

    fn sealer() -> SecretSealer {
        SecretSealer::from_provider(ExternalWrappingKeyProvider::from_bytes([7; 32])).unwrap()
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
        connection.pragma_update(None, "user_version", 2).unwrap();
        drop(connection);
        assert_eq!(
            locked.open_store(sealer()).err(),
            Some(ProfileStoreError::UnsupportedSchema)
        );
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
