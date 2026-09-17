use std::collections::BTreeSet;

use KonclaveCryptographicCore::DeviceIdentity;
use KonclaveDomainCore::{
    DeviceId, Ed25519PublicKey, KonclaveDomainError, MAX_TRUSTED_DEVICE_ALIAS_BYTES,
    TrustedDeviceAlias, TrustedDeviceAliasDecision, TrustedDeviceBinding, TrustedDeviceEvidence,
    decide_trusted_device_alias,
};
use KonclaveSecretStorage::{SealedBlob, SecretRecordContext, SecretRecordKind};
use rusqlite::{Connection, OptionalExtension, params};

use super::{ProfileStore, ProfileStoreError};

const PRIOR_PROFILE_SCHEMA_VERSION: u32 = 19;
const TRUSTED_DEVICE_SCHEMA_VERSION: u32 = 20;
const MAX_TRUSTED_DEVICE_BINDINGS: usize = 256;
const TRUSTED_DEVICE_BINDING_VERSION: u8 = 1;
const TRUSTED_DEVICE_BINDING_STATE_VERSION: u8 = 1;
const MAX_TRUSTED_DEVICE_BINDING_BYTES: usize =
    2 + MAX_TRUSTED_DEVICE_ALIAS_BYTES + DeviceId::LENGTH + Ed25519PublicKey::LENGTH;
const MAX_SEALED_TRUSTED_DEVICE_BINDING_BYTES: usize = MAX_TRUSTED_DEVICE_BINDING_BYTES + 64;
const TRUSTED_DEVICE_BINDING_STATE_BYTES: usize = 1 + 8;
const MAX_SEALED_TRUSTED_DEVICE_BINDING_STATE_BYTES: usize =
    TRUSTED_DEVICE_BINDING_STATE_BYTES + 64;
const TRUSTED_DEVICE_BINDING_CONTEXT_VERSION: &[u8] = b"trusted-device-binding-v1";
const TRUSTED_DEVICE_BINDING_STATE_CONTEXT_VERSION: &[u8] = b"trusted-device-binding-state-v1";

impl ProfileStore {
    pub(super) fn initialize_trusted_device_schema(&self) -> Result<(), ProfileStoreError> {
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
        if current_version == TRUSTED_DEVICE_SCHEMA_VERSION {
            if let Some((_, floor)) = opened_identity
                && floor != TRUSTED_DEVICE_SCHEMA_VERSION
            {
                return Err(ProfileStoreError::CorruptData);
            }
            return Ok(());
        }
        if current_version > TRUSTED_DEVICE_SCHEMA_VERSION {
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
                        TRUSTED_DEVICE_SCHEMA_VERSION,
                    )
                    .map_err(|_| ProfileStoreError::Cryptographic)?,
            ),
            Some(_) => return Err(ProfileStoreError::CorruptData),
            None => None,
        };
        let sealed_state = self.seal_trusted_device_binding_state(0)?;
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction()
            .map_err(|_| ProfileStoreError::Storage)?;
        transaction
            .execute_batch(
                "CREATE TABLE daemon_trusted_device_binding (
                    device_id BLOB PRIMARY KEY CHECK (length(device_id) = 32),
                    sealed_binding BLOB NOT NULL
                 ) WITHOUT ROWID;
                 CREATE TABLE daemon_trusted_device_binding_state (
                    singleton_id INTEGER PRIMARY KEY CHECK (singleton_id = 1),
                    sealed_state BLOB NOT NULL
                 );",
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        if transaction
            .execute(
                "INSERT INTO daemon_trusted_device_binding_state (
                    singleton_id,
                    sealed_state
                 ) VALUES (1, ?1)",
                params![sealed_state.as_bytes()],
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
            .pragma_update(None, "user_version", TRUSTED_DEVICE_SCHEMA_VERSION)
            .map_err(|_| ProfileStoreError::Storage)?;
        transaction.commit().map_err(|_| ProfileStoreError::Storage)
    }

    pub(super) fn verify_trusted_device_bindings(&self) -> Result<(), ProfileStoreError> {
        let connection = self.lock()?;
        let bindings = self.load_trusted_device_bindings_from(&connection)?;
        let committed_count = self.open_trusted_device_binding_state(&connection)?;
        if committed_count != bindings.len() || bindings.len() > MAX_TRUSTED_DEVICE_BINDINGS {
            return Err(ProfileStoreError::CorruptData);
        }
        let mut aliases = BTreeSet::new();
        if bindings
            .iter()
            .any(|binding| !aliases.insert(binding.alias().as_str()))
        {
            return Err(ProfileStoreError::CorruptData);
        }
        Ok(())
    }

    pub(crate) fn trusted_device_bindings(
        &self,
    ) -> Result<Vec<TrustedDeviceBinding>, ProfileStoreError> {
        let connection = self.lock()?;
        self.load_trusted_device_bindings_from(&connection)
    }

    pub(crate) fn trusted_device_binding(
        &self,
        alias: &TrustedDeviceAlias,
    ) -> Result<TrustedDeviceBinding, ProfileStoreError> {
        self.trusted_device_bindings()?
            .into_iter()
            .find(|binding| binding.alias() == alias)
            .ok_or(ProfileStoreError::TrustedDeviceNotFound)
    }

    pub(crate) fn store_trusted_device_binding(
        &self,
        candidate: &TrustedDeviceBinding,
        evidence: &[TrustedDeviceEvidence],
    ) -> Result<TrustedDeviceAliasDecision, ProfileStoreError> {
        let connection = self.lock()?;
        let bindings = self.load_trusted_device_bindings_from(&connection)?;
        let existing_by_alias = bindings
            .iter()
            .find(|binding| binding.alias() == candidate.alias());
        let existing_by_device = bindings
            .iter()
            .find(|binding| binding.device_id() == candidate.device_id());
        let decision =
            decide_trusted_device_alias(candidate, existing_by_alias, existing_by_device, evidence)
                .map_err(trusted_device_domain_error)?;
        if decision == TrustedDeviceAliasDecision::Identical {
            return Ok(decision);
        }
        let committed_count = self.open_trusted_device_binding_state(&connection)?;
        if committed_count != bindings.len() {
            return Err(ProfileStoreError::CorruptData);
        }
        let transaction = connection
            .unchecked_transaction()
            .map_err(|_| ProfileStoreError::Storage)?;
        if let Some(existing) = existing_by_alias {
            transaction
                .execute(
                    "DELETE FROM daemon_trusted_device_binding WHERE device_id = ?1",
                    params![existing.device_id().as_bytes().as_slice()],
                )
                .map_err(|_| ProfileStoreError::Storage)?;
        }
        if existing_by_device.is_some_and(|existing| {
            existing_by_alias.is_none_or(|by_alias| by_alias.device_id() != existing.device_id())
        }) {
            transaction
                .execute(
                    "DELETE FROM daemon_trusted_device_binding WHERE device_id = ?1",
                    params![candidate.device_id().as_bytes().as_slice()],
                )
                .map_err(|_| ProfileStoreError::Storage)?;
        }
        let sealed = self.seal_trusted_device_binding(candidate)?;
        if transaction
            .execute(
                "INSERT INTO daemon_trusted_device_binding (device_id, sealed_binding)
                 VALUES (?1, ?2)",
                params![
                    candidate.device_id().as_bytes().as_slice(),
                    sealed.as_bytes()
                ],
            )
            .map_err(|_| ProfileStoreError::Storage)?
            != 1
        {
            return Err(ProfileStoreError::Storage);
        }
        let count = trusted_device_binding_count(&transaction)?;
        if count > MAX_TRUSTED_DEVICE_BINDINGS {
            return Err(ProfileStoreError::TrustedDeviceCapacityExceeded);
        }
        let sealed_state = self.seal_trusted_device_binding_state(count)?;
        if transaction
            .execute(
                "UPDATE daemon_trusted_device_binding_state
                 SET sealed_state = ?1
                 WHERE singleton_id = 1",
                params![sealed_state.as_bytes()],
            )
            .map_err(|_| ProfileStoreError::Storage)?
            != 1
        {
            return Err(ProfileStoreError::CorruptData);
        }
        transaction
            .commit()
            .map_err(|_| ProfileStoreError::Storage)?;
        Ok(decision)
    }

    fn load_trusted_device_bindings_from(
        &self,
        connection: &Connection,
    ) -> Result<Vec<TrustedDeviceBinding>, ProfileStoreError> {
        let mut statement = connection
            .prepare(
                "SELECT
                    CASE WHEN length(device_id) = 32 THEN device_id END,
                    length(sealed_binding)
                 FROM daemon_trusted_device_binding
                 ORDER BY device_id",
            )
            .map_err(|_| ProfileStoreError::Storage)?;
        let metadata = statement
            .query_map([], |row| {
                Ok((row.get::<_, Option<Vec<u8>>>(0)?, row.get::<_, i64>(1)?))
            })
            .map_err(|_| ProfileStoreError::Storage)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| ProfileStoreError::Storage)?;
        if metadata.len() > MAX_TRUSTED_DEVICE_BINDINGS {
            return Err(ProfileStoreError::CorruptData);
        }
        metadata
            .into_iter()
            .map(|(device_id, sealed_length)| {
                let device_id =
                    DeviceId::from_slice(&device_id.ok_or(ProfileStoreError::CorruptData)?)
                        .map_err(|_| ProfileStoreError::CorruptData)?;
                let sealed_length =
                    validate_sealed_length(sealed_length, MAX_SEALED_TRUSTED_DEVICE_BINDING_BYTES)?;
                let sealed: Vec<u8> = connection
                    .query_row(
                        "SELECT sealed_binding
                         FROM daemon_trusted_device_binding
                         WHERE device_id = ?1",
                        params![device_id.as_bytes().as_slice()],
                        |row| row.get(0),
                    )
                    .map_err(|_| ProfileStoreError::Storage)?;
                if sealed.len() != sealed_length {
                    return Err(ProfileStoreError::CorruptData);
                }
                let sealed =
                    SealedBlob::from_bytes(sealed).map_err(|_| ProfileStoreError::CorruptData)?;
                let plaintext = self
                    .sealer
                    .open(
                        &trusted_device_binding_context(
                            self.locked_profile.profile_id.as_bytes(),
                            device_id,
                        )?,
                        &sealed,
                    )
                    .map_err(|_| ProfileStoreError::CorruptData)?;
                let binding = decode_trusted_device_binding(&plaintext)?;
                if binding.device_id() != device_id {
                    return Err(ProfileStoreError::CorruptData);
                }
                Ok(binding)
            })
            .collect()
    }

    fn seal_trusted_device_binding(
        &self,
        binding: &TrustedDeviceBinding,
    ) -> Result<SealedBlob, ProfileStoreError> {
        self.sealer
            .seal(
                &trusted_device_binding_context(
                    self.locked_profile.profile_id.as_bytes(),
                    binding.device_id(),
                )?,
                &encode_trusted_device_binding(binding),
            )
            .map_err(|_| ProfileStoreError::Storage)
    }

    fn seal_trusted_device_binding_state(
        &self,
        count: usize,
    ) -> Result<SealedBlob, ProfileStoreError> {
        let count = u64::try_from(count).map_err(|_| ProfileStoreError::Storage)?;
        let mut plaintext = [0; TRUSTED_DEVICE_BINDING_STATE_BYTES];
        plaintext[0] = TRUSTED_DEVICE_BINDING_STATE_VERSION;
        plaintext[1..].copy_from_slice(&count.to_be_bytes());
        self.sealer
            .seal(
                &trusted_device_binding_state_context(self.locked_profile.profile_id.as_bytes())?,
                &plaintext,
            )
            .map_err(|_| ProfileStoreError::Storage)
    }

    fn open_trusted_device_binding_state(
        &self,
        connection: &Connection,
    ) -> Result<usize, ProfileStoreError> {
        let sealed_length: Option<i64> = connection
            .query_row(
                "SELECT length(sealed_state)
                 FROM daemon_trusted_device_binding_state
                 WHERE singleton_id = 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| ProfileStoreError::Storage)?;
        let sealed_length = validate_sealed_length(
            sealed_length.ok_or(ProfileStoreError::CorruptData)?,
            MAX_SEALED_TRUSTED_DEVICE_BINDING_STATE_BYTES,
        )?;
        let sealed: Vec<u8> = connection
            .query_row(
                "SELECT sealed_state
                 FROM daemon_trusted_device_binding_state
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
                &trusted_device_binding_state_context(self.locked_profile.profile_id.as_bytes())?,
                &sealed,
            )
            .map_err(|_| ProfileStoreError::CorruptData)?;
        if plaintext.len() != TRUSTED_DEVICE_BINDING_STATE_BYTES
            || plaintext[0] != TRUSTED_DEVICE_BINDING_STATE_VERSION
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
}

fn trusted_device_binding_count(connection: &Connection) -> Result<usize, ProfileStoreError> {
    let count: i64 = connection
        .query_row(
            "SELECT count(*) FROM daemon_trusted_device_binding",
            [],
            |row| row.get(0),
        )
        .map_err(|_| ProfileStoreError::Storage)?;
    usize::try_from(count).map_err(|_| ProfileStoreError::CorruptData)
}

fn validate_sealed_length(length: i64, maximum: usize) -> Result<usize, ProfileStoreError> {
    let length = usize::try_from(length).map_err(|_| ProfileStoreError::CorruptData)?;
    if length == 0 || length > maximum {
        return Err(ProfileStoreError::CorruptData);
    }
    Ok(length)
}

fn encode_trusted_device_binding(binding: &TrustedDeviceBinding) -> Vec<u8> {
    let alias = binding.alias().as_str().as_bytes();
    let mut output =
        Vec::with_capacity(2 + alias.len() + DeviceId::LENGTH + Ed25519PublicKey::LENGTH);
    output.push(TRUSTED_DEVICE_BINDING_VERSION);
    output.push(u8::try_from(alias.len()).expect("trusted device alias length fits in u8"));
    output.extend_from_slice(alias);
    output.extend_from_slice(binding.device_id().as_bytes());
    output.extend_from_slice(binding.device_root_public_key().as_bytes());
    output
}

fn decode_trusted_device_binding(bytes: &[u8]) -> Result<TrustedDeviceBinding, ProfileStoreError> {
    if bytes.len() < 2 + DeviceId::LENGTH + Ed25519PublicKey::LENGTH
        || bytes.len() > MAX_TRUSTED_DEVICE_BINDING_BYTES
        || bytes[0] != TRUSTED_DEVICE_BINDING_VERSION
    {
        return Err(ProfileStoreError::CorruptData);
    }
    let alias_length = usize::from(bytes[1]);
    let device_start = 2 + alias_length;
    let root_start = device_start + DeviceId::LENGTH;
    if alias_length == 0
        || alias_length > MAX_TRUSTED_DEVICE_ALIAS_BYTES
        || root_start + Ed25519PublicKey::LENGTH != bytes.len()
    {
        return Err(ProfileStoreError::CorruptData);
    }
    let alias =
        std::str::from_utf8(&bytes[2..device_start]).map_err(|_| ProfileStoreError::CorruptData)?;
    Ok(TrustedDeviceBinding::new(
        TrustedDeviceAlias::parse(alias.to_owned()).map_err(|_| ProfileStoreError::CorruptData)?,
        DeviceId::from_slice(&bytes[device_start..root_start])
            .map_err(|_| ProfileStoreError::CorruptData)?,
        Ed25519PublicKey::from_slice(&bytes[root_start..])
            .map_err(|_| ProfileStoreError::CorruptData)?,
    ))
}

fn trusted_device_binding_context(
    profile_id: &[u8],
    device_id: DeviceId,
) -> Result<SecretRecordContext, ProfileStoreError> {
    SecretRecordContext::derive(
        SecretRecordKind::TrustedDeviceBinding,
        &[
            TRUSTED_DEVICE_BINDING_CONTEXT_VERSION,
            profile_id,
            device_id.as_bytes(),
        ],
    )
    .map_err(|_| ProfileStoreError::Storage)
}

fn trusted_device_binding_state_context(
    profile_id: &[u8],
) -> Result<SecretRecordContext, ProfileStoreError> {
    SecretRecordContext::derive(
        SecretRecordKind::TrustedDeviceBindingState,
        &[TRUSTED_DEVICE_BINDING_STATE_CONTEXT_VERSION, profile_id],
    )
    .map_err(|_| ProfileStoreError::Storage)
}

fn trusted_device_domain_error(error: KonclaveDomainError) -> ProfileStoreError {
    match error {
        KonclaveDomainError::TrustedDeviceAliasConflict => {
            ProfileStoreError::TrustedDeviceAliasConflict
        }
        KonclaveDomainError::TrustedDeviceRootMismatch => {
            ProfileStoreError::TrustedDeviceRootMismatch
        }
        KonclaveDomainError::TrustedDeviceRemoved => ProfileStoreError::TrustedDeviceRemoved,
        KonclaveDomainError::TrustedDeviceRepeatPairingUnsupported => {
            ProfileStoreError::TrustedDeviceRepeatPairingUnsupported
        }
        _ => ProfileStoreError::CorruptData,
    }
}

#[cfg(test)]
mod tests {
    use KonclaveSecretStorage::{ExternalWrappingKeyProvider, SecretSealer};

    use super::*;
    use crate::persistence::{LockedProfile, PROFILE_SCHEMA_VERSION, ProfileId};

    fn open_store(root: &std::path::Path, profile: &str) -> ProfileStore {
        LockedProfile::acquire(root, ProfileId::parse(profile).unwrap())
            .unwrap()
            .open_store(
                SecretSealer::from_provider(ExternalWrappingKeyProvider::from_bytes([7; 32]))
                    .unwrap(),
            )
            .unwrap()
    }

    fn binding(alias: &str, device: u8, root: u8) -> TrustedDeviceBinding {
        TrustedDeviceBinding::new(
            TrustedDeviceAlias::parse(alias).unwrap(),
            DeviceId::from_bytes([device; 32]),
            Ed25519PublicKey::from_bytes([root; 32]),
        )
    }

    fn evidence(conversation: u8, device: u8, root: u8) -> TrustedDeviceEvidence {
        TrustedDeviceEvidence::new(
            KonclaveDomainCore::ConversationId::from_bytes([conversation; 32]),
            DeviceId::from_bytes([device; 32]),
            Ed25519PublicKey::from_bytes([root; 32]),
            true,
        )
    }

    #[test]
    fn trusted_device_aliases_are_sealed_and_mutated_atomically() {
        let root = tempfile::tempdir().unwrap();
        let store = open_store(root.path(), "trusted-device-store");
        let alienware = binding("alienware", 2, 3);
        assert_eq!(
            store
                .store_trusted_device_binding(&alienware, &[evidence(1, 2, 3)])
                .unwrap(),
            TrustedDeviceAliasDecision::Insert
        );
        let sealed: Vec<u8> = store
            .lock()
            .unwrap()
            .query_row(
                "SELECT sealed_binding FROM daemon_trusted_device_binding",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!sealed.windows(9).any(|window| window == b"alienware"));
        assert_eq!(
            store
                .store_trusted_device_binding(&alienware, &[evidence(1, 2, 3)])
                .unwrap(),
            TrustedDeviceAliasDecision::Identical
        );
        let renamed = binding("workstation", 2, 3);
        assert_eq!(
            store
                .store_trusted_device_binding(&renamed, &[evidence(1, 2, 3)])
                .unwrap(),
            TrustedDeviceAliasDecision::Rename
        );
        let bindings = store.trusted_device_bindings().unwrap();
        assert_eq!(bindings.len(), 1);
        assert_eq!(bindings[0].alias().as_str(), "workstation");
    }

    #[test]
    fn trusted_device_alias_collision_and_stale_rebind_fail_closed() {
        let root = tempfile::tempdir().unwrap();
        let store = open_store(root.path(), "trusted-device-decisions");
        store
            .store_trusted_device_binding(&binding("alienware", 2, 3), &[evidence(1, 2, 3)])
            .unwrap();
        assert_eq!(
            store.store_trusted_device_binding(
                &binding("alienware", 4, 5),
                &[evidence(1, 2, 3), evidence(1, 4, 5)],
            ),
            Err(ProfileStoreError::TrustedDeviceAliasConflict)
        );
        assert_eq!(
            store
                .store_trusted_device_binding(&binding("alienware", 4, 5), &[evidence(1, 4, 5)],)
                .unwrap(),
            TrustedDeviceAliasDecision::RebindStale
        );
        assert_eq!(
            store
                .trusted_device_binding(&TrustedDeviceAlias::parse("alienware").unwrap())
                .unwrap()
                .device_id(),
            DeviceId::from_bytes([4; 32])
        );
    }

    #[test]
    fn schema_nineteen_migrates_identity_and_alias_tables_transactionally() {
        let root = tempfile::tempdir().unwrap();
        let profile = "trusted-device-schema";
        let store = open_store(root.path(), profile);
        let device = store.load_or_create_device().unwrap();
        let database_path = store.locked_profile.profile_database_path();
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
                     DROP TABLE daemon_trusted_device_binding_state;
                     DROP TABLE daemon_trusted_device_binding;
                     PRAGMA user_version = 19;",
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
    fn tampering_deletion_and_cross_profile_substitution_fail_startup() {
        let root = tempfile::tempdir().unwrap();
        let first = open_store(root.path(), "trusted-device-first");
        first
            .store_trusted_device_binding(&binding("alienware", 2, 3), &[evidence(1, 2, 3)])
            .unwrap();
        let copied: Vec<u8> = first
            .lock()
            .unwrap()
            .query_row(
                "SELECT sealed_binding FROM daemon_trusted_device_binding",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let first_profile = first.locked_profile.profile_id.clone();
        drop(first);
        {
            let locked = LockedProfile::acquire(root.path(), first_profile).unwrap();
            let connection = rusqlite::Connection::open(locked.profile_database_path()).unwrap();
            connection
                .execute("DELETE FROM daemon_trusted_device_binding", [])
                .unwrap();
        }
        assert_eq!(
            LockedProfile::acquire(
                root.path(),
                ProfileId::parse("trusted-device-first").unwrap(),
            )
            .unwrap()
            .open_store(
                SecretSealer::from_provider(ExternalWrappingKeyProvider::from_bytes([7; 32]))
                    .unwrap(),
            )
            .err(),
            Some(ProfileStoreError::CorruptData)
        );

        let second = open_store(root.path(), "trusted-device-second");
        second
            .store_trusted_device_binding(&binding("desktop", 2, 3), &[evidence(1, 2, 3)])
            .unwrap();
        second
            .lock()
            .unwrap()
            .execute(
                "UPDATE daemon_trusted_device_binding SET sealed_binding = ?1",
                params![copied],
            )
            .unwrap();
        let second_profile = second.locked_profile.profile_id.clone();
        drop(second);
        assert_eq!(
            LockedProfile::acquire(root.path(), second_profile)
                .unwrap()
                .open_store(
                    SecretSealer::from_provider(ExternalWrappingKeyProvider::from_bytes([7; 32]))
                        .unwrap(),
                )
                .err(),
            Some(ProfileStoreError::CorruptData)
        );
    }
}
