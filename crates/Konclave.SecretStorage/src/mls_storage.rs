use std::sync::Arc;

use aws_lc_rs::digest::{Context, SHA256};
use mls_rs_core::crypto::HpkeSecretKey;
use mls_rs_core::error::IntoAnyError;
use mls_rs_core::group::{EpochRecord, GroupState, GroupStateStorage};
use mls_rs_core::key_package::{KeyPackageData, KeyPackageStorage};
use zeroize::Zeroizing;

use crate::{SealedBlob, SecretRecordContext, SecretRecordKind, SecretSealer, SecretStorageError};

const KEY_PACKAGE_INIT_FIELD: u8 = 1;
const KEY_PACKAGE_LEAF_FIELD: u8 = 2;

/// mls-rs storage wrapper that seals all private bytes before delegation.
///
/// Cloning this adapter shares the same sealer and clones only the backend handle;
/// it does not duplicate the wrapping key.
pub struct SealedMlsStorage<S> {
    pub(crate) inner: S,
    pub(crate) sealer: Arc<SecretSealer>,
}

impl<S> SealedMlsStorage<S> {
    /// Creates a sealed wrapper around one storage backend.
    #[must_use]
    pub fn new(inner: S, sealer: SecretSealer) -> Self {
        Self {
            inner,
            sealer: Arc::new(sealer),
        }
    }

    /// Consumes the adapter and returns the backend when no shared clones remain.
    ///
    /// # Errors
    ///
    /// Returns the adapter unchanged when another clone still shares the sealer.
    pub fn try_into_inner(self) -> Result<S, Self> {
        if Arc::strong_count(&self.sealer) == 1 {
            Ok(self.inner)
        } else {
            Err(self)
        }
    }
}

impl<S: Clone> Clone for SealedMlsStorage<S> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            sealer: Arc::clone(&self.sealer),
        }
    }
}

impl<S> GroupStateStorage for SealedMlsStorage<S>
where
    S: GroupStateStorage,
{
    type Error = SecretStorageError;

    fn state(&self, group_id: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>, Self::Error> {
        let Some(sealed) = self
            .inner
            .state(group_id)
            .map_err(|_| backend_failure("group state read"))?
        else {
            return Ok(None);
        };
        let context = SecretRecordContext::new(SecretRecordKind::MlsGroupState, group_id.to_vec())?;
        let blob = SealedBlob::from_slice(&sealed)?;
        self.sealer.open(&context, &blob).map(Some)
    }

    fn epoch(
        &self,
        group_id: &[u8],
        epoch_id: u64,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, Self::Error> {
        let Some(sealed) = self
            .inner
            .epoch(group_id, epoch_id)
            .map_err(|_| backend_failure("prior epoch read"))?
        else {
            return Ok(None);
        };
        let context = epoch_context(group_id, epoch_id)?;
        let blob = SealedBlob::from_slice(&sealed)?;
        self.sealer.open(&context, &blob).map(Some)
    }

    fn write(
        &mut self,
        state: GroupState,
        epoch_inserts: Vec<EpochRecord>,
        epoch_updates: Vec<EpochRecord>,
    ) -> Result<(), Self::Error> {
        let group_id = state.id.clone();
        let state_context =
            SecretRecordContext::new(SecretRecordKind::MlsGroupState, group_id.clone())?;
        let sealed_state = self.sealer.seal(&state_context, &state.data)?;
        let state = GroupState {
            id: state.id,
            data: Zeroizing::new(sealed_state.into_bytes()),
        };
        let epoch_inserts = self.seal_epochs(&group_id, epoch_inserts)?;
        let epoch_updates = self.seal_epochs(&group_id, epoch_updates)?;
        self.inner
            .write(state, epoch_inserts, epoch_updates)
            .map_err(|_| backend_failure("group state write"))
    }

    fn max_epoch_id(&self, group_id: &[u8]) -> Result<Option<u64>, Self::Error> {
        self.inner
            .max_epoch_id(group_id)
            .map_err(|_| backend_failure("prior epoch maximum read"))
    }
}

impl<S> SealedMlsStorage<S>
where
    S: GroupStateStorage,
{
    fn seal_epochs(
        &self,
        group_id: &[u8],
        epochs: Vec<EpochRecord>,
    ) -> Result<Vec<EpochRecord>, SecretStorageError> {
        epochs
            .into_iter()
            .map(|epoch| {
                let context = epoch_context(group_id, epoch.id)?;
                let sealed = self.sealer.seal(&context, &epoch.data)?;
                Ok(EpochRecord::new(
                    epoch.id,
                    Zeroizing::new(sealed.into_bytes()),
                ))
            })
            .collect()
    }
}

impl<S> KeyPackageStorage for SealedMlsStorage<S>
where
    S: KeyPackageStorage,
{
    type Error = SecretStorageError;

    fn delete(&mut self, id: &[u8]) -> Result<(), Self::Error> {
        self.inner
            .delete(id)
            .map_err(|_| backend_failure("KeyPackage delete"))
    }

    fn insert(&mut self, id: Vec<u8>, pkg: KeyPackageData) -> Result<(), Self::Error> {
        let init_context = key_package_context(
            &id,
            KEY_PACKAGE_INIT_FIELD,
            &pkg.key_package_bytes,
            pkg.expiration,
        )?;
        let leaf_context = key_package_context(
            &id,
            KEY_PACKAGE_LEAF_FIELD,
            &pkg.key_package_bytes,
            pkg.expiration,
        )?;
        let sealed_init = self.sealer.seal(&init_context, pkg.init_key.as_ref())?;
        let sealed_leaf = self
            .sealer
            .seal(&leaf_context, pkg.leaf_node_key.as_ref())?;
        let sealed = KeyPackageData::new(
            pkg.key_package_bytes,
            HpkeSecretKey::from(sealed_init.into_bytes()),
            HpkeSecretKey::from(sealed_leaf.into_bytes()),
            pkg.expiration,
        );
        self.inner
            .insert(id, sealed)
            .map_err(|_| backend_failure("KeyPackage insert"))
    }

    fn get(&self, id: &[u8]) -> Result<Option<KeyPackageData>, Self::Error> {
        let Some(pkg) = self
            .inner
            .get(id)
            .map_err(|_| backend_failure("KeyPackage read"))?
        else {
            return Ok(None);
        };
        let init_context = key_package_context(
            id,
            KEY_PACKAGE_INIT_FIELD,
            &pkg.key_package_bytes,
            pkg.expiration,
        )?;
        let leaf_context = key_package_context(
            id,
            KEY_PACKAGE_LEAF_FIELD,
            &pkg.key_package_bytes,
            pkg.expiration,
        )?;
        let init_blob = SealedBlob::from_slice(pkg.init_key.as_ref())?;
        let leaf_blob = SealedBlob::from_slice(pkg.leaf_node_key.as_ref())?;
        let init_key = self.sealer.open(&init_context, &init_blob)?;
        let leaf_key = self.sealer.open(&leaf_context, &leaf_blob)?;
        Ok(Some(KeyPackageData::new(
            pkg.key_package_bytes,
            HpkeSecretKey::from(init_key.to_vec()),
            HpkeSecretKey::from(leaf_key.to_vec()),
            pkg.expiration,
        )))
    }
}

impl IntoAnyError for SecretStorageError {
    fn into_dyn_error(self) -> Result<Box<dyn std::error::Error + Send + Sync>, Self> {
        Ok(Box::new(self))
    }
}

fn epoch_context(
    group_id: &[u8],
    epoch_id: u64,
) -> Result<SecretRecordContext, SecretStorageError> {
    let mut identifier = Vec::with_capacity(group_id.len() + 8);
    identifier.extend_from_slice(group_id);
    identifier.extend_from_slice(&epoch_id.to_be_bytes());
    SecretRecordContext::new(SecretRecordKind::MlsPriorEpoch, identifier)
}

fn key_package_context(
    key_package_id: &[u8],
    field: u8,
    key_package_bytes: &[u8],
    expiration: u64,
) -> Result<SecretRecordContext, SecretStorageError> {
    let mut digest = Context::new(&SHA256);
    digest.update(key_package_bytes);
    digest.update(&expiration.to_be_bytes());
    let metadata_digest = digest.finish();
    let mut identifier =
        Vec::with_capacity(key_package_id.len() + 1 + metadata_digest.as_ref().len());
    identifier.push(field);
    identifier.extend_from_slice(key_package_id);
    identifier.extend_from_slice(metadata_digest.as_ref());
    SecretRecordContext::new(SecretRecordKind::MlsKeyPackage, identifier)
}

const fn backend_failure(operation: &'static str) -> SecretStorageError {
    SecretStorageError::MlsStorageBackendFailure { operation }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::ExternalWrappingKeyProvider;

    #[derive(Clone, Default)]
    struct MemoryStorage {
        data: Arc<Mutex<MemoryData>>,
    }

    #[derive(Default)]
    struct MemoryData {
        state: BTreeMap<Vec<u8>, Zeroizing<Vec<u8>>>,
        epochs: BTreeMap<(Vec<u8>, u64), Zeroizing<Vec<u8>>>,
        key_packages: BTreeMap<Vec<u8>, KeyPackageData>,
    }

    impl GroupStateStorage for MemoryStorage {
        type Error = SecretStorageError;

        fn state(&self, group_id: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>, Self::Error> {
            Ok(self.data.lock().unwrap().state.get(group_id).cloned())
        }

        fn epoch(
            &self,
            group_id: &[u8],
            epoch_id: u64,
        ) -> Result<Option<Zeroizing<Vec<u8>>>, Self::Error> {
            Ok(self
                .data
                .lock()
                .unwrap()
                .epochs
                .get(&(group_id.to_vec(), epoch_id))
                .cloned())
        }

        fn write(
            &mut self,
            state: GroupState,
            epoch_inserts: Vec<EpochRecord>,
            epoch_updates: Vec<EpochRecord>,
        ) -> Result<(), Self::Error> {
            let mut data = self.data.lock().unwrap();
            let group_id = state.id.clone();
            data.state.insert(state.id, state.data);
            for epoch in epoch_inserts.into_iter().chain(epoch_updates) {
                data.epochs.insert((group_id.clone(), epoch.id), epoch.data);
            }
            Ok(())
        }

        fn max_epoch_id(&self, group_id: &[u8]) -> Result<Option<u64>, Self::Error> {
            Ok(self
                .data
                .lock()
                .unwrap()
                .epochs
                .keys()
                .filter(|(stored_group, _)| stored_group == group_id)
                .map(|(_, epoch)| *epoch)
                .max())
        }
    }

    impl KeyPackageStorage for MemoryStorage {
        type Error = SecretStorageError;

        fn delete(&mut self, id: &[u8]) -> Result<(), Self::Error> {
            self.data.lock().unwrap().key_packages.remove(id);
            Ok(())
        }

        fn insert(&mut self, id: Vec<u8>, pkg: KeyPackageData) -> Result<(), Self::Error> {
            self.data.lock().unwrap().key_packages.insert(id, pkg);
            Ok(())
        }

        fn get(&self, id: &[u8]) -> Result<Option<KeyPackageData>, Self::Error> {
            Ok(self.data.lock().unwrap().key_packages.get(id).cloned())
        }
    }

    fn storage() -> (SealedMlsStorage<MemoryStorage>, MemoryStorage) {
        let inner = MemoryStorage::default();
        let sealer =
            SecretSealer::from_provider(ExternalWrappingKeyProvider::from_bytes([7; 32])).unwrap();
        (SealedMlsStorage::new(inner.clone(), sealer), inner)
    }

    #[test]
    fn group_and_epoch_state_cross_the_backend_only_as_ciphertext() {
        let (mut storage, inner) = storage();
        storage
            .write(
                GroupState {
                    id: b"group".to_vec(),
                    data: Zeroizing::new(b"group-secret".to_vec()),
                },
                vec![EpochRecord::new(
                    1,
                    Zeroizing::new(b"epoch-secret".to_vec()),
                )],
                vec![],
            )
            .unwrap();
        let data = inner.data.lock().unwrap();
        assert_ne!(data.state[b"group".as_slice()].as_slice(), b"group-secret");
        assert_ne!(
            data.epochs[&(b"group".to_vec(), 1)].as_slice(),
            b"epoch-secret"
        );
        drop(data);
        assert_eq!(
            storage.state(b"group").unwrap().unwrap().as_slice(),
            b"group-secret"
        );
        assert_eq!(
            storage.epoch(b"group", 1).unwrap().unwrap().as_slice(),
            b"epoch-secret"
        );
        assert_eq!(storage.max_epoch_id(b"group").unwrap(), Some(1));
    }

    #[test]
    fn key_package_private_keys_cross_backend_only_as_ciphertext() {
        let (mut storage, inner) = storage();
        storage
            .insert(
                b"key-package".to_vec(),
                KeyPackageData::new(
                    b"public-package".to_vec(),
                    HpkeSecretKey::from(b"init-secret".to_vec()),
                    HpkeSecretKey::from(b"leaf-secret".to_vec()),
                    100,
                ),
            )
            .unwrap();
        let data = inner.data.lock().unwrap();
        let stored = &data.key_packages[b"key-package".as_slice()];
        assert_eq!(stored.key_package_bytes, b"public-package");
        assert_ne!(stored.init_key.as_ref(), b"init-secret");
        assert_ne!(stored.leaf_node_key.as_ref(), b"leaf-secret");
        drop(data);

        let restored = storage.get(b"key-package").unwrap().unwrap();
        assert_eq!(restored.key_package_bytes, b"public-package");
        assert_eq!(restored.init_key.as_ref(), b"init-secret");
        assert_eq!(restored.leaf_node_key.as_ref(), b"leaf-secret");
        storage.delete(b"key-package").unwrap();
        assert!(storage.get(b"key-package").unwrap().is_none());
    }

    #[test]
    fn key_package_public_metadata_is_bound_to_private_ciphertext() {
        let (mut storage, inner) = storage();
        storage
            .insert(
                b"key-package".to_vec(),
                KeyPackageData::new(
                    b"public-package".to_vec(),
                    HpkeSecretKey::from(b"init-secret".to_vec()),
                    HpkeSecretKey::from(b"leaf-secret".to_vec()),
                    100,
                ),
            )
            .unwrap();
        inner
            .data
            .lock()
            .unwrap()
            .key_packages
            .get_mut(b"key-package".as_slice())
            .unwrap()
            .key_package_bytes = b"tampered-package".to_vec();
        assert_eq!(
            storage.get(b"key-package").err(),
            Some(SecretStorageError::AuthenticationFailed)
        );
    }
}
