use std::sync::{Arc, Mutex, MutexGuard};

use mls_rs_core::group::{EpochRecord, GroupState, GroupStateStorage};
use mls_rs_core::key_package::{KeyPackageData, KeyPackageStorage};
use zeroize::Zeroizing;

use crate::{SealedMlsStorage, SecretStorageError};

trait SealedBackend:
    GroupStateStorage<Error = SecretStorageError> + KeyPackageStorage<Error = SecretStorageError> + Send
{
}

impl<T> SealedBackend for T where
    T: GroupStateStorage<Error = SecretStorageError>
        + KeyPackageStorage<Error = SecretStorageError>
        + Send
{
}

/// Shared, backend-independent handle to already-sealed MLS persistence.
///
/// Construction accepts only the project sealing wrappers, never a raw plaintext
/// backend. Clones share both the underlying storage instance and key ownership.
/// The synchronous provider port remains blocking; hosts select its executor and
/// retain responsibility for atomic backend writes and persistence lifetime.
#[derive(Clone)]
pub struct SealedMlsStorageHandle {
    inner: Arc<Mutex<Box<dyn SealedBackend>>>,
}

impl SealedMlsStorageHandle {
    fn new(storage: impl SealedBackend + 'static) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Box::new(storage))),
        }
    }

    fn lock(&self) -> Result<MutexGuard<'_, Box<dyn SealedBackend>>, SecretStorageError> {
        self.inner
            .lock()
            .map_err(|_| SecretStorageError::MlsStorageBackendFailure {
                operation: "shared sealed MLS storage lock",
            })
    }

    /// Checks authenticated group presence through the existing sealed provider.
    ///
    /// # Errors
    ///
    /// Returns storage, authentication or poisoned-owner errors without a memory
    /// fallback or replacement key.
    pub fn contains_group(&self, group_id: &[u8]) -> Result<bool, SecretStorageError> {
        self.state(group_id).map(|state| state.is_some())
    }
}

impl<S> From<SealedMlsStorage<S>> for SealedMlsStorageHandle
where
    S: GroupStateStorage + KeyPackageStorage + Send + 'static,
{
    fn from(storage: SealedMlsStorage<S>) -> Self {
        Self::new(storage)
    }
}

#[cfg(feature = "sqlite")]
impl From<crate::SealedSqliteMlsStorage> for SealedMlsStorageHandle {
    fn from(storage: crate::SealedSqliteMlsStorage) -> Self {
        Self::new(storage)
    }
}

impl GroupStateStorage for SealedMlsStorageHandle {
    type Error = SecretStorageError;

    fn state(&self, group_id: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>, Self::Error> {
        self.lock()?.state(group_id)
    }

    fn epoch(
        &self,
        group_id: &[u8],
        epoch_id: u64,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, Self::Error> {
        self.lock()?.epoch(group_id, epoch_id)
    }

    fn write(
        &mut self,
        state: GroupState,
        epoch_inserts: Vec<EpochRecord>,
        epoch_updates: Vec<EpochRecord>,
    ) -> Result<(), Self::Error> {
        self.lock()?.write(state, epoch_inserts, epoch_updates)
    }

    fn max_epoch_id(&self, group_id: &[u8]) -> Result<Option<u64>, Self::Error> {
        self.lock()?.max_epoch_id(group_id)
    }
}

impl KeyPackageStorage for SealedMlsStorageHandle {
    type Error = SecretStorageError;

    fn delete(&mut self, id: &[u8]) -> Result<(), Self::Error> {
        self.lock()?.delete(id)
    }

    fn insert(&mut self, id: Vec<u8>, package: KeyPackageData) -> Result<(), Self::Error> {
        self.lock()?.insert(id, package)
    }

    fn get(&self, id: &[u8]) -> Result<Option<KeyPackageData>, Self::Error> {
        self.lock()?.get(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mls_storage::tests::storage;
    use mls_rs_core::crypto::HpkeSecretKey;

    #[test]
    fn cloned_handles_share_a_sealed_non_sqlite_backend() {
        let (sealed, raw) = storage();
        let mut handle = SealedMlsStorageHandle::from(sealed);
        assert!(!handle.contains_group(b"group").unwrap());
        handle
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
        let mut other = handle.clone();
        other
            .insert(
                b"package".to_vec(),
                KeyPackageData::new(
                    b"public-package".to_vec(),
                    HpkeSecretKey::from(b"init-secret".to_vec()),
                    HpkeSecretKey::from(b"leaf-secret".to_vec()),
                    100,
                ),
            )
            .unwrap();
        assert!(other.contains_group(b"group").unwrap());
        assert_eq!(
            other.state(b"group").unwrap().unwrap().as_slice(),
            b"group-secret"
        );
        assert_eq!(
            other.epoch(b"group", 1).unwrap().unwrap().as_slice(),
            b"epoch-secret"
        );
        assert_eq!(other.max_epoch_id(b"group").unwrap(), Some(1));
        assert_eq!(
            handle.get(b"package").unwrap().unwrap().init_key.as_ref(),
            b"init-secret"
        );
        assert_ne!(
            raw.state(b"group").unwrap().unwrap().as_slice(),
            b"group-secret"
        );
        assert_ne!(
            raw.get(b"package").unwrap().unwrap().init_key.as_ref(),
            b"init-secret"
        );
        other.delete(b"package").unwrap();
        assert!(handle.get(b"package").unwrap().is_none());
    }

    #[test]
    fn poisoned_storage_ownership_fails_without_fallback() {
        let (sealed, _) = storage();
        let handle = SealedMlsStorageHandle::from(sealed);
        let poison = handle.clone();
        assert!(
            std::thread::spawn(move || {
                let _guard = poison.inner.lock().unwrap();
                panic!("synthetic storage-owner failure");
            })
            .join()
            .is_err()
        );
        assert!(matches!(
            handle.state(b"group"),
            Err(SecretStorageError::MlsStorageBackendFailure { .. })
        ));
    }
}
