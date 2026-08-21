use std::path::Path;
use std::sync::{Arc, Mutex};

use mls_rs_core::crypto::HpkeSecretKey;
use mls_rs_core::error::IntoAnyError;
use mls_rs_core::group::{EpochRecord, GroupState, GroupStateStorage};
use mls_rs_core::key_package::{KeyPackageData, KeyPackageStorage};
use rusqlite::{Connection, OptionalExtension, params};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::{SealedMlsStorage, SecretSealer, SecretStorageError};

/// File-backed SQLite MLS storage that never exposes its ciphertext backend.
#[derive(Clone)]
pub struct SealedSqliteMlsStorage {
    sealed: SealedMlsStorage<SqliteCiphertextStorage>,
}

impl SealedSqliteMlsStorage {
    /// Opens or creates a profile database and wraps it with the provided sealer.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed backend error when SQLite cannot open or migrate.
    pub fn open(path: &Path, sealer: SecretSealer) -> Result<Self, SecretStorageError> {
        let connection = Connection::open(path).map_err(|_| backend_failure("SQLite open"))?;
        initialize_schema(&connection)?;
        Ok(Self {
            sealed: SealedMlsStorage::new(
                SqliteCiphertextStorage {
                    connection: Arc::new(Mutex::new(connection)),
                },
                sealer,
            ),
        })
    }

    /// Returns whether sealed MLS group state exists for the exact group identifier.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed backend error when storage cannot be read or opened.
    pub fn contains_group(&self, group_id: &[u8]) -> Result<bool, SecretStorageError> {
        self.sealed.state(group_id).map(|state| state.is_some())
    }
}

impl GroupStateStorage for SealedSqliteMlsStorage {
    type Error = SecretStorageError;

    fn state(&self, group_id: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>, Self::Error> {
        self.sealed.state(group_id)
    }

    fn epoch(
        &self,
        group_id: &[u8],
        epoch_id: u64,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, Self::Error> {
        self.sealed.epoch(group_id, epoch_id)
    }

    fn write(
        &mut self,
        state: GroupState,
        epoch_inserts: Vec<EpochRecord>,
        epoch_updates: Vec<EpochRecord>,
    ) -> Result<(), Self::Error> {
        self.sealed.write(state, epoch_inserts, epoch_updates)
    }

    fn max_epoch_id(&self, group_id: &[u8]) -> Result<Option<u64>, Self::Error> {
        self.sealed.max_epoch_id(group_id)
    }
}

impl KeyPackageStorage for SealedSqliteMlsStorage {
    type Error = SecretStorageError;

    fn delete(&mut self, id: &[u8]) -> Result<(), Self::Error> {
        self.sealed.delete(id)
    }

    fn insert(&mut self, id: Vec<u8>, pkg: KeyPackageData) -> Result<(), Self::Error> {
        self.sealed.insert(id, pkg)
    }

    fn get(&self, id: &[u8]) -> Result<Option<KeyPackageData>, Self::Error> {
        self.sealed.get(id)
    }
}

#[derive(Clone)]
struct SqliteCiphertextStorage {
    connection: Arc<Mutex<Connection>>,
}

impl GroupStateStorage for SqliteCiphertextStorage {
    type Error = SqliteCiphertextError;

    fn state(&self, group_id: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>, Self::Error> {
        let connection = self.connection.lock().map_err(|_| SqliteCiphertextError)?;
        connection
            .query_row(
                "SELECT sealed_state FROM konclave_mls_group WHERE group_id = ?1",
                params![group_id],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map(|value| value.map(Zeroizing::new))
            .map_err(|_| SqliteCiphertextError)
    }

    fn epoch(
        &self,
        group_id: &[u8],
        epoch_id: u64,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, Self::Error> {
        let epoch_id = to_sql_integer(epoch_id)?;
        let connection = self.connection.lock().map_err(|_| SqliteCiphertextError)?;
        connection
            .query_row(
                "SELECT sealed_epoch FROM konclave_mls_epoch
                 WHERE group_id = ?1 AND epoch_id = ?2",
                params![group_id, epoch_id],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map(|value| value.map(Zeroizing::new))
            .map_err(|_| SqliteCiphertextError)
    }

    fn write(
        &mut self,
        state: GroupState,
        epoch_inserts: Vec<EpochRecord>,
        epoch_updates: Vec<EpochRecord>,
    ) -> Result<(), Self::Error> {
        let mut connection = self.connection.lock().map_err(|_| SqliteCiphertextError)?;
        let transaction = connection
            .transaction()
            .map_err(|_| SqliteCiphertextError)?;
        transaction
            .execute(
                "INSERT INTO konclave_mls_group (group_id, sealed_state)
                 VALUES (?1, ?2)
                 ON CONFLICT(group_id) DO UPDATE SET sealed_state = excluded.sealed_state",
                params![state.id, state.data.as_slice()],
            )
            .map_err(|_| SqliteCiphertextError)?;
        for epoch in epoch_inserts.into_iter().chain(epoch_updates) {
            transaction
                .execute(
                    "INSERT INTO konclave_mls_epoch (group_id, epoch_id, sealed_epoch)
                     VALUES (?1, ?2, ?3)
                     ON CONFLICT(group_id, epoch_id)
                     DO UPDATE SET sealed_epoch = excluded.sealed_epoch",
                    params![state.id, to_sql_integer(epoch.id)?, epoch.data.as_slice()],
                )
                .map_err(|_| SqliteCiphertextError)?;
        }
        transaction.commit().map_err(|_| SqliteCiphertextError)
    }

    fn max_epoch_id(&self, group_id: &[u8]) -> Result<Option<u64>, Self::Error> {
        let connection = self.connection.lock().map_err(|_| SqliteCiphertextError)?;
        let value = connection
            .query_row(
                "SELECT MAX(epoch_id) FROM konclave_mls_epoch WHERE group_id = ?1",
                params![group_id],
                |row| row.get::<_, Option<i64>>(0),
            )
            .map_err(|_| SqliteCiphertextError)?;
        value
            .map(|value| u64::try_from(value).map_err(|_| SqliteCiphertextError))
            .transpose()
    }
}

impl KeyPackageStorage for SqliteCiphertextStorage {
    type Error = SqliteCiphertextError;

    fn delete(&mut self, id: &[u8]) -> Result<(), Self::Error> {
        let connection = self.connection.lock().map_err(|_| SqliteCiphertextError)?;
        connection
            .execute(
                "DELETE FROM konclave_mls_key_package WHERE key_package_id = ?1",
                params![id],
            )
            .map(|_| ())
            .map_err(|_| SqliteCiphertextError)
    }

    fn insert(&mut self, id: Vec<u8>, pkg: KeyPackageData) -> Result<(), Self::Error> {
        let expiration = to_sql_integer(pkg.expiration)?;
        let connection = self.connection.lock().map_err(|_| SqliteCiphertextError)?;
        connection
            .execute(
                "INSERT INTO konclave_mls_key_package (
                    key_package_id,
                    public_key_package,
                    sealed_init_key,
                    sealed_leaf_key,
                    expiration
                 ) VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(key_package_id) DO UPDATE SET
                    public_key_package = excluded.public_key_package,
                    sealed_init_key = excluded.sealed_init_key,
                    sealed_leaf_key = excluded.sealed_leaf_key,
                    expiration = excluded.expiration",
                params![
                    id,
                    pkg.key_package_bytes,
                    pkg.init_key.as_ref(),
                    pkg.leaf_node_key.as_ref(),
                    expiration
                ],
            )
            .map(|_| ())
            .map_err(|_| SqliteCiphertextError)
    }

    fn get(&self, id: &[u8]) -> Result<Option<KeyPackageData>, Self::Error> {
        let connection = self.connection.lock().map_err(|_| SqliteCiphertextError)?;
        connection
            .query_row(
                "SELECT public_key_package, sealed_init_key, sealed_leaf_key, expiration
                 FROM konclave_mls_key_package
                 WHERE key_package_id = ?1",
                params![id],
                |row| {
                    let expiration = row.get::<_, i64>(3)?;
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        expiration,
                    ))
                },
            )
            .optional()
            .map_err(|_| SqliteCiphertextError)?
            .map(|(public, init, leaf, expiration)| {
                Ok(KeyPackageData::new(
                    public,
                    HpkeSecretKey::from(init),
                    HpkeSecretKey::from(leaf),
                    u64::try_from(expiration).map_err(|_| SqliteCiphertextError)?,
                ))
            })
            .transpose()
    }
}

#[derive(Debug, Error)]
#[error("SQLite ciphertext storage failed")]
struct SqliteCiphertextError;

impl IntoAnyError for SqliteCiphertextError {
    fn into_dyn_error(self) -> Result<Box<dyn std::error::Error + Send + Sync>, Self> {
        Ok(Box::new(self))
    }
}

fn initialize_schema(connection: &Connection) -> Result<(), SecretStorageError> {
    connection
        .pragma_update(None, "foreign_keys", "ON")
        .map_err(|_| backend_failure("SQLite foreign-key configuration"))?;
    let version = connection
        .pragma_query_value(None, "user_version", |row| row.get::<_, u32>(0))
        .map_err(|_| backend_failure("SQLite schema version read"))?;
    if version == 1 {
        return Ok(());
    }
    if version != 0 {
        return Err(backend_failure("SQLite schema version"));
    }
    connection
        .execute_batch(
            "BEGIN;
             CREATE TABLE konclave_mls_group (
                group_id BLOB PRIMARY KEY,
                sealed_state BLOB NOT NULL
             ) WITHOUT ROWID;
             CREATE TABLE konclave_mls_epoch (
                group_id BLOB NOT NULL,
                epoch_id INTEGER NOT NULL,
                sealed_epoch BLOB NOT NULL,
                PRIMARY KEY (group_id, epoch_id),
                FOREIGN KEY (group_id)
                    REFERENCES konclave_mls_group(group_id)
                    ON DELETE CASCADE
             ) WITHOUT ROWID;
             CREATE TABLE konclave_mls_key_package (
                key_package_id BLOB PRIMARY KEY,
                public_key_package BLOB NOT NULL,
                sealed_init_key BLOB NOT NULL,
                sealed_leaf_key BLOB NOT NULL,
                expiration INTEGER NOT NULL
             ) WITHOUT ROWID;
             CREATE INDEX konclave_mls_key_package_expiration
                ON konclave_mls_key_package(expiration);
             PRAGMA user_version = 1;
             COMMIT;",
        )
        .map_err(|_| backend_failure("SQLite schema initialization"))
}

fn to_sql_integer(value: u64) -> Result<i64, SqliteCiphertextError> {
    i64::try_from(value).map_err(|_| SqliteCiphertextError)
}

const fn backend_failure(operation: &'static str) -> SecretStorageError {
    SecretStorageError::MlsStorageBackendFailure { operation }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ExternalWrappingKeyProvider;
    use tempfile::tempdir;

    fn sealer() -> SecretSealer {
        SecretSealer::from_provider(ExternalWrappingKeyProvider::from_bytes([7; 32])).unwrap()
    }

    #[test]
    fn sqlite_reopens_group_epochs_and_key_packages_without_plaintext_rows() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("mls.sqlite");
        let mut storage = SealedSqliteMlsStorage::open(&path, sealer()).unwrap();
        assert!(!storage.contains_group(b"group").unwrap());
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
        assert!(storage.contains_group(b"group").unwrap());
        storage
            .insert(
                b"package".to_vec(),
                KeyPackageData::new(
                    b"public".to_vec(),
                    HpkeSecretKey::from(b"init-secret".to_vec()),
                    HpkeSecretKey::from(b"leaf-secret".to_vec()),
                    100,
                ),
            )
            .unwrap();
        drop(storage);

        let connection = Connection::open(&path).unwrap();
        let version: u32 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, 1);
        let raw_group: Vec<u8> = connection
            .query_row("SELECT sealed_state FROM konclave_mls_group", [], |row| {
                row.get(0)
            })
            .unwrap();
        let raw_package: (Vec<u8>, Vec<u8>) = connection
            .query_row(
                "SELECT sealed_init_key, sealed_leaf_key
                 FROM konclave_mls_key_package",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_ne!(raw_group, b"group-secret");
        assert_ne!(raw_package.0, b"init-secret");
        assert_ne!(raw_package.1, b"leaf-secret");
        drop(connection);

        let storage = SealedSqliteMlsStorage::open(&path, sealer()).unwrap();
        assert!(storage.contains_group(b"group").unwrap());
        assert_eq!(
            storage.state(b"group").unwrap().unwrap().as_slice(),
            b"group-secret"
        );
        assert_eq!(
            storage.epoch(b"group", 1).unwrap().unwrap().as_slice(),
            b"epoch-secret"
        );
        let package = storage.get(b"package").unwrap().unwrap();
        assert_eq!(package.init_key.as_ref(), b"init-secret");
        assert_eq!(package.leaf_node_key.as_ref(), b"leaf-secret");
    }

    #[test]
    fn sqlite_group_write_is_atomic_on_epoch_failure() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("mls.sqlite");
        let mut storage = SealedSqliteMlsStorage::open(&path, sealer()).unwrap();
        let result = storage.write(
            GroupState {
                id: b"group".to_vec(),
                data: Zeroizing::new(b"group-secret".to_vec()),
            },
            vec![EpochRecord::new(
                u64::MAX,
                Zeroizing::new(b"invalid-epoch".to_vec()),
            )],
            vec![],
        );
        assert!(result.is_err());
        assert!(storage.state(b"group").unwrap().is_none());
    }

    #[test]
    fn sqlite_rejects_unknown_schema_versions() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("mls.sqlite");
        let connection = Connection::open(&path).unwrap();
        connection.pragma_update(None, "user_version", 2).unwrap();
        drop(connection);
        assert_eq!(
            SealedSqliteMlsStorage::open(&path, sealer()).err(),
            Some(SecretStorageError::MlsStorageBackendFailure {
                operation: "SQLite schema version"
            })
        );
    }
}
