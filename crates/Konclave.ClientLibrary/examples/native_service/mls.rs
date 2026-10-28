//! Bounded service-owned MLS persistence, with project sealing at both boundaries.
//! Slots are individually atomic; this is not a journal/MLS transaction or rollback defense.

use std::sync::Arc;

use KonclaveSecretStorage::{
    SealedBlob, SealedMlsStorage, SecretRecordContext, SecretRecordKind, SecretSealer,
    SecretStorageError,
};
use mls_rs_core::crypto::HpkeSecretKey;
use mls_rs_core::error::IntoAnyError;
use mls_rs_core::group::{EpochRecord, GroupState, GroupStateStorage};
use mls_rs_core::key_package::{KeyPackageData, KeyPackageStorage};
use zeroize::Zeroizing;

use super::storage::{ServiceStorage, SnapshotKind, StorageError};

const MAGIC: &[u8; 8] = b"KNSMLS01";
const MAX_GROUPS: usize = 64;
const MAX_EPOCHS: usize = 256;
const MAX_PACKAGES: usize = 256;
const MAX_ID: usize = 64;
const MAX_RECORD: usize = 1024 * 1024;
const MAX_ENCODED: usize = 8 * 1024 * 1024;

/// Finite diagnostics, never containing record bytes, paths, or custody details.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MlsStorageError {
    #[error("MLS storage owner failed")]
    Storage(#[from] StorageError),
    #[error("invalid MLS snapshot or record")]
    Invalid,
    #[error("MLS storage capacity exceeded")]
    Capacity,
    #[error("MLS backing operation failed")]
    Backend,
    #[error("MLS snapshot protection failed")]
    Protection,
}

impl IntoAnyError for MlsStorageError {
    fn into_dyn_error(self) -> Result<Box<dyn std::error::Error + Send + Sync>, Self> {
        Ok(Box::new(self))
    }
}

/// Only exposes the project-sealed provider adapter, never its raw backing store.
#[derive(Clone)]
pub struct ServiceMlsStorage {
    sealed: SealedMlsStorage<CiphertextStorage>,
}

impl ServiceMlsStorage {
    /// Transfers the existing project-sealed provider into native client composition.
    pub fn into_handle(self) -> KonclaveSecretStorage::SealedMlsStorageHandle {
        self.sealed.into()
    }

    /// Binds an existing exclusive owner to explicit custody and an endpoint namespace.
    ///
    /// Namespace bytes must be stable, nonempty, and at most 128 bytes. No custody
    /// discovery, owner acquisition, or fallback occurs here. Clones and separately
    /// constructed handles from the same owner reload under that owner's mutex.
    ///
    /// # Errors
    /// Rejects invalid context, released ownership, and malformed or unauthentic snapshots.
    pub fn new(
        storage: ServiceStorage,
        sealer: SecretSealer,
        namespace: &[u8],
    ) -> Result<Self, MlsStorageError> {
        if namespace.is_empty() || namespace.len() > 128 {
            return Err(MlsStorageError::Invalid);
        }
        let binding = SecretRecordContext::derive(
            SecretRecordKind::MlsGroupState,
            &[b"native-service-mls-snapshot-v1", namespace],
        )
        .map_err(|_| MlsStorageError::Invalid)?;
        // The prefixed identifier exceeds MAX_ID, so no inner group record can
        // authenticate as an outer snapshot even when its ID is attacker-selected.
        let mut identifier = b"konclave-native-service-mls-outer-snapshot-v1\0".to_vec();
        identifier.extend_from_slice(binding.identifier());
        let context = SecretRecordContext::new(SecretRecordKind::MlsGroupState, identifier)
            .map_err(|_| MlsStorageError::Invalid)?;
        let backend = CiphertextStorage {
            storage,
            sealer: Arc::new(sealer.share()),
            context,
        };
        backend.read()?;
        Ok(Self {
            sealed: SealedMlsStorage::new(backend, sealer),
        })
    }
}

fn identifier(id: &[u8]) -> Result<(), MlsStorageError> {
    field(id, MAX_ID)
}

fn field(bytes: &[u8], maximum: usize) -> Result<(), MlsStorageError> {
    if bytes.is_empty() {
        Err(MlsStorageError::Invalid)
    } else if bytes.len() > maximum {
        Err(MlsStorageError::Capacity)
    } else {
        Ok(())
    }
}

fn protection(error: SecretStorageError) -> MlsStorageError {
    match error {
        SecretStorageError::MlsStorageBackendFailure { .. } => MlsStorageError::Backend,
        _ => MlsStorageError::Protection,
    }
}

impl GroupStateStorage for ServiceMlsStorage {
    type Error = MlsStorageError;

    fn state(&self, id: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>, Self::Error> {
        identifier(id)?;
        self.sealed.state(id).map_err(protection)
    }

    fn epoch(&self, id: &[u8], epoch: u64) -> Result<Option<Zeroizing<Vec<u8>>>, Self::Error> {
        identifier(id)?;
        self.sealed.epoch(id, epoch).map_err(protection)
    }

    fn write(
        &mut self,
        state: GroupState,
        inserts: Vec<EpochRecord>,
        updates: Vec<EpochRecord>,
    ) -> Result<(), Self::Error> {
        identifier(&state.id)?;
        field(&state.data, MAX_RECORD - 64)?;
        if inserts.len().saturating_add(updates.len()) > MAX_EPOCHS {
            return Err(MlsStorageError::Capacity);
        }
        for epoch in inserts.iter().chain(&updates) {
            field(&epoch.data, MAX_RECORD - 64)?;
        }
        let mut incoming = 16;
        budget(&mut incoming, &state.id, MAX_ID)?;
        budget(&mut incoming, &state.data, MAX_RECORD)?;
        for epoch in inserts.iter().chain(&updates) {
            incoming += 8 + 64;
            budget(&mut incoming, &epoch.data, MAX_RECORD)?;
        }
        self.sealed
            .write(state, inserts, updates)
            .map_err(protection)
    }

    fn max_epoch_id(&self, id: &[u8]) -> Result<Option<u64>, Self::Error> {
        identifier(id)?;
        self.sealed.max_epoch_id(id).map_err(protection)
    }
}

impl KeyPackageStorage for ServiceMlsStorage {
    type Error = MlsStorageError;

    fn delete(&mut self, id: &[u8]) -> Result<(), Self::Error> {
        identifier(id)?;
        self.sealed.delete(id).map_err(protection)
    }

    fn insert(&mut self, id: Vec<u8>, pkg: KeyPackageData) -> Result<(), Self::Error> {
        identifier(&id)?;
        field(&pkg.key_package_bytes, MAX_RECORD)?;
        field(pkg.init_key.as_ref(), MAX_RECORD - 64)?;
        field(pkg.leaf_node_key.as_ref(), MAX_RECORD - 64)?;
        self.sealed.insert(id, pkg).map_err(protection)
    }

    fn get(&self, id: &[u8]) -> Result<Option<KeyPackageData>, Self::Error> {
        identifier(id)?;
        self.sealed.get(id).map_err(protection)
    }
}

#[derive(Clone)]
struct CiphertextStorage {
    storage: ServiceStorage,
    sealer: Arc<SecretSealer>,
    context: SecretRecordContext,
}

#[derive(Default)]
struct Rows {
    groups: Vec<Group>,
    packages: Vec<Package>,
}

struct Group {
    id: Vec<u8>,
    data: Vec<u8>,
    epochs: Vec<(u64, Vec<u8>)>,
}

struct Package {
    id: Vec<u8>,
    public: Vec<u8>,
    init: Vec<u8>,
    leaf: Vec<u8>,
    expiration: u64,
}

impl CiphertextStorage {
    fn decode(&self, bytes: Option<&[u8]>) -> Result<Rows, MlsStorageError> {
        let Some(bytes) = bytes else {
            return Ok(Rows::default());
        };
        if bytes.len() > MAX_ENCODED + 64 {
            return Err(MlsStorageError::Capacity);
        }
        let blob = SealedBlob::from_slice(bytes).map_err(protection)?;
        let plaintext = self.sealer.open(&self.context, &blob).map_err(protection)?;
        decode(&plaintext)
    }

    fn read(&self) -> Result<Rows, MlsStorageError> {
        self.decode(self.storage.read_slot(SnapshotKind::Mls)?.as_deref())
    }

    fn update(
        &self,
        update: impl FnOnce(&mut Rows) -> Result<(), MlsStorageError>,
    ) -> Result<(), MlsStorageError> {
        self.storage.update_slot(SnapshotKind::Mls, |bytes| {
            let mut rows = self.decode(bytes)?;
            update(&mut rows)?;
            let encoded = Zeroizing::new(encode(&rows)?);
            let sealed = self
                .sealer
                .seal(&self.context, &encoded)
                .map_err(protection)?;
            Ok((sealed.into_bytes(), ()))
        })
    }
}

impl GroupStateStorage for CiphertextStorage {
    type Error = MlsStorageError;

    fn state(&self, id: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>, Self::Error> {
        identifier(id)?;
        Ok(self
            .read()?
            .groups
            .into_iter()
            .find(|g| g.id == id)
            .map(|g| Zeroizing::new(g.data)))
    }

    fn epoch(&self, id: &[u8], epoch: u64) -> Result<Option<Zeroizing<Vec<u8>>>, Self::Error> {
        identifier(id)?;
        Ok(self
            .read()?
            .groups
            .into_iter()
            .find(|g| g.id == id)
            .and_then(|g| g.epochs.into_iter().find(|(e, _)| *e == epoch))
            .map(|(_, data)| Zeroizing::new(data)))
    }

    fn write(
        &mut self,
        state: GroupState,
        inserts: Vec<EpochRecord>,
        updates: Vec<EpochRecord>,
    ) -> Result<(), Self::Error> {
        identifier(&state.id)?;
        field(&state.data, MAX_RECORD)?;
        if inserts.len().saturating_add(updates.len()) > MAX_EPOCHS {
            return Err(MlsStorageError::Capacity);
        }
        for epoch in inserts.iter().chain(&updates) {
            field(&epoch.data, MAX_RECORD)?;
        }
        self.update(|rows| {
            let position = rows.groups.iter().position(|g| g.id == state.id);
            let group = match position {
                Some(index) => &mut rows.groups[index],
                None => {
                    if rows.groups.len() >= MAX_GROUPS {
                        return Err(MlsStorageError::Capacity);
                    }
                    rows.groups.push(Group {
                        id: state.id,
                        data: Vec::new(),
                        epochs: Vec::new(),
                    });
                    rows.groups.last_mut().ok_or(MlsStorageError::Invalid)?
                }
            };
            group.data = state.data.to_vec();
            for epoch in inserts.into_iter().chain(updates) {
                if let Some((_, data)) =
                    group.epochs.iter_mut().find(|(id, _)| *id == epoch.id)
                {
                    *data = epoch.data.to_vec();
                } else {
                    if group.epochs.len() >= MAX_EPOCHS {
                        return Err(MlsStorageError::Capacity);
                    }
                    group.epochs.push((epoch.id, epoch.data.to_vec()));
                }
            }
            Ok(())
        })
    }

    fn max_epoch_id(&self, id: &[u8]) -> Result<Option<u64>, Self::Error> {
        identifier(id)?;
        Ok(self
            .read()?
            .groups
            .into_iter()
            .find(|g| g.id == id)
            .and_then(|g| g.epochs.iter().map(|(id, _)| *id).max()))
    }
}

impl KeyPackageStorage for CiphertextStorage {
    type Error = MlsStorageError;

    fn delete(&mut self, id: &[u8]) -> Result<(), Self::Error> {
        identifier(id)?;
        self.update(|rows| {
            rows.packages.retain(|p| p.id != id);
            Ok(())
        })
    }

    fn insert(&mut self, id: Vec<u8>, pkg: KeyPackageData) -> Result<(), Self::Error> {
        identifier(&id)?;
        field(&pkg.key_package_bytes, MAX_RECORD)?;
        field(pkg.init_key.as_ref(), MAX_RECORD)?;
        field(pkg.leaf_node_key.as_ref(), MAX_RECORD)?;
        self.update(|rows| {
            let position = rows.packages.iter().position(|p| p.id == id);
            if position.is_none() && rows.packages.len() >= MAX_PACKAGES {
                return Err(MlsStorageError::Capacity);
            }
            let package = Package {
                id,
                public: pkg.key_package_bytes,
                init: pkg.init_key.as_ref().to_vec(),
                leaf: pkg.leaf_node_key.as_ref().to_vec(),
                expiration: pkg.expiration,
            };
            if let Some(index) = position {
                rows.packages[index] = package;
            } else {
                rows.packages.push(package);
            }
            Ok(())
        })
    }

    fn get(&self, id: &[u8]) -> Result<Option<KeyPackageData>, Self::Error> {
        identifier(id)?;
        Ok(self
            .read()?
            .packages
            .into_iter()
            .find(|p| p.id == id)
            .map(|p| {
                KeyPackageData::new(
                    p.public,
                    HpkeSecretKey::from(p.init),
                    HpkeSecretKey::from(p.leaf),
                    p.expiration,
                )
            }))
    }
}

fn budget(total: &mut usize, bytes: &[u8], maximum: usize) -> Result<(), MlsStorageError> {
    field(bytes, maximum)?;
    *total = total
        .checked_add(4 + bytes.len())
        .ok_or(MlsStorageError::Capacity)?;
    if *total > MAX_ENCODED {
        return Err(MlsStorageError::Capacity);
    }
    Ok(())
}

fn encode(rows: &Rows) -> Result<Vec<u8>, MlsStorageError> {
    if rows.groups.len() > MAX_GROUPS || rows.packages.len() > MAX_PACKAGES {
        return Err(MlsStorageError::Capacity);
    }
    let mut total = 16;
    for group in &rows.groups {
        budget(&mut total, &group.id, MAX_ID)?;
        budget(&mut total, &group.data, MAX_RECORD)?;
        if group.epochs.len() > MAX_EPOCHS {
            return Err(MlsStorageError::Capacity);
        }
        total += 4;
        for (_, data) in &group.epochs {
            total += 8;
            budget(&mut total, data, MAX_RECORD)?;
        }
    }
    for package in &rows.packages {
        total += 8;
        budget(&mut total, &package.id, MAX_ID)?;
        for bytes in [&package.public, &package.init, &package.leaf] {
            budget(&mut total, bytes, MAX_RECORD)?;
        }
    }
    if total > MAX_ENCODED {
        return Err(MlsStorageError::Capacity);
    }
    let mut out = Vec::new();
    out.try_reserve_exact(total)
        .map_err(|_| MlsStorageError::Capacity)?;
    out.extend_from_slice(MAGIC);
    put_u32(&mut out, rows.groups.len());
    put_u32(&mut out, rows.packages.len());
    for group in &rows.groups {
        put(&mut out, &group.id);
        put(&mut out, &group.data);
        put_u32(&mut out, group.epochs.len());
        for (id, data) in &group.epochs {
            out.extend_from_slice(&id.to_be_bytes());
            put(&mut out, data);
        }
    }
    for package in &rows.packages {
        put(&mut out, &package.id);
        put(&mut out, &package.public);
        put(&mut out, &package.init);
        put(&mut out, &package.leaf);
        out.extend_from_slice(&package.expiration.to_be_bytes());
    }
    Ok(out)
}

fn put_u32(out: &mut Vec<u8>, value: usize) {
    out.extend_from_slice(&(value as u32).to_be_bytes());
}

fn put(out: &mut Vec<u8>, bytes: &[u8]) {
    put_u32(out, bytes.len());
    out.extend_from_slice(bytes);
}

struct Reader<'a>(&'a [u8]);

impl Reader<'_> {
    fn take(&mut self, length: usize) -> Result<&[u8], MlsStorageError> {
        if length > self.0.len() {
            return Err(MlsStorageError::Invalid);
        }
        let (head, tail) = self.0.split_at(length);
        self.0 = tail;
        Ok(head)
    }

    fn count(&mut self, maximum: usize) -> Result<usize, MlsStorageError> {
        let bytes: [u8; 4] = self
            .take(4)?
            .try_into()
            .map_err(|_| MlsStorageError::Invalid)?;
        let value = u32::from_be_bytes(bytes) as usize;
        if value > maximum {
            return Err(MlsStorageError::Capacity);
        }
        Ok(value)
    }

    fn bytes(&mut self, maximum: usize) -> Result<Vec<u8>, MlsStorageError> {
        let length = self.count(maximum)?;
        let bytes = self.take(length)?;
        field(bytes, maximum)?;
        Ok(bytes.to_vec())
    }

    fn u64(&mut self) -> Result<u64, MlsStorageError> {
        Ok(u64::from_be_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| MlsStorageError::Invalid)?,
        ))
    }
}

fn decode(bytes: &[u8]) -> Result<Rows, MlsStorageError> {
    if bytes.len() > MAX_ENCODED {
        return Err(MlsStorageError::Capacity);
    }
    let mut reader = Reader(bytes);
    if reader.take(8)? != MAGIC {
        return Err(MlsStorageError::Invalid);
    }
    let groups = reader.count(MAX_GROUPS)?;
    let packages = reader.count(MAX_PACKAGES)?;
    let mut rows = Rows::default();
    for _ in 0..groups {
        let id = reader.bytes(MAX_ID)?;
        if rows.groups.iter().any(|g| g.id == id) {
            return Err(MlsStorageError::Invalid);
        }
        let data = reader.bytes(MAX_RECORD)?;
        let count = reader.count(MAX_EPOCHS)?;
        let mut epochs = Vec::new();
        for _ in 0..count {
            let epoch = reader.u64()?;
            if epochs.iter().any(|(id, _)| *id == epoch) {
                return Err(MlsStorageError::Invalid);
            }
            epochs.push((epoch, reader.bytes(MAX_RECORD)?));
        }
        rows.groups.push(Group { id, data, epochs });
    }
    for _ in 0..packages {
        let id = reader.bytes(MAX_ID)?;
        if rows.packages.iter().any(|p| p.id == id) {
            return Err(MlsStorageError::Invalid);
        }
        rows.packages.push(Package {
            id,
            public: reader.bytes(MAX_RECORD)?,
            init: reader.bytes(MAX_RECORD)?,
            leaf: reader.bytes(MAX_RECORD)?,
            expiration: reader.u64()?,
        });
    }
    if !reader.0.is_empty() {
        return Err(MlsStorageError::Invalid);
    }
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finite_codec_rejections_and_boundaries() {
        let valid = encode(&Rows::default()).unwrap();
        assert!(decode(&valid).is_ok());
        for length in 0..valid.len() {
            assert!(matches!(
                decode(&valid[..length]),
                Err(MlsStorageError::Invalid)
            ));
        }
        let mut unknown = valid.clone();
        unknown[7] = b'2';
        let mut trailing = valid.clone();
        trailing.push(0);
        let mut groups = valid.clone();
        groups[8..12].copy_from_slice(&65_u32.to_be_bytes());
        let mut packages = valid;
        packages[12..16].copy_from_slice(&257_u32.to_be_bytes());
        for (bytes, error) in [
            (unknown, MlsStorageError::Invalid),
            (trailing, MlsStorageError::Invalid),
            (groups, MlsStorageError::Capacity),
            (packages, MlsStorageError::Capacity),
        ] {
            assert!(matches!(decode(&bytes), Err(actual) if actual == error));
        }
        for (length, maximum, expected) in [
            (0, MAX_ID, Err(MlsStorageError::Invalid)),
            (MAX_ID, MAX_ID, Ok(())),
            (MAX_ID + 1, MAX_ID, Err(MlsStorageError::Capacity)),
            (MAX_RECORD, MAX_RECORD, Ok(())),
            (MAX_RECORD + 1, MAX_RECORD, Err(MlsStorageError::Capacity)),
        ] {
            assert_eq!(field(&vec![1; length], maximum), expected);
        }
    }

    fn group() -> Group {
        Group {
            id: vec![1],
            data: vec![2],
            epochs: vec![(3, vec![4])],
        }
    }

    fn package() -> Package {
        Package {
            id: vec![5],
            public: vec![6],
            init: vec![7],
            leaf: vec![8],
            expiration: u64::MAX,
        }
    }

    #[test]
    fn codec_rejects_duplicate_rows_and_invalid_fields() {
        for rows in [
            Rows {
                groups: vec![group(), group()],
                packages: vec![],
            },
            Rows {
                groups: vec![Group {
                    id: vec![1],
                    data: vec![2],
                    epochs: vec![(3, vec![4]), (3, vec![5])],
                }],
                packages: vec![],
            },
            Rows {
                groups: vec![],
                packages: vec![package(), package()],
            },
        ] {
            let bytes = encode(&rows).unwrap();
            assert!(matches!(decode(&bytes), Err(MlsStorageError::Invalid)));
        }
        let rows = Rows {
            groups: vec![group()],
            packages: vec![package()],
        };
        let valid = encode(&rows).unwrap();
        assert_eq!(encode(&decode(&valid).unwrap()).unwrap(), valid);
        for length in 0..valid.len() {
            assert!(decode(&valid[..length]).is_err());
        }
        for length in [0_u32, 65, u32::MAX] {
            let mut invalid = valid.clone();
            invalid[16..20].copy_from_slice(&length.to_be_bytes());
            assert!(decode(&invalid).is_err());
        }
    }

    #[test]
    fn encoded_capacity_is_checked_before_output_allocation() {
        let mut total = MAX_ENCODED - 5;
        assert_eq!(budget(&mut total, &[1], MAX_RECORD), Ok(()));
        assert_eq!(total, MAX_ENCODED);
        assert_eq!(
            budget(&mut total, &[1], MAX_RECORD),
            Err(MlsStorageError::Capacity)
        );
        for (groups, epochs, packages) in [
            (MAX_GROUPS + 1, 0, 0),
            (1, MAX_EPOCHS + 1, 0),
            (0, 0, MAX_PACKAGES + 1),
        ] {
            let rows = Rows {
                groups: (0..groups)
                    .map(|_| Group {
                        id: vec![1],
                        data: vec![2],
                        epochs: (0..epochs).map(|id| (id as u64, vec![3])).collect(),
                    })
                    .collect(),
                packages: (0..packages).map(|_| package()).collect(),
            };
            assert_eq!(encode(&rows), Err(MlsStorageError::Capacity));
        }
        let over_bound = vec![0; MAX_ENCODED + 1];
        assert!(matches!(
            decode(&over_bound),
            Err(MlsStorageError::Capacity)
        ));
    }

    #[test]
    fn provider_errors_are_finite_and_never_absence() {
        let outer_identifier_length =
            b"konclave-native-service-mls-outer-snapshot-v1\0".len() + 32;
        assert!(outer_identifier_length > MAX_ID);
        assert!(outer_identifier_length <= 128);
        for (error, expected) in [
            (
                SecretStorageError::AuthenticationFailed,
                MlsStorageError::Protection,
            ),
            (
                SecretStorageError::InvalidSealedBlob,
                MlsStorageError::Protection,
            ),
            (
                SecretStorageError::RandomGenerationFailed,
                MlsStorageError::Protection,
            ),
            (
                SecretStorageError::MlsStorageBackendFailure { operation: "test" },
                MlsStorageError::Backend,
            ),
        ] {
            assert_eq!(protection(error), expected);
        }
    }
}
