#[path = "../examples/native_service/mls.rs"]
mod mls;
#[path = "../examples/native_service/storage.rs"]
#[allow(dead_code)]
mod storage;

use std::fs;
use std::sync::{Arc, Barrier};
use std::thread;

use KonclaveSecretStorage::{
    ExternalWrappingKeyProvider, SecretRecordContext, SecretRecordKind, SecretSealer,
    SecretStorageError,
};
use mls::{MlsStorageError, ServiceMlsStorage};
use mls_rs_core::crypto::HpkeSecretKey;
use mls_rs_core::group::{EpochRecord, GroupState, GroupStateStorage};
use mls_rs_core::key_package::{KeyPackageData, KeyPackageStorage};
use storage::{ServiceStorage, SnapshotKind, StorageError};
use tempfile::TempDir;
use zeroize::Zeroizing;

fn directory() -> TempDir {
    tempfile::Builder::new()
        .prefix(".native-mls-test-")
        .tempdir_in(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests"))
        .unwrap()
}

fn sealer(key: u8) -> SecretSealer {
    SecretSealer::from_provider(ExternalWrappingKeyProvider::from_bytes([key; 32])).unwrap()
}

fn state(id: &[u8]) -> GroupState {
    GroupState {
        id: id.to_vec(),
        data: Zeroizing::new(b"synthetic-group-secret-marker".to_vec()),
    }
}

fn package() -> KeyPackageData {
    KeyPackageData::new(
        b"synthetic-public-package-marker".to_vec(),
        HpkeSecretKey::from(b"synthetic-init-private-marker".to_vec()),
        HpkeSecretKey::from(b"synthetic-leaf-private-marker".to_vec()),
        u64::MAX,
    )
}

#[test]
fn sealed_provider_roundtrip_reopen_and_stale_clone_fencing() {
    let directory = directory();
    let owner = ServiceStorage::open(directory.path()).unwrap();
    let mut backend = ServiceMlsStorage::new(owner.clone(), sealer(7), b"endpoint-a").unwrap();
    backend
        .write(
            state(b"group"),
            vec![EpochRecord::new(
                1,
                Zeroizing::new(b"synthetic-epoch-secret-marker".to_vec()),
            )],
            vec![],
        )
        .unwrap();
    backend
        .write(
            state(b"group"),
            vec![],
            vec![EpochRecord::new(
                1,
                Zeroizing::new(b"updated-epoch-secret-marker".to_vec()),
            )],
        )
        .unwrap();
    backend.insert(b"package".to_vec(), package()).unwrap();
    assert_eq!(backend.max_epoch_id(b"group").unwrap(), Some(1));
    assert_eq!(
        backend.state(b"group").unwrap().unwrap().as_slice(),
        state(b"group").data.as_slice()
    );
    assert_eq!(
        backend.epoch(b"group", 1).unwrap().unwrap().as_slice(),
        b"updated-epoch-secret-marker"
    );
    let actual = backend.get(b"package").unwrap().unwrap();
    assert_eq!(actual.init_key.as_ref(), package().init_key.as_ref());
    assert_eq!(
        actual.leaf_node_key.as_ref(),
        package().leaf_node_key.as_ref()
    );
    assert_eq!(actual.expiration, u64::MAX);
    assert!(backend.state(b"missing").unwrap().is_none());
    assert!(backend.epoch(b"group", 2).unwrap().is_none());
    assert!(backend.get(b"missing").unwrap().is_none());
    assert!(backend.max_epoch_id(b"missing").unwrap().is_none());
    let ordinary = fs::read(directory.path().join("native-service.mls")).unwrap();
    for marker in [
        b"synthetic-group-secret-marker".as_slice(),
        b"synthetic-public-package-marker",
        b"synthetic-init-private-marker",
        b"synthetic-leaf-private-marker",
        b"updated-epoch-secret-marker",
    ] {
        assert!(
            !ordinary
                .windows(marker.len())
                .any(|window| window == marker)
        );
    }
    assert!(ServiceMlsStorage::new(owner.clone(), sealer(8), b"endpoint-a").is_err());
    assert!(ServiceMlsStorage::new(owner.clone(), sealer(7), b"endpoint-b").is_err());
    let mut stale = backend.clone();
    owner.release().unwrap();
    let reopened = ServiceStorage::open(directory.path()).unwrap();
    assert_eq!(
        owner.read_slot(SnapshotKind::Mls),
        Err(StorageError::Released)
    );
    assert!(stale.write(state(b"stale"), vec![], vec![]).is_err());
    assert!(stale.insert(b"stale".to_vec(), package()).is_err());
    assert!(stale.delete(b"package").is_err());
    assert!(stale.state(b"group").is_err());
    let mut resumed = ServiceMlsStorage::new(reopened, sealer(7), b"endpoint-a").unwrap();
    assert_eq!(
        resumed.state(b"group").unwrap().unwrap().as_slice(),
        state(b"group").data.as_slice()
    );
    assert_eq!(
        resumed.epoch(b"group", 1).unwrap().unwrap().as_slice(),
        b"updated-epoch-secret-marker"
    );
    let restored = resumed.get(b"package").unwrap().unwrap();
    assert_eq!(restored.key_package_bytes, package().key_package_bytes);
    assert_eq!(restored.init_key.as_ref(), package().init_key.as_ref());
    assert_eq!(
        restored.leaf_node_key.as_ref(),
        package().leaf_node_key.as_ref()
    );
    assert_eq!(restored.expiration, u64::MAX);
    let replacement = KeyPackageData::new(
        b"replacement-public-package".to_vec(),
        HpkeSecretKey::from(b"replacement-init-private".to_vec()),
        HpkeSecretKey::from(b"replacement-leaf-private".to_vec()),
        0,
    );
    resumed.insert(b"package".to_vec(), replacement).unwrap();
    let replaced = resumed.get(b"package").unwrap().unwrap();
    assert_eq!(replaced.key_package_bytes, b"replacement-public-package");
    assert_eq!(replaced.init_key.as_ref(), b"replacement-init-private");
    assert_eq!(replaced.leaf_node_key.as_ref(), b"replacement-leaf-private");
    assert_eq!(replaced.expiration, 0);
    resumed.delete(b"package").unwrap();
    resumed.delete(b"package").unwrap();
    assert!(resumed.get(b"package").unwrap().is_none());
}

#[test]
fn independently_constructed_handles_share_owner_update_serialization() {
    let directory = directory();
    let owner = ServiceStorage::open(directory.path()).unwrap();
    let first = ServiceMlsStorage::new(owner.clone(), sealer(7), b"endpoint").unwrap();
    let second = ServiceMlsStorage::new(owner.clone(), sealer(7), b"endpoint").unwrap();
    let barrier = Arc::new(Barrier::new(3));
    let workers: Vec<_> = [first, second]
        .into_iter()
        .enumerate()
        .map(|(index, mut backend)| {
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                backend
                    .write(state(&[index as u8 + 1]), vec![], vec![])
                    .unwrap();
                backend.insert(vec![index as u8 + 1], package()).unwrap();
            })
        })
        .collect();
    barrier.wait();
    for worker in workers {
        worker.join().unwrap();
    }
    let backend = ServiceMlsStorage::new(owner, sealer(7), b"endpoint").unwrap();
    for id in [1, 2] {
        assert!(backend.state(&[id]).unwrap().is_some());
        assert!(backend.get(&[id]).unwrap().is_some());
    }
}

#[test]
fn malformed_outer_snapshot_and_real_file_failure_are_not_absence() {
    let directory = directory();
    let owner = ServiceStorage::open(directory.path()).unwrap();
    let backend = ServiceMlsStorage::new(owner.clone(), sealer(7), b"endpoint").unwrap();
    owner.replace_slot(SnapshotKind::Mls, b"truncated").unwrap();
    assert!(backend.state(b"group").is_err());
    assert!(ServiceMlsStorage::new(owner.clone(), sealer(7), b"endpoint").is_err());
    fs::remove_file(directory.path().join("native-service.mls")).unwrap();
    fs::create_dir(directory.path().join("native-service.mls")).unwrap();
    assert!(backend.get(b"package").is_err());
    assert!(owner.read_slot(SnapshotKind::Mls).is_err());
    assert!(matches!(
        ServiceMlsStorage::new(owner, sealer(7), b"endpoint"),
        Err(MlsStorageError::Storage(_))
    ));
}

#[test]
fn authenticated_outer_snapshot_still_requires_a_valid_bounded_codec() {
    let directory = directory();
    let owner = ServiceStorage::open(directory.path()).unwrap();
    let binding = SecretRecordContext::derive(
        SecretRecordKind::MlsGroupState,
        &[b"native-service-mls-snapshot-v1", b"endpoint"],
    )
    .unwrap();
    let mut identifier = b"konclave-native-service-mls-outer-snapshot-v1\0".to_vec();
    identifier.extend_from_slice(binding.identifier());
    let context = SecretRecordContext::new(SecretRecordKind::MlsGroupState, identifier).unwrap();
    let mut excessive = b"KNSMLS01".to_vec();
    excessive.extend_from_slice(&u32::MAX.to_be_bytes());
    excessive.extend_from_slice(&0_u32.to_be_bytes());
    for plaintext in [vec![], b"KNSMLS02".to_vec(), excessive] {
        let sealed = sealer(7).seal(&context, &plaintext).unwrap();
        owner
            .replace_slot(SnapshotKind::Mls, sealed.as_bytes())
            .unwrap();
        assert!(ServiceMlsStorage::new(owner.clone(), sealer(7), b"endpoint").is_err());
    }
}

#[test]
fn explicit_custody_failure_has_no_implicit_replacement() {
    struct Unavailable;
    impl std::io::Read for Unavailable {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::ErrorKind::PermissionDenied.into())
        }
    }
    assert!(matches!(
        ExternalWrappingKeyProvider::from_reader(Unavailable),
        Err(SecretStorageError::InvalidExternalKey)
    ));
}

#[test]
fn reaching_group_capacity_fails_without_pruning_existing_state() {
    let directory = directory();
    let owner = ServiceStorage::open(directory.path()).unwrap();
    let mut backend = ServiceMlsStorage::new(owner.clone(), sealer(7), b"endpoint").unwrap();
    for id in 1..=64 {
        backend.write(state(&[id]), vec![], vec![]).unwrap();
    }
    let before = owner.read_slot(SnapshotKind::Mls).unwrap().unwrap();
    assert_eq!(
        backend.write(state(&[65]), vec![], vec![]),
        Err(MlsStorageError::Backend)
    );
    assert_eq!(owner.read_slot(SnapshotKind::Mls).unwrap().unwrap(), before);
    for id in 1..=64 {
        assert!(backend.state(&[id]).unwrap().is_some());
    }
    backend.write(state(&[1]), vec![], vec![]).unwrap();
    assert!(backend.state(&[65]).unwrap().is_none());
    assert!(backend.into_handle().contains_group(&[1]).unwrap());
}
