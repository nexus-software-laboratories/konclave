#[path = "../examples/native_service/storage.rs"]
mod storage;

use std::fs::{self, File, OpenOptions};
use std::sync::mpsc;
use std::thread;

use fs4::FileExt;
use storage::{MAX_SNAPSHOT_BYTES, ServiceStorage, SnapshotKind, StorageError};
use tempfile::TempDir;

const GENERATION: &str = "native-service.generation";
const SNAPSHOT: &str = "native-service.snapshot";

fn directory() -> TempDir {
    let parent = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    tempfile::Builder::new()
        .prefix(".native-storage-test-")
        .tempdir_in(parent)
        .unwrap()
}

fn generation(value: u64) -> [u8; 16] {
    let mut record = [0; 16];
    record[..8].copy_from_slice(b"KNSGEN01");
    record[8..].copy_from_slice(&value.to_be_bytes());
    record
}

#[test]
fn fixed_slots_are_independent_and_share_release_and_generation() {
    let directory = directory();
    let owner = ServiceStorage::open(directory.path()).unwrap();
    owner.replace_snapshot(b"journal").unwrap();
    owner.replace_slot(SnapshotKind::Mls, b"sealed mls").unwrap();
    assert_eq!(owner.read_snapshot().unwrap().unwrap(), b"journal");
    assert_eq!(
        owner.read_slot(SnapshotKind::Mls).unwrap().unwrap(),
        b"sealed mls"
    );
    let clone = owner.clone();
    owner.release().unwrap();
    let reopened = ServiceStorage::open(directory.path()).unwrap();
    for kind in [SnapshotKind::Journal, SnapshotKind::Mls] {
        assert_eq!(clone.read_slot(kind), Err(StorageError::Released));
        assert_eq!(
            clone.replace_slot(kind, b"stale"),
            Err(StorageError::Released)
        );
        assert_eq!(
            clone.update_slot(kind, |_| Ok::<_, StorageError>((vec![], ()))),
            Err(StorageError::Released)
        );
    }
    assert_eq!(reopened.read_snapshot().unwrap().unwrap(), b"journal");
    assert_eq!(
        reopened.read_slot(SnapshotKind::Mls).unwrap().unwrap(),
        b"sealed mls"
    );
}

#[test]
fn fresh_initialization_rejects_either_orphan_slot() {
    for filename in [SNAPSHOT, "native-service.mls"] {
        let directory = directory();
        fs::write(directory.path().join(filename), b"orphan").unwrap();
        assert!(matches!(
            ServiceStorage::open(directory.path()),
            Err(StorageError::InvalidGeneration)
        ));
    }
}

#[test]
fn shared_owner_updates_reload_without_lost_writes() {
    let directory = directory();
    let owner = ServiceStorage::open(directory.path()).unwrap();
    let (admitted_tx, admitted_rx) = mpsc::channel();
    let (continue_tx, continue_rx) = mpsc::channel();
    let first = owner.clone();
    let worker = thread::spawn(move || {
        first.update_slot(SnapshotKind::Mls, |current| {
            assert!(current.is_none());
            admitted_tx.send(()).unwrap();
            continue_rx.recv().unwrap();
            Ok::<_, StorageError>((b"first".to_vec(), ()))
        })
    });
    admitted_rx.recv().unwrap();
    let second = owner.clone();
    let (attempt_tx, attempt_rx) = mpsc::channel();
    let competitor = thread::spawn(move || {
        attempt_tx.send(()).unwrap();
        second.update_slot(SnapshotKind::Mls, |current| {
            let mut next = current.unwrap().to_vec();
            next.extend_from_slice(b" second");
            Ok::<_, StorageError>((next, ()))
        })
    });
    attempt_rx.recv().unwrap();
    continue_tx.send(()).unwrap();
    worker.join().unwrap().unwrap();
    competitor.join().unwrap().unwrap();
    assert_eq!(
        owner.read_slot(SnapshotKind::Mls).unwrap().unwrap(),
        b"first second"
    );
    let rejected = owner.update_slot(SnapshotKind::Mls, |_| {
        Err::<(Vec<u8>, ()), _>(StorageError::InvalidFile)
    });
    assert_eq!(rejected, Err(StorageError::InvalidFile));
    assert_eq!(
        owner.read_slot(SnapshotKind::Mls).unwrap().unwrap(),
        b"first second"
    );
}

#[test]
fn exclusive_os_lock_precedes_generation_access() {
    let directory = directory();
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(directory.path().join("native-service.lock"))
        .unwrap();
    FileExt::try_lock(&lock).unwrap();
    fs::write(directory.path().join(GENERATION), b"malformed").unwrap();
    assert!(matches!(
        ServiceStorage::open(directory.path()),
        Err(StorageError::Busy)
    ));
    drop(lock);
    assert!(matches!(
        ServiceStorage::open(directory.path()),
        Err(StorageError::InvalidGeneration)
    ));
}

#[test]
fn persists_replaces_reopens_and_invalidates_every_old_clone() {
    let directory = directory();
    let owner = ServiceStorage::open(directory.path()).unwrap();
    assert_eq!(owner.generation().unwrap(), 1);
    assert_eq!(owner.read_snapshot().unwrap(), None);
    let old = owner.clone();
    owner
        .replace_snapshot(b"opaque sealed fixture one")
        .unwrap();
    assert!(matches!(
        ServiceStorage::open(directory.path()),
        Err(StorageError::Busy)
    ));
    owner.release().unwrap();
    let reopened = ServiceStorage::open(directory.path()).unwrap();
    assert_eq!(reopened.generation().unwrap(), 2);
    assert_eq!(
        reopened.read_snapshot().unwrap().unwrap(),
        b"opaque sealed fixture one"
    );
    assert_eq!(old.read_snapshot(), Err(StorageError::Released));
    assert_eq!(old.generation(), Err(StorageError::Released));
    assert_eq!(old.replace_snapshot(b"stale"), Err(StorageError::Released));
    owner.release().unwrap();
    reopened
        .replace_snapshot(b"opaque sealed fixture two")
        .unwrap();
    assert_eq!(
        reopened.read_snapshot().unwrap().unwrap(),
        b"opaque sealed fixture two"
    );
    assert_eq!(
        fs::read(directory.path().join(GENERATION)).unwrap(),
        generation(2)
    );
    reopened.release().unwrap();
}

#[test]
fn last_clone_drop_also_closes_the_os_lease() {
    let directory = directory();
    let owner = ServiceStorage::open(directory.path()).unwrap();
    let clone = owner.clone();
    drop(owner);
    assert!(matches!(
        ServiceStorage::open(directory.path()),
        Err(StorageError::Busy)
    ));
    drop(clone);
    ServiceStorage::open(directory.path())
        .unwrap()
        .release()
        .unwrap();
}

#[test]
fn release_orders_after_an_admitted_write_and_before_reopen() {
    let directory = directory();
    let owner = ServiceStorage::open(directory.path()).unwrap();
    let writer = owner.clone();
    let releaser = owner.clone();
    let (admitted_tx, admitted_rx) = mpsc::sync_channel(0);
    let (resume_tx, resume_rx) = mpsc::sync_channel(0);
    let (release_started_tx, release_started_rx) = mpsc::sync_channel(0);
    let (events_tx, events_rx) = mpsc::channel();
    let write_events = events_tx.clone();
    let write = thread::spawn(move || {
        writer.replace_with_test_gate(
            b"admitted opaque sealed bytes",
            || {
                admitted_tx.send(()).unwrap();
                resume_rx.recv().unwrap();
            },
            || write_events.send("committed").unwrap(),
        )
    });
    admitted_rx.recv().unwrap();
    let release = thread::spawn(move || {
        release_started_tx.send(()).unwrap();
        releaser.release_with_test_gate(|| events_tx.send("released").unwrap())
    });
    release_started_rx.recv().unwrap();
    assert!(matches!(
        ServiceStorage::open(directory.path()),
        Err(StorageError::Busy)
    ));
    resume_tx.send(()).unwrap();
    assert_eq!(events_rx.recv().unwrap(), "committed");
    assert_eq!(events_rx.recv().unwrap(), "released");
    write.join().unwrap().unwrap();
    release.join().unwrap().unwrap();
    let reopened = ServiceStorage::open(directory.path()).unwrap();
    assert_eq!(
        reopened.read_snapshot().unwrap().unwrap(),
        b"admitted opaque sealed bytes"
    );
    assert_eq!(owner.replace_snapshot(b"late"), Err(StorageError::Released));
    assert_eq!(owner.read_snapshot(), Err(StorageError::Released));
    reopened.release().unwrap();
}

#[test]
fn bounds_reads_before_allocation_and_writes_before_replacement() {
    let directory = directory();
    let owner = ServiceStorage::open(directory.path()).unwrap();
    owner.replace_snapshot(b"unchanged").unwrap();
    let oversized = vec![0; MAX_SNAPSHOT_BYTES + 1];
    assert_eq!(
        owner.replace_snapshot(&oversized),
        Err(StorageError::TooLarge)
    );
    assert_eq!(owner.read_snapshot().unwrap().unwrap(), b"unchanged");
    let snapshot = OpenOptions::new()
        .write(true)
        .open(directory.path().join(SNAPSHOT))
        .unwrap();
    snapshot.set_len(MAX_SNAPSHOT_BYTES as u64 + 1).unwrap();
    drop(snapshot);
    assert_eq!(owner.read_snapshot(), Err(StorageError::TooLarge));
    owner.release().unwrap();
    assert_eq!(
        owner.replace_snapshot(&oversized),
        Err(StorageError::Released)
    );
}

#[test]
fn generation_records_are_strict_and_bounded() {
    let records = [
        Vec::new(),
        b"1".to_vec(),
        vec![0; 16],
        generation(0).to_vec(),
        generation(1)[..15].to_vec(),
        [generation(1).as_slice(), &[0]].concat(),
    ];
    for record in records {
        let directory = directory();
        fs::write(directory.path().join(GENERATION), record).unwrap();
        assert!(matches!(
            ServiceStorage::open(directory.path()),
            Err(StorageError::InvalidGeneration)
        ));
    }
    let directory = directory();
    let record = File::create(directory.path().join(GENERATION)).unwrap();
    record.set_len(1024 * 1024).unwrap();
    drop(record);
    assert!(matches!(
        ServiceStorage::open(directory.path()),
        Err(StorageError::InvalidGeneration)
    ));
}

#[test]
fn generation_exhaustion_and_missing_generation_fail_closed() {
    let directory = directory();
    fs::write(directory.path().join(GENERATION), generation(u64::MAX)).unwrap();
    assert!(matches!(
        ServiceStorage::open(directory.path()),
        Err(StorageError::GenerationExhausted)
    ));
    fs::remove_file(directory.path().join(GENERATION)).unwrap();
    fs::write(directory.path().join(SNAPSHOT), b"orphaned opaque bytes").unwrap();
    assert!(matches!(
        ServiceStorage::open(directory.path()),
        Err(StorageError::InvalidGeneration)
    ));
}

#[test]
fn loss_of_generation_never_reinitializes_an_existing_owner_directory() {
    let directory = directory();
    ServiceStorage::open(directory.path())
        .unwrap()
        .release()
        .unwrap();
    fs::remove_file(directory.path().join(GENERATION)).unwrap();
    assert!(matches!(
        ServiceStorage::open(directory.path()),
        Err(StorageError::InvalidGeneration)
    ));
}

#[test]
fn stale_generation_is_checked_on_both_read_and_write() {
    let directory = directory();
    let owner = ServiceStorage::open(directory.path()).unwrap();
    fs::write(directory.path().join(GENERATION), generation(2)).unwrap();
    assert_eq!(owner.read_snapshot(), Err(StorageError::Released));
    assert_eq!(
        owner.replace_snapshot(b"stale"),
        Err(StorageError::Released)
    );
    fs::write(directory.path().join(GENERATION), b"bad").unwrap();
    assert_eq!(owner.read_snapshot(), Err(StorageError::InvalidGeneration));
    assert_eq!(
        owner.replace_snapshot(b"stale"),
        Err(StorageError::InvalidGeneration)
    );
    owner.release().unwrap();
}

#[test]
fn operational_failures_are_not_absence_or_success() {
    let directory = directory();
    assert!(matches!(
        ServiceStorage::open(&directory.path().join("missing")),
        Err(StorageError::Io(std::io::ErrorKind::NotFound))
    ));
    let owner = ServiceStorage::open(directory.path()).unwrap();
    fs::create_dir(directory.path().join(SNAPSHOT)).unwrap();
    assert!(owner.read_snapshot().is_err());
    assert!(matches!(
        owner.replace_snapshot(b"opaque"),
        Err(StorageError::Io(_))
    ));
    fs::remove_dir(directory.path().join(SNAPSHOT)).unwrap();
    fs::remove_file(directory.path().join(GENERATION)).unwrap();
    assert_eq!(
        owner.read_snapshot(),
        Err(StorageError::Io(std::io::ErrorKind::NotFound))
    );
    assert_eq!(
        owner.replace_snapshot(b"opaque"),
        Err(StorageError::Io(std::io::ErrorKind::NotFound))
    );
    owner.release().unwrap();
}

#[test]
fn poisoned_ownership_never_degrades_to_an_unfenced_write() {
    let directory = directory();
    let owner = ServiceStorage::open(directory.path()).unwrap();
    let writer = owner.clone();
    let failed = thread::spawn(move || {
        writer.replace_with_test_gate(b"opaque", || panic!("injected ownership failure"), || {})
    });
    assert!(failed.join().is_err());
    assert_eq!(owner.read_snapshot(), Err(StorageError::Poisoned));
    assert_eq!(
        owner.replace_snapshot(b"opaque"),
        Err(StorageError::Poisoned)
    );
    assert_eq!(owner.release(), Err(StorageError::Poisoned));
    assert!(matches!(
        ServiceStorage::open(directory.path()),
        Err(StorageError::Busy)
    ));
    drop(owner);
    ServiceStorage::open(directory.path())
        .unwrap()
        .release()
        .unwrap();
}
