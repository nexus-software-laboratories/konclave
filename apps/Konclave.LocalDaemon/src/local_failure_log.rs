use std::fs::File;
use std::io::{self, Seek as _, Write as _};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, SyncSender};
use std::thread::JoinHandle;
use std::time::Duration;

use KonclaveSecretStorage::open_or_create_owner_protected_file;
use tracing_subscriber::fmt::MakeWriter;

const MAX_LOG_BYTES: u64 = 64 * 1024;
const MAX_RECORD_BYTES: usize = 2048;
const MAX_PENDING_RECORDS: usize = 64;
pub(crate) const LOCAL_FAILURE_TARGET: &str = "konclave.local_failure";

/// A bounded nonblocking writer for the dedicated, body-free diagnostic target only.
#[derive(Clone)]
pub(crate) struct LocalFailureLog {
    sender: SyncSender<Vec<u8>>,
    failed: Arc<AtomicBool>,
    stopping: Arc<AtomicBool>,
}

pub(crate) struct LocalFailureLogGuard {
    stopping: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

pub(crate) struct RecordWriter {
    log: LocalFailureLog,
    bytes: Vec<u8>,
    oversized: bool,
}

fn report_failure(failed: &AtomicBool, reported: &mut bool) {
    if failed.load(Ordering::Acquire) && !*reported {
        *reported = true;
        eprintln!("konclave: local failure diagnostic log is unavailable");
    }
}

fn append_record(file: &mut File, record: &[u8]) -> io::Result<()> {
    if record.len() > MAX_RECORD_BYTES {
        return Err(io::Error::other(
            "local diagnostic record exceeded its bound",
        ));
    }
    if file.metadata()?.len() + record.len() as u64 > MAX_LOG_BYTES {
        file.set_len(0)?;
        file.rewind()?;
    }
    file.write_all(record)?;
    file.flush()
}

impl LocalFailureLog {
    /// Opens a verified owner-only file without following links, then owns one writer thread.
    pub(crate) fn open(path: &Path) -> anyhow::Result<(Self, LocalFailureLogGuard)> {
        let lock = open_or_create_owner_protected_file(&path.with_extension("lock"))?;
        if fs4::FileExt::try_lock(&lock).is_err() {
            anyhow::bail!("local diagnostic writer is already owned or unavailable");
        }
        let mut file = open_or_create_owner_protected_file(path)?;
        if file.metadata()?.len() > MAX_LOG_BYTES {
            file.set_len(0)?;
        }
        file.seek(io::SeekFrom::End(0))?;
        let (sender, receiver) = mpsc::sync_channel::<Vec<u8>>(MAX_PENDING_RECORDS);
        let stopping = Arc::new(AtomicBool::new(false));
        let failed = Arc::new(AtomicBool::new(false));
        let worker_stopping = Arc::clone(&stopping);
        let worker_failed = Arc::clone(&failed);
        let worker = std::thread::Builder::new()
            .name("konclave-local-diagnostics".into())
            .spawn(move || {
                let _lock = lock;
                let mut drained = 0;
                let mut reported = false;
                loop {
                    report_failure(&worker_failed, &mut reported);
                    let record = if worker_stopping.load(Ordering::Acquire) {
                        if drained == MAX_PENDING_RECORDS {
                            break;
                        }
                        drained += 1;
                        match receiver.try_recv() {
                            Ok(record) => record,
                            Err(_) => break,
                        }
                    } else {
                        match receiver.recv_timeout(Duration::from_millis(100)) {
                            Ok(record) => record,
                            Err(mpsc::RecvTimeoutError::Timeout) => continue,
                            Err(mpsc::RecvTimeoutError::Disconnected) => break,
                        }
                    };
                    if append_record(&mut file, &record).is_err() {
                        worker_failed.store(true, Ordering::Release);
                        report_failure(&worker_failed, &mut reported);
                        break;
                    }
                }
                report_failure(&worker_failed, &mut reported);
            })?;
        Ok((
            Self {
                sender,
                failed,
                stopping: Arc::clone(&stopping),
            },
            LocalFailureLogGuard {
                stopping,
                worker: Some(worker),
            },
        ))
    }
}

impl Drop for LocalFailureLogGuard {
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take()
            && worker.join().is_err()
        {
            eprintln!("konclave: local failure diagnostic worker failed");
        }
    }
}

impl<'a> MakeWriter<'a> for LocalFailureLog {
    type Writer = RecordWriter;

    fn make_writer(&'a self) -> Self::Writer {
        RecordWriter {
            log: self.clone(),
            bytes: Vec::new(),
            oversized: false,
        }
    }
}

impl io::Write for RecordWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.bytes.len().saturating_add(bytes.len()) > MAX_RECORD_BYTES {
            self.oversized = true;
            return Err(io::Error::other(
                "local diagnostic record exceeded its bound",
            ));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for RecordWriter {
    fn drop(&mut self) {
        if self.log.stopping.load(Ordering::Acquire) {
            return;
        }
        if self.oversized
            || (!self.bytes.is_empty()
                && self
                    .log
                    .sender
                    .try_send(std::mem::take(&mut self.bytes))
                    .is_err())
        {
            self.log.failed.store(true, Ordering::Release);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Read as _;

    use super::*;

    #[test]
    fn saturation_marks_failure_without_waiting_for_a_worker() {
        let (sender, receiver) = mpsc::sync_channel(MAX_PENDING_RECORDS);
        let failed = Arc::new(AtomicBool::new(false));
        let log = LocalFailureLog {
            sender,
            failed: Arc::clone(&failed),
            stopping: Arc::new(AtomicBool::new(false)),
        };
        for _ in 0..=MAX_PENDING_RECORDS {
            let mut writer = log.make_writer();
            writer.write_all(b"finite record\n").unwrap();
        }
        assert!(failed.load(Ordering::Acquire));
        assert_eq!(receiver.try_iter().count(), MAX_PENDING_RECORDS);
    }

    #[test]
    fn log_is_owner_protected_and_drained_on_shutdown() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("private");
        KonclaveSecretStorage::ensure_owner_protected_directory(&directory).unwrap();
        let path = directory.join("diagnostics.log");
        let (log, guard) = LocalFailureLog::open(&path).unwrap();
        {
            let mut writer = log.make_writer();
            writer
                .write_all(b"{\"code\":\"profile_locked\"}\n")
                .unwrap();
        }
        drop(guard);
        let mut contents = String::new();
        KonclaveSecretStorage::open_owner_protected_file(&path)
            .unwrap()
            .read_to_string(&mut contents)
            .unwrap();
        assert_eq!(contents, "{\"code\":\"profile_locked\"}\n");
    }

    #[test]
    fn file_size_and_whole_record_retention_are_bounded() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("private");
        KonclaveSecretStorage::ensure_owner_protected_directory(&directory).unwrap();
        let path = directory.join("diagnostics.log");
        let mut file = open_or_create_owner_protected_file(&path).unwrap();
        let record = vec![b'x'; MAX_RECORD_BYTES];
        for _ in 0..100 {
            append_record(&mut file, &record).unwrap();
            assert!(file.metadata().unwrap().len() <= MAX_LOG_BYTES);
        }
        assert_eq!(file.metadata().unwrap().len() % MAX_RECORD_BYTES as u64, 0);
        assert!(append_record(&mut file, &vec![0; MAX_RECORD_BYTES + 1]).is_err());
    }

    #[test]
    fn one_writer_owns_the_file_and_shutdown_releases_its_lock() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("private");
        KonclaveSecretStorage::ensure_owner_protected_directory(&directory).unwrap();
        let path = directory.join("diagnostics.log");
        let (_log, guard) = LocalFailureLog::open(&path).unwrap();
        assert!(LocalFailureLog::open(&path).is_err());
        drop(guard);
        let (_, guard) = LocalFailureLog::open(&path).unwrap();
        drop(guard);
    }

    #[test]
    fn oversized_records_and_writers_outliving_shutdown_are_not_persisted() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("private");
        KonclaveSecretStorage::ensure_owner_protected_directory(&directory).unwrap();
        let path = directory.join("diagnostics.log");
        let (log, guard) = LocalFailureLog::open(&path).unwrap();
        let mut oversized = log.make_writer();
        oversized.write_all(&vec![b'x'; MAX_RECORD_BYTES]).unwrap();
        assert!(oversized.write_all(b"x").is_err());
        drop(oversized);
        let mut late = log.make_writer();
        late.write_all(b"late record").unwrap();
        drop(guard);
        drop(late);
        assert_eq!(std::fs::read(&path).unwrap(), b"");
    }

    #[cfg(unix)]
    #[test]
    fn unsafe_files_and_symbolic_links_are_not_repaired_or_followed() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("private");
        KonclaveSecretStorage::ensure_owner_protected_directory(&directory).unwrap();
        let target = directory.join("foreign");
        std::fs::write(&target, b"must remain intact").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(LocalFailureLog::open(&target).is_err());
        let link = directory.join("diagnostics.log");
        symlink(&target, &link).unwrap();
        assert!(LocalFailureLog::open(&link).is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"must remain intact");
    }
}
