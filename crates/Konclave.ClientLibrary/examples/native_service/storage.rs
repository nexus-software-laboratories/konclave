//! Service-owned storage for opaque, already project-sealed snapshots.
//!
//! The operator must supply an existing, exclusively operator-controlled directory
//! on a local filesystem supporting OS locks and atomic replacement. Directory
//! mutation by other actors, rollback, and deletion are outside this capsule's
//! guarantees. No plaintext, key custody, or journal/MLS codec belongs here.
//! The caller must authenticate and decode returned sealed bytes; this layer
//! does not claim to recognize ciphertext tampering or an invalid sealed record.
//! Files are synced before replacement. Unix also syncs the directory; Windows
//! provides atomic visibility and file sync only, NOT power-loss durability.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use fs4::{FileExt, TryLockError};

const LOCK: &str = "native-service.lock";
const GENERATION: &str = "native-service.generation";
const SNAPSHOT: &str = "native-service.snapshot";
const MAGIC: &[u8; 8] = b"KNSGEN01";

/// Hard ceiling, independently of any caller's codec or record limits.
pub const MAX_SNAPSHOT_BYTES: usize = 16 * 1024 * 1024;

/// Finite diagnostics intentionally exclude filesystem paths and payloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum StorageError {
    #[error("storage is already owned")]
    Busy,
    #[error("storage ownership was released or superseded")]
    Released,
    #[error("storage ownership synchronization failed")]
    Poisoned,
    #[error("invalid owner generation")]
    InvalidGeneration,
    #[error("owner generation exhausted")]
    GenerationExhausted,
    #[error("snapshot exceeds storage bound")]
    TooLarge,
    #[error("storage entry is not a regular file")]
    InvalidFile,
    #[error("bounded allocation failed")]
    Allocation,
    #[error("unsupported storage platform")]
    UnsupportedPlatform,
    #[error("storage I/O failed ({0:?})")]
    Io(io::ErrorKind),
}

impl From<io::Error> for StorageError {
    fn from(error: io::Error) -> Self {
        Self::Io(error.kind())
    }
}

struct Lease {
    directory: PathBuf,
    generation: u64,
    lock: Mutex<Option<File>>,
}

/// Clones share one lease; explicit release invalidates every clone.
#[derive(Clone)]
pub struct ServiceStorage {
    lease: Arc<Lease>,
}

impl ServiceStorage {
    /// Acquires the OS lock before reading or advancing the owner generation.
    ///
    /// # Errors
    /// Returns contention, malformed/exhausted generation, or sanitized I/O errors.
    /// The directory is never created and no alternative backend is selected.
    /// An existing lock without a generation fails closed, including an interrupted
    /// first initialization; recovery of that directory is an operator decision.
    pub fn open(directory: &Path) -> Result<Self, StorageError> {
        if !cfg!(any(unix, windows)) {
            return Err(StorageError::UnsupportedPlatform);
        }
        if !directory.metadata()?.is_dir() {
            return Err(StorageError::InvalidFile);
        }
        let (lock, fresh_lock) = match OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(directory.join(LOCK))
        {
            Ok(lock) => (lock, true),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => (
                OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(directory.join(LOCK))?,
                false,
            ),
            Err(error) => return Err(error.into()),
        };
        if !lock.metadata()?.is_file() {
            return Err(StorageError::InvalidFile);
        }
        match FileExt::try_lock(&lock) {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => return Err(StorageError::Busy),
            Err(TryLockError::Error(error)) => return Err(error.into()),
        }
        let previous = match read_generation(directory) {
            Ok(value) => value,
            Err(StorageError::Io(io::ErrorKind::NotFound)) => {
                if !fresh_lock {
                    return Err(StorageError::InvalidGeneration);
                }
                match std::fs::symlink_metadata(directory.join(SNAPSHOT)) {
                    Err(error) if error.kind() == io::ErrorKind::NotFound => 0,
                    Ok(_) => return Err(StorageError::InvalidGeneration),
                    Err(error) => return Err(error.into()),
                }
            }
            Err(error) => return Err(error),
        };
        let generation = next_generation(previous)?;
        let mut record = [0; 16];
        record[..8].copy_from_slice(MAGIC);
        record[8..].copy_from_slice(&generation.to_be_bytes());
        replace_file(directory, GENERATION, &record)?;
        Ok(Self {
            lease: Arc::new(Lease {
                directory: directory.to_owned(),
                generation,
                lock: Mutex::new(Some(lock)),
            }),
        })
    }

    fn owned(&self) -> Result<MutexGuard<'_, Option<File>>, StorageError> {
        let guard = self.lease.lock.lock().map_err(|_| StorageError::Poisoned)?;
        if guard.is_none() {
            return Err(StorageError::Released);
        }
        if read_generation(&self.lease.directory)? != self.lease.generation {
            return Err(StorageError::Released);
        }
        Ok(guard)
    }

    /// Returns the current fenced owner generation, not a rollback guarantee.
    ///
    /// # Errors
    /// Rejects released/stale ownership and invalid generation or I/O evidence.
    pub fn generation(&self) -> Result<u64, StorageError> {
        let _owner = self.owned()?;
        Ok(self.lease.generation)
    }

    /// Reads only bounded opaque bytes; only a genuinely missing snapshot is `None`.
    ///
    /// # Errors
    /// Rejects released/stale leases, oversized/nonregular files, and I/O failures.
    pub fn read_snapshot(&self) -> Result<Option<Vec<u8>>, StorageError> {
        let _owner = self.owned()?;
        let mut file = match File::open(self.lease.directory.join(SNAPSHOT)) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(StorageError::InvalidFile);
        }
        if metadata.len() > MAX_SNAPSHOT_BYTES as u64 {
            return Err(StorageError::TooLarge);
        }
        let length = usize::try_from(metadata.len()).map_err(|_| StorageError::TooLarge)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(length)
            .map_err(|_| StorageError::Allocation)?;
        bytes.resize(length, 0);
        file.read_exact(&mut bytes)?;
        let mut extra = [0];
        if file.read(&mut extra)? != 0 {
            return Err(StorageError::TooLarge);
        }
        Ok(Some(bytes))
    }

    /// Atomically replaces the snapshot with already project-sealed bytes.
    ///
    /// # Errors
    /// Rejects stale ownership, oversize input, and I/O/sync failures. A failure
    /// after replacement may mean the new snapshot is visible; do not assume rollback.
    pub fn replace_snapshot(&self, bytes: &[u8]) -> Result<(), StorageError> {
        self.replace_with(bytes, || {}, || {})
    }

    fn replace_with(
        &self,
        bytes: &[u8],
        admitted: impl FnOnce(),
        committed: impl FnOnce(),
    ) -> Result<(), StorageError> {
        let _owner = self.owned()?;
        if bytes.len() > MAX_SNAPSHOT_BYTES {
            return Err(StorageError::TooLarge);
        }
        admitted();
        replace_file(&self.lease.directory, SNAPSHOT, bytes)?;
        committed();
        Ok(())
    }

    /// Invalidates all clones, waiting for admitted reads/writes before closing the lock.
    ///
    /// # Errors
    /// Poisoned synchronization fails closed. Repeated release is harmless.
    pub fn release(&self) -> Result<(), StorageError> {
        self.release_with(|| {})
    }

    fn release_with(&self, released: impl FnOnce()) -> Result<(), StorageError> {
        let mut owner = self.lease.lock.lock().map_err(|_| StorageError::Poisoned)?;
        drop(owner.take());
        released();
        Ok(())
    }

    #[cfg(test)]
    /// Pauses an admitted write while retaining the exact production ownership guard.
    pub(crate) fn replace_with_test_gate(
        &self,
        bytes: &[u8],
        admitted: impl FnOnce(),
        committed: impl FnOnce(),
    ) -> Result<(), StorageError> {
        self.replace_with(bytes, admitted, committed)
    }

    #[cfg(test)]
    /// Observes release inside the same synchronization scope as production release.
    pub(crate) fn release_with_test_gate(&self, released: impl FnOnce()) -> Result<(), StorageError> {
        self.release_with(released)
    }
}

fn read_generation(directory: &Path) -> Result<u64, StorageError> {
    let mut file = File::open(directory.join(GENERATION))?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() != 16 {
        return Err(StorageError::InvalidGeneration);
    }
    let mut record = [0; 16];
    file.read_exact(&mut record)?;
    let mut extra = [0];
    if file.read(&mut extra)? != 0 {
        return Err(StorageError::InvalidGeneration);
    }
    decode_generation(&record)
}

fn decode_generation(record: &[u8]) -> Result<u64, StorageError> {
    if record.len() != 16 || &record[..8] != MAGIC {
        return Err(StorageError::InvalidGeneration);
    }
    let mut value = [0; 8];
    value.copy_from_slice(&record[8..]);
    let generation = u64::from_be_bytes(value);
    if generation == 0 {
        return Err(StorageError::InvalidGeneration);
    }
    Ok(generation)
}

fn next_generation(previous: u64) -> Result<u64, StorageError> {
    previous
        .checked_add(1)
        .ok_or(StorageError::GenerationExhausted)
}

fn replace_file(directory: &Path, name: &str, bytes: &[u8]) -> Result<(), StorageError> {
    let mut pending = tempfile::Builder::new()
        .prefix(".native-service-")
        .tempfile_in(directory)?;
    pending.write_all(bytes)?;
    pending.as_file().sync_all()?;
    let committed = pending
        .persist(directory.join(name))
        .map_err(|error| StorageError::from(error.error))?;
    committed.sync_all()?;
    #[cfg(unix)]
    File::open(directory)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generation_decisions_are_pure_and_fail_closed() {
        for (previous, expected) in [
            (0, Ok(1)),
            (1, Ok(2)),
            (u64::MAX - 1, Ok(u64::MAX)),
            (u64::MAX, Err(StorageError::GenerationExhausted)),
        ] {
            assert_eq!(next_generation(previous), expected);
        }
        for generation in [1, 2, u64::MAX] {
            let mut record = [0; 16];
            record[..8].copy_from_slice(MAGIC);
            record[8..].copy_from_slice(&generation.to_be_bytes());
            assert_eq!(decode_generation(&record), Ok(generation));
        }
        let mut zero = [0; 16];
        zero[..8].copy_from_slice(MAGIC);
        for malformed in [vec![], vec![0; 15], vec![0; 16], vec![0; 17], zero.to_vec()] {
            assert_eq!(
                decode_generation(&malformed),
                Err(StorageError::InvalidGeneration)
            );
        }
    }
}
