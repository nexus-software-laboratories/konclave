use std::fs::File;
use std::path::Path;

use crate::SecretStorageError;

/// Creates or verifies one owner-only directory.
///
/// # Errors
///
/// Returns a finite unavailable or unsafe-storage error. Existing links, foreign
/// ownership, and group/other access fail closed.
pub fn ensure_owner_protected_directory(path: &Path) -> Result<(), SecretStorageError> {
    platform::ensure_directory(path)
}

/// Creates one owner-only file or verifies an existing exact value.
///
/// The destination is never overwritten. A concurrent creator can succeed only when
/// it produced the same bytes under the same owner-only policy.
///
/// # Errors
///
/// Returns a finite unavailable, unsafe, or conflicting-storage error.
pub fn create_or_verify_owner_protected_file(
    path: &Path,
    expected: &[u8],
) -> Result<(), SecretStorageError> {
    if expected.is_empty() {
        return Err(SecretStorageError::OwnerProtectedStorageUnsafe);
    }
    platform::create_or_verify_file(path, expected)
}

/// Opens one existing owner-only ordinary file without following the final link.
///
/// # Errors
///
/// Returns a finite unavailable or unsafe-storage error.
pub fn open_owner_protected_file(path: &Path) -> Result<File, SecretStorageError> {
    platform::open_file(path)
}

#[cfg(unix)]
mod platform {
    use std::fs::{DirBuilder, File, OpenOptions};
    use std::io::{Read as _, Write as _};
    use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _};
    use std::path::Path;

    use crate::SecretStorageError;

    const DIRECTORY_MODE: u32 = 0o700;
    const FILE_MODE: u32 = 0o600;

    pub(super) fn ensure_directory(path: &Path) -> Result<(), SecretStorageError> {
        match std::fs::symlink_metadata(path) {
            Ok(metadata) => verify_directory(&metadata),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                DirBuilder::new()
                    .mode(DIRECTORY_MODE)
                    .create(path)
                    .map_err(|_| SecretStorageError::OwnerProtectedStorageUnavailable)?;
                let metadata = std::fs::symlink_metadata(path)
                    .map_err(|_| SecretStorageError::OwnerProtectedStorageUnavailable)?;
                verify_directory(&metadata)
            }
            Err(_) => Err(SecretStorageError::OwnerProtectedStorageUnavailable),
        }
    }

    pub(super) fn create_or_verify_file(
        path: &Path,
        expected: &[u8],
    ) -> Result<(), SecretStorageError> {
        let parent = path
            .parent()
            .ok_or(SecretStorageError::OwnerProtectedStorageUnsafe)?;
        let metadata = std::fs::symlink_metadata(parent)
            .map_err(|_| SecretStorageError::OwnerProtectedStorageUnavailable)?;
        verify_directory(&metadata)?;

        let created = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(FILE_MODE)
            .custom_flags(libc_flags())
            .open(path);
        match created {
            Ok(mut file) => {
                if file.write_all(expected).is_err() || file.sync_all().is_err() {
                    drop(file);
                    let _ = std::fs::remove_file(path);
                    return Err(SecretStorageError::OwnerProtectedStorageUnavailable);
                }
                verify_file(&file)?;
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let mut file = open_file(path)?;
                let maximum = expected
                    .len()
                    .checked_add(1)
                    .ok_or(SecretStorageError::OwnerProtectedStorageUnsafe)?;
                let mut actual = Vec::with_capacity(maximum);
                std::io::Read::by_ref(&mut file)
                    .take(maximum as u64)
                    .read_to_end(&mut actual)
                    .map_err(|_| SecretStorageError::OwnerProtectedStorageUnavailable)?;
                if actual == expected {
                    Ok(())
                } else {
                    Err(SecretStorageError::OwnerProtectedStorageConflict)
                }
            }
            Err(_) => Err(SecretStorageError::OwnerProtectedStorageUnavailable),
        }
    }

    pub(super) fn open_file(path: &Path) -> Result<File, SecretStorageError> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc_flags())
            .open(path)
            .map_err(|_| SecretStorageError::OwnerProtectedStorageUnavailable)?;
        verify_file(&file)?;
        Ok(file)
    }

    fn verify_directory(metadata: &std::fs::Metadata) -> Result<(), SecretStorageError> {
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.mode() & 0o077 != 0
        {
            return Err(SecretStorageError::OwnerProtectedStorageUnsafe);
        }
        Ok(())
    }

    fn verify_file(file: &File) -> Result<(), SecretStorageError> {
        let metadata = file
            .metadata()
            .map_err(|_| SecretStorageError::OwnerProtectedStorageUnavailable)?;
        if !metadata.is_file()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.mode() & 0o077 != 0
            || metadata.nlink() != 1
        {
            return Err(SecretStorageError::OwnerProtectedStorageUnsafe);
        }
        Ok(())
    }

    fn libc_flags() -> i32 {
        (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC).bits() as i32
    }
}

#[cfg(windows)]
mod platform {
    use std::fs::File;
    use std::path::Path;

    use crate::SecretStorageError;

    pub(super) fn ensure_directory(path: &Path) -> Result<(), SecretStorageError> {
        KonclaveWindowsSecurity::ensure_owner_restricted_directory(path).map_err(map_error)
    }

    pub(super) fn create_or_verify_file(
        path: &Path,
        expected: &[u8],
    ) -> Result<(), SecretStorageError> {
        KonclaveWindowsSecurity::create_or_verify_owner_restricted_file(path, expected)
            .map_err(map_error)
    }

    pub(super) fn open_file(path: &Path) -> Result<File, SecretStorageError> {
        KonclaveWindowsSecurity::open_owner_restricted_file(path).map_err(map_error)
    }

    fn map_error(error: std::io::Error) -> SecretStorageError {
        match error.kind() {
            std::io::ErrorKind::AlreadyExists => SecretStorageError::OwnerProtectedStorageConflict,
            std::io::ErrorKind::NotFound => SecretStorageError::OwnerProtectedStorageUnavailable,
            std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::InvalidInput => {
                SecretStorageError::OwnerProtectedStorageUnsafe
            }
            _ => SecretStorageError::OwnerProtectedStorageUnavailable,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Read as _;

    use super::*;

    #[test]
    fn owner_protected_file_creation_is_exact_and_idempotent() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("private");
        ensure_owner_protected_directory(&directory).unwrap();
        let file = directory.join("record");
        create_or_verify_owner_protected_file(&file, b"exact").unwrap();
        create_or_verify_owner_protected_file(&file, b"exact").unwrap();
        assert_eq!(
            create_or_verify_owner_protected_file(&file, b"different").unwrap_err(),
            SecretStorageError::OwnerProtectedStorageConflict
        );
        let mut value = Vec::new();
        open_owner_protected_file(&file)
            .unwrap()
            .read_to_end(&mut value)
            .unwrap();
        assert_eq!(value, b"exact");
    }

    #[cfg(unix)]
    #[test]
    fn links_permissions_and_foreign_shapes_fail_closed() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("private");
        ensure_owner_protected_directory(&directory).unwrap();
        let file = directory.join("record");
        create_or_verify_owner_protected_file(&file, b"exact").unwrap();

        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert_eq!(
            open_owner_protected_file(&file).unwrap_err(),
            SecretStorageError::OwnerProtectedStorageUnsafe
        );
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        let link = directory.join("linked");
        std::fs::hard_link(&file, &link).unwrap();
        assert_eq!(
            open_owner_protected_file(&file).unwrap_err(),
            SecretStorageError::OwnerProtectedStorageUnsafe
        );
    }
}
