use std::io::Read as _;
use std::path::{Path, PathBuf};

use aws_lc_rs::rand::{SecureRandom as _, SystemRandom};
use zeroize::Zeroizing;

use crate::key::{WRAPPING_KEY_BYTES, WrappingKey, validate_profile_id};
use crate::{
    SecretStorageError, WrappingKeyProvider, create_or_verify_owner_protected_file,
    ensure_owner_protected_directory, open_owner_protected_file,
};

const FILE_MAGIC: &[u8; 4] = b"KDP1";
const PAYLOAD_MAGIC: &[u8; 4] = b"KWP1";
const MAX_FILE_BYTES: usize = 4100;

/// Independent profile KEK in an owner-only, current-user DPAPI-protected file.
///
/// This provider never uses Windows Credential Manager. The caller must retain the
/// profile's exclusive lock through custody and database opening.
pub struct WindowsWrappingKeyProvider {
    directory: PathBuf,
    context: Vec<u8>,
    allow_create: bool,
}

impl WindowsWrappingKeyProvider {
    /// Selects DPAPI custody for one canonical profile identifier and directory.
    ///
    /// `allow_create` must be false whenever any dependent persistent state already
    /// exists. An absent key then fails rather than replacing the identity or
    /// migrating a legacy Credential Manager entry.
    ///
    /// # Errors
    ///
    /// Returns a validation error for a non-canonical profile identifier.
    pub fn new(
        profile_id: &str,
        profile_directory: &Path,
        allow_create: bool,
    ) -> Result<Self, SecretStorageError> {
        validate_profile_id(profile_id)?;
        let mut context = b"konclave-windows-profile-kek-v1:slot-1:".to_vec();
        context.extend_from_slice(profile_id.as_bytes());
        Ok(Self {
            directory: profile_directory.join("custody"),
            context,
            allow_create,
        })
    }

    /// Authenticates an existing key file without creating any directory or key.
    ///
    /// This read-only diagnostic does not open profile databases or require their
    /// process lock. Runtime load-or-create still requires exclusive ownership.
    ///
    /// # Errors
    ///
    /// Returns a validation, storage or authentication error on unavailable custody.
    pub fn verify_existing(
        profile_id: &str,
        profile_directory: &Path,
    ) -> Result<(), SecretStorageError> {
        Self::new(profile_id, profile_directory, false)?
            .load()
            .map(|_| ())
    }

    fn key_path(&self) -> PathBuf {
        self.directory.join("wrapping-key-1.dpapi")
    }

    fn load(&self) -> Result<WrappingKey, SecretStorageError> {
        let file = open_owner_protected_file(&self.key_path())?;
        let mut record = Zeroizing::new(Vec::new());
        file.take((MAX_FILE_BYTES + 1) as u64)
            .read_to_end(&mut record)
            .map_err(|_| SecretStorageError::OwnerProtectedStorageUnavailable)?;
        let protected = protected_bytes(&record)?;
        let plaintext =
            KonclaveWindowsSecurity::unprotect_current_user_data(protected, &self.context)
                .map_err(|_| SecretStorageError::InvalidNativeCredential)?;
        payload_key(&plaintext)
    }
}

fn may_create_key(present: bool, allow_create: bool) -> Result<bool, SecretStorageError> {
    match (present, allow_create) {
        (true, _) => Ok(false),
        (false, true) => Ok(true),
        (false, false) => Err(SecretStorageError::NativeCredentialNotFound),
    }
}

fn protected_bytes(record: &[u8]) -> Result<&[u8], SecretStorageError> {
    if record.len() <= FILE_MAGIC.len()
        || record.len() > MAX_FILE_BYTES
        || !record.starts_with(FILE_MAGIC)
    {
        return Err(SecretStorageError::InvalidNativeCredential);
    }
    Ok(&record[FILE_MAGIC.len()..])
}

fn payload_key(plaintext: &[u8]) -> Result<WrappingKey, SecretStorageError> {
    if plaintext.len() != PAYLOAD_MAGIC.len() + WRAPPING_KEY_BYTES
        || !plaintext.starts_with(PAYLOAD_MAGIC)
    {
        return Err(SecretStorageError::InvalidNativeCredential);
    }
    WrappingKey::from_slice(&plaintext[PAYLOAD_MAGIC.len()..])
}

impl WrappingKeyProvider for WindowsWrappingKeyProvider {
    fn load_or_create(self) -> Result<WrappingKey, SecretStorageError> {
        let present = self
            .key_path()
            .try_exists()
            .map_err(|_| SecretStorageError::OwnerProtectedStorageUnavailable)?;
        if !may_create_key(present, self.allow_create)? {
            ensure_owner_protected_directory(&self.directory)?;
            return self.load();
        }
        ensure_owner_protected_directory(&self.directory)?;
        let mut plaintext = Zeroizing::new(vec![0; PAYLOAD_MAGIC.len() + WRAPPING_KEY_BYTES]);
        plaintext[..PAYLOAD_MAGIC.len()].copy_from_slice(PAYLOAD_MAGIC);
        SystemRandom::new()
            .fill(&mut plaintext[PAYLOAD_MAGIC.len()..])
            .map_err(|_| SecretStorageError::RandomGenerationFailed)?;
        let protected =
            KonclaveWindowsSecurity::protect_current_user_data(&plaintext, &self.context)
                .map_err(|_| SecretStorageError::NativeCustodyUnavailable)?;
        let mut record = Zeroizing::new(FILE_MAGIC.to_vec());
        record.extend_from_slice(&protected);
        create_or_verify_owner_protected_file(&self.key_path(), &record)?;
        let key = self.load()?;
        if key.as_bytes().as_slice() != &plaintext[PAYLOAD_MAGIC.len()..] {
            return Err(SecretStorageError::InvalidNativeCredential);
        }
        Ok(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider(root: &Path, id: &str, allow_create: bool) -> WindowsWrappingKeyProvider {
        WindowsWrappingKeyProvider::new(id, root, allow_create).unwrap()
    }

    #[test]
    fn creation_decisions_never_replace_dependent_custody() {
        for (present, allowed, expected) in [
            (true, true, Ok(false)),
            (true, false, Ok(false)),
            (false, true, Ok(true)),
            (
                false,
                false,
                Err(SecretStorageError::NativeCredentialNotFound),
            ),
        ] {
            assert_eq!(may_create_key(present, allowed), expected);
        }
    }

    #[test]
    fn dpapi_profile_key_reopens_without_credential_manager_and_binds_profile() {
        let root = tempfile::tempdir().unwrap();
        let first = provider(root.path(), "profile-a", true)
            .load_or_create()
            .unwrap();
        let reopened = provider(root.path(), "profile-a", false)
            .load_or_create()
            .unwrap();
        assert!(first.as_bytes() == reopened.as_bytes());
        assert!(
            provider(root.path(), "profile-b", false)
                .load_or_create()
                .is_err()
        );
        let other = tempfile::tempdir().unwrap();
        let independent = provider(other.path(), "profile-a", true)
            .load_or_create()
            .unwrap();
        assert!(first.as_bytes() != independent.as_bytes());
    }

    #[test]
    fn missing_or_invalid_key_is_not_recreated() {
        let root = tempfile::tempdir().unwrap();
        let missing = provider(root.path(), "profile-a", false);
        assert_eq!(
            missing.load_or_create().err(),
            Some(SecretStorageError::NativeCredentialNotFound)
        );
        assert!(!root.path().join("custody").exists());
        let initialized = provider(root.path(), "profile-a", true);
        let key_path = initialized.key_path();
        initialized.load_or_create().unwrap();
        std::fs::write(&key_path, b"KDP1damaged").unwrap();
        assert!(
            provider(root.path(), "profile-a", true)
                .load_or_create()
                .is_err()
        );
        assert_eq!(std::fs::read(&key_path).unwrap(), b"KDP1damaged");
    }

    #[test]
    fn protected_record_and_payload_reject_invalid_shapes() {
        for record in [b"".as_slice(), b"KDP1", b"KDP2payload"] {
            assert!(protected_bytes(record).is_err());
        }
        assert!(protected_bytes(&vec![0; MAX_FILE_BYTES + 1]).is_err());
        for payload in [
            vec![],
            vec![0; 36],
            [PAYLOAD_MAGIC.as_slice(), &[0; 31]].concat(),
        ] {
            assert!(payload_key(&payload).is_err());
        }
    }

    #[test]
    fn many_profile_keys_do_not_consume_credential_manager_entries() {
        fn profile_credentials() -> usize {
            let result = std::process::Command::new("cmdkey")
                .arg("/list")
                .output()
                .unwrap();
            assert!(result.status.success());
            String::from_utf8(result.stdout)
                .unwrap()
                .lines()
                .filter(|line| line.contains("profile:") && line.ends_with(".Konclave"))
                .count()
        }
        let before = profile_credentials();
        let root = tempfile::tempdir().unwrap();
        for index in 0..32 {
            let id = format!("profile-{index}");
            let directory = root.path().join(&id);
            std::fs::create_dir(&directory).unwrap();
            provider(&directory, &id, true).load_or_create().unwrap();
            provider(&directory, &id, false).load_or_create().unwrap();
        }
        assert_eq!(profile_credentials(), before);
    }
}
