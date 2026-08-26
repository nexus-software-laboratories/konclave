use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use zeroize::Zeroizing;

use crate::key::{WRAPPING_KEY_BYTES, WrappingKey};
use crate::{SecretStorageError, WrappingKeyProvider};

const SERVICE_NAME: &str = "Konclave";
const ENROLLMENT_SERVICE_NAME: &str = "Konclave Relay Enrollment";
const LOCAL_SERVICE_IDENTITY_SERVICE_NAME: &str = "Konclave Local Service";
const MAX_PROFILE_ID_BYTES: usize = 32;
const MAX_INSTALLATION_ID_BYTES: usize = 64;
const MAX_ENROLLMENT_RECORD_BYTES: usize = 4 * 1024;

/// Native operating-system credential-store provider for one local profile.
///
/// The caller must hold the profile's exclusive process lock while loading or
/// creating the credential; native stores do not provide a portable create-if-absent
/// transaction.
pub struct NativeWrappingKeyProvider {
    account_name: String,
}

/// Dedicated operating-system credential-store entry for relay enrollment authority.
///
/// Native credential stores do not expose a portable create-if-absent transaction.
/// Callers must derive each installation identifier from the complete record identity
/// so concurrent writers for one identifier can only supply identical bytes.
pub struct NativeEnrollmentCredentialStore {
    account_name: String,
}

/// Dedicated operating-system credential-store entry for the shared service identity.
///
/// The installation record pins the corresponding public key, while only this native
/// entry holds the private seed.
pub struct NativeLocalServiceIdentityStore;

impl NativeLocalServiceIdentityStore {
    const ACCOUNT_NAME: &'static str = "local-service:identity:1";

    /// Loads the bounded service signing seed without creating it.
    ///
    /// # Errors
    ///
    /// Returns a missing, unavailable, or malformed native credential error.
    pub fn load(&self) -> Result<Zeroizing<Vec<u8>>, SecretStorageError> {
        let entry = KeyringEntry(
            keyring::Entry::new(LOCAL_SERVICE_IDENTITY_SERVICE_NAME, Self::ACCOUNT_NAME)
                .map_err(|_| SecretStorageError::NativeCustodyUnavailable)?,
        );
        load_bounded_from(&entry)
    }

    /// Creates or verifies the exact service signing seed.
    ///
    /// # Errors
    ///
    /// An existing different value is never overwritten. Returns a bounded-record,
    /// mismatch, or native credential-store error.
    pub fn store(&self, secret: &[u8]) -> Result<(), SecretStorageError> {
        let entry = KeyringEntry(
            keyring::Entry::new(LOCAL_SERVICE_IDENTITY_SERVICE_NAME, Self::ACCOUNT_NAME)
                .map_err(|_| SecretStorageError::NativeCustodyUnavailable)?,
        );
        store_bounded_to(&entry, secret)
    }
}

impl NativeEnrollmentCredentialStore {
    /// Opens one installation identifier in the enrollment-only keyring namespace.
    ///
    /// # Errors
    ///
    /// Returns a validation error for an empty, oversized, or unsafe name.
    pub fn new(installation_id: impl Into<String>) -> Result<Self, SecretStorageError> {
        let installation_id = installation_id.into();
        if installation_id.is_empty()
            || installation_id.len() > MAX_INSTALLATION_ID_BYTES
            || !installation_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(SecretStorageError::InvalidRecordIdentifier {
                maximum: MAX_INSTALLATION_ID_BYTES,
            });
        }
        Ok(Self {
            account_name: format!("installation:{installation_id}:authority:1"),
        })
    }

    /// Loads one bounded endpoint-bound credential record without creating it.
    ///
    /// # Errors
    ///
    /// Returns a missing, unavailable, or invalid native credential error.
    pub fn load(&self) -> Result<Zeroizing<Vec<u8>>, SecretStorageError> {
        let entry = KeyringEntry(
            keyring::Entry::new(ENROLLMENT_SERVICE_NAME, &self.account_name)
                .map_err(|_| SecretStorageError::NativeCustodyUnavailable)?,
        );
        load_bounded_from(&entry)
    }

    /// Creates or verifies one exact bounded endpoint-bound credential record.
    ///
    /// # Errors
    ///
    /// An observed existing record is never overwritten. Returns an invalid-length,
    /// mismatch, or unavailable native credential-store error. The caller remains
    /// responsible for clearing any additional secret copy and for the identifier
    /// uniqueness contract documented on this type.
    pub fn store(&self, secret: &[u8]) -> Result<(), SecretStorageError> {
        let entry = KeyringEntry(
            keyring::Entry::new(ENROLLMENT_SERVICE_NAME, &self.account_name)
                .map_err(|_| SecretStorageError::NativeCustodyUnavailable)?,
        );
        store_bounded_to(&entry, secret)
    }
}

impl NativeWrappingKeyProvider {
    /// Creates a provider for a bounded profile identifier.
    ///
    /// # Errors
    ///
    /// Returns a validation error when the identifier is empty, oversized, or
    /// contains a character outside lowercase ASCII letters, digits, `-`, and `_`.
    /// Uppercase is rejected rather than folded so credential-store lookup cannot
    /// alias a filesystem profile under another spelling.
    pub fn new(profile_id: &str) -> Result<Self, SecretStorageError> {
        if profile_id.is_empty()
            || profile_id.len() > MAX_PROFILE_ID_BYTES
            || !profile_id.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
            })
        {
            return Err(SecretStorageError::InvalidRecordIdentifier {
                maximum: MAX_PROFILE_ID_BYTES,
            });
        }
        Ok(Self {
            account_name: format!("profile:{profile_id}:wrapping-key:1"),
        })
    }

    /// Verifies that an existing profile wrapping key is readable without creating it.
    ///
    /// # Errors
    ///
    /// Returns a missing, unavailable, or malformed native credential error.
    pub fn verify_existing(profile_id: &str) -> Result<(), SecretStorageError> {
        let provider = Self::new(profile_id)?;
        let entry = KeyringEntry(
            keyring::Entry::new(SERVICE_NAME, &provider.account_name)
                .map_err(|_| SecretStorageError::NativeCustodyUnavailable)?,
        );
        verify_existing_from(&entry)
    }
}

impl WrappingKeyProvider for NativeWrappingKeyProvider {
    fn load_or_create(self) -> Result<WrappingKey, SecretStorageError> {
        let entry = KeyringEntry(
            keyring::Entry::new(SERVICE_NAME, &self.account_name)
                .map_err(|_| SecretStorageError::NativeCustodyUnavailable)?,
        );
        load_or_create_from(&entry)
    }
}

fn load_or_create_from(entry: &impl NativeEntry) -> Result<WrappingKey, SecretStorageError> {
    match entry.get_secret() {
        Ok(secret) => parse_native_secret(secret),
        Err(NativeEntryError::NotFound) => {
            let mut generated = Zeroizing::new([0_u8; WRAPPING_KEY_BYTES]);
            SystemRandom::new()
                .fill(generated.as_mut())
                .map_err(|_| SecretStorageError::RandomGenerationFailed)?;
            entry
                .set_secret(generated.as_ref())
                .map_err(|_| SecretStorageError::NativeCustodyUnavailable)?;
            let stored = entry
                .get_secret()
                .map_err(|_| SecretStorageError::NativeCustodyUnavailable)?;
            parse_native_secret(stored)
        }
        Err(NativeEntryError::Unavailable) => Err(SecretStorageError::NativeCustodyUnavailable),
    }
}

enum NativeEntryError {
    NotFound,
    Unavailable,
}

trait NativeEntry {
    fn get_secret(&self) -> Result<Vec<u8>, NativeEntryError>;
    fn set_secret(&self, secret: &[u8]) -> Result<(), NativeEntryError>;
}

struct KeyringEntry(keyring::Entry);

impl NativeEntry for KeyringEntry {
    fn get_secret(&self) -> Result<Vec<u8>, NativeEntryError> {
        match self.0.get_secret() {
            Ok(secret) => Ok(secret),
            Err(keyring::Error::NoEntry) => Err(NativeEntryError::NotFound),
            Err(_) => Err(NativeEntryError::Unavailable),
        }
    }

    fn set_secret(&self, secret: &[u8]) -> Result<(), NativeEntryError> {
        self.0
            .set_secret(secret)
            .map_err(|_| NativeEntryError::Unavailable)
    }
}

fn parse_native_secret(secret: Vec<u8>) -> Result<WrappingKey, SecretStorageError> {
    let secret = Zeroizing::new(secret);
    WrappingKey::from_slice(&secret)
}

fn load_bounded_from(entry: &impl NativeEntry) -> Result<Zeroizing<Vec<u8>>, SecretStorageError> {
    let secret = match entry.get_secret() {
        Ok(secret) => Zeroizing::new(secret),
        Err(NativeEntryError::NotFound) => {
            return Err(SecretStorageError::NativeCredentialNotFound);
        }
        Err(NativeEntryError::Unavailable) => {
            return Err(SecretStorageError::NativeCustodyUnavailable);
        }
    };
    if secret.is_empty() || secret.len() > MAX_ENROLLMENT_RECORD_BYTES {
        return Err(SecretStorageError::InvalidNativeCredential);
    }
    Ok(secret)
}

fn store_bounded_to(entry: &impl NativeEntry, secret: &[u8]) -> Result<(), SecretStorageError> {
    if secret.is_empty() || secret.len() > MAX_ENROLLMENT_RECORD_BYTES {
        return Err(SecretStorageError::InvalidNativeCredential);
    }
    match entry.get_secret() {
        Ok(existing) => {
            let existing = Zeroizing::new(existing);
            if existing.as_slice() == secret {
                Ok(())
            } else {
                Err(SecretStorageError::InvalidNativeCredential)
            }
        }
        Err(NativeEntryError::NotFound) => {
            entry
                .set_secret(secret)
                .map_err(|_| SecretStorageError::NativeCustodyUnavailable)?;
            let stored = load_bounded_from(entry)?;
            if stored.as_slice() == secret {
                Ok(())
            } else {
                Err(SecretStorageError::InvalidNativeCredential)
            }
        }
        Err(NativeEntryError::Unavailable) => Err(SecretStorageError::NativeCustodyUnavailable),
    }
}

fn verify_existing_from(entry: &impl NativeEntry) -> Result<(), SecretStorageError> {
    match entry.get_secret() {
        Ok(secret) => parse_native_secret(secret).map(|_| ()),
        Err(NativeEntryError::NotFound) => Err(SecretStorageError::NativeCredentialNotFound),
        Err(NativeEntryError::Unavailable) => Err(SecretStorageError::NativeCustodyUnavailable),
    }
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::collections::VecDeque;

    use super::*;

    #[test]
    fn profile_identifier_is_portable_and_bounded() {
        assert!(NativeWrappingKeyProvider::new("default-profile").is_ok());
        assert!(NativeWrappingKeyProvider::new(&"a".repeat(MAX_PROFILE_ID_BYTES)).is_ok());
        assert!(NativeWrappingKeyProvider::new("Default-Profile").is_err());
        assert!(NativeWrappingKeyProvider::new(&"a".repeat(MAX_PROFILE_ID_BYTES + 1)).is_err());
        assert!(NativeEnrollmentCredentialStore::new("installation-a").is_ok());
        assert!(NativeEnrollmentCredentialStore::new("../credential").is_err());
        assert!(NativeEnrollmentCredentialStore::new("profile:victim:wrapping-key:1").is_err());
        assert_eq!(
            NativeWrappingKeyProvider::new("../profile").err(),
            Some(SecretStorageError::InvalidRecordIdentifier {
                maximum: MAX_PROFILE_ID_BYTES
            })
        );
    }

    #[test]
    fn only_not_found_creates_and_readback_supplies_the_key() {
        let entry = FakeEntry::new([
            Err(NativeEntryError::NotFound),
            Ok(vec![9; WRAPPING_KEY_BYTES]),
        ]);
        let key = load_or_create_from(&entry).unwrap();
        assert_eq!(entry.set_count.get(), 1);
        assert_eq!(key.as_bytes(), &[9; WRAPPING_KEY_BYTES]);

        let unavailable = FakeEntry::new([Err(NativeEntryError::Unavailable)]);
        assert_eq!(
            load_or_create_from(&unavailable).err(),
            Some(SecretStorageError::NativeCustodyUnavailable)
        );
        assert_eq!(unavailable.set_count.get(), 0);
    }

    #[test]
    fn invalid_existing_or_readback_credentials_fail_closed() {
        let existing = FakeEntry::new([Ok(vec![1; WRAPPING_KEY_BYTES - 1])]);
        assert_eq!(
            load_or_create_from(&existing).err(),
            Some(SecretStorageError::InvalidNativeCredential)
        );
        assert_eq!(existing.set_count.get(), 0);

        let readback = FakeEntry::new([
            Err(NativeEntryError::NotFound),
            Ok(vec![1; WRAPPING_KEY_BYTES - 1]),
        ]);
        assert_eq!(
            load_or_create_from(&readback).err(),
            Some(SecretStorageError::InvalidNativeCredential)
        );
        assert_eq!(readback.set_count.get(), 1);

        let missing = FakeEntry::new([Err(NativeEntryError::NotFound)]);
        assert_eq!(
            verify_existing_from(&missing).err(),
            Some(SecretStorageError::NativeCredentialNotFound)
        );
        assert_eq!(missing.set_count.get(), 0);
    }

    #[test]
    fn bounded_enrollment_record_never_creates_or_truncates() {
        let zero = FakeEntry::new([Ok(Vec::new())]);
        assert_eq!(
            load_bounded_from(&zero).err(),
            Some(SecretStorageError::InvalidNativeCredential)
        );
        assert_eq!(
            store_bounded_to(&zero, &[]).err(),
            Some(SecretStorageError::InvalidNativeCredential)
        );

        let exact = FakeEntry::new([Ok(vec![7; 64])]);
        assert_eq!(load_bounded_from(&exact).unwrap().as_slice(), &[7; 64]);

        let missing = FakeEntry::new([Err(NativeEntryError::NotFound)]);
        assert_eq!(
            load_bounded_from(&missing).err(),
            Some(SecretStorageError::NativeCredentialNotFound)
        );
        assert_eq!(missing.set_count.get(), 0);

        let wrong_length = FakeEntry::new([Ok(vec![7; MAX_ENROLLMENT_RECORD_BYTES + 1])]);
        assert_eq!(
            load_bounded_from(&wrong_length).err(),
            Some(SecretStorageError::InvalidNativeCredential)
        );

        let existing = FakeEntry::new([Ok(vec![8; 64])]);
        store_bounded_to(&existing, &[8; 64]).unwrap();
        assert_eq!(existing.set_count.get(), 0);
        let mismatched = FakeEntry::new([Ok(vec![9; 64])]);
        assert_eq!(
            store_bounded_to(&mismatched, &[8; 64]).err(),
            Some(SecretStorageError::InvalidNativeCredential)
        );
        assert_eq!(mismatched.set_count.get(), 0);

        let missing = FakeEntry::new([Err(NativeEntryError::NotFound), Ok(vec![8; 64])]);
        store_bounded_to(&missing, &[8; 64]).unwrap();
        assert_eq!(missing.set_count.get(), 1);
    }

    struct FakeEntry {
        gets: RefCell<VecDeque<Result<Vec<u8>, NativeEntryError>>>,
        set_count: Cell<usize>,
    }

    impl FakeEntry {
        fn new<const N: usize>(gets: [Result<Vec<u8>, NativeEntryError>; N]) -> Self {
            Self {
                gets: RefCell::new(gets.into()),
                set_count: Cell::new(0),
            }
        }
    }

    impl NativeEntry for FakeEntry {
        fn get_secret(&self) -> Result<Vec<u8>, NativeEntryError> {
            self.gets
                .borrow_mut()
                .pop_front()
                .unwrap_or(Err(NativeEntryError::Unavailable))
        }

        fn set_secret(&self, _secret: &[u8]) -> Result<(), NativeEntryError> {
            self.set_count.set(self.set_count.get() + 1);
            Ok(())
        }
    }
}
