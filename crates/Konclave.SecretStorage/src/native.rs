use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use zeroize::Zeroizing;

use crate::key::{WRAPPING_KEY_BYTES, WrappingKey};
use crate::{SecretStorageError, WrappingKeyProvider};

const SERVICE_NAME: &str = "Konclave";
const MAX_PROFILE_ID_BYTES: usize = 64;

/// Native operating-system credential-store provider for one local profile.
///
/// The caller must hold the profile's exclusive process lock while loading or
/// creating the credential; native stores do not provide a portable create-if-absent
/// transaction.
pub struct NativeWrappingKeyProvider {
    account_name: String,
}

impl NativeWrappingKeyProvider {
    /// Creates a provider for a bounded profile identifier.
    ///
    /// # Errors
    ///
    /// Returns a validation error when the identifier is empty, oversized, or
    /// contains characters unsafe for a portable credential name.
    pub fn new(profile_id: &str) -> Result<Self, SecretStorageError> {
        if profile_id.is_empty()
            || profile_id.len() > MAX_PROFILE_ID_BYTES
            || !profile_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(SecretStorageError::InvalidRecordIdentifier {
                maximum: MAX_PROFILE_ID_BYTES,
            });
        }
        Ok(Self {
            account_name: format!("profile:{profile_id}:wrapping-key:1"),
        })
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

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::collections::VecDeque;

    use super::*;

    #[test]
    fn profile_identifier_is_portable_and_bounded() {
        assert!(NativeWrappingKeyProvider::new("default-profile").is_ok());
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
