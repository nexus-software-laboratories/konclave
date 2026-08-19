use std::io::Read;

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::SecretStorageError;

pub(crate) const WRAPPING_KEY_BYTES: usize = 32;

/// Source that yields one profile wrapping key during daemon startup.
pub trait WrappingKeyProvider {
    /// Loads or creates the configured wrapping key.
    ///
    /// # Errors
    ///
    /// Returns a typed error instead of falling back when custody is unavailable.
    fn load_or_create(self) -> Result<WrappingKey, SecretStorageError>;
}

/// Explicit wrapping key supplied by an external secret mechanism.
pub struct ExternalWrappingKeyProvider {
    key: WrappingKey,
}

impl ExternalWrappingKeyProvider {
    /// Takes ownership of exactly 32 raw wrapping-key bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; WRAPPING_KEY_BYTES]) -> Self {
        Self {
            key: WrappingKey(bytes),
        }
    }

    /// Reads exactly 32 raw bytes and rejects short or trailing input.
    ///
    /// # Errors
    ///
    /// Returns [`SecretStorageError::InvalidExternalKey`] for any length other
    /// than 32 bytes or when the reader fails.
    pub fn from_reader(mut reader: impl Read) -> Result<Self, SecretStorageError> {
        let mut bytes = Zeroizing::new([0_u8; WRAPPING_KEY_BYTES]);
        reader
            .read_exact(&mut *bytes)
            .map_err(|_| SecretStorageError::InvalidExternalKey)?;
        let mut trailing = [0_u8; 1];
        match reader.read(&mut trailing) {
            Ok(0) => Ok(Self::from_bytes(*bytes)),
            _ => Err(SecretStorageError::InvalidExternalKey),
        }
    }
}

impl WrappingKeyProvider for ExternalWrappingKeyProvider {
    fn load_or_create(self) -> Result<WrappingKey, SecretStorageError> {
        Ok(self.key)
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct WrappingKey(pub(crate) [u8; WRAPPING_KEY_BYTES]);

impl WrappingKey {
    #[cfg(feature = "native-keyring")]
    pub(crate) fn from_slice(bytes: &[u8]) -> Result<Self, SecretStorageError> {
        let key = bytes
            .try_into()
            .map_err(|_| SecretStorageError::InvalidNativeCredential)?;
        Ok(Self(key))
    }

    pub(crate) const fn as_bytes(&self) -> &[u8; WRAPPING_KEY_BYTES] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn external_reader_requires_exact_key_length() {
        assert!(ExternalWrappingKeyProvider::from_reader(&[7_u8; 32][..]).is_ok());
        assert_eq!(
            ExternalWrappingKeyProvider::from_reader(&[7_u8; 31][..]).err(),
            Some(SecretStorageError::InvalidExternalKey)
        );
        assert_eq!(
            ExternalWrappingKeyProvider::from_reader(&[7_u8; 33][..]).err(),
            Some(SecretStorageError::InvalidExternalKey)
        );
    }
}
