use std::sync::Arc;

use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::SecretStorageError;

/// Byte length of an AES-256-GCM key.
pub const AUTHENTICATED_CIPHER_KEY_BYTES: usize = 32;
/// Byte length of an AES-GCM nonce.
pub const AUTHENTICATED_CIPHER_NONCE_BYTES: usize = 12;
/// Byte length of the authentication tag appended to ciphertext.
pub const AUTHENTICATED_CIPHER_TAG_BYTES: usize = 16;

/// Authenticated ciphertext plus the nonce required to open it.
///
/// The caller owns format and compatibility. This type deliberately carries no
/// storage magic, key slot, record kind, or associated-data domain, so an at-rest
/// format and a wire format can share the vetted primitive without becoming the same
/// contract.
#[derive(PartialEq, Eq)]
pub struct AuthenticatedCiphertext {
    nonce: [u8; AUTHENTICATED_CIPHER_NONCE_BYTES],
    bytes: Vec<u8>,
}

impl AuthenticatedCiphertext {
    /// Validates and owns one nonce and bounded ciphertext.
    ///
    /// `maximum_plaintext_bytes` is the caller's format bound. The accepted
    /// ciphertext is at most that bound plus one authentication tag, and must contain
    /// at least a tag even when the plaintext is empty.
    ///
    /// # Errors
    ///
    /// Returns a typed storage error before allocation for a wrong nonce length,
    /// truncated ciphertext, or ciphertext exceeding the caller's bound.
    pub fn from_parts(
        nonce: &[u8],
        bytes: Vec<u8>,
        maximum_plaintext_bytes: usize,
    ) -> Result<Self, SecretStorageError> {
        let nonce = nonce
            .try_into()
            .map_err(|_| SecretStorageError::InvalidSealedBlob)?;
        validate_ciphertext_length(bytes.len(), maximum_plaintext_bytes)?;
        Ok(Self { nonce, bytes })
    }

    /// Returns the nonce authenticated with this ciphertext.
    #[must_use]
    pub const fn nonce(&self) -> &[u8; AUTHENTICATED_CIPHER_NONCE_BYTES] {
        &self.nonce
    }

    /// Returns ciphertext with its appended authentication tag.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consumes the wrapper into its ciphertext bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

/// Shared AES-256-GCM primitive for bounded, domain-owned formats.
///
/// This type owns key material, supplies fresh operating-system-random nonces, and
/// authenticates caller-provided associated data. It does not define a serialized
/// format. Secret storage and pairing each provide their own versioned framing and
/// associated-data domain above it.
pub struct AuthenticatedCipher {
    key: Arc<CipherKey>,
    random: SystemRandom,
}

impl AuthenticatedCipher {
    /// Copies exactly one AES-256 key into zeroizing ownership.
    ///
    /// The caller retains ownership of the source. Secret-bearing callers should keep
    /// that source in a zeroizing wrapper so only the cipher's protected copy remains
    /// after construction.
    #[must_use]
    pub fn new(key: &[u8; AUTHENTICATED_CIPHER_KEY_BYTES]) -> Self {
        Self {
            key: Arc::new(CipherKey(*key)),
            random: SystemRandom::new(),
        }
    }

    /// Creates another handle sharing the same key without copying key bytes.
    #[must_use]
    pub fn share(&self) -> Self {
        Self {
            key: Arc::clone(&self.key),
            random: SystemRandom::new(),
        }
    }

    /// Seals bounded plaintext under a fresh nonce and caller-owned associated data.
    ///
    /// # Errors
    ///
    /// Returns a typed error when plaintext exceeds the supplied bound, secure
    /// randomness is unavailable, or the provider rejects encryption.
    pub fn seal(
        &self,
        associated_data: &[u8],
        plaintext: &[u8],
        maximum_plaintext_bytes: usize,
    ) -> Result<AuthenticatedCiphertext, SecretStorageError> {
        self.seal_with_associated_data(plaintext, maximum_plaintext_bytes, |_| {
            associated_data.to_vec()
        })
    }

    /// Seals bounded plaintext while deriving associated data from the fresh nonce.
    ///
    /// Versioned formats commonly authenticate their nonce-bearing clear header. The
    /// nonce must be known before that header can be encoded, so this callback receives
    /// the generated nonce and returns the exact associated data to authenticate.
    ///
    /// # Errors
    ///
    /// Returns a typed error when plaintext exceeds the supplied bound, secure
    /// randomness is unavailable, or the provider rejects encryption.
    pub fn seal_with_associated_data(
        &self,
        plaintext: &[u8],
        maximum_plaintext_bytes: usize,
        associated_data: impl FnOnce(&[u8; AUTHENTICATED_CIPHER_NONCE_BYTES]) -> Vec<u8>,
    ) -> Result<AuthenticatedCiphertext, SecretStorageError> {
        if plaintext.len() > maximum_plaintext_bytes {
            return Err(SecretStorageError::PlaintextTooLarge {
                maximum: maximum_plaintext_bytes,
                actual: plaintext.len(),
            });
        }
        let mut nonce = [0_u8; AUTHENTICATED_CIPHER_NONCE_BYTES];
        self.random
            .fill(&mut nonce)
            .map_err(|_| SecretStorageError::RandomGenerationFailed)?;
        let associated_data = associated_data(&nonce);
        self.seal_with_nonce(&associated_data, plaintext, maximum_plaintext_bytes, nonce)
    }

    /// Authenticates and opens bounded ciphertext.
    ///
    /// # Errors
    ///
    /// Returns a typed error for malformed bounds, a wrong key, modified associated
    /// data, a modified nonce, or modified ciphertext.
    pub fn open(
        &self,
        associated_data: &[u8],
        ciphertext: &AuthenticatedCiphertext,
        maximum_plaintext_bytes: usize,
    ) -> Result<Zeroizing<Vec<u8>>, SecretStorageError> {
        validate_ciphertext_length(ciphertext.bytes.len(), maximum_plaintext_bytes)?;
        let key = less_safe_key(self.key.as_ref())?;
        let mut plaintext = Zeroizing::new(ciphertext.bytes.clone());
        let length = key
            .open_in_place(
                Nonce::assume_unique_for_key(ciphertext.nonce),
                Aad::from(associated_data),
                &mut plaintext,
            )
            .map_err(|_| SecretStorageError::AuthenticationFailed)?
            .len();
        plaintext.truncate(length);
        Ok(plaintext)
    }

    pub(crate) fn seal_with_nonce(
        &self,
        associated_data: &[u8],
        plaintext: &[u8],
        maximum_plaintext_bytes: usize,
        nonce: [u8; AUTHENTICATED_CIPHER_NONCE_BYTES],
    ) -> Result<AuthenticatedCiphertext, SecretStorageError> {
        if plaintext.len() > maximum_plaintext_bytes {
            return Err(SecretStorageError::PlaintextTooLarge {
                maximum: maximum_plaintext_bytes,
                actual: plaintext.len(),
            });
        }
        let key = less_safe_key(self.key.as_ref())?;
        let mut bytes = Zeroizing::new(plaintext.to_vec());
        key.seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(associated_data),
            &mut *bytes,
        )
        .map_err(|_| SecretStorageError::AuthenticationFailed)?;
        AuthenticatedCiphertext::from_parts(&nonce, bytes.to_vec(), maximum_plaintext_bytes)
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct CipherKey([u8; AUTHENTICATED_CIPHER_KEY_BYTES]);

fn less_safe_key(key: &CipherKey) -> Result<LessSafeKey, SecretStorageError> {
    UnboundKey::new(&AES_256_GCM, &key.0)
        .map(LessSafeKey::new)
        .map_err(|_| SecretStorageError::AuthenticationFailed)
}

fn validate_ciphertext_length(
    actual: usize,
    maximum_plaintext_bytes: usize,
) -> Result<(), SecretStorageError> {
    let maximum = maximum_plaintext_bytes
        .checked_add(AUTHENTICATED_CIPHER_TAG_BYTES)
        .ok_or(SecretStorageError::SealedBlobTooLarge {
            maximum: maximum_plaintext_bytes,
            actual,
        })?;
    if actual < AUTHENTICATED_CIPHER_TAG_BYTES || actual > maximum {
        return Err(SecretStorageError::SealedBlobTooLarge { maximum, actual });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAXIMUM: usize = 64;

    #[test]
    fn round_trip_and_context_binding() {
        let cipher = AuthenticatedCipher::new(&[7; AUTHENTICATED_CIPHER_KEY_BYTES]);
        let ciphertext = cipher.seal(b"domain-a", b"secret", MAXIMUM).unwrap();
        assert_eq!(
            cipher
                .open(b"domain-a", &ciphertext, MAXIMUM)
                .unwrap()
                .as_slice(),
            b"secret"
        );
        assert_eq!(
            cipher.open(b"domain-b", &ciphertext, MAXIMUM).unwrap_err(),
            SecretStorageError::AuthenticationFailed
        );
    }

    #[test]
    fn repeated_plaintext_uses_fresh_nonces() {
        let cipher = AuthenticatedCipher::new(&[7; AUTHENTICATED_CIPHER_KEY_BYTES]);
        let first = cipher.seal(b"domain", b"same", MAXIMUM).unwrap();
        let second = cipher.seal(b"domain", b"same", MAXIMUM).unwrap();
        assert_ne!(first.nonce(), second.nonce());
        assert_ne!(first.as_bytes(), second.as_bytes());
    }

    #[test]
    fn wrong_key_nonce_ciphertext_and_bounds_fail_closed() {
        let cipher = AuthenticatedCipher::new(&[1; AUTHENTICATED_CIPHER_KEY_BYTES]);
        let wrong = AuthenticatedCipher::new(&[2; AUTHENTICATED_CIPHER_KEY_BYTES]);
        let ciphertext = cipher.seal(b"domain", b"secret", MAXIMUM).unwrap();
        assert_eq!(
            wrong.open(b"domain", &ciphertext, MAXIMUM).unwrap_err(),
            SecretStorageError::AuthenticationFailed
        );

        let mut nonce = *ciphertext.nonce();
        nonce[0] ^= 1;
        let wrong_nonce =
            AuthenticatedCiphertext::from_parts(&nonce, ciphertext.bytes.clone(), MAXIMUM).unwrap();
        assert_eq!(
            cipher.open(b"domain", &wrong_nonce, MAXIMUM).unwrap_err(),
            SecretStorageError::AuthenticationFailed
        );

        let mut bytes = ciphertext.bytes.clone();
        bytes[0] ^= 1;
        let modified =
            AuthenticatedCiphertext::from_parts(ciphertext.nonce(), bytes, MAXIMUM).unwrap();
        assert_eq!(
            cipher.open(b"domain", &modified, MAXIMUM).unwrap_err(),
            SecretStorageError::AuthenticationFailed
        );

        assert!(cipher.seal(b"domain", &[0; MAXIMUM + 1], MAXIMUM).is_err());
        assert!(AuthenticatedCiphertext::from_parts(&[0; 11], vec![0; 16], MAXIMUM).is_err());
        assert!(AuthenticatedCiphertext::from_parts(&[0; 12], vec![0; 15], MAXIMUM).is_err());
        assert!(
            AuthenticatedCiphertext::from_parts(&[0; 12], vec![0; MAXIMUM + 17], MAXIMUM).is_err()
        );
    }
}
