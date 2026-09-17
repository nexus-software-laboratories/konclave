use aws_lc_rs::hkdf::{self, KeyType};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use KonclaveDomainCore::ProtocolVersion;
use KonclaveSecretStorage::{
    AUTHENTICATED_CIPHER_KEY_BYTES, AuthenticatedCipher, AuthenticatedCiphertext,
    SecretStorageError,
};

use crate::{KonclaveCryptographicError, fill_random};

/// Byte length of one compact pairing rendezvous token.
pub const PAIRING_RENDEZVOUS_TOKEN_BYTES: usize = 16;
/// Byte length of one non-secret relay rendezvous lookup identifier.
pub const PAIRING_RENDEZVOUS_LOOKUP_BYTES: usize = 32;
/// Maximum plaintext bytes protected by one rendezvous record.
pub const MAX_PAIRING_RENDEZVOUS_PLAINTEXT_BYTES: usize = 8 * 1024;

const KEY_SCHEDULE_SALT: &[u8] = b"konclave-pairing-rendezvous-key-schedule-v1\0";
const LOOKUP_INFO: &[u8] = b"konclave-pairing-rendezvous-lookup-v1\0";
const ENCRYPTION_KEY_INFO: &[u8] = b"konclave-pairing-rendezvous-encryption-v1\0";
const RECORD_AAD_DOMAIN: &[u8] = b"konclave-pairing-rendezvous-record-aad-v1\0";

/// Random bearer secret represented by one compact pairing token.
///
/// The value implements neither `Clone` nor `Debug`. Its sole export path appends
/// bytes into a caller-owned zeroizing transfer buffer.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PairingRendezvousSecret([u8; PAIRING_RENDEZVOUS_TOKEN_BYTES]);

impl PairingRendezvousSecret {
    /// Generates one token from the operating-system random source.
    ///
    /// # Errors
    ///
    /// Returns a provider error when secure randomness is unavailable.
    pub fn generate() -> Result<Self, KonclaveCryptographicError> {
        let mut bytes = [0_u8; PAIRING_RENDEZVOUS_TOKEN_BYTES];
        fill_random(&mut bytes)?;
        Ok(Self(bytes))
    }

    /// Takes ownership of exactly one compact token.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; PAIRING_RENDEZVOUS_TOKEN_BYTES]) -> Self {
        Self(bytes)
    }

    /// Appends token bytes to an explicitly secret-bearing transfer buffer.
    pub fn write_token_bytes(&self, destination: &mut Vec<u8>) {
        destination.extend_from_slice(&self.0);
    }

    fn as_bytes(&self) -> &[u8; PAIRING_RENDEZVOUS_TOKEN_BYTES] {
        &self.0
    }
}

/// Token-derived lookup identity and authenticated-encryption key.
pub struct PairingRendezvousKeySchedule {
    lookup_id: [u8; PAIRING_RENDEZVOUS_LOOKUP_BYTES],
    cipher: AuthenticatedCipher,
}

impl PairingRendezvousKeySchedule {
    /// Derives one opaque relay lookup and AES-256-GCM key from a compact token.
    ///
    /// # Errors
    ///
    /// Returns a provider error when HKDF expansion fails.
    pub fn derive(
        secret: &PairingRendezvousSecret,
    ) -> Result<Self, KonclaveCryptographicError> {
        let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, KEY_SCHEDULE_SALT);
        let prk = salt.extract(secret.as_bytes());
        let lookup_id = derive(&prk, LOOKUP_INFO)?;
        let encryption_key = derive(&prk, ENCRYPTION_KEY_INFO)?;
        Ok(Self {
            lookup_id: *lookup_id,
            cipher: AuthenticatedCipher::new(&encryption_key),
        })
    }

    /// Returns the non-secret relay lookup identifier.
    #[must_use]
    pub const fn lookup_id(&self) -> &[u8; PAIRING_RENDEZVOUS_LOOKUP_BYTES] {
        &self.lookup_id
    }

    /// Encrypts one bounded capability under a fresh nonce.
    ///
    /// # Errors
    ///
    /// Returns a provider or size error when encryption cannot complete.
    pub fn seal(
        &self,
        expires_at_unix_seconds: u64,
        plaintext: &[u8],
    ) -> Result<AuthenticatedCiphertext, KonclaveCryptographicError> {
        self.cipher
            .seal_with_associated_data(
                plaintext,
                MAX_PAIRING_RENDEZVOUS_PLAINTEXT_BYTES,
                |nonce| canonical_header(&self.lookup_id, expires_at_unix_seconds, nonce),
            )
            .map_err(rendezvous_cipher_error)
    }

    /// Authenticates and decrypts one bounded capability record.
    ///
    /// # Errors
    ///
    /// Returns an authentication error for a wrong token, lookup, expiry, nonce, or
    /// modified ciphertext.
    pub fn open(
        &self,
        expires_at_unix_seconds: u64,
        ciphertext: &AuthenticatedCiphertext,
    ) -> Result<Zeroizing<Vec<u8>>, KonclaveCryptographicError> {
        let header = canonical_header(
            &self.lookup_id,
            expires_at_unix_seconds,
            ciphertext.nonce(),
        );
        self.cipher
            .open(
                &header,
                ciphertext,
                MAX_PAIRING_RENDEZVOUS_PLAINTEXT_BYTES,
            )
            .map_err(rendezvous_cipher_error)
    }
}

fn derive(
    prk: &hkdf::Prk,
    label: &[u8],
) -> Result<Zeroizing<[u8; AUTHENTICATED_CIPHER_KEY_BYTES]>, KonclaveCryptographicError> {
    let info = [label];
    let okm = prk
        .expand(&info, FixedLength(AUTHENTICATED_CIPHER_KEY_BYTES))
        .map_err(|_| KonclaveCryptographicError::ProviderFailure {
            operation: "pairing rendezvous key derivation",
        })?;
    let mut output = Zeroizing::new([0_u8; AUTHENTICATED_CIPHER_KEY_BYTES]);
    okm.fill(&mut *output)
        .map_err(|_| KonclaveCryptographicError::ProviderFailure {
            operation: "pairing rendezvous key derivation",
        })?;
    Ok(output)
}

#[derive(Clone, Copy)]
struct FixedLength(usize);

impl KeyType for FixedLength {
    fn len(&self) -> usize {
        self.0
    }
}

fn canonical_header(
    lookup_id: &[u8; PAIRING_RENDEZVOUS_LOOKUP_BYTES],
    expires_at_unix_seconds: u64,
    nonce: &[u8; 12],
) -> Vec<u8> {
    let version = ProtocolVersion::application_v1();
    let mut output = Vec::with_capacity(RECORD_AAD_DOMAIN.len() + 4 + 32 + 8 + 12);
    output.extend_from_slice(RECORD_AAD_DOMAIN);
    output.extend_from_slice(&version.major().to_be_bytes());
    output.extend_from_slice(&version.minor().to_be_bytes());
    output.extend_from_slice(lookup_id);
    output.extend_from_slice(&expires_at_unix_seconds.to_be_bytes());
    output.extend_from_slice(nonce);
    output
}

fn rendezvous_cipher_error(error: SecretStorageError) -> KonclaveCryptographicError {
    match error {
        SecretStorageError::PlaintextTooLarge { maximum, actual }
        | SecretStorageError::SealedBlobTooLarge { maximum, actual } => {
            KonclaveCryptographicError::PairingPayloadTooLarge { maximum, actual }
        }
        SecretStorageError::RandomGenerationFailed => KonclaveCryptographicError::ProviderFailure {
            operation: "pairing rendezvous nonce generation",
        },
        _ => KonclaveCryptographicError::PairingAuthenticationFailed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schedule_derives_stable_lookup_and_authenticated_ciphertext() {
        let first =
            PairingRendezvousKeySchedule::derive(&PairingRendezvousSecret::from_bytes([7; 16]))
                .unwrap();
        let second =
            PairingRendezvousKeySchedule::derive(&PairingRendezvousSecret::from_bytes([7; 16]))
                .unwrap();
        let other =
            PairingRendezvousKeySchedule::derive(&PairingRendezvousSecret::from_bytes([8; 16]))
                .unwrap();
        assert_eq!(first.lookup_id(), second.lookup_id());
        assert_ne!(first.lookup_id(), other.lookup_id());

        let ciphertext = first.seal(2_000, b"capability").unwrap();
        assert_eq!(
            first.open(2_000, &ciphertext).unwrap().as_slice(),
            b"capability"
        );
        assert!(first.open(2_001, &ciphertext).is_err());
        assert!(other.open(2_000, &ciphertext).is_err());
    }

    #[test]
    fn lookup_derivation_matches_the_v1_vector() {
        let token = std::array::from_fn(|index| u8::try_from(index).unwrap());
        let schedule =
            PairingRendezvousKeySchedule::derive(&PairingRendezvousSecret::from_bytes(token))
                .unwrap();
        assert_eq!(
            schedule.lookup_id(),
            &[
                0x8e, 0x07, 0x5d, 0x02, 0xf5, 0x2f, 0xad, 0xae, 0xc4, 0x9c, 0x1e, 0x55, 0xde, 0xa2,
                0xe8, 0x58, 0x1d, 0x7f, 0xa3, 0x62, 0x0e, 0x8a, 0x4b, 0x17, 0x19, 0x11, 0xf4, 0xe8,
                0xc2, 0x7f, 0x39, 0xb5,
            ]
        );
    }

    #[test]
    fn repeated_plaintext_uses_fresh_ciphertext() {
        let schedule =
            PairingRendezvousKeySchedule::derive(&PairingRendezvousSecret::from_bytes([9; 16]))
                .unwrap();
        let first = schedule.seal(2_000, b"same").unwrap();
        let second = schedule.seal(2_000, b"same").unwrap();
        assert_ne!(first.nonce(), second.nonce());
        assert_ne!(first.as_bytes(), second.as_bytes());
    }
}
