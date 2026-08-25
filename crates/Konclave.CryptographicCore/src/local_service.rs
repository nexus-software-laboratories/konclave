use KonclaveDomainCore::{Ed25519PublicKey, Ed25519Signature};
use mls_rs::CipherSuiteProvider;
use mls_rs_core::crypto::{SignaturePublicKey, SignatureSecretKey};
use mls_rs_crypto_awslc::AwsLcCryptoProvider;

use crate::KonclaveCryptographicError;
use crate::identity::{cipher_suite, configured_provider};

/// Ed25519 signing identity for one local-service participant.
///
/// The shared local service and each registered harness adapter authenticate a local
/// connection with a signature over a canonical transcript. Both roles need the same
/// operation, so this type stays deliberately generic: it holds one key pair, signs
/// arbitrary already-canonical bytes, and knows nothing about the transcript layout
/// or the transport that carries it.
///
/// The secret key never leaves this boundary. The type is intentionally not
/// `Clone`, not `Debug`, and not serializable, so a copy cannot be made by accident
/// and the key cannot reach a log, snapshot, or configuration record. Persistent
/// custody is a separate concern; an instance created here lives only in memory.
pub struct LocalServiceIdentity {
    provider: AwsLcCryptoProvider,
    secret_key: SignatureSecretKey,
    public_key: Ed25519PublicKey,
}

impl LocalServiceIdentity {
    /// Generates a new local-service signing identity with provider-backed
    /// randomness.
    ///
    /// # Errors
    ///
    /// Returns [`KonclaveCryptographicError::ProviderFailure`] when the configured
    /// provider cannot generate a key pair, or a domain validation error when the
    /// generated public key is not a canonical Ed25519 key.
    pub fn generate() -> Result<Self, KonclaveCryptographicError> {
        let provider = configured_provider();
        let cipher_suite = cipher_suite(&provider)?;
        let (secret_key, public_key) = cipher_suite.signature_key_generate().map_err(|_| {
            KonclaveCryptographicError::ProviderFailure {
                operation: "local service key generation",
            }
        })?;
        let public_key = Ed25519PublicKey::from_slice(public_key.as_bytes())?;
        Ok(Self {
            provider,
            secret_key,
            public_key,
        })
    }

    /// Returns the public verification key that peers pin or register.
    #[must_use]
    pub const fn public_key(&self) -> Ed25519PublicKey {
        self.public_key
    }

    /// Signs one already-canonical, domain-separated message.
    ///
    /// This function does not add a domain separator. The caller owns the canonical
    /// encoding, because only the caller knows which protocol role and transcript the
    /// bytes represent.
    ///
    /// # Errors
    ///
    /// Returns [`KonclaveCryptographicError::ProviderFailure`] when the configured
    /// provider rejects the signing operation, or a domain validation error when the
    /// produced signature is not a canonical Ed25519 signature.
    pub fn sign(&self, message: &[u8]) -> Result<Ed25519Signature, KonclaveCryptographicError> {
        let cipher_suite = cipher_suite(&self.provider)?;
        let signature = cipher_suite.sign(&self.secret_key, message).map_err(|_| {
            KonclaveCryptographicError::ProviderFailure {
                operation: "local service signature",
            }
        })?;
        Ok(Ed25519Signature::from_slice(&signature)?)
    }
}

/// Verifies one local-service signature against an expected public key.
///
/// A caller supplies the same canonical, domain-separated bytes the signer used. A
/// signature over any other message, or under any other key, fails.
///
/// # Errors
///
/// Returns [`KonclaveCryptographicError::InvalidLocalServiceSignature`] when the
/// signature does not authenticate `message` under `public_key`.
pub fn verify_local_service_signature(
    public_key: Ed25519PublicKey,
    message: &[u8],
    signature: &Ed25519Signature,
) -> Result<(), KonclaveCryptographicError> {
    let provider = configured_provider();
    let cipher_suite = cipher_suite(&provider)?;
    cipher_suite
        .verify(
            &SignaturePublicKey::new_slice(public_key.as_bytes()),
            signature.as_bytes(),
            message,
        )
        .map_err(|_| KonclaveCryptographicError::InvalidLocalServiceSignature)
}

#[cfg(test)]
mod tests {
    use super::{LocalServiceIdentity, verify_local_service_signature};
    use crate::KonclaveCryptographicError;
    use KonclaveDomainCore::{Ed25519PublicKey, Ed25519Signature};

    #[test]
    fn a_signature_verifies_under_its_own_key_and_message() {
        let identity = LocalServiceIdentity::generate().unwrap();
        let signature = identity.sign(b"canonical transcript").unwrap();
        verify_local_service_signature(identity.public_key(), b"canonical transcript", &signature)
            .unwrap();
    }

    #[test]
    fn a_signature_does_not_verify_over_another_message() {
        let identity = LocalServiceIdentity::generate().unwrap();
        let signature = identity.sign(b"canonical transcript").unwrap();
        assert_eq!(
            verify_local_service_signature(identity.public_key(), b"other transcript", &signature)
                .unwrap_err(),
            KonclaveCryptographicError::InvalidLocalServiceSignature
        );
    }

    #[test]
    fn a_signature_does_not_verify_under_another_key() {
        let signer = LocalServiceIdentity::generate().unwrap();
        let other = LocalServiceIdentity::generate().unwrap();
        let signature = signer.sign(b"canonical transcript").unwrap();
        assert_eq!(
            verify_local_service_signature(other.public_key(), b"canonical transcript", &signature)
                .unwrap_err(),
            KonclaveCryptographicError::InvalidLocalServiceSignature
        );
    }

    #[test]
    fn distinct_identities_hold_distinct_keys() {
        let first = LocalServiceIdentity::generate().unwrap();
        let second = LocalServiceIdentity::generate().unwrap();
        assert_ne!(first.public_key(), second.public_key());
    }

    #[test]
    fn a_corrupted_signature_or_unknown_key_fails_closed() {
        let identity = LocalServiceIdentity::generate().unwrap();
        let mut bytes = identity.sign(b"canonical transcript").unwrap().into_bytes();
        bytes[0] ^= 1;
        assert_eq!(
            verify_local_service_signature(
                identity.public_key(),
                b"canonical transcript",
                &Ed25519Signature::from_bytes(bytes)
            )
            .unwrap_err(),
            KonclaveCryptographicError::InvalidLocalServiceSignature
        );
        assert_eq!(
            verify_local_service_signature(
                Ed25519PublicKey::from_bytes([0_u8; Ed25519PublicKey::LENGTH]),
                b"canonical transcript",
                &identity.sign(b"canonical transcript").unwrap()
            )
            .unwrap_err(),
            KonclaveCryptographicError::InvalidLocalServiceSignature
        );
    }
}
