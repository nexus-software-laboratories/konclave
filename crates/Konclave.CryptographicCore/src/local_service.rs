use std::io::{Read, Write};

use KonclaveDomainCore::{AdapterConsumerId, Ed25519PublicKey, Ed25519Signature};
use aws_lc_rs::digest::{Context, SHA256};
use aws_lc_rs::rand::{SecureRandom as _, SystemRandom};
use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair as _};
use mls_rs::CipherSuiteProvider;
use mls_rs_core::crypto::{SignaturePublicKey, SignatureSecretKey};
use mls_rs_crypto_awslc::AwsLcCryptoProvider;
use zeroize::Zeroizing;

use crate::KonclaveCryptographicError;
use crate::identity::{cipher_suite, configured_provider};

/// Byte length of an Ed25519 seed accepted by every local-service client.
pub const LOCAL_SERVICE_SIGNING_SEED_LENGTH: usize = 32;
const LOCAL_SERVICE_SESSION_CONSUMER_ID_DOMAIN: &[u8] =
    b"konclave-local-service-session-consumer-id-v1\0";

/// Derives the delivery-consumer identifier shared by authenticated lanes for one
/// session key.
///
/// Connection instance identifiers remain fresh per handshake. This local
/// correlation instead binds interactive policy evaluation to the delivery lease
/// owned by the same already-authenticated session identity.
#[must_use]
pub fn derive_local_service_session_consumer_id(
    session_public_key: Ed25519PublicKey,
) -> AdapterConsumerId {
    let mut context = Context::new(&SHA256);
    context.update(LOCAL_SERVICE_SESSION_CONSUMER_ID_DOMAIN);
    context.update(session_public_key.as_bytes());
    let digest = context.finish();
    let mut consumer = [0_u8; AdapterConsumerId::LENGTH];
    consumer.copy_from_slice(&digest.as_ref()[..AdapterConsumerId::LENGTH]);
    AdapterConsumerId::from_bytes(consumer)
}

/// Exportable installation seed for a local-service participant.
///
/// Installation writes this value only to an owner-protected custody record. The
/// wrapper is intentionally not cloneable, debuggable, or serializable and clears its
/// bytes on drop.
pub struct LocalServiceSigningSeed(Zeroizing<[u8; LOCAL_SERVICE_SIGNING_SEED_LENGTH]>);

impl LocalServiceSigningSeed {
    /// Generates a seed from the operating-system random source.
    ///
    /// # Errors
    ///
    /// Returns [`KonclaveCryptographicError::ProviderFailure`] when secure random
    /// generation fails.
    pub fn generate() -> Result<Self, KonclaveCryptographicError> {
        let mut bytes = Zeroizing::new([0_u8; LOCAL_SERVICE_SIGNING_SEED_LENGTH]);
        SystemRandom::new().fill(bytes.as_mut()).map_err(|_| {
            KonclaveCryptographicError::ProviderFailure {
                operation: "local service seed generation",
            }
        })?;
        Ok(Self(bytes))
    }

    /// Reads exactly one raw seed from a bounded reader.
    ///
    /// # Errors
    ///
    /// Returns a secret-storage failure when the reader does not contain exactly 32
    /// bytes or cannot be read.
    pub fn from_reader(mut reader: impl Read) -> Result<Self, KonclaveCryptographicError> {
        let mut bytes = Zeroizing::new(Vec::with_capacity(LOCAL_SERVICE_SIGNING_SEED_LENGTH + 1));
        reader
            .by_ref()
            .take((LOCAL_SERVICE_SIGNING_SEED_LENGTH + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| KonclaveCryptographicError::SecretStorageFailure {
                operation: "local service seed read",
            })?;
        let seed: [u8; LOCAL_SERVICE_SIGNING_SEED_LENGTH] =
            bytes.as_slice().try_into().map_err(|_| {
                KonclaveCryptographicError::SecretStorageFailure {
                    operation: "local service seed length",
                }
            })?;
        Ok(Self(Zeroizing::new(seed)))
    }

    /// Writes the raw seed to an already owner-protected destination.
    ///
    /// # Errors
    ///
    /// Returns a secret-storage failure when the destination rejects the complete
    /// write.
    pub fn write_to(&self, mut writer: impl Write) -> Result<(), KonclaveCryptographicError> {
        writer.write_all(self.0.as_ref()).map_err(|_| {
            KonclaveCryptographicError::SecretStorageFailure {
                operation: "local service seed write",
            }
        })
    }
}

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

    /// Imports a zeroizing installation seed through the configured Ed25519 provider.
    ///
    /// # Errors
    ///
    /// Returns a provider or domain validation error when the seed cannot produce a
    /// canonical Ed25519 key pair.
    pub fn from_signing_seed(
        seed: &LocalServiceSigningSeed,
    ) -> Result<Self, KonclaveCryptographicError> {
        let provider = configured_provider();
        let key_pair = Ed25519KeyPair::from_seed_unchecked(seed.0.as_ref()).map_err(|_| {
            KonclaveCryptographicError::ProviderFailure {
                operation: "local service public key derivation",
            }
        })?;
        let public_key = Ed25519PublicKey::from_slice(key_pair.public_key().as_ref())?;
        let mut secret = Zeroizing::new(Vec::with_capacity(
            LOCAL_SERVICE_SIGNING_SEED_LENGTH + Ed25519PublicKey::LENGTH,
        ));
        secret.extend_from_slice(seed.0.as_ref());
        secret.extend_from_slice(public_key.as_bytes());
        let secret_key = SignatureSecretKey::new(secret.as_slice().to_vec());
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
    use super::{
        LOCAL_SERVICE_SIGNING_SEED_LENGTH, LocalServiceIdentity, LocalServiceSigningSeed,
        derive_local_service_session_consumer_id, verify_local_service_signature,
    };
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
    fn session_consumer_identity_is_stable_and_key_bound() {
        let first = Ed25519PublicKey::from_bytes([1; Ed25519PublicKey::LENGTH]);
        let second = Ed25519PublicKey::from_bytes([2; Ed25519PublicKey::LENGTH]);

        assert_eq!(
            derive_local_service_session_consumer_id(first),
            derive_local_service_session_consumer_id(first)
        );
        assert_ne!(
            derive_local_service_session_consumer_id(first),
            derive_local_service_session_consumer_id(second)
        );
    }

    #[test]
    fn a_seed_round_trips_and_matches_the_cross_language_ed25519_vector() {
        let bytes: Vec<u8> = (0..LOCAL_SERVICE_SIGNING_SEED_LENGTH)
            .map(|value| u8::try_from(value).unwrap())
            .collect();
        let seed = LocalServiceSigningSeed::from_reader(bytes.as_slice()).unwrap();
        let identity = LocalServiceIdentity::from_signing_seed(&seed).unwrap();
        assert_eq!(
            identity.public_key().as_bytes(),
            &[
                0x03, 0xa1, 0x07, 0xbf, 0xf3, 0xce, 0x10, 0xbe, 0x1d, 0x70, 0xdd, 0x18, 0xe7, 0x4b,
                0xc0, 0x99, 0x67, 0xe4, 0xd6, 0x30, 0x9b, 0xa5, 0x0d, 0x5f, 0x1d, 0xdc, 0x86, 0x64,
                0x12, 0x55, 0x31, 0xb8,
            ]
        );
        let signature = identity.sign(b"seed-imported transcript").unwrap();
        verify_local_service_signature(
            identity.public_key(),
            b"seed-imported transcript",
            &signature,
        )
        .unwrap();
        let mut encoded = Vec::new();
        seed.write_to(&mut encoded).unwrap();
        assert_eq!(encoded, bytes);
        assert!(LocalServiceSigningSeed::from_reader([0_u8; 31].as_slice()).is_err());
        assert!(LocalServiceSigningSeed::from_reader([0_u8; 33].as_slice()).is_err());
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
