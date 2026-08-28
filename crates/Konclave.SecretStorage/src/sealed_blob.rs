use aws_lc_rs::digest::{Context as DigestContext, SHA256};
use zeroize::Zeroizing;

use crate::{
    AuthenticatedCipher, AuthenticatedCiphertext, SecretStorageError, WrappingKeyProvider,
};

const MAGIC: &[u8; 4] = b"KSC1";
const FORMAT_VERSION: u8 = 1;
const ALGORITHM_AES_256_GCM: u8 = 1;
const KEY_SLOT: u32 = 1;
const NONCE_BYTES: usize = 12;
const TAG_BYTES: usize = 16;
const HEADER_BYTES: usize = MAGIC.len() + 1 + 1 + 4 + NONCE_BYTES;
const AAD_DOMAIN: &[u8] = b"konclave-sealed-secret-aad-v1\0";
const CONTEXT_DERIVATION_DOMAIN: &[u8] = b"konclave-secret-record-context-v1\0";
const MAX_RECORD_IDENTIFIER_BYTES: usize = 128;
const MAX_CONTEXT_COMPONENTS: usize = 8;

/// Maximum plaintext bytes accepted by one sealed secret record.
pub const MAX_SECRET_PLAINTEXT_BYTES: usize = 16 * 1024 * 1024;
const MAX_SEALED_BLOB_BYTES: usize = HEADER_BYTES + MAX_SECRET_PLAINTEXT_BYTES + TAG_BYTES;

/// Closed namespace for secret record associated-data binding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SecretRecordKind {
    DeviceRootIdentity = 1,
    MlsKeyPackage = 2,
    MlsGroupState = 3,
    MlsPriorEpoch = 4,
    ConversationSigningMaterial = 5,
    RelayAccessCredential = 6,
    ConversationPolicyState = 7,
    ConversationCredentialBinding = 8,
    LocalApplicationMessage = 9,
    LocalOperation = 10,
    RemoteEvent = 11,
    RemoteEventDeliveryState = 12,
    RemoteEventJournalHead = 13,
    RemoteEventDeliveryPolicy = 14,
    PairingOperation = 15,
    RelayEnrollmentIntent = 16,
    LocalServiceRequestOutcome = 17,
    CollaborationPolicyBundle = 18,
    CollaborationPolicyBinding = 19,
    CollaborationPolicyExchangeRecord = 20,
    CollaborationPolicyExchangeState = 21,
}

/// Bounded non-secret context authenticated with one sealed record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretRecordContext {
    kind: SecretRecordKind,
    identifier: Vec<u8>,
}

impl SecretRecordContext {
    /// Creates associated-data context for one stable secret record.
    ///
    /// # Errors
    ///
    /// Returns a validation error for an empty or oversized identifier.
    pub fn new(
        kind: SecretRecordKind,
        identifier: impl Into<Vec<u8>>,
    ) -> Result<Self, SecretStorageError> {
        let identifier = identifier.into();
        if identifier.is_empty() || identifier.len() > MAX_RECORD_IDENTIFIER_BYTES {
            return Err(SecretStorageError::InvalidRecordIdentifier {
                maximum: MAX_RECORD_IDENTIFIER_BYTES,
            });
        }
        Ok(Self { kind, identifier })
    }

    /// Derives a compact identifier from bounded, non-empty context components.
    ///
    /// Component order and byte lengths are authenticated, so concatenation
    /// ambiguities cannot map distinct record contexts to the same digest input.
    ///
    /// # Errors
    ///
    /// Returns a validation error for an empty or excessive component set, an empty
    /// component, or cumulative input beyond the sealed-plaintext bound.
    pub fn derive(
        kind: SecretRecordKind,
        components: &[&[u8]],
    ) -> Result<Self, SecretStorageError> {
        if components.is_empty()
            || components.len() > MAX_CONTEXT_COMPONENTS
            || components.iter().any(|component| component.is_empty())
        {
            return Err(SecretStorageError::InvalidRecordIdentifier {
                maximum: MAX_RECORD_IDENTIFIER_BYTES,
            });
        }
        let mut total = 0_usize;
        let component_count = u8::try_from(components.len()).map_err(|_| {
            SecretStorageError::InvalidRecordIdentifier {
                maximum: MAX_RECORD_IDENTIFIER_BYTES,
            }
        })?;
        let mut digest = DigestContext::new(&SHA256);
        digest.update(CONTEXT_DERIVATION_DOMAIN);
        digest.update(&[kind as u8, component_count]);
        for component in components {
            total = total.checked_add(component.len()).ok_or(
                SecretStorageError::InvalidRecordIdentifier {
                    maximum: MAX_RECORD_IDENTIFIER_BYTES,
                },
            )?;
            if total > MAX_SECRET_PLAINTEXT_BYTES {
                return Err(SecretStorageError::InvalidRecordIdentifier {
                    maximum: MAX_RECORD_IDENTIFIER_BYTES,
                });
            }
            digest.update(
                &u64::try_from(component.len())
                    .map_err(|_| SecretStorageError::InvalidRecordIdentifier {
                        maximum: MAX_RECORD_IDENTIFIER_BYTES,
                    })?
                    .to_be_bytes(),
            );
            digest.update(component);
        }
        Self::new(kind, digest.finish().as_ref().to_vec())
    }

    /// Returns the record namespace.
    #[must_use]
    pub const fn kind(&self) -> SecretRecordKind {
        self.kind
    }

    /// Returns the stable record identifier.
    #[must_use]
    pub fn identifier(&self) -> &[u8] {
        &self.identifier
    }
}

/// Versioned authenticated ciphertext safe to cross into ordinary persistence.
#[derive(Clone, PartialEq, Eq)]
pub struct SealedBlob(Vec<u8>);

impl SealedBlob {
    /// Validates framing without attempting decryption.
    ///
    /// # Errors
    ///
    /// Returns a typed error for oversized, truncated, or unsupported framing.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, SecretStorageError> {
        validate_header(&bytes)?;
        Ok(Self(bytes))
    }

    /// Validates framing and copies a bounded transport slice.
    ///
    /// # Errors
    ///
    /// Returns a typed error before allocation for oversized or invalid framing.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, SecretStorageError> {
        validate_header(bytes)?;
        Ok(Self(bytes.to_vec()))
    }

    /// Returns the complete versioned ciphertext bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consumes the wrapper and returns the complete ciphertext bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

/// AES-256-GCM sealer initialized from one explicit custody provider.
pub struct SecretSealer {
    cipher: AuthenticatedCipher,
}

impl SecretSealer {
    /// Loads the wrapping key once and constructs a sealer.
    ///
    /// # Errors
    ///
    /// Returns the provider error without attempting any fallback.
    pub fn from_provider(provider: impl WrappingKeyProvider) -> Result<Self, SecretStorageError> {
        let key = provider.load_or_create()?;
        Ok(Self {
            cipher: AuthenticatedCipher::new(key.as_bytes()),
        })
    }

    /// Creates another sealer that shares the same in-memory wrapping key.
    ///
    /// This does not reload key custody or duplicate key bytes. Each handle uses an
    /// independent operating-system random source for nonces.
    #[must_use]
    pub fn share(&self) -> Self {
        Self {
            cipher: self.cipher.share(),
        }
    }

    /// Seals plaintext under a fresh nonce and bound record context.
    ///
    /// # Errors
    ///
    /// Returns a typed error for oversized plaintext, random failure, or AEAD
    /// initialization failure.
    pub fn seal(
        &self,
        context: &SecretRecordContext,
        plaintext: &[u8],
    ) -> Result<SealedBlob, SecretStorageError> {
        let ciphertext = self.cipher.seal_with_associated_data(
            plaintext,
            MAX_SECRET_PLAINTEXT_BYTES,
            |nonce| {
                let header = header(*nonce);
                associated_data(context, &header)
            },
        )?;
        let mut output = Vec::with_capacity(HEADER_BYTES + ciphertext.as_bytes().len());
        output.extend_from_slice(&header(*ciphertext.nonce()));
        output.extend_from_slice(ciphertext.as_bytes());
        SealedBlob::from_bytes(output)
    }

    /// Authenticates and opens one sealed record.
    ///
    /// # Errors
    ///
    /// Returns a typed error for malformed framing, context mismatch, wrong key, or
    /// modified ciphertext.
    pub fn open(
        &self,
        context: &SecretRecordContext,
        blob: &SealedBlob,
    ) -> Result<Zeroizing<Vec<u8>>, SecretStorageError> {
        let header = validate_header(blob.as_bytes())?;
        let nonce: [u8; NONCE_BYTES] = header[10..HEADER_BYTES]
            .try_into()
            .map_err(|_| SecretStorageError::InvalidSealedBlob)?;
        let aad = associated_data(context, header);
        let ciphertext = AuthenticatedCiphertext::from_parts(
            &nonce,
            blob.as_bytes()[HEADER_BYTES..].to_vec(),
            MAX_SECRET_PLAINTEXT_BYTES,
        )?;
        self.cipher
            .open(&aad, &ciphertext, MAX_SECRET_PLAINTEXT_BYTES)
    }

    #[cfg(test)]
    fn seal_with_nonce(
        &self,
        context: &SecretRecordContext,
        plaintext: &[u8],
        nonce: [u8; NONCE_BYTES],
    ) -> Result<SealedBlob, SecretStorageError> {
        let header = header(nonce);
        let aad = associated_data(context, &header);
        let ciphertext =
            self.cipher
                .seal_with_nonce(&aad, plaintext, MAX_SECRET_PLAINTEXT_BYTES, nonce)?;
        let mut output = Vec::with_capacity(HEADER_BYTES + ciphertext.as_bytes().len());
        output.extend_from_slice(&header);
        output.extend_from_slice(ciphertext.as_bytes());
        SealedBlob::from_bytes(output)
    }
}

fn header(nonce: [u8; NONCE_BYTES]) -> [u8; HEADER_BYTES] {
    let mut header = [0_u8; HEADER_BYTES];
    header[..4].copy_from_slice(MAGIC);
    header[4] = FORMAT_VERSION;
    header[5] = ALGORITHM_AES_256_GCM;
    header[6..10].copy_from_slice(&KEY_SLOT.to_be_bytes());
    header[10..].copy_from_slice(&nonce);
    header
}

fn validate_header(bytes: &[u8]) -> Result<&[u8], SecretStorageError> {
    if bytes.len() > MAX_SEALED_BLOB_BYTES {
        return Err(SecretStorageError::SealedBlobTooLarge {
            maximum: MAX_SEALED_BLOB_BYTES,
            actual: bytes.len(),
        });
    }
    if bytes.len() < HEADER_BYTES + TAG_BYTES
        || &bytes[..4] != MAGIC
        || bytes[4] != FORMAT_VERSION
        || bytes[5] != ALGORITHM_AES_256_GCM
        || bytes[6..10] != KEY_SLOT.to_be_bytes()
    {
        return Err(SecretStorageError::InvalidSealedBlob);
    }
    Ok(&bytes[..HEADER_BYTES])
}

fn associated_data(context: &SecretRecordContext, header: &[u8]) -> Vec<u8> {
    let mut aad =
        Vec::with_capacity(AAD_DOMAIN.len() + header.len() + 1 + 2 + context.identifier.len());
    aad.extend_from_slice(AAD_DOMAIN);
    aad.extend_from_slice(header);
    aad.push(context.kind as u8);
    aad.extend_from_slice(&(context.identifier.len() as u16).to_be_bytes());
    aad.extend_from_slice(&context.identifier);
    aad
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ExternalWrappingKeyProvider;

    #[test]
    fn sealed_blob_vector_is_stable() {
        let key = std::array::from_fn(|index| index as u8);
        let sealer =
            SecretSealer::from_provider(ExternalWrappingKeyProvider::from_bytes(key)).unwrap();
        let context =
            SecretRecordContext::new(SecretRecordKind::MlsGroupState, b"group-1".to_vec()).unwrap();
        let nonce = std::array::from_fn(|index| 0xa0 + index as u8);
        let blob = sealer
            .seal_with_nonce(&context, b"secret-state", nonce)
            .unwrap();
        assert_eq!(
            blob.as_bytes(),
            decode_hex(
                "4b534331010100000001a0a1a2a3a4a5a6a7a8a9aaab957d1f5f20bf2fcc1604f3b6959610c96ebef98ebd4dba2b47e40a21"
            )
        );
        assert_eq!(
            sealer.open(&context, &blob).unwrap().as_slice(),
            b"secret-state"
        );
    }

    #[test]
    fn repeated_plaintext_uses_distinct_ciphertext() {
        let sealer =
            SecretSealer::from_provider(ExternalWrappingKeyProvider::from_bytes([7; 32])).unwrap();
        let context =
            SecretRecordContext::new(SecretRecordKind::DeviceRootIdentity, b"device".to_vec())
                .unwrap();
        let first = sealer.seal(&context, b"same").unwrap();
        let second = sealer.seal(&context, b"same").unwrap();
        assert_ne!(first.as_bytes(), second.as_bytes());
        assert_eq!(sealer.open(&context, &first).unwrap().as_slice(), b"same");
        assert_eq!(sealer.open(&context, &second).unwrap().as_slice(), b"same");
    }

    #[test]
    fn derived_contexts_bind_component_order_lengths_and_kind() {
        let first = SecretRecordContext::derive(
            SecretRecordKind::RelayEnrollmentIntent,
            &[b"profile", b"ab", b"c"],
        )
        .unwrap();
        let reordered = SecretRecordContext::derive(
            SecretRecordKind::RelayEnrollmentIntent,
            &[b"profile", b"c", b"ab"],
        )
        .unwrap();
        let repartitioned = SecretRecordContext::derive(
            SecretRecordKind::RelayEnrollmentIntent,
            &[b"profile", b"a", b"bc"],
        )
        .unwrap();
        let wrong_kind = SecretRecordContext::derive(
            SecretRecordKind::PairingOperation,
            &[b"profile", b"ab", b"c"],
        )
        .unwrap();

        assert_eq!(first.identifier().len(), 32);
        assert_ne!(first, reordered);
        assert_ne!(first, repartitioned);
        assert_ne!(first, wrong_kind);
        assert!(
            SecretRecordContext::derive(SecretRecordKind::RelayEnrollmentIntent, &[],).is_err()
        );
        assert!(
            SecretRecordContext::derive(
                SecretRecordKind::RelayEnrollmentIntent,
                &[b"profile", b""],
            )
            .is_err()
        );
    }

    #[test]
    fn shared_sealers_use_the_same_key_without_reloading_custody() {
        let sealer =
            SecretSealer::from_provider(ExternalWrappingKeyProvider::from_bytes([4; 32])).unwrap();
        let shared = sealer.share();
        let context =
            SecretRecordContext::new(SecretRecordKind::MlsGroupState, b"shared".to_vec()).unwrap();
        let blob = sealer.seal(&context, b"state").unwrap();
        assert_eq!(shared.open(&context, &blob).unwrap().as_slice(), b"state");
    }

    #[test]
    fn wrong_key_context_and_modified_ciphertext_fail_closed() {
        let sealer =
            SecretSealer::from_provider(ExternalWrappingKeyProvider::from_bytes([1; 32])).unwrap();
        let wrong_key =
            SecretSealer::from_provider(ExternalWrappingKeyProvider::from_bytes([2; 32])).unwrap();
        let context =
            SecretRecordContext::new(SecretRecordKind::MlsGroupState, b"group".to_vec()).unwrap();
        let wrong_context =
            SecretRecordContext::new(SecretRecordKind::MlsPriorEpoch, b"group".to_vec()).unwrap();
        let wrong_identifier =
            SecretRecordContext::new(SecretRecordKind::MlsGroupState, b"other".to_vec()).unwrap();
        let blob = sealer.seal(&context, b"state").unwrap();
        assert_eq!(
            wrong_key.open(&context, &blob).unwrap_err(),
            SecretStorageError::AuthenticationFailed
        );
        assert_eq!(
            sealer.open(&wrong_context, &blob).unwrap_err(),
            SecretStorageError::AuthenticationFailed
        );
        assert_eq!(
            sealer.open(&wrong_identifier, &blob).unwrap_err(),
            SecretStorageError::AuthenticationFailed
        );

        let mut nonce_modified = blob.as_bytes().to_vec();
        nonce_modified[10] ^= 1;
        let nonce_modified = SealedBlob::from_bytes(nonce_modified).unwrap();
        assert_eq!(
            sealer.open(&context, &nonce_modified).unwrap_err(),
            SecretStorageError::AuthenticationFailed
        );

        let mut modified = blob.into_bytes();
        let last = modified.len() - 1;
        modified[last] ^= 1;
        let modified = SealedBlob::from_bytes(modified).unwrap();
        assert_eq!(
            sealer.open(&context, &modified).unwrap_err(),
            SecretStorageError::AuthenticationFailed
        );
    }

    #[test]
    fn invalid_context_and_header_are_rejected() {
        assert_eq!(
            SecretRecordContext::new(SecretRecordKind::MlsGroupState, Vec::new()).unwrap_err(),
            SecretStorageError::InvalidRecordIdentifier {
                maximum: MAX_RECORD_IDENTIFIER_BYTES
            }
        );
        assert_eq!(
            SealedBlob::from_bytes(vec![0; HEADER_BYTES + TAG_BYTES]).err(),
            Some(SecretStorageError::InvalidSealedBlob)
        );
        let mut unsupported = header([0; NONCE_BYTES]).to_vec();
        unsupported.extend_from_slice(&[0; TAG_BYTES]);
        unsupported[4] = 2;
        assert_eq!(
            SealedBlob::from_bytes(unsupported).err(),
            Some(SecretStorageError::InvalidSealedBlob)
        );
    }

    fn decode_hex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                let high = (pair[0] as char).to_digit(16).unwrap();
                let low = (pair[1] as char).to_digit(16).unwrap();
                ((high << 4) | low) as u8
            })
            .collect()
    }
}
