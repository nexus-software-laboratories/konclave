use aws_lc_rs::hkdf::{self, KeyType};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use KonclaveDomainCore::{
    MAX_PAIRING_CIPHERTEXT_BYTES, PairingEnvelope, PairingId, PairingMessageId, PairingNonce,
    PairingSenderRole, PairingStage, ProtocolVersion, RoutingId,
};
use KonclaveSecretStorage::{
    AUTHENTICATED_CIPHER_KEY_BYTES, AuthenticatedCipher, AuthenticatedCiphertext,
    SecretStorageError,
};

use crate::{KonclaveCryptographicError, fill_random};

/// Byte length of one transferable pairing secret.
pub const PAIRING_SECRET_BYTES: usize = 32;
const _: () = assert!(PAIRING_SECRET_BYTES == AUTHENTICATED_CIPHER_KEY_BYTES);

const KEY_SCHEDULE_SALT: &[u8] = b"konclave-pairing-key-schedule-v1\0";
const ROUTING_KEY_INFO: &[u8] = b"konclave-pairing-routing-id-v1\0";
const JOINER_KEY_INFO: &[u8] = b"konclave-pairing-joiner-key-v1\0";
const INVITER_KEY_INFO: &[u8] = b"konclave-pairing-inviter-key-v1\0";
const ENVELOPE_AAD_DOMAIN: &[u8] = b"konclave-pairing-envelope-aad-v1\0";

/// Random bearer secret transferred in one pairing capability.
///
/// The value intentionally implements neither `Clone`, `Debug`, nor serialization.
/// A later capability codec owns the one explicit export path. Ordinary callers can
/// derive a route and directional keys without exposing the bytes.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PairingSecret([u8; PAIRING_SECRET_BYTES]);

impl PairingSecret {
    /// Generates a pairing secret from the operating-system random source.
    ///
    /// # Errors
    ///
    /// Returns a provider error when secure randomness is unavailable.
    pub fn generate() -> Result<Self, KonclaveCryptographicError> {
        let mut bytes = [0_u8; PAIRING_SECRET_BYTES];
        fill_random(&mut bytes)?;
        Ok(Self(bytes))
    }

    /// Takes ownership of exactly one pairing secret.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; PAIRING_SECRET_BYTES]) -> Self {
        Self(bytes)
    }

    pub(crate) const fn as_bytes(&self) -> &[u8; PAIRING_SECRET_BYTES] {
        &self.0
    }
}

/// Domain-separated route and directional encryption keys for one pairing.
///
/// The schedule implements neither `Clone` nor `Debug`; derived keys remain inside
/// the vetted cipher primitive and are zeroized after the last handle drops.
pub struct PairingKeySchedule {
    pairing_id: PairingId,
    routing_id: RoutingId,
    joiner_cipher: AuthenticatedCipher,
    inviter_cipher: AuthenticatedCipher,
}

impl PairingKeySchedule {
    /// Derives one route and two direction-specific keys from a pairing secret.
    ///
    /// # Errors
    ///
    /// Returns a provider error if HKDF expansion fails.
    pub fn derive(
        pairing_id: PairingId,
        secret: &PairingSecret,
    ) -> Result<Self, KonclaveCryptographicError> {
        let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, KEY_SCHEDULE_SALT);
        let prk = salt.extract(secret.as_bytes());
        let route = derive(&prk, ROUTING_KEY_INFO, pairing_id)?;
        let joiner_key = derive(&prk, JOINER_KEY_INFO, pairing_id)?;
        let inviter_key = derive(&prk, INVITER_KEY_INFO, pairing_id)?;
        Ok(Self {
            pairing_id,
            routing_id: RoutingId::from_bytes(*route),
            joiner_cipher: AuthenticatedCipher::new(&joiner_key),
            inviter_cipher: AuthenticatedCipher::new(&inviter_key),
        })
    }

    /// Returns the pseudorandom relay route for this pairing.
    #[must_use]
    pub const fn routing_id(&self) -> RoutingId {
        self.routing_id
    }

    /// Encrypts one stage payload under a fresh nonce and the sender's directional key.
    ///
    /// # Errors
    ///
    /// Returns a domain or provider error for an invalid stage grammar, oversized
    /// plaintext, unavailable randomness, or rejected encryption.
    pub fn seal(
        &self,
        message_id: PairingMessageId,
        sender: PairingSenderRole,
        stage: PairingStage,
        in_reply_to: Option<PairingMessageId>,
        expires_at_unix_seconds: u64,
        plaintext: &[u8],
    ) -> Result<PairingEnvelope, KonclaveCryptographicError> {
        let cipher = self.cipher(sender);
        let ciphertext = cipher
            .seal_with_associated_data(plaintext, maximum_pairing_plaintext_bytes(), |nonce| {
                canonical_header(
                    self.pairing_id,
                    message_id,
                    sender,
                    stage,
                    in_reply_to,
                    expires_at_unix_seconds,
                    nonce,
                )
            })
            .map_err(pairing_cipher_error)?;
        Ok(PairingEnvelope::new(
            ProtocolVersion::application_v1(),
            self.pairing_id,
            message_id,
            sender,
            stage,
            in_reply_to,
            expires_at_unix_seconds,
            PairingNonce::from_bytes(*ciphertext.nonce()),
            ciphertext.into_bytes(),
        )?)
    }

    /// Authenticates and opens one envelope under its declared sender direction.
    ///
    /// Deadline policy belongs to the durable state machine rather than this method:
    /// an already-committed Welcome remains recoverable after the authorization
    /// deadline under ADR 0006. This operation authenticates the deadline but does not
    /// decide whether the current state may still accept it.
    ///
    /// # Errors
    ///
    /// Returns an authentication failure for a different pairing, unsupported
    /// version, wrong direction, modified header, wrong key, or modified ciphertext.
    pub fn open(
        &self,
        envelope: &PairingEnvelope,
    ) -> Result<Zeroizing<Vec<u8>>, KonclaveCryptographicError> {
        if envelope.version() != ProtocolVersion::application_v1()
            || envelope.pairing_id() != self.pairing_id
        {
            return Err(KonclaveCryptographicError::PairingAuthenticationFailed);
        }
        let aad = canonical_header(
            envelope.pairing_id(),
            envelope.message_id(),
            envelope.sender(),
            envelope.stage(),
            envelope.in_reply_to(),
            envelope.expires_at_unix_seconds(),
            envelope.nonce().as_bytes(),
        );
        let ciphertext = AuthenticatedCiphertext::from_parts(
            envelope.nonce().as_bytes(),
            envelope.ciphertext().to_vec(),
            maximum_pairing_plaintext_bytes(),
        )
        .map_err(pairing_cipher_error)?;
        self.cipher(envelope.sender())
            .open(&aad, &ciphertext, maximum_pairing_plaintext_bytes())
            .map_err(pairing_cipher_error)
    }

    fn cipher(&self, sender: PairingSenderRole) -> &AuthenticatedCipher {
        match sender {
            PairingSenderRole::Joiner => &self.joiner_cipher,
            PairingSenderRole::Inviter => &self.inviter_cipher,
        }
    }
}

fn derive(
    prk: &hkdf::Prk,
    label: &[u8],
    pairing_id: PairingId,
) -> Result<Zeroizing<[u8; AUTHENTICATED_CIPHER_KEY_BYTES]>, KonclaveCryptographicError> {
    let info = [label, pairing_id.as_bytes().as_slice()];
    let okm = prk
        .expand(&info, FixedLength(AUTHENTICATED_CIPHER_KEY_BYTES))
        .map_err(|_| KonclaveCryptographicError::ProviderFailure {
            operation: "pairing key derivation",
        })?;
    let mut output = Zeroizing::new([0_u8; AUTHENTICATED_CIPHER_KEY_BYTES]);
    okm.fill(&mut *output)
        .map_err(|_| KonclaveCryptographicError::ProviderFailure {
            operation: "pairing key derivation",
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

fn maximum_pairing_plaintext_bytes() -> usize {
    MAX_PAIRING_CIPHERTEXT_BYTES
        .checked_sub(KonclaveSecretStorage::AUTHENTICATED_CIPHER_TAG_BYTES)
        .expect("pairing ciphertext bound must leave room for an authentication tag")
}

fn canonical_header(
    pairing_id: PairingId,
    message_id: PairingMessageId,
    sender: PairingSenderRole,
    stage: PairingStage,
    in_reply_to: Option<PairingMessageId>,
    expires_at_unix_seconds: u64,
    nonce: &[u8; 12],
) -> Vec<u8> {
    let mut output = Vec::with_capacity(128);
    output.extend_from_slice(ENVELOPE_AAD_DOMAIN);
    output.extend_from_slice(&ProtocolVersion::application_v1().major().to_be_bytes());
    output.extend_from_slice(&ProtocolVersion::application_v1().minor().to_be_bytes());
    output.extend_from_slice(pairing_id.as_bytes());
    output.extend_from_slice(message_id.as_bytes());
    output.push(sender_code(sender));
    output.push(stage_code(stage));
    match in_reply_to {
        Some(identifier) => {
            output.push(1);
            output.extend_from_slice(identifier.as_bytes());
        }
        None => output.push(0),
    }
    output.extend_from_slice(&expires_at_unix_seconds.to_be_bytes());
    output.extend_from_slice(nonce);
    output
}

const fn sender_code(sender: PairingSenderRole) -> u8 {
    match sender {
        PairingSenderRole::Joiner => 1,
        PairingSenderRole::Inviter => 2,
    }
}

const fn stage_code(stage: PairingStage) -> u8 {
    match stage {
        PairingStage::Invitation => 1,
        PairingStage::JoinProof => 2,
        PairingStage::Welcome => 3,
        PairingStage::Completion => 4,
        PairingStage::Cancellation => 5,
    }
}

fn pairing_cipher_error(error: SecretStorageError) -> KonclaveCryptographicError {
    match error {
        SecretStorageError::PlaintextTooLarge { maximum, actual }
        | SecretStorageError::SealedBlobTooLarge { maximum, actual } => {
            KonclaveCryptographicError::PairingPayloadTooLarge { maximum, actual }
        }
        SecretStorageError::RandomGenerationFailed => KonclaveCryptographicError::ProviderFailure {
            operation: "pairing nonce generation",
        },
        _ => KonclaveCryptographicError::PairingAuthenticationFailed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEADLINE: u64 = 2_000;

    fn pairing_id(value: u8) -> PairingId {
        PairingId::from_bytes([value; PairingId::LENGTH])
    }

    fn message_id(value: u8) -> PairingMessageId {
        PairingMessageId::from_bytes([value; PairingMessageId::LENGTH])
    }

    #[test]
    fn same_secret_and_pairing_derive_the_same_route_and_keys() {
        let secret = PairingSecret::from_bytes([7; PAIRING_SECRET_BYTES]);
        let first = PairingKeySchedule::derive(pairing_id(1), &secret).unwrap();
        let second = PairingKeySchedule::derive(pairing_id(1), &secret).unwrap();
        assert_eq!(first.routing_id(), second.routing_id());

        let envelope = first
            .seal(
                message_id(1),
                PairingSenderRole::Inviter,
                PairingStage::Invitation,
                None,
                DEADLINE,
                b"invitation",
            )
            .unwrap();
        assert_eq!(second.open(&envelope).unwrap().as_slice(), b"invitation");
    }

    #[test]
    fn another_secret_or_pairing_cannot_open_the_record() {
        let secret = PairingSecret::from_bytes([7; PAIRING_SECRET_BYTES]);
        let schedule = PairingKeySchedule::derive(pairing_id(1), &secret).unwrap();
        let envelope = schedule
            .seal(
                message_id(1),
                PairingSenderRole::Inviter,
                PairingStage::Invitation,
                None,
                DEADLINE,
                b"invitation",
            )
            .unwrap();

        let wrong_secret = PairingSecret::from_bytes([8; PAIRING_SECRET_BYTES]);
        let wrong = PairingKeySchedule::derive(pairing_id(1), &wrong_secret).unwrap();
        assert_eq!(
            wrong.open(&envelope).unwrap_err(),
            KonclaveCryptographicError::PairingAuthenticationFailed
        );
        let wrong_pairing = PairingKeySchedule::derive(pairing_id(2), &secret).unwrap();
        assert_eq!(
            wrong_pairing.open(&envelope).unwrap_err(),
            KonclaveCryptographicError::PairingAuthenticationFailed
        );
    }

    #[test]
    fn header_mutation_and_direction_reflection_fail_authentication() {
        let secret = PairingSecret::from_bytes([7; PAIRING_SECRET_BYTES]);
        let schedule = PairingKeySchedule::derive(pairing_id(1), &secret).unwrap();
        let envelope = schedule
            .seal(
                message_id(1),
                PairingSenderRole::Inviter,
                PairingStage::Welcome,
                Some(message_id(0)),
                DEADLINE,
                b"welcome",
            )
            .unwrap();

        for modified in [
            PairingEnvelope::new(
                envelope.version(),
                envelope.pairing_id(),
                message_id(2),
                envelope.sender(),
                envelope.stage(),
                envelope.in_reply_to(),
                envelope.expires_at_unix_seconds(),
                envelope.nonce(),
                envelope.ciphertext().to_vec(),
            )
            .unwrap(),
            PairingEnvelope::new(
                envelope.version(),
                envelope.pairing_id(),
                envelope.message_id(),
                PairingSenderRole::Joiner,
                PairingStage::JoinProof,
                envelope.in_reply_to(),
                envelope.expires_at_unix_seconds(),
                envelope.nonce(),
                envelope.ciphertext().to_vec(),
            )
            .unwrap(),
            PairingEnvelope::new(
                envelope.version(),
                envelope.pairing_id(),
                envelope.message_id(),
                envelope.sender(),
                envelope.stage(),
                envelope.in_reply_to(),
                DEADLINE + 1,
                envelope.nonce(),
                envelope.ciphertext().to_vec(),
            )
            .unwrap(),
        ] {
            assert_eq!(
                schedule.open(&modified).unwrap_err(),
                KonclaveCryptographicError::PairingAuthenticationFailed
            );
        }
    }

    #[test]
    fn repeated_plaintext_uses_distinct_nonces() {
        let secret = PairingSecret::from_bytes([7; PAIRING_SECRET_BYTES]);
        let schedule = PairingKeySchedule::derive(pairing_id(1), &secret).unwrap();
        let first = schedule
            .seal(
                message_id(1),
                PairingSenderRole::Inviter,
                PairingStage::Invitation,
                None,
                DEADLINE,
                b"same",
            )
            .unwrap();
        let second = schedule
            .seal(
                message_id(2),
                PairingSenderRole::Inviter,
                PairingStage::Invitation,
                None,
                DEADLINE,
                b"same",
            )
            .unwrap();
        assert_ne!(first.nonce(), second.nonce());
        assert_ne!(first.ciphertext(), second.ciphertext());
    }
}
