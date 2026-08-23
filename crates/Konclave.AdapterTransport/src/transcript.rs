use KonclaveCryptographicCore::{HMAC_SHA256_TAG_LENGTH, HmacSha256Key};

use crate::capability::LaunchCapability;
use crate::error::AdapterTransportError;

/// Byte length of a handshake challenge.
pub const CHALLENGE_LENGTH: usize = 32;

/// Largest accepted length for a bounded handshake identifier.
pub const MAX_IDENTIFIER_LENGTH: usize = 64;

/// Adapter local-channel protocol version implemented by this build.
pub const ADAPTER_PROTOCOL_VERSION: u16 = 1;

/// Domain separator for the proof a daemon presents to an adapter.
const DAEMON_PROOF_DOMAIN: &[u8; 32] = b"konclave.adapter.v1.proof.daemon";

/// Domain separator for the proof an adapter returns to a daemon.
const ADAPTER_PROOF_DOMAIN: &[u8; 32] = b"konclave.adapter.v1.proof.client";

/// A handshake challenge contributed by one side of the channel.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct AuthChallenge([u8; CHALLENGE_LENGTH]);

impl AuthChallenge {
    /// Wraps exactly [`CHALLENGE_LENGTH`] random bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; CHALLENGE_LENGTH]) -> Self {
        Self(bytes)
    }

    /// Returns the challenge bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; CHALLENGE_LENGTH] {
        &self.0
    }
}

impl core::fmt::Debug for AuthChallenge {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("AuthChallenge")
            .finish_non_exhaustive()
    }
}

/// The exact values both sides authenticate before any event data may flow.
///
/// Both sides derive one canonical byte string from this transcript. Encoding it in
/// one place is what lets a Rust daemon and a non-Rust adapter agree byte for byte
/// without either side reimplementing the layout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthTranscript {
    version: u16,
    profile: String,
    consumer: String,
    adapter_challenge: AuthChallenge,
    daemon_challenge: AuthChallenge,
}

impl AuthTranscript {
    /// Validates and assembles a transcript.
    ///
    /// # Errors
    ///
    /// Returns [`AdapterTransportError::UnsupportedVersion`] for an unimplemented
    /// version and [`AdapterTransportError::InvalidIdentifier`] when the profile or
    /// consumer identifier is empty, oversized, or not printable ASCII.
    pub fn new(
        version: u16,
        profile: &str,
        consumer: &str,
        adapter_challenge: AuthChallenge,
        daemon_challenge: AuthChallenge,
    ) -> Result<Self, AdapterTransportError> {
        if version != ADAPTER_PROTOCOL_VERSION {
            return Err(AdapterTransportError::UnsupportedVersion);
        }
        validate_identifier(profile, "profile")?;
        validate_identifier(consumer, "consumer")?;
        Ok(Self {
            version,
            profile: profile.to_string(),
            consumer: consumer.to_string(),
            adapter_challenge,
            daemon_challenge,
        })
    }

    /// Returns the negotiated protocol version.
    #[must_use]
    pub const fn version(&self) -> u16 {
        self.version
    }

    /// Returns the validated profile identifier.
    #[must_use]
    pub fn profile(&self) -> &str {
        &self.profile
    }

    /// Returns the consumer instance identifier.
    #[must_use]
    pub fn consumer(&self) -> &str {
        &self.consumer
    }

    /// Encodes the canonical authenticated byte string.
    ///
    /// Every variable-length field carries an explicit two-byte length, so no pair of
    /// distinct transcripts can share an encoding. Concatenating the fields directly
    /// would let a profile and consumer identifier trade characters and authenticate
    /// the same bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let profile = self.profile.as_bytes();
        let consumer = self.consumer.as_bytes();
        let mut encoded =
            Vec::with_capacity(2 + 2 + profile.len() + 2 + consumer.len() + CHALLENGE_LENGTH * 2);
        encoded.extend_from_slice(&self.version.to_be_bytes());
        encoded.extend_from_slice(&length_prefix(profile.len()));
        encoded.extend_from_slice(profile);
        encoded.extend_from_slice(&length_prefix(consumer.len()));
        encoded.extend_from_slice(consumer);
        encoded.extend_from_slice(self.adapter_challenge.as_bytes());
        encoded.extend_from_slice(self.daemon_challenge.as_bytes());
        encoded
    }

    /// Computes the proof a daemon presents to an adapter.
    ///
    /// # Errors
    ///
    /// Returns [`AdapterTransportError::UnusableKeyMaterial`] when the capability
    /// cannot key the vetted authenticator.
    pub fn daemon_proof(
        &self,
        capability: &LaunchCapability,
    ) -> Result<[u8; HMAC_SHA256_TAG_LENGTH], AdapterTransportError> {
        self.proof(capability, DAEMON_PROOF_DOMAIN)
    }

    /// Computes the proof an adapter returns to a daemon.
    ///
    /// # Errors
    ///
    /// Returns [`AdapterTransportError::UnusableKeyMaterial`] when the capability
    /// cannot key the vetted authenticator.
    pub fn adapter_proof(
        &self,
        capability: &LaunchCapability,
    ) -> Result<[u8; HMAC_SHA256_TAG_LENGTH], AdapterTransportError> {
        self.proof(capability, ADAPTER_PROOF_DOMAIN)
    }

    /// Verifies a daemon proof in constant time.
    ///
    /// # Errors
    ///
    /// Returns [`AdapterTransportError::UnauthenticPeer`] when the proof does not
    /// authenticate this transcript.
    pub fn verify_daemon_proof(
        &self,
        capability: &LaunchCapability,
        proof: &[u8],
    ) -> Result<(), AdapterTransportError> {
        self.verify(capability, DAEMON_PROOF_DOMAIN, proof)
    }

    /// Verifies an adapter proof in constant time.
    ///
    /// # Errors
    ///
    /// Returns [`AdapterTransportError::UnauthenticPeer`] when the proof does not
    /// authenticate this transcript.
    pub fn verify_adapter_proof(
        &self,
        capability: &LaunchCapability,
        proof: &[u8],
    ) -> Result<(), AdapterTransportError> {
        self.verify(capability, ADAPTER_PROOF_DOMAIN, proof)
    }

    fn proof(
        &self,
        capability: &LaunchCapability,
        domain: &[u8; 32],
    ) -> Result<[u8; HMAC_SHA256_TAG_LENGTH], AdapterTransportError> {
        let key = HmacSha256Key::new(capability.as_bytes())
            .map_err(|_| AdapterTransportError::UnusableKeyMaterial)?;
        Ok(key.sign(&domain_separated(domain, &self.encode())))
    }

    fn verify(
        &self,
        capability: &LaunchCapability,
        domain: &[u8; 32],
        proof: &[u8],
    ) -> Result<(), AdapterTransportError> {
        let key = HmacSha256Key::new(capability.as_bytes())
            .map_err(|_| AdapterTransportError::UnusableKeyMaterial)?;
        if key.verify(&domain_separated(domain, &self.encode()), proof) {
            Ok(())
        } else {
            Err(AdapterTransportError::UnauthenticPeer)
        }
    }
}

fn domain_separated(domain: &[u8; 32], encoded: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(domain.len() + encoded.len());
    message.extend_from_slice(domain);
    message.extend_from_slice(encoded);
    message
}

fn length_prefix(length: usize) -> [u8; 2] {
    debug_assert!(length <= MAX_IDENTIFIER_LENGTH);
    u16::try_from(length).unwrap_or(u16::MAX).to_be_bytes()
}

fn validate_identifier(value: &str, field: &'static str) -> Result<(), AdapterTransportError> {
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_IDENTIFIER_LENGTH {
        return Err(AdapterTransportError::InvalidIdentifier { field });
    }
    if !bytes
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(AdapterTransportError::InvalidIdentifier { field });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        ADAPTER_PROTOCOL_VERSION, AuthChallenge, AuthTranscript, CHALLENGE_LENGTH,
        MAX_IDENTIFIER_LENGTH,
    };
    use crate::capability::LaunchCapability;
    use crate::error::AdapterTransportError;

    fn capability() -> LaunchCapability {
        LaunchCapability::from_bytes([9_u8; LaunchCapability::LENGTH])
    }

    fn transcript(profile: &str, consumer: &str) -> AuthTranscript {
        AuthTranscript::new(
            ADAPTER_PROTOCOL_VERSION,
            profile,
            consumer,
            AuthChallenge::from_bytes([1_u8; CHALLENGE_LENGTH]),
            AuthChallenge::from_bytes([2_u8; CHALLENGE_LENGTH]),
        )
        .unwrap()
    }

    #[test]
    fn rejects_an_unimplemented_version() {
        let error = AuthTranscript::new(
            ADAPTER_PROTOCOL_VERSION + 1,
            "alice",
            "consumer",
            AuthChallenge::from_bytes([1_u8; CHALLENGE_LENGTH]),
            AuthChallenge::from_bytes([2_u8; CHALLENGE_LENGTH]),
        )
        .unwrap_err();
        assert_eq!(error, AdapterTransportError::UnsupportedVersion);
    }

    #[test]
    fn rejects_empty_oversized_and_unprintable_identifiers() {
        for (profile, consumer, field) in [
            ("", "consumer", "profile"),
            ("alice", "", "consumer"),
            ("alice", "consumer\u{0}", "consumer"),
            ("alice/../bob", "consumer", "profile"),
        ] {
            let error = AuthTranscript::new(
                ADAPTER_PROTOCOL_VERSION,
                profile,
                consumer,
                AuthChallenge::from_bytes([1_u8; CHALLENGE_LENGTH]),
                AuthChallenge::from_bytes([2_u8; CHALLENGE_LENGTH]),
            )
            .unwrap_err();
            assert_eq!(error, AdapterTransportError::InvalidIdentifier { field });
        }

        let oversized = "a".repeat(MAX_IDENTIFIER_LENGTH + 1);
        assert!(
            AuthTranscript::new(
                ADAPTER_PROTOCOL_VERSION,
                &oversized,
                "consumer",
                AuthChallenge::from_bytes([1_u8; CHALLENGE_LENGTH]),
                AuthChallenge::from_bytes([2_u8; CHALLENGE_LENGTH]),
            )
            .is_err()
        );
    }

    #[test]
    fn encoding_is_length_prefixed_and_unambiguous() {
        let first = transcript("alice", "consumer");
        let second = transcript("alicec", "onsumer");
        assert_ne!(first.encode(), second.encode());

        let encoded = first.encode();
        assert_eq!(&encoded[0..2], &ADAPTER_PROTOCOL_VERSION.to_be_bytes());
        assert_eq!(&encoded[2..4], &5_u16.to_be_bytes());
        assert_eq!(&encoded[4..9], b"alice");
        assert_eq!(&encoded[9..11], &8_u16.to_be_bytes());
        assert_eq!(&encoded[11..19], b"consumer");
        assert_eq!(&encoded[19..51], &[1_u8; CHALLENGE_LENGTH]);
        assert_eq!(&encoded[51..83], &[2_u8; CHALLENGE_LENGTH]);
        assert_eq!(encoded.len(), 83);
    }

    #[test]
    fn each_role_produces_a_distinct_proof() {
        let transcript = transcript("alice", "consumer");
        let capability = capability();
        let daemon = transcript.daemon_proof(&capability).unwrap();
        let adapter = transcript.adapter_proof(&capability).unwrap();
        assert_ne!(daemon, adapter);
        transcript
            .verify_daemon_proof(&capability, &daemon)
            .unwrap();
        transcript
            .verify_adapter_proof(&capability, &adapter)
            .unwrap();
    }

    #[test]
    fn a_role_proof_cannot_be_replayed_as_the_other_role() {
        let transcript = transcript("alice", "consumer");
        let capability = capability();
        let daemon = transcript.daemon_proof(&capability).unwrap();
        assert_eq!(
            transcript
                .verify_adapter_proof(&capability, &daemon)
                .unwrap_err(),
            AdapterTransportError::UnauthenticPeer
        );
    }

    #[test]
    fn a_proof_does_not_authenticate_another_profile_consumer_or_challenge() {
        let capability = capability();
        let original = transcript("alice", "consumer");
        let proof = original.daemon_proof(&capability).unwrap();

        for other in [
            transcript("bob", "consumer"),
            transcript("alice", "other"),
            AuthTranscript::new(
                ADAPTER_PROTOCOL_VERSION,
                "alice",
                "consumer",
                AuthChallenge::from_bytes([3_u8; CHALLENGE_LENGTH]),
                AuthChallenge::from_bytes([2_u8; CHALLENGE_LENGTH]),
            )
            .unwrap(),
            AuthTranscript::new(
                ADAPTER_PROTOCOL_VERSION,
                "alice",
                "consumer",
                AuthChallenge::from_bytes([1_u8; CHALLENGE_LENGTH]),
                AuthChallenge::from_bytes([4_u8; CHALLENGE_LENGTH]),
            )
            .unwrap(),
        ] {
            assert_eq!(
                other.verify_daemon_proof(&capability, &proof).unwrap_err(),
                AdapterTransportError::UnauthenticPeer
            );
        }
    }

    #[test]
    fn a_proof_does_not_authenticate_under_another_capability() {
        let transcript = transcript("alice", "consumer");
        let proof = transcript.daemon_proof(&capability()).unwrap();
        let other = LaunchCapability::from_bytes([8_u8; LaunchCapability::LENGTH]);
        assert_eq!(
            transcript.verify_daemon_proof(&other, &proof).unwrap_err(),
            AdapterTransportError::UnauthenticPeer
        );
    }

    #[test]
    fn a_truncated_or_padded_proof_is_rejected() {
        let transcript = transcript("alice", "consumer");
        let capability = capability();
        let proof = transcript.daemon_proof(&capability).unwrap();
        assert!(
            transcript
                .verify_daemon_proof(&capability, &proof[..31])
                .is_err()
        );
        let mut padded = proof.to_vec();
        padded.push(0);
        assert!(
            transcript
                .verify_daemon_proof(&capability, &padded)
                .is_err()
        );
        assert!(transcript.verify_daemon_proof(&capability, &[]).is_err());
    }
}
