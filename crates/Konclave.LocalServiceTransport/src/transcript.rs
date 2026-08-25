use KonclaveCryptographicCore::{LocalServiceIdentity, verify_local_service_signature};
use KonclaveDomainCore::{Ed25519PublicKey, Ed25519Signature};

use crate::binding::LocalServiceBinding;
use crate::error::LocalServiceTransportError;
use crate::identifiers::{
    AdapterKeyId, CHALLENGE_LENGTH, ClientInstanceId, LocalServiceChallenge, MAX_PROFILE_ID_LENGTH,
};

/// Domain separator for the signature a client presents to the service.
const CLIENT_SIGNATURE_DOMAIN: &[u8; 32] = b"konclave.local-service.v1.client";

/// Domain separator for the acceptance signature the service returns.
const SERVICE_SIGNATURE_DOMAIN: &[u8; 32] = b"konclave.local-service.v1.accept";

const _: () = assert!(
    CLIENT_SIGNATURE_DOMAIN.len() == SERVICE_SIGNATURE_DOMAIN.len(),
    "role domains must share one fixed width so neither can extend into the transcript"
);

/// The exact values both peers authenticate before any request may flow.
///
/// Both sides derive one canonical byte string from this transcript. Encoding it in
/// one place is what lets the Rust service and a non-Rust client agree byte for byte
/// without either side reimplementing the layout.
///
/// The transcript covers the whole connection binding, both fresh challenges, and the
/// service identity. A signature captured from one connection therefore authenticates
/// nothing on another connection, because the peer challenges differ.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalServiceTranscript {
    binding: LocalServiceBinding,
    client_challenge: LocalServiceChallenge,
    service_challenge: LocalServiceChallenge,
    service_public_key: Ed25519PublicKey,
}

impl LocalServiceTranscript {
    /// Assembles a transcript from an already-validated binding.
    #[must_use]
    pub const fn new(
        binding: LocalServiceBinding,
        client_challenge: LocalServiceChallenge,
        service_challenge: LocalServiceChallenge,
        service_public_key: Ed25519PublicKey,
    ) -> Self {
        Self {
            binding,
            client_challenge,
            service_challenge,
            service_public_key,
        }
    }

    /// Returns the connection binding this transcript authenticates.
    #[must_use]
    pub const fn binding(&self) -> &LocalServiceBinding {
        &self.binding
    }

    /// Returns the service verification key this transcript binds.
    #[must_use]
    pub const fn service_public_key(&self) -> Ed25519PublicKey {
        self.service_public_key
    }

    /// Consumes the transcript and returns its binding.
    #[must_use]
    pub fn into_binding(self) -> LocalServiceBinding {
        self.binding
    }

    /// Encodes the canonical authenticated byte string.
    ///
    /// The one variable-length field carries an explicit two-byte length and every
    /// other field is fixed width, so no pair of distinct transcripts can share an
    /// encoding.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let profile = self.binding.profile().as_str().as_bytes();
        let mut encoded = Vec::with_capacity(
            2 + AdapterKeyId::LENGTH
                + 4
                + ClientInstanceId::LENGTH
                + 2
                + 2
                + profile.len()
                + CHALLENGE_LENGTH * 2
                + Ed25519PublicKey::LENGTH,
        );
        encoded.extend_from_slice(&self.binding.version().to_be_bytes());
        encoded.extend_from_slice(self.binding.adapter_key_id().as_bytes());
        encoded.extend_from_slice(&self.binding.adapter_key_version().get().to_be_bytes());
        encoded.extend_from_slice(self.binding.client_instance().as_bytes());
        encoded.extend_from_slice(&self.binding.harness().wire_value().to_be_bytes());
        encoded.extend_from_slice(&length_prefix(profile.len()));
        encoded.extend_from_slice(profile);
        encoded.extend_from_slice(self.client_challenge.as_bytes());
        encoded.extend_from_slice(self.service_challenge.as_bytes());
        encoded.extend_from_slice(self.service_public_key.as_bytes());
        encoded
    }

    /// Returns the exact bytes a client signs.
    #[must_use]
    pub fn client_signing_message(&self) -> Vec<u8> {
        domain_separated(CLIENT_SIGNATURE_DOMAIN, &self.encode())
    }

    /// Returns the exact bytes the service signs on acceptance.
    #[must_use]
    pub fn service_signing_message(&self) -> Vec<u8> {
        domain_separated(SERVICE_SIGNATURE_DOMAIN, &self.encode())
    }

    /// Signs this transcript as the connecting client.
    ///
    /// # Errors
    ///
    /// Returns [`LocalServiceTransportError::UnusableKeyMaterial`] when the vetted
    /// provider rejects the signing operation.
    pub fn sign_as_client(
        &self,
        identity: &LocalServiceIdentity,
    ) -> Result<Ed25519Signature, LocalServiceTransportError> {
        identity
            .sign(&self.client_signing_message())
            .map_err(|_| LocalServiceTransportError::UnusableKeyMaterial)
    }

    /// Signs this transcript as the accepting service.
    ///
    /// # Errors
    ///
    /// Returns [`LocalServiceTransportError::UnusableKeyMaterial`] when the vetted
    /// provider rejects the signing operation.
    pub fn sign_as_service(
        &self,
        identity: &LocalServiceIdentity,
    ) -> Result<Ed25519Signature, LocalServiceTransportError> {
        identity
            .sign(&self.service_signing_message())
            .map_err(|_| LocalServiceTransportError::UnusableKeyMaterial)
    }

    /// Verifies a client signature against the registered adapter key.
    ///
    /// # Errors
    ///
    /// Returns [`LocalServiceTransportError::UnauthenticClient`] when the signature
    /// does not authenticate this transcript under `public_key`.
    pub fn verify_client_signature(
        &self,
        public_key: Ed25519PublicKey,
        signature: &Ed25519Signature,
    ) -> Result<(), LocalServiceTransportError> {
        verify_local_service_signature(public_key, &self.client_signing_message(), signature)
            .map_err(|_| LocalServiceTransportError::UnauthenticClient)
    }

    /// Verifies a service acceptance signature against the bound service key.
    ///
    /// # Errors
    ///
    /// Returns [`LocalServiceTransportError::UnauthenticService`] when the signature
    /// does not authenticate this transcript under the bound service key.
    pub fn verify_service_signature(
        &self,
        signature: &Ed25519Signature,
    ) -> Result<(), LocalServiceTransportError> {
        verify_local_service_signature(
            self.service_public_key,
            &self.service_signing_message(),
            signature,
        )
        .map_err(|_| LocalServiceTransportError::UnauthenticService)
    }
}

fn domain_separated(domain: &[u8; 32], encoded: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(domain.len() + encoded.len());
    message.extend_from_slice(domain);
    message.extend_from_slice(encoded);
    message
}

fn length_prefix(length: usize) -> [u8; 2] {
    debug_assert!(length <= MAX_PROFILE_ID_LENGTH);
    u16::try_from(length).unwrap_or(u16::MAX).to_be_bytes()
}

#[cfg(test)]
mod tests {
    use super::{CLIENT_SIGNATURE_DOMAIN, LocalServiceTranscript, SERVICE_SIGNATURE_DOMAIN};
    use crate::binding::LocalServiceBinding;
    use crate::error::LocalServiceTransportError;
    use crate::identifiers::{
        AdapterKeyId, AdapterKeyVersion, CHALLENGE_LENGTH, ClientInstanceId, HarnessKind,
        LOCAL_SERVICE_PROTOCOL_VERSION, LocalServiceChallenge, ServiceProfileId,
    };
    use KonclaveCryptographicCore::LocalServiceIdentity;
    use KonclaveDomainCore::Ed25519PublicKey;

    fn transcript_with(
        profile: &str,
        harness: HarnessKind,
        service_public_key: Ed25519PublicKey,
    ) -> LocalServiceTranscript {
        LocalServiceTranscript::new(
            LocalServiceBinding::new(
                LOCAL_SERVICE_PROTOCOL_VERSION,
                AdapterKeyId::from_bytes([1_u8; AdapterKeyId::LENGTH]),
                AdapterKeyVersion::new(1).unwrap(),
                ClientInstanceId::from_bytes([2_u8; ClientInstanceId::LENGTH]),
                harness,
                ServiceProfileId::parse(profile).unwrap(),
            )
            .unwrap(),
            LocalServiceChallenge::from_bytes([3_u8; CHALLENGE_LENGTH]),
            LocalServiceChallenge::from_bytes([4_u8; CHALLENGE_LENGTH]),
            service_public_key,
        )
    }

    fn service_key() -> Ed25519PublicKey {
        Ed25519PublicKey::from_bytes([5_u8; Ed25519PublicKey::LENGTH])
    }

    #[test]
    fn the_encoding_places_every_field_at_a_fixed_offset() {
        let transcript = transcript_with("alice", HarnessKind::Copilot, service_key());
        let encoded = transcript.encode();
        assert_eq!(
            &encoded[0..2],
            &LOCAL_SERVICE_PROTOCOL_VERSION.to_be_bytes()
        );
        assert_eq!(&encoded[2..18], &[1_u8; AdapterKeyId::LENGTH]);
        assert_eq!(&encoded[18..22], &1_u32.to_be_bytes());
        assert_eq!(&encoded[22..38], &[2_u8; ClientInstanceId::LENGTH]);
        assert_eq!(
            &encoded[38..40],
            &HarnessKind::Copilot.wire_value().to_be_bytes()
        );
        assert_eq!(&encoded[40..42], &5_u16.to_be_bytes());
        assert_eq!(&encoded[42..47], b"alice");
        assert_eq!(&encoded[47..79], &[3_u8; CHALLENGE_LENGTH]);
        assert_eq!(&encoded[79..111], &[4_u8; CHALLENGE_LENGTH]);
        assert_eq!(&encoded[111..143], &[5_u8; Ed25519PublicKey::LENGTH]);
        assert_eq!(encoded.len(), 143);
    }

    #[test]
    fn the_profile_length_prefix_keeps_neighbouring_fields_unambiguous() {
        let first = transcript_with("alice", HarnessKind::Copilot, service_key());
        let second = transcript_with("alic", HarnessKind::Copilot, service_key());
        assert_ne!(first.encode(), second.encode());
    }

    #[test]
    fn each_role_signs_a_distinct_domain_separated_message() {
        let transcript = transcript_with("alice", HarnessKind::Copilot, service_key());
        let client = transcript.client_signing_message();
        let service = transcript.service_signing_message();
        assert_ne!(client, service);
        assert_eq!(&client[..32], CLIENT_SIGNATURE_DOMAIN);
        assert_eq!(&service[..32], SERVICE_SIGNATURE_DOMAIN);
        assert_eq!(&client[32..], transcript.encode().as_slice());
    }

    #[test]
    fn a_client_signature_verifies_only_over_its_own_transcript() {
        let identity = LocalServiceIdentity::generate().unwrap();
        let transcript = transcript_with("alice", HarnessKind::Copilot, service_key());
        let signature = transcript.sign_as_client(&identity).unwrap();
        transcript
            .verify_client_signature(identity.public_key(), &signature)
            .unwrap();

        for other in [
            transcript_with("bob", HarnessKind::Copilot, service_key()),
            transcript_with("alice", HarnessKind::Codex, service_key()),
            transcript_with(
                "alice",
                HarnessKind::Copilot,
                Ed25519PublicKey::from_bytes([6_u8; Ed25519PublicKey::LENGTH]),
            ),
        ] {
            assert_eq!(
                other
                    .verify_client_signature(identity.public_key(), &signature)
                    .unwrap_err(),
                LocalServiceTransportError::UnauthenticClient
            );
        }
    }

    #[test]
    fn a_client_signature_is_not_a_service_signature() {
        let identity = LocalServiceIdentity::generate().unwrap();
        let transcript = transcript_with("alice", HarnessKind::Copilot, identity.public_key());
        let as_client = transcript.sign_as_client(&identity).unwrap();
        assert_eq!(
            transcript.verify_service_signature(&as_client).unwrap_err(),
            LocalServiceTransportError::UnauthenticService
        );
        let as_service = transcript.sign_as_service(&identity).unwrap();
        transcript.verify_service_signature(&as_service).unwrap();
        assert_eq!(
            transcript
                .verify_client_signature(identity.public_key(), &as_service)
                .unwrap_err(),
            LocalServiceTransportError::UnauthenticClient
        );
    }

    #[test]
    fn a_service_signature_does_not_verify_under_another_service_key() {
        let service_identity = LocalServiceIdentity::generate().unwrap();
        let impostor = LocalServiceIdentity::generate().unwrap();
        let transcript =
            transcript_with("alice", HarnessKind::Copilot, service_identity.public_key());
        let signature = transcript.sign_as_service(&impostor).unwrap();
        assert_eq!(
            transcript.verify_service_signature(&signature).unwrap_err(),
            LocalServiceTransportError::UnauthenticService
        );
    }

    #[test]
    fn a_challenge_never_appears_in_debug_output() {
        let transcript = transcript_with("alice", HarnessKind::Copilot, service_key());
        let rendered = format!("{transcript:?}");
        assert!(
            !rendered.contains("3, 3, 3"),
            "challenge bytes must not be formatted: {rendered}"
        );
    }
}
