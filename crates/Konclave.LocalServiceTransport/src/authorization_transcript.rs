use KonclaveCryptographicCore::{LocalServiceIdentity, verify_local_service_signature};
use KonclaveDomainCore::{Ed25519PublicKey, Ed25519Signature};

use crate::{
    AuthorizationBinding, CHALLENGE_LENGTH, ClientInstanceId, IssuerKeyId, LocalServiceChallenge,
    LocalServiceTransportError, SESSION_GRANT_ID_LENGTH,
};

const CLIENT_SIGNATURE_DOMAIN: &[u8; 32] = b"konclave.local-service.v2.client";
const SERVICE_SIGNATURE_DOMAIN: &[u8; 32] = b"konclave.local-service.v2.accept";
const ROLE_ISSUER: u8 = 1;
const ROLE_SESSION: u8 = 2;

/// Canonical protocol-v2 authorization transcript.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizationTranscript {
    binding: AuthorizationBinding,
    client_challenge: LocalServiceChallenge,
    service_challenge: LocalServiceChallenge,
    service_public_key: Ed25519PublicKey,
}

impl AuthorizationTranscript {
    /// Creates one transcript from an already validated immutable binding.
    #[must_use]
    pub const fn new(
        binding: AuthorizationBinding,
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

    /// Returns the immutable connection binding.
    #[must_use]
    pub const fn binding(&self) -> &AuthorizationBinding {
        &self.binding
    }

    /// Consumes the transcript into its binding.
    #[must_use]
    pub fn into_binding(self) -> AuthorizationBinding {
        self.binding
    }

    /// Encodes the exact byte string authenticated by both roles.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(256);
        encoded.extend_from_slice(&self.binding.version().to_be_bytes());
        match &self.binding {
            AuthorizationBinding::Issuer {
                issuer_key_id,
                issuer_key_version,
                issuer_public_key,
                client_instance,
                harness,
            } => {
                encoded.push(ROLE_ISSUER);
                encoded.extend_from_slice(issuer_key_id.as_bytes());
                encoded.extend_from_slice(&issuer_key_version.get().to_be_bytes());
                encoded.extend_from_slice(issuer_public_key.as_bytes());
                encoded.extend_from_slice(client_instance.as_bytes());
                encoded.extend_from_slice(&harness.wire_value().to_be_bytes());
            }
            AuthorizationBinding::Session {
                grant,
                client_instance,
            } => {
                encoded.push(ROLE_SESSION);
                encoded.extend_from_slice(grant.grant_id().as_bytes());
                encoded.extend_from_slice(grant.issuer_key_id().as_bytes());
                encoded.extend_from_slice(&grant.issuer_key_version().get().to_be_bytes());
                encoded.extend_from_slice(grant.session_public_key().as_bytes());
                encoded.extend_from_slice(client_instance.as_bytes());
                encoded.extend_from_slice(&grant.harness().wire_value().to_be_bytes());
                let profile = grant.profile().as_str().as_bytes();
                encoded.extend_from_slice(
                    &u16::try_from(profile.len())
                        .unwrap_or(u16::MAX)
                        .to_be_bytes(),
                );
                encoded.extend_from_slice(profile);
                encoded.push(grant.evidence().bits());
                encoded.extend_from_slice(&grant.policy_version().get().to_be_bytes());
                encoded.extend_from_slice(&grant.issued_at_unix_milliseconds().to_be_bytes());
                encoded.extend_from_slice(&grant.expires_at_unix_milliseconds().to_be_bytes());
                encoded.extend_from_slice(&grant.capabilities().bits().to_be_bytes());
            }
        }
        encoded.extend_from_slice(self.client_challenge.as_bytes());
        encoded.extend_from_slice(self.service_challenge.as_bytes());
        encoded.extend_from_slice(self.service_public_key.as_bytes());
        encoded
    }

    /// Returns the domain-separated bytes the client signs.
    #[must_use]
    pub fn client_signing_message(&self) -> Vec<u8> {
        domain_separated(CLIENT_SIGNATURE_DOMAIN, &self.encode())
    }

    /// Returns the domain-separated bytes the service signs.
    #[must_use]
    pub fn service_signing_message(&self) -> Vec<u8> {
        domain_separated(SERVICE_SIGNATURE_DOMAIN, &self.encode())
    }

    /// Signs as the issuer or session client.
    ///
    /// # Errors
    ///
    /// Returns unusable key material when the provider rejects signing.
    pub fn sign_as_client(
        &self,
        identity: &LocalServiceIdentity,
    ) -> Result<Ed25519Signature, LocalServiceTransportError> {
        identity
            .sign(&self.client_signing_message())
            .map_err(|_| LocalServiceTransportError::UnusableKeyMaterial)
    }

    /// Signs as the accepting service.
    ///
    /// # Errors
    ///
    /// Returns unusable key material when the provider rejects signing.
    pub fn sign_as_service(
        &self,
        identity: &LocalServiceIdentity,
    ) -> Result<Ed25519Signature, LocalServiceTransportError> {
        identity
            .sign(&self.service_signing_message())
            .map_err(|_| LocalServiceTransportError::UnusableKeyMaterial)
    }

    /// Verifies the client proof under the key included in the transcript.
    ///
    /// # Errors
    ///
    /// Returns a uniform unauthentic-client failure.
    pub fn verify_client_signature(
        &self,
        public_key: Ed25519PublicKey,
        signature: &Ed25519Signature,
    ) -> Result<(), LocalServiceTransportError> {
        verify_local_service_signature(public_key, &self.client_signing_message(), signature)
            .map_err(|_| LocalServiceTransportError::UnauthenticClient)
    }

    /// Verifies the service acceptance under the pinned key.
    ///
    /// # Errors
    ///
    /// Returns an unauthentic-service failure.
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

fn domain_separated(domain: &[u8; 32], transcript: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(domain.len() + transcript.len());
    message.extend_from_slice(domain);
    message.extend_from_slice(transcript);
    message
}

const _: () = assert!(IssuerKeyId::LENGTH == SESSION_GRANT_ID_LENGTH);
const _: () = assert!(ClientInstanceId::LENGTH * 2 == CHALLENGE_LENGTH);

#[cfg(test)]
mod tests {
    use KonclaveDomainCore::Ed25519PublicKey;

    use super::*;
    use crate::{
        AuthorizationEvidenceKind, AuthorizationEvidenceSet, AuthorizationPolicyVersion,
        HarnessKind, IssuerKeyVersion, ServiceProfileId, SessionCapabilities, SessionGrant,
        SessionGrantClaims, SessionGrantId,
    };

    fn session_binding() -> AuthorizationBinding {
        AuthorizationBinding::Session {
            grant: SessionGrant::new(SessionGrantClaims {
                grant_id: SessionGrantId::from_bytes([1; 16]),
                issuer_key_id: IssuerKeyId::from_bytes([2; 16]),
                issuer_key_version: IssuerKeyVersion::new(3).unwrap(),
                profile: ServiceProfileId::parse("session-a").unwrap(),
                session_public_key: Ed25519PublicKey::from_bytes([4; 32]),
                harness: HarnessKind::Copilot,
                evidence: AuthorizationEvidenceSet::new([
                    AuthorizationEvidenceKind::AccountTrusted,
                ])
                .unwrap(),
                policy_version: AuthorizationPolicyVersion::new(5).unwrap(),
                issued_at_unix_milliseconds: 6,
                expires_at_unix_milliseconds: 7,
                capabilities: SessionCapabilities::ALL,
            })
            .unwrap(),
            client_instance: ClientInstanceId::from_bytes([8; 16]),
        }
    }

    #[test]
    fn session_transcript_binds_every_grant_claim_and_role() {
        let transcript = AuthorizationTranscript::new(
            session_binding(),
            LocalServiceChallenge::from_bytes([9; 32]),
            LocalServiceChallenge::from_bytes([10; 32]),
            Ed25519PublicKey::from_bytes([11; 32]),
        );
        let encoded = transcript.encode();
        assert_eq!(&encoded[..2], &2_u16.to_be_bytes());
        assert_eq!(encoded[2], ROLE_SESSION);
        assert_eq!(
            &transcript.client_signing_message()[..32],
            CLIENT_SIGNATURE_DOMAIN
        );
        assert_eq!(
            &transcript.service_signing_message()[..32],
            SERVICE_SIGNATURE_DOMAIN
        );
        assert_ne!(
            transcript.client_signing_message(),
            transcript.service_signing_message()
        );
    }

    #[test]
    fn a_signature_cannot_move_between_grants() {
        let identity = LocalServiceIdentity::generate().unwrap();
        let transcript = AuthorizationTranscript::new(
            session_binding(),
            LocalServiceChallenge::from_bytes([9; 32]),
            LocalServiceChallenge::from_bytes([10; 32]),
            identity.public_key(),
        );
        let signature = transcript.sign_as_client(&identity).unwrap();
        let mut other_binding = session_binding();
        let AuthorizationBinding::Session { grant, .. } = &mut other_binding else {
            unreachable!()
        };
        *grant = SessionGrant::new(SessionGrantClaims {
            grant_id: SessionGrantId::from_bytes([12; 16]),
            issuer_key_id: grant.issuer_key_id(),
            issuer_key_version: grant.issuer_key_version(),
            profile: grant.profile().clone(),
            session_public_key: grant.session_public_key(),
            harness: grant.harness(),
            evidence: grant.evidence(),
            policy_version: grant.policy_version(),
            issued_at_unix_milliseconds: grant.issued_at_unix_milliseconds(),
            expires_at_unix_milliseconds: grant.expires_at_unix_milliseconds(),
            capabilities: grant.capabilities(),
        })
        .unwrap();
        let other = AuthorizationTranscript::new(
            other_binding,
            LocalServiceChallenge::from_bytes([9; 32]),
            LocalServiceChallenge::from_bytes([10; 32]),
            identity.public_key(),
        );
        assert_eq!(
            other
                .verify_client_signature(identity.public_key(), &signature)
                .unwrap_err(),
            LocalServiceTransportError::UnauthenticClient
        );
    }
}
