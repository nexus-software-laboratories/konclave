//! Pins protocol-v2 authorization bytes shared with non-Rust clients.

use std::path::PathBuf;

use KonclaveCryptographicCore::verify_local_service_signature;
use KonclaveDomainCore::{Ed25519PublicKey, Ed25519Signature};
use KonclaveLocalServiceTransport::{
    AdapterKeyId, AdapterKeyVersion, AuthorizationBinding, AuthorizationEvidenceSet,
    AuthorizationHandshakeMessage, AuthorizationPolicyVersion, AuthorizationTranscript,
    ClientInstanceId, HarnessKind, LocalServiceChallenge, ServiceProfileId, SessionCapabilities,
    SessionGrant, SessionGrantClaims, SessionGrantId,
};

#[test]
fn issuer_and_session_transcripts_match_the_shared_fixture() {
    let fixture = load_fixture();
    let (issuer, session) = transcripts(&fixture);
    assert_eq!(issuer.encode(), hex(&fixture, "issuerTranscript"));
    assert_eq!(session.encode(), hex(&fixture, "sessionTranscript"));
    assert_eq!(
        issuer.client_signing_message(),
        hex(&fixture, "issuerClientSigningMessage")
    );
    assert_eq!(
        session.client_signing_message(),
        hex(&fixture, "sessionClientSigningMessage")
    );
    assert_eq!(
        issuer.service_signing_message(),
        hex(&fixture, "issuerServiceSigningMessage")
    );
    assert_eq!(
        session.service_signing_message(),
        hex(&fixture, "sessionServiceSigningMessage")
    );
}

#[test]
fn every_role_signature_and_handshake_message_matches() {
    let fixture = load_fixture();
    let (issuer, session) = transcripts(&fixture);
    verify_local_service_signature(
        public_key(&fixture, "issuerPublicKey"),
        &issuer.client_signing_message(),
        &signature(&fixture, "issuerSignature"),
    )
    .unwrap();
    verify_local_service_signature(
        public_key(&fixture, "sessionPublicKey"),
        &session.client_signing_message(),
        &signature(&fixture, "sessionSignature"),
    )
    .unwrap();
    verify_local_service_signature(
        public_key(&fixture, "servicePublicKey"),
        &session.service_signing_message(),
        &signature(&fixture, "sessionAcceptance"),
    )
    .unwrap();

    let grant = fixture_grant(&fixture);
    let messages = [
        (
            AuthorizationHandshakeMessage::IssuerHello {
                version: 2,
                issuer_key_id: grant.issuer_key_id(),
                issuer_key_version: grant.issuer_key_version(),
                issuer_public_key: public_key(&fixture, "issuerPublicKey"),
                client_instance: identifier(&fixture, "issuerClientInstance"),
                harness: HarnessKind::Copilot,
                challenge: challenge(&fixture, "clientChallenge"),
            },
            "issuerHelloMessage",
        ),
        (
            AuthorizationHandshakeMessage::SessionHello {
                version: 2,
                grant,
                client_instance: identifier(&fixture, "sessionClientInstance"),
                challenge: challenge(&fixture, "clientChallenge"),
            },
            "sessionHelloMessage",
        ),
        (
            AuthorizationHandshakeMessage::ServiceChallenge {
                service_public_key: public_key(&fixture, "servicePublicKey"),
                challenge: challenge(&fixture, "serviceChallenge"),
            },
            "serviceChallengeMessage",
        ),
        (
            AuthorizationHandshakeMessage::ServiceReject {
                signature: signature(&fixture, "sessionAcceptance"),
            },
            "sessionRejectMessage",
        ),
    ];
    for (message, field_name) in messages {
        let expected = hex(&fixture, field_name);
        assert_eq!(message.encode(), expected);
        assert_eq!(
            AuthorizationHandshakeMessage::decode(&expected).unwrap(),
            message
        );
    }
}

fn transcripts(document: &str) -> (AuthorizationTranscript, AuthorizationTranscript) {
    let grant = fixture_grant(document);
    let client_challenge = challenge(document, "clientChallenge");
    let service_challenge = challenge(document, "serviceChallenge");
    let service_key = public_key(document, "servicePublicKey");
    (
        AuthorizationTranscript::new(
            AuthorizationBinding::Issuer {
                issuer_key_id: grant.issuer_key_id(),
                issuer_key_version: grant.issuer_key_version(),
                issuer_public_key: public_key(document, "issuerPublicKey"),
                client_instance: identifier(document, "issuerClientInstance"),
                harness: HarnessKind::Copilot,
            },
            client_challenge,
            service_challenge,
            service_key,
        ),
        AuthorizationTranscript::new(
            AuthorizationBinding::Session {
                grant,
                client_instance: identifier(document, "sessionClientInstance"),
            },
            client_challenge,
            service_challenge,
            service_key,
        ),
    )
}

fn fixture_grant(document: &str) -> SessionGrant {
    SessionGrant::new(SessionGrantClaims {
        grant_id: SessionGrantId::from_slice(&hex(document, "grantId")).unwrap(),
        issuer_key_id: AdapterKeyId::from_slice(&hex(document, "issuerKeyId")).unwrap(),
        issuer_key_version: AdapterKeyVersion::new(
            u32::try_from(number(document, "issuerKeyVersion")).unwrap(),
        )
        .unwrap(),
        profile: ServiceProfileId::parse(&field(document, "profile")).unwrap(),
        session_public_key: public_key(document, "sessionPublicKey"),
        harness: HarnessKind::Copilot,
        evidence: AuthorizationEvidenceSet::from_bits(
            u8::try_from(number(document, "evidenceBits")).unwrap(),
        )
        .unwrap(),
        policy_version: AuthorizationPolicyVersion::new(number(document, "policyVersion")).unwrap(),
        issued_at_unix_milliseconds: number(document, "issuedAtUnixMilliseconds"),
        expires_at_unix_milliseconds: number(document, "expiresAtUnixMilliseconds"),
        capabilities: SessionCapabilities::from_bits(number(document, "capabilityBits")).unwrap(),
    })
    .unwrap()
}

fn load_fixture() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/local-service/v2/authorization-transcript.json");
    std::fs::read_to_string(path).unwrap()
}

fn field(document: &str, name: &str) -> String {
    let key = format!("\"{name}\":");
    let rest = document[document.find(&key).unwrap() + key.len()..].trim_start();
    if let Some(quoted) = rest.strip_prefix('"') {
        quoted.split('"').next().unwrap().to_string()
    } else {
        rest.split([',', '\n']).next().unwrap().trim().to_string()
    }
}

fn number(document: &str, name: &str) -> u64 {
    field(document, name).parse().unwrap()
}

fn hex(document: &str, name: &str) -> Vec<u8> {
    let value = field(document, name);
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
        .collect()
}

fn public_key(document: &str, name: &str) -> Ed25519PublicKey {
    Ed25519PublicKey::from_slice(&hex(document, name)).unwrap()
}

fn signature(document: &str, name: &str) -> Ed25519Signature {
    Ed25519Signature::from_slice(&hex(document, name)).unwrap()
}

fn identifier(document: &str, name: &str) -> ClientInstanceId {
    ClientInstanceId::from_slice(&hex(document, name)).unwrap()
}

fn challenge(document: &str, name: &str) -> LocalServiceChallenge {
    LocalServiceChallenge::from_bytes(hex(document, name).try_into().unwrap())
}
