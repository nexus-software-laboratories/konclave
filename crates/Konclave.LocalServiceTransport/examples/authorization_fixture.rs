use KonclaveCryptographicCore::{LocalServiceIdentity, LocalServiceSigningSeed};
use KonclaveLocalServiceTransport::{
    AdapterKeyId, AdapterKeyVersion, AuthorizationBinding, AuthorizationEvidenceKind,
    AuthorizationEvidenceSet, AuthorizationHandshakeMessage, AuthorizationPolicyVersion,
    AuthorizationTranscript, ClientInstanceId, HarnessKind, LocalServiceChallenge,
    SessionCapabilities, SessionGrant, SessionGrantClaims, SessionGrantId,
};
use serde_json::json;

fn main() {
    let issuer = identity(0);
    let service = identity(32);
    let session = identity(64);
    let issuer_binding = AuthorizationBinding::Issuer {
        issuer_key_id: AdapterKeyId::from_bytes(sequence(0)),
        issuer_key_version: AdapterKeyVersion::new(3).unwrap(),
        issuer_public_key: issuer.public_key(),
        client_instance: ClientInstanceId::from_bytes(sequence(16)),
        harness: HarnessKind::Copilot,
    };
    let grant = SessionGrant::new(SessionGrantClaims {
        grant_id: SessionGrantId::from_bytes(sequence(128)),
        issuer_key_id: AdapterKeyId::from_bytes(sequence(0)),
        issuer_key_version: AdapterKeyVersion::new(3).unwrap(),
        profile: KonclaveLocalServiceTransport::ServiceProfileId::parse("session-a").unwrap(),
        session_public_key: session.public_key(),
        harness: HarnessKind::Copilot,
        evidence: AuthorizationEvidenceSet::new([AuthorizationEvidenceKind::AccountTrusted])
            .unwrap(),
        policy_version: AuthorizationPolicyVersion::new(1).unwrap(),
        issued_at_unix_milliseconds: 1_000,
        expires_at_unix_milliseconds: 2_000,
        capabilities: SessionCapabilities::ALL,
    })
    .unwrap();
    let session_binding = AuthorizationBinding::Session {
        grant: grant.clone(),
        client_instance: ClientInstanceId::from_bytes(sequence(96)),
    };
    let client_challenge = LocalServiceChallenge::from_bytes(sequence(32));
    let service_challenge = LocalServiceChallenge::from_bytes(sequence(160));
    let issuer_transcript = AuthorizationTranscript::new(
        issuer_binding,
        client_challenge,
        service_challenge,
        service.public_key(),
    );
    let session_transcript = AuthorizationTranscript::new(
        session_binding,
        client_challenge,
        service_challenge,
        service.public_key(),
    );
    let issuer_signature = issuer_transcript.sign_as_client(&issuer).unwrap();
    let session_signature = session_transcript.sign_as_client(&session).unwrap();
    let issuer_acceptance = issuer_transcript.sign_as_service(&service).unwrap();
    let session_acceptance = session_transcript.sign_as_service(&service).unwrap();

    let document = json!({
        "$comment": "Canonical protocol-v2 local authorization vectors. Hex values are lowercase.",
        "schemaVersion": 2,
        "protocolVersion": 2,
        "issuerKeyId": hex(sequence::<16>(0)),
        "issuerKeyVersion": 3,
        "issuerPublicKey": hex(issuer.public_key().as_bytes()),
        "sessionPublicKey": hex(session.public_key().as_bytes()),
        "servicePublicKey": hex(service.public_key().as_bytes()),
        "issuerClientInstance": hex(sequence::<16>(16)),
        "sessionClientInstance": hex(sequence::<16>(96)),
        "harness": "copilot",
        "harnessWireValue": 1,
        "profile": "session-a",
        "grantId": hex(grant.grant_id().as_bytes()),
        "evidenceBits": grant.evidence().bits(),
        "policyVersion": grant.policy_version().get(),
        "issuedAtUnixMilliseconds": grant.issued_at_unix_milliseconds(),
        "expiresAtUnixMilliseconds": grant.expires_at_unix_milliseconds(),
        "capabilityBits": grant.capabilities().bits(),
        "clientChallenge": hex(client_challenge.as_bytes()),
        "serviceChallenge": hex(service_challenge.as_bytes()),
        "issuerTranscript": hex(issuer_transcript.encode()),
        "sessionTranscript": hex(session_transcript.encode()),
        "issuerClientSigningMessage": hex(issuer_transcript.client_signing_message()),
        "sessionClientSigningMessage": hex(session_transcript.client_signing_message()),
        "issuerServiceSigningMessage": hex(issuer_transcript.service_signing_message()),
        "sessionServiceSigningMessage": hex(session_transcript.service_signing_message()),
        "issuerSignature": hex(issuer_signature.as_bytes()),
        "sessionSignature": hex(session_signature.as_bytes()),
        "issuerAcceptance": hex(issuer_acceptance.as_bytes()),
        "sessionAcceptance": hex(session_acceptance.as_bytes()),
        "issuerHelloMessage": hex(AuthorizationHandshakeMessage::IssuerHello {
            version: 2,
            issuer_key_id: grant.issuer_key_id(),
            issuer_key_version: grant.issuer_key_version(),
            issuer_public_key: issuer.public_key(),
            client_instance: ClientInstanceId::from_bytes(sequence(16)),
            harness: HarnessKind::Copilot,
            challenge: client_challenge,
        }.encode()),
        "sessionHelloMessage": hex(AuthorizationHandshakeMessage::SessionHello {
            version: 2,
            grant,
            client_instance: ClientInstanceId::from_bytes(sequence(96)),
            challenge: client_challenge,
        }.encode()),
        "serviceChallengeMessage": hex(AuthorizationHandshakeMessage::ServiceChallenge {
            service_public_key: service.public_key(),
            challenge: service_challenge,
        }.encode()),
        "issuerAuthMessage": hex(AuthorizationHandshakeMessage::ClientAuth {
            signature: issuer_signature,
        }.encode()),
        "sessionAuthMessage": hex(AuthorizationHandshakeMessage::ClientAuth {
            signature: session_signature,
        }.encode()),
        "issuerAcceptMessage": hex(AuthorizationHandshakeMessage::ServiceAccept {
            signature: issuer_acceptance,
        }.encode()),
        "sessionAcceptMessage": hex(AuthorizationHandshakeMessage::ServiceAccept {
            signature: session_acceptance,
        }.encode()),
        "sessionRejectMessage": hex(AuthorizationHandshakeMessage::ServiceReject {
            signature: session_acceptance,
        }.encode()),
        "clientSignatureDomain": "konclave.local-service.v2.client",
        "serviceSignatureDomain": "konclave.local-service.v2.accept"
    });
    println!("{}", serde_json::to_string_pretty(&document).unwrap());
}

fn identity(start: u8) -> LocalServiceIdentity {
    let seed = LocalServiceSigningSeed::from_reader(sequence::<32>(start).as_slice()).unwrap();
    LocalServiceIdentity::from_signing_seed(&seed).unwrap()
}

fn sequence<const N: usize>(start: u8) -> [u8; N] {
    std::array::from_fn(|index| start.wrapping_add(u8::try_from(index).unwrap()))
}

fn hex(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
