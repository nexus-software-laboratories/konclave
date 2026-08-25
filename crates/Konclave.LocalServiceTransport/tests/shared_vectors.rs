//! Verifies the Rust implementation against the shared cross-language vectors.
//!
//! The fixture is the contract every local service client must satisfy, so this test
//! parses it as data rather than restating the expected bytes in Rust. A change that
//! alters the transcript layout, a signature domain, a message tag, or a bound fails
//! here before it can silently desynchronize a non-Rust client.

use std::path::PathBuf;

use KonclaveCryptographicCore::verify_local_service_signature;
use KonclaveDomainCore::{Ed25519PublicKey, Ed25519Signature};
use KonclaveLocalServiceTransport::{
    AdapterKeyId, AdapterKeyVersion, CHALLENGE_LENGTH, ClientInstanceId, HandshakeMessage,
    HarnessKind, LOCAL_SERVICE_PROTOCOL_VERSION, LocalServiceBinding, LocalServiceChallenge,
    LocalServiceErrorCode, LocalServiceRequest, LocalServiceResponse, LocalServiceTranscript,
    MAX_HANDSHAKE_FRAME_BYTES, MAX_OPERATION_LENGTH, MAX_PROFILE_ID_LENGTH, MAX_RPC_PAYLOAD_BYTES,
    OperationName, REQUEST_ID_LENGTH, RequestId, ServiceProfileId,
};

#[test]
fn the_declared_bounds_match_the_shared_fixture() {
    let fixture = load_fixture();
    assert_eq!(
        field(&fixture, "protocolVersion"),
        LOCAL_SERVICE_PROTOCOL_VERSION.to_string()
    );
    assert_eq!(
        field(&fixture, "maxHandshakeFrameBytes"),
        MAX_HANDSHAKE_FRAME_BYTES.to_string()
    );
    assert_eq!(
        field(&fixture, "maxOperationLength"),
        MAX_OPERATION_LENGTH.to_string()
    );
    assert_eq!(
        field(&fixture, "maxProfileIdLength"),
        MAX_PROFILE_ID_LENGTH.to_string()
    );
    assert_eq!(
        field(&fixture, "maxRpcPayloadBytes"),
        MAX_RPC_PAYLOAD_BYTES.to_string()
    );
    assert_eq!(
        field(&fixture, "requestIdLength"),
        REQUEST_ID_LENGTH.to_string()
    );
    assert_eq!(
        field(&fixture, "adapterKeyIdLength"),
        AdapterKeyId::LENGTH.to_string()
    );
    assert_eq!(
        field(&fixture, "clientInstanceLength"),
        ClientInstanceId::LENGTH.to_string()
    );
    assert_eq!(
        field(&fixture, "challengeLength"),
        CHALLENGE_LENGTH.to_string()
    );
    assert_eq!(
        field(&fixture, "harnessWireValue"),
        HarnessKind::Copilot.wire_value().to_string()
    );
    assert_eq!(field(&fixture, "harness"), HarnessKind::Copilot.as_str());
    assert_eq!(
        field(&fixture, "failureErrorCode"),
        LocalServiceErrorCode::Busy.as_str()
    );
    assert_eq!(
        field(&fixture, "failureErrorWireValue"),
        LocalServiceErrorCode::Busy.wire_value().to_string()
    );
}

#[test]
fn the_canonical_transcript_matches_the_shared_fixture() {
    let fixture = load_fixture();
    let transcript = fixture_transcript(&fixture);

    assert_eq!(
        transcript.encode(),
        hex(&fixture, "encodedTranscript"),
        "canonical transcript encoding drifted from the shared fixture"
    );
    assert_eq!(
        transcript.client_signing_message(),
        hex(&fixture, "clientSigningMessage"),
        "client signing message drifted from the shared fixture"
    );
    assert_eq!(
        transcript.service_signing_message(),
        hex(&fixture, "serviceSigningMessage"),
        "service signing message drifted from the shared fixture"
    );
    assert_eq!(
        &transcript.client_signing_message()[..32],
        field(&fixture, "clientSignatureDomain").as_bytes()
    );
    assert_eq!(
        &transcript.service_signing_message()[..32],
        field(&fixture, "serviceSignatureDomain").as_bytes()
    );
}

#[test]
fn both_role_separated_signatures_match_the_shared_fixture() {
    let fixture = load_fixture();
    let transcript = fixture_transcript(&fixture);
    verify_local_service_signature(
        Ed25519PublicKey::from_slice(&hex(&fixture, "clientPublicKey")).unwrap(),
        &transcript.client_signing_message(),
        &Ed25519Signature::from_slice(&hex(&fixture, "clientSignature")).unwrap(),
    )
    .unwrap();
    verify_local_service_signature(
        Ed25519PublicKey::from_slice(&hex(&fixture, "servicePublicKey")).unwrap(),
        &transcript.service_signing_message(),
        &Ed25519Signature::from_slice(&hex(&fixture, "serviceSignature")).unwrap(),
    )
    .unwrap();
}

#[test]
fn every_handshake_message_matches_the_shared_fixture() {
    let fixture = load_fixture();
    let expected = [
        (
            HandshakeMessage::ClientHello {
                version: LOCAL_SERVICE_PROTOCOL_VERSION,
                adapter_key_id: AdapterKeyId::from_slice(&hex(&fixture, "adapterKeyId")).unwrap(),
                adapter_key_version: AdapterKeyVersion::new(
                    field(&fixture, "adapterKeyVersion").parse().unwrap(),
                )
                .unwrap(),
                client_instance: ClientInstanceId::from_slice(&hex(&fixture, "clientInstance"))
                    .unwrap(),
                harness: HarnessKind::Copilot,
                profile: ServiceProfileId::parse(&field(&fixture, "profile")).unwrap(),
                challenge: challenge(&hex(&fixture, "clientChallenge")),
            },
            "clientHelloMessage",
        ),
        (
            HandshakeMessage::ServiceChallenge {
                service_public_key: Ed25519PublicKey::from_slice(&hex(
                    &fixture,
                    "servicePublicKey",
                ))
                .unwrap(),
                challenge: challenge(&hex(&fixture, "serviceChallenge")),
            },
            "serviceChallengeMessage",
        ),
        (
            HandshakeMessage::ClientAuth {
                signature: Ed25519Signature::from_slice(&hex(&fixture, "clientSignature")).unwrap(),
            },
            "clientAuthMessage",
        ),
        (
            HandshakeMessage::ServiceAccept {
                signature: Ed25519Signature::from_slice(&hex(&fixture, "serviceSignature"))
                    .unwrap(),
            },
            "serviceAcceptMessage",
        ),
    ];

    for (message, member) in expected {
        let encoded = hex(&fixture, member);
        assert_eq!(
            message.encode(),
            encoded,
            "{member} encoding drifted from the shared fixture"
        );
        assert_eq!(
            HandshakeMessage::decode(&encoded).unwrap(),
            message,
            "{member} does not decode back to its message"
        );
    }
}

#[test]
fn every_request_and_response_matches_the_shared_fixture() {
    let fixture = load_fixture();
    let request_id = RequestId::from_slice(&hex(&fixture, "requestId")).unwrap();
    let request = LocalServiceRequest::new(
        request_id,
        OperationName::parse(&field(&fixture, "operation")).unwrap(),
        hex(&fixture, "requestPayload"),
    )
    .unwrap();
    assert_eq!(
        request.encode(),
        hex(&fixture, "encodedRequest"),
        "request encoding drifted from the shared fixture"
    );
    assert_eq!(
        LocalServiceRequest::decode(&hex(&fixture, "encodedRequest")).unwrap(),
        request
    );

    let success =
        LocalServiceResponse::success(request_id, hex(&fixture, "successPayload")).unwrap();
    assert_eq!(
        success.encode().unwrap(),
        hex(&fixture, "encodedSuccessResponse"),
        "success response encoding drifted from the shared fixture"
    );
    assert_eq!(
        LocalServiceResponse::decode(&hex(&fixture, "encodedSuccessResponse")).unwrap(),
        success
    );

    let failure = LocalServiceResponse::failure(request_id, LocalServiceErrorCode::Busy);
    assert_eq!(
        failure.encode().unwrap(),
        hex(&fixture, "encodedFailureResponse"),
        "failure response encoding drifted from the shared fixture"
    );
    assert_eq!(
        LocalServiceResponse::decode(&hex(&fixture, "encodedFailureResponse")).unwrap(),
        failure
    );
}

fn fixture_transcript(fixture: &str) -> LocalServiceTranscript {
    LocalServiceTranscript::new(
        LocalServiceBinding::new(
            LOCAL_SERVICE_PROTOCOL_VERSION,
            AdapterKeyId::from_slice(&hex(fixture, "adapterKeyId")).unwrap(),
            AdapterKeyVersion::new(field(fixture, "adapterKeyVersion").parse().unwrap()).unwrap(),
            ClientInstanceId::from_slice(&hex(fixture, "clientInstance")).unwrap(),
            HarnessKind::Copilot,
            ServiceProfileId::parse(&field(fixture, "profile")).unwrap(),
        )
        .unwrap(),
        challenge(&hex(fixture, "clientChallenge")),
        challenge(&hex(fixture, "serviceChallenge")),
        Ed25519PublicKey::from_slice(&hex(fixture, "servicePublicKey")).unwrap(),
    )
}

fn load_fixture() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/local-service/v1/handshake-transcript.json");
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("missing fixture at {}: {error}", path.display()))
}

/// Reads one flat JSON member without adding a parser dependency to the test.
fn field(document: &str, name: &str) -> String {
    let key = format!("\"{name}\":");
    let start = document
        .find(&key)
        .unwrap_or_else(|| panic!("fixture has no member '{name}'"))
        + key.len();
    let rest = document[start..].trim_start();
    let value = if let Some(quoted) = rest.strip_prefix('"') {
        quoted
            .split('"')
            .next()
            .unwrap_or_else(|| panic!("member '{name}' is unterminated"))
    } else {
        rest.split([',', '\n'])
            .next()
            .unwrap_or_else(|| panic!("member '{name}' is unterminated"))
    };
    value.trim().to_string()
}

fn hex(document: &str, name: &str) -> Vec<u8> {
    let value = field(document, name);
    assert!(value.len() % 2 == 0, "member '{name}' is not hex");
    (0..value.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&value[index..index + 2], 16)
                .unwrap_or_else(|_| panic!("member '{name}' is not hex"))
        })
        .collect()
}

fn challenge(value: &[u8]) -> LocalServiceChallenge {
    let mut bytes = [0_u8; CHALLENGE_LENGTH];
    bytes.copy_from_slice(value);
    LocalServiceChallenge::from_bytes(bytes)
}
