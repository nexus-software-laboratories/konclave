//! Verifies the Rust implementation against the shared cross-language vectors.
//!
//! The fixture is the contract every adapter implementation must satisfy, so this
//! test parses it as data rather than restating the expected bytes in Rust. A change
//! that alters the transcript layout or a proof domain fails here before it can
//! silently desynchronize a non-Rust adapter.

use std::path::PathBuf;

use KonclaveAdapterTransport::{
    ADAPTER_PROTOCOL_VERSION, AuthChallenge, AuthTranscript, CHALLENGE_LENGTH, LaunchCapability,
};

#[test]
fn matches_the_shared_authentication_vectors() {
    let fixture = load_fixture();

    assert_eq!(
        field(&fixture, "protocolVersion"),
        ADAPTER_PROTOCOL_VERSION.to_string()
    );

    let capability = LaunchCapability::from_bytes(fixed_bytes(&hex(&fixture, "launchCapability")));
    let transcript = AuthTranscript::new(
        ADAPTER_PROTOCOL_VERSION,
        &string(&fixture, "profile"),
        &string(&fixture, "consumer"),
        AuthChallenge::from_bytes(challenge(&hex(&fixture, "adapterChallenge"))),
        AuthChallenge::from_bytes(challenge(&hex(&fixture, "daemonChallenge"))),
    )
    .unwrap();

    assert_eq!(
        transcript.encode(),
        hex(&fixture, "encodedTranscript"),
        "canonical transcript encoding drifted from the shared fixture"
    );
    assert_eq!(
        transcript.daemon_proof(&capability).unwrap().to_vec(),
        hex(&fixture, "daemonProof"),
        "daemon proof drifted from the shared fixture"
    );
    assert_eq!(
        transcript.adapter_proof(&capability).unwrap().to_vec(),
        hex(&fixture, "adapterProof"),
        "adapter proof drifted from the shared fixture"
    );

    transcript
        .verify_daemon_proof(&capability, &hex(&fixture, "daemonProof"))
        .unwrap();
    transcript
        .verify_adapter_proof(&capability, &hex(&fixture, "adapterProof"))
        .unwrap();
}

fn load_fixture() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/adapter/v1/auth-transcript.json");
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

fn string(document: &str, name: &str) -> String {
    field(document, name)
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

fn fixed_bytes(value: &[u8]) -> [u8; LaunchCapability::LENGTH] {
    let mut bytes = [0_u8; LaunchCapability::LENGTH];
    bytes.copy_from_slice(value);
    bytes
}

fn challenge(value: &[u8]) -> [u8; CHALLENGE_LENGTH] {
    let mut bytes = [0_u8; CHALLENGE_LENGTH];
    bytes.copy_from_slice(value);
    bytes
}
