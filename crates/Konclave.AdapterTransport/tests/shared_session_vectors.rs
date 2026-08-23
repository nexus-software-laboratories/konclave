//! Pins the Rust session codec to the shared cross-language vectors.
//!
//! The TypeScript adapter decodes these exact bytes. Reading the fixture as data
//! rather than restating it here means a layout change fails on both sides instead of
//! silently desynchronizing one of them.

use std::path::PathBuf;

use KonclaveAdapterTransport::{
    AdapterRequest, AdapterResponse, AdapterStatus, DeliveredPayload, MAX_CLAIM_BATCH,
    MAX_EVENT_TEXT_BYTES, MAX_WAIT_MILLISECONDS, NOTIFICATION_ID_LENGTH, ROUTED_ID_LENGTH,
};

#[test]
fn requests_match_the_shared_session_vectors() {
    let fixture = load();

    assert_eq!(
        AdapterRequest::WaitAndClaim {
            max_events: 10,
            wait_milliseconds: 5_000,
        }
        .encode(),
        hex(&fixture, "\"waitAndClaim\"", "encoded")
    );
    assert_eq!(
        AdapterRequest::Acknowledge {
            notification_id: [4_u8; NOTIFICATION_ID_LENGTH],
            lease_generation: 3,
        }
        .encode(),
        hex(&fixture, "\"acknowledge\"", "encoded")
    );
    assert_eq!(
        AdapterRequest::Release {
            notification_id: [5_u8; NOTIFICATION_ID_LENGTH],
            lease_generation: 4,
        }
        .encode(),
        hex(&fixture, "\"release\"", "encoded")
    );
    assert_eq!(
        AdapterRequest::Status.encode(),
        hex(section(&fixture, "\"requests\""), "\"status\"", "encoded")
    );
}

/// Returns the document from the start of `anchor` onward.
fn section<'a>(document: &'a str, anchor: &str) -> &'a str {
    let start = document
        .find(anchor)
        .unwrap_or_else(|| panic!("fixture has no section {anchor}"));
    &document[start..]
}

#[test]
fn responses_match_the_shared_session_vectors() {
    let fixture = load();
    // Both sections declare a "status" member, so response lookups are anchored to
    // the responses object rather than matching the first occurrence in the file.
    let responses = section(&fixture, "\"responses\"");

    assert_eq!(
        AdapterResponse::Accepted.encode().unwrap(),
        hex(responses, "\"accepted\"", "encoded")
    );
    assert_eq!(
        AdapterResponse::Batch(Vec::new()).encode().unwrap(),
        hex(responses, "\"emptyBatch\"", "encoded")
    );
    assert_eq!(
        AdapterResponse::Failure {
            code: "adapter_stale_lease".to_string(),
        }
        .encode()
        .unwrap(),
        hex(responses, "\"failure\"", "encoded")
    );
    assert_eq!(
        AdapterResponse::Status(AdapterStatus {
            pending_events: 3,
            claimed_events: 1,
            watched_conversations: 2,
            delivery_degraded: true,
        })
        .encode()
        .unwrap(),
        hex(responses, "\"status\"", "encoded")
    );
}

#[test]
fn every_event_kind_matches_the_shared_batch_vector() {
    let fixture = load();
    let event = |payload| KonclaveAdapterTransport::DeliveredEvent {
        notification_id: [1_u8; NOTIFICATION_ID_LENGTH],
        lease_generation: 7,
        sequence: 42,
        conversation: [2_u8; ROUTED_ID_LENGTH],
        sender: [3_u8; ROUTED_ID_LENGTH],
        relay_cursor: 9,
        payload,
    };

    let batch = AdapterResponse::Batch(vec![
        event(DeliveredPayload::ApplicationText("hello".to_string())),
        event(DeliveredPayload::MemberAdded {
            device: [6_u8; ROUTED_ID_LENGTH],
            role: KonclaveAdapterTransport::DeliveredRole::Administrator,
        }),
        event(DeliveredPayload::MemberRemoved {
            device: [7_u8; ROUTED_ID_LENGTH],
        }),
        event(DeliveredPayload::MemberRoleChanged {
            device: [8_u8; ROUTED_ID_LENGTH],
            role: KonclaveAdapterTransport::DeliveredRole::Member,
        }),
        event(DeliveredPayload::LocalAccessRemoved {
            device: [9_u8; ROUTED_ID_LENGTH],
        }),
    ]);

    assert_eq!(
        batch.encode().unwrap(),
        hex(section(&fixture, "\"responses\""), "\"batch\"", "encoded")
    );
}

#[test]
fn handshake_messages_match_the_shared_vectors() {
    use KonclaveAdapterTransport::{
        ADAPTER_PROTOCOL_VERSION, AuthChallenge, CHALLENGE_LENGTH, HandshakeMessage,
    };

    let fixture = load();
    let handshake = section(&fixture, "\"handshake\"");

    assert_eq!(
        HandshakeMessage::AdapterHello {
            version: ADAPTER_PROTOCOL_VERSION,
            consumer: "01HQ8Z3K".to_string(),
            challenge: AuthChallenge::from_bytes([1_u8; CHALLENGE_LENGTH]),
        }
        .encode(),
        hex(handshake, "\"adapterHello\"", "encoded")
    );
    assert_eq!(
        HandshakeMessage::DaemonAuth {
            profile: "alice".to_string(),
            challenge: AuthChallenge::from_bytes([2_u8; CHALLENGE_LENGTH]),
            proof: [3_u8; CHALLENGE_LENGTH],
        }
        .encode(),
        hex(handshake, "\"daemonAuth\"", "encoded")
    );
    assert_eq!(
        HandshakeMessage::AdapterAuth {
            proof: [4_u8; CHALLENGE_LENGTH],
        }
        .encode(),
        hex(handshake, "\"adapterAuth\"", "encoded")
    );
}

#[test]
fn bounds_match_the_shared_session_vectors() {
    let fixture = load();
    assert_eq!(
        number(&fixture, "maxClaimBatch"),
        u64::from(MAX_CLAIM_BATCH)
    );
    assert_eq!(
        number(&fixture, "maxWaitMilliseconds"),
        u64::from(MAX_WAIT_MILLISECONDS)
    );
    assert_eq!(
        number(&fixture, "maxEventTextBytes"),
        MAX_EVENT_TEXT_BYTES as u64
    );
    assert_eq!(
        number(&fixture, "notificationIdLength"),
        NOTIFICATION_ID_LENGTH as u64
    );
    assert_eq!(number(&fixture, "routedIdLength"), ROUTED_ID_LENGTH as u64);
}

fn load() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/adapter/v1/session-operations.json");
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("missing fixture at {}: {error}", path.display()))
}

/// Reads the first `member` that appears after `section`.
///
/// The fixture nests each vector under a named section, and a full parser would add a
/// dependency this crate does not otherwise need.
fn hex(document: &str, section: &str, member: &str) -> Vec<u8> {
    let start = document
        .find(section)
        .unwrap_or_else(|| panic!("fixture has no section {section}"));
    let key = format!("\"{member}\":");
    let value_start = document[start..]
        .find(&key)
        .unwrap_or_else(|| panic!("section {section} has no member '{member}'"))
        + start
        + key.len();
    let rest = document[value_start..].trim_start();
    let value = rest
        .strip_prefix('"')
        .and_then(|quoted| quoted.split('"').next())
        .unwrap_or_else(|| panic!("member '{member}' is not a string"));
    assert!(value.len() % 2 == 0, "member '{member}' is not hex");
    (0..value.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&value[index..index + 2], 16)
                .unwrap_or_else(|_| panic!("member '{member}' is not hex"))
        })
        .collect()
}

fn number(document: &str, member: &str) -> u64 {
    let key = format!("\"{member}\":");
    let start = document
        .find(&key)
        .unwrap_or_else(|| panic!("fixture has no member '{member}'"))
        + key.len();
    document[start..]
        .trim_start()
        .split([',', '\n', '}'])
        .next()
        .and_then(|value| value.trim().parse().ok())
        .unwrap_or_else(|| panic!("member '{member}' is not a number"))
}
