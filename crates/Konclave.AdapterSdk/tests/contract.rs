use std::collections::VecDeque;
use std::time::Duration;

use KonclaveAdapterSdk::{
    ADAPTER_SDK_VERSION, AdapterRequestId, AdapterRpc, AdapterSdkError, AdapterSession,
    AdapterStatus, CollaborationTurnClaim, DeliveredPayload, DeliveredPolicyResponseOutcome,
    DeliveredRole, DeliverySettlement, MAX_CLAIM_BATCH, MAX_EVENT_TEXT_BYTES,
    MAX_WAIT_MILLISECONDS, RECOMMENDED_HEARTBEAT_INTERVAL,
};
use KonclaveLocalServiceTransport::decode_lowercase_hex;
use async_trait::async_trait;
use serde_json::{Value, json};

struct RecordingRpc {
    responses: VecDeque<(&'static str, Vec<u8>)>,
    requests: Vec<(&'static str, Value)>,
}

#[async_trait]
impl AdapterRpc for RecordingRpc {
    async fn request(
        &mut self,
        _request_id: AdapterRequestId,
        operation: &'static str,
        payload: Vec<u8>,
    ) -> Result<Vec<u8>, AdapterSdkError> {
        self.requests
            .push((operation, serde_json::from_slice(&payload).unwrap()));
        let (expected, response) = self.responses.pop_front().unwrap();
        assert_eq!(operation, expected);
        Ok(response)
    }
}

struct FailingRpc(AdapterSdkError);

#[async_trait]
impl AdapterRpc for FailingRpc {
    async fn request(
        &mut self,
        _request_id: AdapterRequestId,
        _operation: &'static str,
        _payload: Vec<u8>,
    ) -> Result<Vec<u8>, AdapterSdkError> {
        Err(self.0)
    }
}

#[tokio::test]
async fn fixture_defines_the_complete_versioned_delivery_contract() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../fixtures/local-service/v1/adapter-delivery.json"
    ))
    .unwrap();
    assert_eq!(
        fixture["adapterApiVersion"].as_u64(),
        Some(u64::from(ADAPTER_SDK_VERSION))
    );
    assert_eq!(
        fixture["limits"]["maxClaimBatch"].as_u64(),
        Some(u64::from(MAX_CLAIM_BATCH))
    );
    assert_eq!(
        fixture["limits"]["maxWaitMilliseconds"].as_u64(),
        Some(u64::from(MAX_WAIT_MILLISECONDS))
    );
    assert_eq!(
        fixture["limits"]["maxEventTextBytes"].as_u64(),
        Some(u64::try_from(MAX_EVENT_TEXT_BYTES).unwrap())
    );
    assert_eq!(
        fixture["limits"]["recommendedHeartbeatMilliseconds"].as_u64(),
        Some(u64::try_from(RECOMMENDED_HEARTBEAT_INTERVAL.as_millis()).unwrap())
    );

    let responses = VecDeque::from([
        (
            "delivery.claim",
            serde_json::to_vec(&fixture["claim"]["response"]).unwrap(),
        ),
        ("delivery.acknowledge", b"{}".to_vec()),
        ("delivery.release", b"{}".to_vec()),
        ("delivery.heartbeat", b"{}".to_vec()),
        (
            "service.status",
            serde_json::to_vec(&fixture["status"]["response"]).unwrap(),
        ),
    ]);
    let mut session = AdapterSession::new(RecordingRpc {
        responses,
        requests: Vec::new(),
    });
    let events = session
        .claim(
            AdapterRequestId::from_bytes([1; 16]),
            9,
            Duration::from_secs(30),
        )
        .await
        .unwrap();
    assert_eq!(events.len(), 9);
    assert!(matches!(
        events[0].payload(),
        DeliveredPayload::ApplicationText { .. }
    ));
    assert!(matches!(
        events[1].payload(),
        DeliveredPayload::DirectedRequest { .. }
    ));
    assert!(matches!(
        events[2].payload(),
        DeliveredPayload::CollaborationPolicyProposal { .. }
    ));
    assert!(matches!(
        events[3].payload(),
        DeliveredPayload::CollaborationPolicyResponse {
            outcome: DeliveredPolicyResponseOutcome::Accepted,
            ..
        }
    ));
    assert!(matches!(
        events[4].payload(),
        DeliveredPayload::CollaborationPolicyRevocation { .. }
    ));
    assert!(matches!(
        events[5].payload(),
        DeliveredPayload::MemberAdded {
            role: DeliveredRole::Administrator,
            ..
        }
    ));
    assert!(matches!(
        events[6].payload(),
        DeliveredPayload::MemberRemoved { .. }
    ));
    assert!(matches!(
        events[7].payload(),
        DeliveredPayload::MemberRoleChanged {
            role: DeliveredRole::Member,
            ..
        }
    ));
    assert!(matches!(
        events[8].payload(),
        DeliveredPayload::LocalAccessRemoved { .. }
    ));

    let settlement = DeliverySettlement::from_event(&events[0]);
    session
        .acknowledge(AdapterRequestId::from_bytes([2; 16]), settlement)
        .await
        .unwrap();
    session
        .release(AdapterRequestId::from_bytes([3; 16]), settlement)
        .await
        .unwrap();
    let turn = CollaborationTurnClaim::new(
        decode_lowercase_hex("101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f")
            .unwrap(),
        decode_lowercase_hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
            .unwrap(),
        decode_lowercase_hex("515152535455565758595a5b5c5d5e5f").unwrap(),
        2,
    )
    .unwrap();
    session
        .heartbeat(AdapterRequestId::from_bytes([4; 16]), Some(turn))
        .await
        .unwrap();
    assert_eq!(
        session
            .status(AdapterRequestId::from_bytes([5; 16]))
            .await
            .unwrap(),
        AdapterStatus {
            pending_events: 3,
            claimed_events: 1,
            watched_conversations: 2,
            delivery_degraded: false,
        }
    );

    let rpc = session.into_inner();
    let expected = [
        ("delivery.claim", &fixture["claim"]["request"]),
        ("delivery.acknowledge", &fixture["acknowledge"]["request"]),
        ("delivery.release", &fixture["release"]["request"]),
        ("delivery.heartbeat", &fixture["heartbeat"]["request"]),
        ("service.status", &fixture["status"]["request"]),
    ];
    for ((operation, actual), (expected_operation, expected_payload)) in
        rpc.requests.iter().zip(expected)
    {
        assert_eq!(operation, &expected_operation);
        assert_eq!(actual, expected_payload);
    }
}

#[tokio::test]
async fn invalid_claim_and_turn_bounds_fail_before_transport() {
    assert!(CollaborationTurnClaim::new([0; 32], [0; 32], [0; 16], 0).is_err());
    let mut session = AdapterSession::new(RecordingRpc {
        responses: VecDeque::new(),
        requests: Vec::new(),
    });
    for outcome in [
        session
            .claim(AdapterRequestId::from_bytes([1; 16]), 0, Duration::ZERO)
            .await,
        session
            .claim(
                AdapterRequestId::from_bytes([2; 16]),
                MAX_CLAIM_BATCH + 1,
                Duration::ZERO,
            )
            .await,
        session
            .claim(
                AdapterRequestId::from_bytes([3; 16]),
                1,
                Duration::from_millis(u64::from(MAX_WAIT_MILLISECONDS) + 1),
            )
            .await,
        session
            .claim(
                AdapterRequestId::from_bytes([4; 16]),
                1,
                Duration::from_nanos(1),
            )
            .await,
    ] {
        assert!(matches!(
            outcome,
            Err(AdapterSdkError::InvalidConfiguration)
        ));
    }
    assert!(session.into_inner().requests.is_empty());
}

#[tokio::test]
async fn ambiguous_claim_transport_outcomes_require_a_fresh_request() {
    for error in [
        AdapterSdkError::Transport,
        AdapterSdkError::DeadlineExceeded,
    ] {
        let mut session = AdapterSession::new(FailingRpc(error));
        assert!(matches!(
            session
                .claim(AdapterRequestId::from_bytes([8; 16]), 1, Duration::ZERO)
                .await,
            Err(AdapterSdkError::ClaimOutcomeUnknown)
        ));
    }
}

#[test]
fn fixture_operation_names_remain_harness_neutral() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../fixtures/local-service/v1/adapter-delivery.json"
    ))
    .unwrap();
    let text = serde_json::to_string(&fixture["operations"]).unwrap();
    for forbidden in ["copilot", "claude", "codex", "prompt", "model"] {
        assert!(!text.contains(forbidden));
    }
    assert_eq!(
        fixture["lifecycle"]["ambiguousClaimRecovery"],
        json!(
            "After a claim transport failure or deadline, discard the session, reconnect, and claim with a fresh request identifier so returned lease generations belong to the replacement connection."
        )
    );
    assert_eq!(
        fixture["lifecycle"]["pollingFallback"],
        json!(
            "Polling skills are best effort and must use finite waits; they do not claim native lifecycle or wakeup guarantees."
        )
    );
}
