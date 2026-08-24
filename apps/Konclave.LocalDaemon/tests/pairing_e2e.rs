//! Proves two real daemons pair from one capability without manual protocol transfer.

#![cfg(unix)]

mod support;

use KonclaveAdapterTransport::{AdapterRequest, AdapterResponse, DeliveredPayload};
use serde_json::{Value, json};
use support::{AdapterHost, DaemonClient, DaemonFixture, text_of};
use tokio::time::{Duration, sleep};
use zeroize::Zeroizing;

const PAIRING_POLL_ATTEMPTS: usize = 80;
const PAIRING_POLL_INTERVAL: Duration = Duration::from_millis(250);
const CLAIM_WAIT_MILLISECONDS: u32 = 15_000;

async fn await_pairing_phase(
    client: &DaemonClient,
    pairing_id: &str,
    expected_phase: &str,
) -> Value {
    for _ in 0..PAIRING_POLL_ATTEMPTS {
        let status = client
            .require("get_pairing_status", json!({"pairing_id": pairing_id}))
            .await;
        if status["phase"] == expected_phase {
            return status;
        }
        sleep(PAIRING_POLL_INTERVAL).await;
    }
    panic!(
        "pairing {pairing_id} never reached {expected_phase}; diagnostics: {}",
        client.diagnostics()
    );
}

fn assert_high_level_contract(value: &Value) {
    for forbidden in [
        "invitation",
        "join_proof",
        "welcome",
        "cursor",
        "routing_id",
        "peer_bindings",
        "issuer_public_key",
    ] {
        assert!(
            value.get(forbidden).is_none(),
            "pairing result exposed raw field {forbidden}"
        );
    }
}

#[tokio::test]
async fn one_capability_pairs_real_daemons_and_enables_automatic_delivery() {
    let fixture = DaemonFixture::start("pairing-e2e").await;
    let bob_host = AdapterHost::new("bob", 31, 31);
    let alice = fixture.connect("alice", None).await;
    let bob = fixture.connect("bob", Some(&bob_host)).await;
    let mut bob_session = bob_host.accept().await;
    let alice_identity = alice.require("get_identity", Value::Null).await;
    let bob_identity = bob.require("get_identity", Value::Null).await;

    let created_pairing = bob
        .require(
            "create_pairing_capability",
            json!({"requested_role": "member"}),
        )
        .await;
    let pairing_id = created_pairing["pairing"]["pairing_id"]
        .as_str()
        .unwrap()
        .to_string();
    let capability = Zeroizing::new(created_pairing["capability"].as_str().unwrap().to_string());
    assert_high_level_contract(&created_pairing["pairing"]);

    let redeemed = alice
        .require(
            "redeem_pairing_capability",
            json!({"capability": capability.as_str()}),
        )
        .await;
    assert_eq!(redeemed["pairing_id"], pairing_id);
    assert_eq!(redeemed["joiner_device_id"], bob_identity["device_id"]);
    assert_eq!(redeemed["requested_role"], "member");
    assert_high_level_contract(&redeemed);

    let conversation = alice.require("create_conversation", Value::Null).await;
    let conversation_id = conversation["conversation_id"]
        .as_str()
        .unwrap()
        .to_string();
    alice
        .require(
            "authorize_pairing_joiner",
            json!({
                "pairing_id": pairing_id,
                "conversation_id": conversation_id,
                "granted_role": "member"
            }),
        )
        .await;

    let awaiting_authorization =
        await_pairing_phase(&bob, &pairing_id, "joiner_awaiting_inviter_authorization").await;
    assert_eq!(
        awaiting_authorization["inviter_device_id"],
        alice_identity["device_id"]
    );
    assert_eq!(awaiting_authorization["conversation_id"], conversation_id);
    assert_eq!(awaiting_authorization["granted_role"], "member");
    assert_high_level_contract(&awaiting_authorization);
    bob.require(
        "authorize_pairing_inviter",
        json!({
            "pairing_id": pairing_id,
            "inviter_device_id": awaiting_authorization["inviter_device_id"],
            "conversation_id": awaiting_authorization["conversation_id"],
            "granted_role": awaiting_authorization["granted_role"]
        }),
    )
    .await;

    let bob_completed = await_pairing_phase(&bob, &pairing_id, "completed").await;
    let alice_completed = await_pairing_phase(&alice, &pairing_id, "completed").await;
    assert_eq!(bob_completed["conversation_id"], conversation_id);
    assert_eq!(alice_completed["conversation_id"], conversation_id);

    alice
        .send(
            &conversation_id,
            "31313131313131313131313131313131",
            "the contract is aligned",
        )
        .await;
    let delivered = bob_session.claim(4, CLAIM_WAIT_MILLISECONDS).await;
    let message = delivered
        .iter()
        .find(|event| matches!(event.payload, DeliveredPayload::ApplicationText(_)))
        .expect("the paired session must receive a message automatically");
    assert_eq!(text_of(&message.payload), "the contract is aligned");
    assert_eq!(
        bob_session
            .request(&AdapterRequest::Acknowledge {
                notification_id: message.notification_id,
                lease_generation: message.lease_generation,
            })
            .await,
        AdapterResponse::Accepted
    );

    assert!(!alice.diagnostics().contains(capability.as_str()));
    assert!(!bob.diagnostics().contains(capability.as_str()));
    bob.close().await;
    alice.close().await;
    fixture
        .relay()
        .assert_opaque(&[capability.as_bytes(), b"the contract is aligned"]);
    fixture.stop().await;
}
