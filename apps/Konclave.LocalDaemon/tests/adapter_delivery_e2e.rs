//! Proves automatic delivery reaches a second session without a manual sync prompt.
//!
//! The other end-to-end suite drives synchronization explicitly, which is the wrong
//! shape for the property that matters here: a session must receive a peer's message
//! because the daemon delivered it, not because something told the session to look.
//! These tests therefore never call `sync_messages` on the receiving side.

#![cfg(unix)]

mod support;

use KonclaveAdapterTransport::{
    AdapterRequest, AdapterResponse, AdapterTransportError, DeliveredPayload,
};
use serde_json::{Value, json};
use support::{AdapterHost, DaemonClient, DaemonFixture, join_conversation, text_of};

/// How long a claim waits before reporting an empty batch.
///
/// Long enough to cover relay round trip plus the daemon's claim poll interval, so an
/// empty batch means nothing was deliverable rather than that the test was impatient.
const CLAIM_WAIT_MILLISECONDS: u32 = 15_000;

/// How long a claim waits when the test expects nothing to arrive.
///
/// Kept short because proving absence costs the full budget every time.
const SILENCE_WAIT_MILLISECONDS: u32 = 1_500;

async fn set_delivery(client: &DaemonClient, conversation_id: &str, enabled: bool) {
    let status = client
        .require(
            "set_auto_delivery",
            json!({"conversation_id": conversation_id, "enabled": enabled}),
        )
        .await;
    assert_eq!(status["auto_delivery_enabled"].as_bool(), Some(enabled));
}

#[tokio::test]
async fn two_sessions_exchange_a_contract_change_without_a_sync_prompt() {
    let fixture = DaemonFixture::start("auto-delivery").await;
    let alice_host = AdapterHost::new("alice", 21, 21);
    let bob_host = AdapterHost::new("bob", 22, 22);
    let alice = fixture.connect("alice", Some(&alice_host)).await;
    let bob = fixture.connect("bob", Some(&bob_host)).await;
    let mut alice_session = alice_host.accept().await;
    let mut bob_session = bob_host.accept().await;

    // Neither side opts in. Creating and joining already asked for these messages, so
    // a configuration step here would be a step a real session could forget.
    let conversation_id = join_conversation(&alice, &bob).await;

    alice
        .send(
            &conversation_id,
            "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a",
            "the response now returns a nullable cursor",
        )
        .await;

    let delivered = bob_session.claim(4, CLAIM_WAIT_MILLISECONDS).await;
    let contract_change = delivered
        .iter()
        .find(|event| matches!(event.payload, DeliveredPayload::ApplicationText(_)))
        .expect("a contract change must reach the receiving session automatically");
    assert_eq!(
        text_of(&contract_change.payload),
        "the response now returns a nullable cursor"
    );
    assert_eq!(
        bob_session
            .request(&AdapterRequest::Acknowledge {
                notification_id: contract_change.notification_id,
                lease_generation: contract_change.lease_generation,
            })
            .await,
        AdapterResponse::Accepted
    );

    bob.send(
        &conversation_id,
        "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        "acknowledged, the client will treat null as unchanged",
    )
    .await;

    let replied = alice_session.claim(4, CLAIM_WAIT_MILLISECONDS).await;
    let reply = replied
        .iter()
        .find(|event| matches!(event.payload, DeliveredPayload::ApplicationText(_)))
        .expect("a reply must reach the originating session automatically");
    assert_eq!(
        text_of(&reply.payload),
        "acknowledged, the client will treat null as unchanged"
    );

    bob.close().await;
    alice.close().await;
    fixture.relay().assert_opaque(&[
        b"the response now returns a nullable cursor",
        b"acknowledged, the client will treat null as unchanged",
    ]);
    fixture.stop().await;
}

#[tokio::test]
async fn a_burst_arrives_as_one_bounded_batch() {
    let fixture = DaemonFixture::start("bounded-batch").await;
    let bob_host = AdapterHost::new("bob", 23, 23);
    let alice = fixture.connect("alice", None).await;
    let bob = fixture.connect("bob", Some(&bob_host)).await;
    let mut bob_session = bob_host.accept().await;

    let conversation_id = join_conversation(&alice, &bob).await;

    for index in 0..6_u8 {
        let message_id = format!("{index:02x}").repeat(16);
        alice
            .send(
                &conversation_id,
                &message_id,
                &format!("burst message {index}"),
            )
            .await;
    }

    let first = bob_session.claim(2, CLAIM_WAIT_MILLISECONDS).await;
    assert_eq!(
        first.len(),
        2,
        "a burst must be bounded by the requested batch size"
    );
    for event in &first {
        assert_eq!(
            bob_session
                .request(&AdapterRequest::Acknowledge {
                    notification_id: event.notification_id,
                    lease_generation: event.lease_generation,
                })
                .await,
            AdapterResponse::Accepted
        );
    }

    let second = bob_session.claim(8, CLAIM_WAIT_MILLISECONDS).await;
    assert!(
        !second.is_empty(),
        "remaining work must stay claimable after the first batch"
    );
    let mut sequences: Vec<u64> = first
        .iter()
        .chain(second.iter())
        .map(|event| event.sequence)
        .collect();
    let observed = sequences.len();
    sequences.sort_unstable();
    sequences.dedup();
    assert_eq!(
        sequences.len(),
        observed,
        "no event may be delivered twice within one attachment"
    );

    bob.close().await;
    alice.close().await;
    fixture.stop().await;
}

#[tokio::test]
async fn an_abandoned_claim_is_redelivered_with_the_same_stable_identifier() {
    let fixture = DaemonFixture::start("redelivery").await;
    let bob_host = AdapterHost::new("bob", 24, 24);
    let alice = fixture.connect("alice", None).await;
    let bob = fixture.connect("bob", Some(&bob_host)).await;
    let mut bob_session = bob_host.accept().await;

    let conversation_id = join_conversation(&alice, &bob).await;
    alice
        .send(
            &conversation_id,
            "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
            "delivered before the adapter died",
        )
        .await;

    let claimed = bob_session.claim(4, CLAIM_WAIT_MILLISECONDS).await;
    let original = claimed
        .iter()
        .find(|event| matches!(event.payload, DeliveredPayload::ApplicationText(_)))
        .expect("the first attachment must receive the message")
        .clone();

    // The adapter accepted delivery but crashed before acknowledging, so the claim
    // must survive as reclaimable work rather than being lost or double-counted.
    bob_session.abandon();
    let mut recovered = bob_host.accept().await;

    let redelivered = recovered.claim(4, CLAIM_WAIT_MILLISECONDS).await;
    let repeated = redelivered
        .iter()
        .find(|event| event.notification_id == original.notification_id)
        .expect("an unacknowledged event must be redelivered after an adapter crash");
    assert_eq!(
        text_of(&repeated.payload),
        "delivered before the adapter died"
    );
    assert_ne!(
        repeated.lease_generation, original.lease_generation,
        "redelivery must invalidate the crashed attachment's lease generation"
    );

    assert_eq!(
        recovered
            .request(&AdapterRequest::Acknowledge {
                notification_id: repeated.notification_id,
                lease_generation: repeated.lease_generation,
            })
            .await,
        AdapterResponse::Accepted
    );
    assert_eq!(
        recovered
            .request(&AdapterRequest::Acknowledge {
                notification_id: repeated.notification_id,
                lease_generation: repeated.lease_generation,
            })
            .await,
        AdapterResponse::Accepted,
        "acknowledgement must be idempotent"
    );
    assert!(
        recovered
            .claim(4, SILENCE_WAIT_MILLISECONDS)
            .await
            .iter()
            .all(|event| event.notification_id != original.notification_id),
        "an acknowledged event must not be delivered again"
    );

    bob.close().await;
    alice.close().await;
    fixture.stop().await;
}

#[tokio::test]
async fn muting_suppresses_delivery_while_replay_continues() {
    let fixture = DaemonFixture::start("muted-delivery").await;
    let bob_host = AdapterHost::new("bob", 25, 25);
    let alice = fixture.connect("alice", None).await;
    let bob = fixture.connect("bob", Some(&bob_host)).await;
    let mut bob_session = bob_host.accept().await;

    let conversation_id = join_conversation(&alice, &bob).await;
    let joined = bob
        .require(
            "delivery_status",
            json!({"conversation_id": conversation_id}),
        )
        .await;
    assert_eq!(
        joined["auto_delivery_enabled"].as_bool(),
        Some(true),
        "joining a conversation must be enough to start receiving it"
    );
    set_delivery(&bob, &conversation_id, false).await;

    alice
        .send(
            &conversation_id,
            "0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d",
            "arrived while muted",
        )
        .await;
    assert!(
        bob_session
            .claim(4, SILENCE_WAIT_MILLISECONDS)
            .await
            .is_empty(),
        "a muted conversation must not deliver into a session"
    );

    set_delivery(&bob, &conversation_id, true).await;
    alice
        .send(
            &conversation_id,
            "0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e",
            "arrived after unmuting",
        )
        .await;

    let delivered = bob_session.claim(8, CLAIM_WAIT_MILLISECONDS).await;
    assert!(
        delivered.iter().any(|event| matches!(
            &event.payload,
            DeliveredPayload::ApplicationText(text) if text == "arrived after unmuting"
        )),
        "enabling delivery must let later messages reach the session"
    );
    assert!(
        delivered.iter().all(|event| !matches!(
            &event.payload,
            DeliveredPayload::ApplicationText(text) if text == "arrived while muted"
        )),
        "unmuting must not replay a backlog the session was deliberately not shown"
    );

    // Relay replay is unaffected by muting: the daemon still received, decrypted, and
    // stored the message. It simply was never allowed to wake the session.
    let history = bob
        .require(
            "read_messages",
            json!({"conversation_id": conversation_id, "limit": 50}),
        )
        .await;
    assert!(
        history["messages"]
            .as_array()
            .unwrap()
            .iter()
            .any(|message| message["text"] == "arrived while muted"),
        "a muted message must remain readable history"
    );

    bob.close().await;
    alice.close().await;
    fixture.stop().await;
}

#[tokio::test]
async fn a_cross_profile_attachment_is_denied() {
    let fixture = DaemonFixture::start("cross-profile").await;
    // The host announces one profile while the daemon runs another, which is what a
    // second session on the same device looks like if it reaches the wrong endpoint.
    let foreign_host = AdapterHost::new("alice", 26, 26);
    let bob = fixture.connect("bob", Some(&foreign_host)).await;

    let outcome = foreign_host
        .try_accept()
        .await
        .expect("the daemon must still connect outward before authentication decides");
    assert_eq!(
        outcome.err(),
        Some(AdapterTransportError::ProfileMismatch),
        "a daemon must not attach to another profile's adapter endpoint"
    );

    bob.close().await;
    fixture.stop().await;
}

#[tokio::test]
async fn delivery_status_reports_what_the_supervisor_is_watching() {
    let fixture = DaemonFixture::start("delivery-status").await;
    let alice = fixture.connect("alice", None).await;
    let bob = fixture.connect("bob", None).await;
    let conversation_id = join_conversation(&alice, &bob).await;

    let status = bob
        .require(
            "delivery_status",
            json!({"conversation_id": conversation_id}),
        )
        .await;
    assert_eq!(status["auto_delivery_enabled"].as_bool(), Some(true));
    assert!(status["watched_conversations"].as_u64().is_some());

    let global = bob.require("delivery_status", Value::Null).await;
    assert!(
        global["auto_delivery_enabled"].is_null(),
        "a status request without a conversation must not guess one"
    );

    bob.close().await;
    alice.close().await;
    fixture.stop().await;
}
