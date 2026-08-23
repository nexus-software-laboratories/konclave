//! Proves delivery survives a daemon crash rather than silently losing work.
//!
//! The delivery suite crashes the adapter. These tests crash the process that owns the
//! journal and the lease, which is the failure that can actually lose a message: the
//! daemon has already told the relay it received an envelope, and the session has not
//! yet seen it.

#![cfg(unix)]

mod support;

use KonclaveAdapterTransport::{AdapterRequest, AdapterResponse, DeliveredPayload};
use serde_json::json;
use support::{AdapterHost, DaemonFixture, join_conversation, text_of};

/// How long a claim waits before reporting an empty batch.
const CLAIM_WAIT_MILLISECONDS: u32 = 15_000;

/// How long a claim waits when the test expects nothing to arrive.
const SILENCE_WAIT_MILLISECONDS: u32 = 1_500;

#[tokio::test]
async fn a_daemon_crash_before_acknowledgement_redelivers_the_same_identifier() {
    let fixture = DaemonFixture::start("daemon-crash").await;
    let bob_host = AdapterHost::new("bob", 31, 31);
    let alice = fixture.connect("alice", None).await;
    let bob = fixture.connect("bob", Some(&bob_host)).await;
    let mut bob_session = bob_host.accept().await;

    let conversation_id = join_conversation(&alice, &bob).await;
    alice
        .send(
            &conversation_id,
            "1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a",
            "sent before the daemon died",
        )
        .await;

    let claimed = bob_session.claim(4, CLAIM_WAIT_MILLISECONDS).await;
    let original = claimed
        .iter()
        .find(|event| matches!(event.payload, DeliveredPayload::ApplicationText(_)))
        .expect("the message must reach the session before the crash")
        .clone();

    // The relay has already been told the envelope arrived. Nothing has acknowledged
    // delivery, so the journal is the only thing standing between the session and a
    // lost message.
    bob.kill().await;
    bob_session.abandon();

    let restarted = fixture.connect("bob", Some(&bob_host)).await;
    let mut recovered = bob_host.accept().await;
    let redelivered = recovered.claim(4, CLAIM_WAIT_MILLISECONDS).await;
    let repeated = redelivered
        .iter()
        .find(|event| event.notification_id == original.notification_id)
        .expect("a crash before acknowledgement must not lose the message");
    assert_eq!(text_of(&repeated.payload), "sent before the daemon died");

    assert_eq!(
        recovered
            .request(&AdapterRequest::Acknowledge {
                notification_id: repeated.notification_id,
                lease_generation: repeated.lease_generation,
            })
            .await,
        AdapterResponse::Accepted
    );

    restarted.close().await;
    alice.close().await;
    fixture.stop().await;
}

#[tokio::test]
async fn a_restart_after_acknowledgement_delivers_nothing_a_second_time() {
    let fixture = DaemonFixture::start("daemon-restart").await;
    let bob_host = AdapterHost::new("bob", 32, 32);
    let alice = fixture.connect("alice", None).await;
    let bob = fixture.connect("bob", Some(&bob_host)).await;
    let mut bob_session = bob_host.accept().await;

    let conversation_id = join_conversation(&alice, &bob).await;
    alice
        .send(
            &conversation_id,
            "1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b",
            "delivered exactly once",
        )
        .await;

    let claimed = bob_session.claim(4, CLAIM_WAIT_MILLISECONDS).await;
    let delivered = claimed
        .iter()
        .find(|event| matches!(event.payload, DeliveredPayload::ApplicationText(_)))
        .expect("the message must reach the session")
        .clone();
    assert_eq!(
        bob_session
            .request(&AdapterRequest::Acknowledge {
                notification_id: delivered.notification_id,
                lease_generation: delivered.lease_generation,
            })
            .await,
        AdapterResponse::Accepted
    );

    // Restarting replays the relay stream from the stored cursor. An envelope the
    // daemon already turned into an acknowledged notification must not become a
    // second, unmarked notification for the same message.
    bob.kill().await;
    bob_session.abandon();

    let restarted = fixture.connect("bob", Some(&bob_host)).await;
    let mut recovered = bob_host.accept().await;
    assert!(
        recovered
            .claim(8, SILENCE_WAIT_MILLISECONDS)
            .await
            .iter()
            .all(|event| event.notification_id != delivered.notification_id),
        "duplicate relay delivery must not create a second notification"
    );

    let history = restarted
        .require(
            "read_messages",
            json!({"conversation_id": conversation_id, "limit": 50}),
        )
        .await;
    let occurrences = history["messages"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|message| message["text"] == "delivered exactly once")
        .count();
    assert_eq!(occurrences, 1, "replay must not duplicate stored history");

    restarted.close().await;
    alice.close().await;
    fixture.stop().await;
}

#[tokio::test]
async fn a_crashed_daemon_releases_its_consumer_lease_to_the_next_start() {
    let fixture = DaemonFixture::start("lease-recovery").await;
    let bob_host = AdapterHost::new("bob", 33, 33);
    let bob = fixture.connect("bob", Some(&bob_host)).await;
    let mut first = bob_host.accept().await;
    assert!(matches!(
        first.request(&AdapterRequest::Status).await,
        AdapterResponse::Status(_)
    ));

    // The daemon dies while still holding the lease. An orderly exit would have
    // released it, so killing first is what leaves the lease recorded with no live
    // holder — the state the next start has to recover from.
    bob.kill().await;
    first.abandon();

    let restarted = fixture.connect("bob", Some(&bob_host)).await;
    let mut recovered = bob_host.accept().await;
    assert!(
        matches!(
            recovered.request(&AdapterRequest::Status).await,
            AdapterResponse::Status(_)
        ),
        "a restarted daemon must reclaim the consumer lease a crash left behind"
    );

    restarted.close().await;
    fixture.stop().await;
}
