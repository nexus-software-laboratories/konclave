//! Proves two real daemons pair from one capability without manual protocol transfer.

#![cfg(unix)]

mod support;

use KonclaveAdapterTransport::{AdapterRequest, AdapterResponse, DeliveredPayload};
use support::{AdapterHost, DaemonFixture, pair_with_capability, text_of};
const CLAIM_WAIT_MILLISECONDS: u32 = 15_000;

#[tokio::test]
async fn one_capability_pairs_real_daemons_and_enables_automatic_delivery() {
    let fixture = DaemonFixture::start("pairing-e2e").await;
    let bob_host = AdapterHost::new("bob", 31, 31);
    let alice = fixture.connect("alice", None).await;
    let bob = fixture.connect("bob", Some(&bob_host)).await;
    let mut bob_session = bob_host.accept().await;
    let (conversation_id, capability) = pair_with_capability(&alice, &bob).await;

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

    bob.close().await;
    alice.close().await;
    fixture
        .relay()
        .assert_opaque(&[capability.as_bytes(), b"the contract is aligned"]);
    fixture.stop().await;
}
