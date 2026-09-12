use std::sync::{Arc, Mutex};
use std::time::Duration;

use KonclaveAdapterSdk::{
    AdapterRequestId, AdapterRpc, AdapterSdkError, AdapterSession, DeliveredPayload,
    DeliverySettlement,
};
use async_trait::async_trait;
use serde_json::{Value, json};

struct BrokerState {
    owner: Option<u64>,
    generation: u64,
    acknowledged: bool,
}

struct FakeBroker {
    state: Arc<Mutex<BrokerState>>,
    next_session: u64,
}

impl FakeBroker {
    fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(BrokerState {
                owner: None,
                generation: 0,
                acknowledged: false,
            })),
            next_session: 1,
        }
    }

    fn connect(&mut self) -> FakeRpc {
        let session = self.next_session;
        self.next_session += 1;
        FakeRpc {
            session,
            state: Arc::clone(&self.state),
        }
    }
}

struct FakeRpc {
    session: u64,
    state: Arc<Mutex<BrokerState>>,
}

impl Drop for FakeRpc {
    fn drop(&mut self) {
        let mut state = self.state.lock().unwrap();
        if state.owner == Some(self.session) {
            state.owner = None;
        }
    }
}

#[async_trait]
impl AdapterRpc for FakeRpc {
    async fn request(
        &mut self,
        _request_id: AdapterRequestId,
        operation: &'static str,
        payload: Vec<u8>,
    ) -> Result<Vec<u8>, AdapterSdkError> {
        let request: Value =
            serde_json::from_slice(&payload).map_err(|_| AdapterSdkError::InvalidResponse)?;
        let mut state = self.state.lock().unwrap();
        match operation {
            "delivery.claim" => {
                if request["maxEvents"] != 1 || request["waitMilliseconds"] != 0 {
                    return Err(AdapterSdkError::InvalidConfiguration);
                }
                if state.acknowledged {
                    return Ok(br#"{"events":[]}"#.to_vec());
                }
                if state.owner != Some(self.session) {
                    state.owner = Some(self.session);
                    state.generation += 1;
                }
                serde_json::to_vec(&json!({
                    "events": [{
                        "notificationId": "000102030405060708090a0b0c0d0e0f",
                        "leaseGeneration": state.generation,
                        "sequence": 1,
                        "conversation": "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
                        "sender": "303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
                        "relayCursor": 11,
                        "payload": {
                            "kind": "application_text",
                            "messageId": "505152535455565758595a5b5c5d5e5f",
                            "text": "deliver exactly once after acknowledgement"
                        }
                    }]
                }))
                .map_err(|_| AdapterSdkError::InvalidResponse)
            }
            "delivery.acknowledge" => {
                if request["leaseGeneration"] != state.generation
                    || request["notificationId"] != "000102030405060708090a0b0c0d0e0f"
                {
                    return Err(AdapterSdkError::Service(
                        KonclaveLocalServiceTransport::LocalServiceErrorCode::Conflict,
                    ));
                }
                state.acknowledged = true;
                state.owner = None;
                Ok(b"{}".to_vec())
            }
            "delivery.release" => {
                if state.owner != Some(self.session)
                    || request["leaseGeneration"] != state.generation
                    || request["notificationId"] != "000102030405060708090a0b0c0d0e0f"
                {
                    return Err(AdapterSdkError::Service(
                        KonclaveLocalServiceTransport::LocalServiceErrorCode::Conflict,
                    ));
                }
                state.owner = None;
                Ok(b"{}".to_vec())
            }
            _ => Err(AdapterSdkError::InvalidConfiguration),
        }
    }
}

#[tokio::test]
async fn fake_harness_claims_crashes_reclaims_delivers_and_acknowledges() {
    let mut broker = FakeBroker::new();
    let mut crashed = AdapterSession::new(broker.connect());
    let mut first_batch = crashed
        .claim(AdapterRequestId::from_bytes([1; 16]), 1, Duration::ZERO)
        .await
        .unwrap();
    let first = first_batch.remove(0);
    assert!(matches!(
        first.payload(),
        DeliveredPayload::ApplicationText { text, .. }
            if text == "deliver exactly once after acknowledgement"
    ));
    crashed.detach();

    let mut recovered = AdapterSession::new(broker.connect());
    let mut repeated_batch = recovered
        .claim(AdapterRequestId::from_bytes([2; 16]), 1, Duration::ZERO)
        .await
        .unwrap();
    let repeated = repeated_batch.remove(0);
    assert_eq!(repeated.notification_id(), first.notification_id());
    assert!(repeated.lease_generation() > first.lease_generation());

    recovered
        .release(
            AdapterRequestId::from_bytes([3; 16]),
            DeliverySettlement::from_event(&repeated),
        )
        .await
        .unwrap();
    let mut final_batch = recovered
        .claim(AdapterRequestId::from_bytes([4; 16]), 1, Duration::ZERO)
        .await
        .unwrap();
    let final_delivery = final_batch.remove(0);
    assert_eq!(final_delivery.notification_id(), first.notification_id());
    assert!(final_delivery.lease_generation() > repeated.lease_generation());

    recovered
        .acknowledge(
            AdapterRequestId::from_bytes([5; 16]),
            DeliverySettlement::from_event(&final_delivery),
        )
        .await
        .unwrap();
    recovered
        .acknowledge(
            AdapterRequestId::from_bytes([6; 16]),
            DeliverySettlement::from_event(&final_delivery),
        )
        .await
        .unwrap();
    assert!(
        recovered
            .claim(AdapterRequestId::from_bytes([7; 16]), 1, Duration::ZERO,)
            .await
            .unwrap()
            .is_empty()
    );
}
