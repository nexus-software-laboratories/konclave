#![forbid(unsafe_code)]
#![allow(non_snake_case)]

//! Harness-neutral delivery SDK for Konclave's authenticated shared local service.
//!
//! Harness integrations retain control over their own lifecycle and permission
//! system. This crate supplies typed claim, settlement, heartbeat, and status
//! operations without importing harness-specific prompt, model, command, or UI types.

mod error;
mod model;

use std::time::Duration;

use KonclaveBoundedDocuments::{BoundedVec, deserialize_strict};
use KonclaveLocalServiceClient::{LocalServiceJsonClient, LocalServiceJsonSession};
use KonclaveLocalServiceTransport::{RequestId, encode_lowercase_hex};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

pub use error::AdapterSdkError;
use model::DeliveryEventDocument;
pub use model::{
    AdapterStatus, CollaborationTurnClaim, DeliveredEvent, DeliveredPayload,
    DeliveredPolicyResponseOutcome, DeliveredRole, DeliverySettlement, MESSAGE_ID_LENGTH,
    NOTIFICATION_ID_LENGTH, ROUTED_ID_LENGTH,
};

/// Version of the harness-neutral adapter API and fixture contract.
pub const ADAPTER_SDK_VERSION: u16 = 1;
/// Largest event batch accepted from one claim.
pub const MAX_CLAIM_BATCH: u16 = 16;
/// Longest service-side wait accepted for one claim.
pub const MAX_WAIT_MILLISECONDS: u32 = 30_000;
/// Largest UTF-8 text body accepted in one delivery event.
pub const MAX_EVENT_TEXT_BYTES: usize = 64 * 1024;
/// Recommended maximum interval between lease heartbeats during active work.
pub const RECOMMENDED_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);

/// Stable request identity supplied by a harness for idempotent operations.
pub type AdapterRequestId = RequestId;

/// Transport-neutral request boundary used by the typed adapter session.
#[async_trait]
pub trait AdapterRpc: Send {
    /// Sends one exact operation and returns its authenticated JSON payload.
    ///
    /// # Errors
    ///
    /// Returns a stable adapter error. Retry behavior after an ambiguous transport
    /// failure is operation-specific because delivery claims own a connection-bound
    /// lease.
    async fn request(
        &mut self,
        request_id: AdapterRequestId,
        operation: &'static str,
        payload: Vec<u8>,
    ) -> Result<Vec<u8>, AdapterSdkError>;
}

#[async_trait]
impl<'a> AdapterRpc for LocalServiceJsonSession<'a> {
    async fn request(
        &mut self,
        request_id: AdapterRequestId,
        operation: &'static str,
        payload: Vec<u8>,
    ) -> Result<Vec<u8>, AdapterSdkError> {
        LocalServiceJsonSession::request(self, request_id, operation, payload)
            .await
            .map_err(Into::into)
    }
}

/// One profile-bound delivery session over an authenticated adapter RPC.
///
/// The session is intentionally single-consumer and mutable. Dropping its transport
/// represents a harness crash or detach; the service releases connection-owned
/// claims so a replacement session can reclaim unacknowledged events.
pub struct AdapterSession<T> {
    rpc: T,
}

impl<T> AdapterSession<T> {
    /// Wraps one authenticated profile-bound RPC session.
    #[must_use]
    pub const fn new(rpc: T) -> Self {
        Self { rpc }
    }

    /// Returns the underlying transport.
    #[must_use]
    pub fn into_inner(self) -> T {
        self.rpc
    }

    /// Detaches this harness session and closes the underlying transport.
    ///
    /// Connection-owned delivery claims become reclaimable according to the local
    /// service lifecycle contract. This method performs no success-shaped remote
    /// operation; dropping the transport is the detach signal.
    pub fn detach(self) {
        drop(self);
    }
}

impl<T: AdapterRpc> AdapterSession<T> {
    /// Waits for and claims one bounded batch.
    ///
    /// An empty batch means the finite wait expired. It is not an acknowledged
    /// transition and callers may issue another claim.
    ///
    /// # Errors
    ///
    /// Returns an invalid-configuration error for a zero/oversized batch, a wait
    /// above 30 seconds, or a sub-millisecond duration. A transport failure or
    /// deadline returns [`AdapterSdkError::ClaimOutcomeUnknown`]; discard the session,
    /// reconnect, and claim with a fresh request identifier so the replacement
    /// connection receives current lease generations.
    pub async fn claim(
        &mut self,
        request_id: AdapterRequestId,
        max_events: u16,
        wait: Duration,
    ) -> Result<Vec<DeliveredEvent>, AdapterSdkError> {
        let wait_milliseconds =
            u32::try_from(wait.as_millis()).map_err(|_| AdapterSdkError::InvalidConfiguration)?;
        if max_events == 0
            || max_events > MAX_CLAIM_BATCH
            || wait_milliseconds > MAX_WAIT_MILLISECONDS
            || Duration::from_millis(u64::from(wait_milliseconds)) != wait
        {
            return Err(AdapterSdkError::InvalidConfiguration);
        }
        let response = match self
            .rpc
            .request(
                request_id,
                DELIVERY_CLAIM_OPERATION,
                encode(&DeliveryClaimRequest {
                    max_events,
                    wait_milliseconds,
                })?,
            )
            .await
        {
            Err(AdapterSdkError::Transport | AdapterSdkError::DeadlineExceeded) => {
                return Err(AdapterSdkError::ClaimOutcomeUnknown);
            }
            result => result?,
        };
        let batch: DeliveryBatchResponse = decode(&response)?;
        batch
            .events
            .into_inner()
            .into_iter()
            .map(TryInto::try_into)
            .collect()
    }

    /// Acknowledges one event only after the harness has accepted its delivery.
    ///
    /// Repeating the same acknowledgement is idempotent.
    ///
    /// # Errors
    ///
    /// Returns a stable transport, service, or response error.
    pub async fn acknowledge(
        &mut self,
        request_id: AdapterRequestId,
        settlement: DeliverySettlement,
    ) -> Result<(), AdapterSdkError> {
        self.finish(request_id, DELIVERY_ACKNOWLEDGE_OPERATION, settlement)
            .await
    }

    /// Releases one claimed event for later redelivery.
    ///
    /// # Errors
    ///
    /// Returns a stable transport, service, or response error.
    pub async fn release(
        &mut self,
        request_id: AdapterRequestId,
        settlement: DeliverySettlement,
    ) -> Result<(), AdapterSdkError> {
        self.finish(request_id, DELIVERY_RELEASE_OPERATION, settlement)
            .await
    }

    /// Renews the delivery lease and optionally one active directed-request turn.
    ///
    /// # Errors
    ///
    /// Returns a stable transport, service, or response error.
    pub async fn heartbeat(
        &mut self,
        request_id: AdapterRequestId,
        turn: Option<CollaborationTurnClaim>,
    ) -> Result<(), AdapterSdkError> {
        let response = self
            .rpc
            .request(
                request_id,
                DELIVERY_HEARTBEAT_OPERATION,
                encode(&DeliveryHeartbeatRequest {
                    turn: turn.as_ref().map(DeliveryHeartbeatTurn::from),
                })?,
            )
            .await?;
        decode_empty(&response)
    }

    /// Loads bounded delivery health for the bound profile.
    ///
    /// # Errors
    ///
    /// Returns a stable transport, service, or response error.
    pub async fn status(
        &mut self,
        request_id: AdapterRequestId,
    ) -> Result<AdapterStatus, AdapterSdkError> {
        let response = self
            .rpc
            .request(request_id, SERVICE_STATUS_OPERATION, b"{}".to_vec())
            .await?;
        let status: ServiceStatusResponse = decode(&response)?;
        Ok(AdapterStatus {
            authorization_generation: status.authorization_generation,
            pending_events: status.pending_events,
            claimed_events: status.claimed_events,
            watched_conversations: status.watched_conversations,
            delivery_degraded: status.delivery_degraded,
        })
    }

    async fn finish(
        &mut self,
        request_id: AdapterRequestId,
        operation: &'static str,
        settlement: DeliverySettlement,
    ) -> Result<(), AdapterSdkError> {
        let response = self
            .rpc
            .request(
                request_id,
                operation,
                encode(&DeliveryFinishRequest {
                    notification_id: encode_lowercase_hex(&settlement.notification_id()),
                    lease_generation: settlement.lease_generation(),
                })?,
            )
            .await?;
        decode_empty(&response)
    }
}

/// Opens a persistent typed adapter session over the shared local service.
///
/// # Errors
///
/// Returns a transport, authentication, deadline, service, or grant failure.
pub async fn open_local_service_adapter(
    client: &LocalServiceJsonClient,
) -> Result<AdapterSession<LocalServiceJsonSession<'_>>, AdapterSdkError> {
    client
        .open_session()
        .await
        .map(AdapterSession::new)
        .map_err(Into::into)
}

const DELIVERY_CLAIM_OPERATION: &str = "delivery.claim";
const DELIVERY_ACKNOWLEDGE_OPERATION: &str = "delivery.acknowledge";
const DELIVERY_RELEASE_OPERATION: &str = "delivery.release";
const DELIVERY_HEARTBEAT_OPERATION: &str = "delivery.heartbeat";
const SERVICE_STATUS_OPERATION: &str = "service.status";

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DeliveryClaimRequest {
    max_events: u16,
    wait_milliseconds: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeliveryBatchResponse {
    events: BoundedVec<DeliveryEventDocument, 16>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DeliveryFinishRequest {
    notification_id: String,
    lease_generation: u64,
}

#[derive(Serialize)]
struct DeliveryHeartbeatRequest {
    turn: Option<DeliveryHeartbeatTurn>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DeliveryHeartbeatTurn {
    conversation_id: String,
    policy_digest: String,
    request_message_id: String,
    attempt: u32,
}

impl From<&CollaborationTurnClaim> for DeliveryHeartbeatTurn {
    fn from(claim: &CollaborationTurnClaim) -> Self {
        Self {
            conversation_id: encode_lowercase_hex(claim.conversation_id()),
            policy_digest: encode_lowercase_hex(claim.policy_digest()),
            request_message_id: encode_lowercase_hex(claim.request_message_id()),
            attempt: claim.attempt(),
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ServiceStatusResponse {
    authorization_generation: u64,
    pending_events: u32,
    claimed_events: u32,
    watched_conversations: u32,
    delivery_degraded: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyResponse {}

fn encode(value: &impl Serialize) -> Result<Vec<u8>, AdapterSdkError> {
    serde_json::to_vec(value).map_err(|_| AdapterSdkError::InvalidConfiguration)
}

fn decode<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, AdapterSdkError> {
    deserialize_strict(bytes, KonclaveLocalServiceTransport::MAX_RPC_PAYLOAD_BYTES)
        .map_err(|_| AdapterSdkError::InvalidResponse)
}

fn decode_empty(bytes: &[u8]) -> Result<(), AdapterSdkError> {
    let _: EmptyResponse = decode(bytes)?;
    Ok(())
}
