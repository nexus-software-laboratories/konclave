use KonclaveDomainCore::{AcknowledgeRequest, RelayEnvelope, ReplayPage, ReplayRequest};
use KonclaveProtocolContracts::v1::encode_relay_envelope;
use async_trait::async_trait;

use crate::{RelayError, RelayPrincipalId};

/// Outcome of one accepted or idempotently retried submission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SubmitResult {
    cursor: u64,
    duplicate: bool,
}

impl SubmitResult {
    /// Creates a submission outcome.
    #[must_use]
    pub const fn new(cursor: u64, duplicate: bool) -> Self {
        Self { cursor, duplicate }
    }

    /// Returns the durable route cursor.
    #[must_use]
    pub const fn cursor(self) -> u64 {
        self.cursor
    }

    /// Returns whether an identical prior submission produced this result.
    #[must_use]
    pub const fn duplicate(self) -> bool {
        self.duplicate
    }
}

/// Durable relay operations whose implementations preserve route atomicity.
#[async_trait]
pub trait RelayRepository: Send + Sync {
    /// Verifies that the exact encoded bytes represent `envelope`, then atomically
    /// checks idempotency and expected epoch, assigns one cursor, and stores those
    /// bytes without re-encoding.
    async fn submit_encoded(
        &self,
        envelope: &RelayEnvelope,
        encoded_envelope: &[u8],
        now_unix_seconds: u64,
    ) -> Result<SubmitResult, RelayError>;

    /// Canonically encodes and submits one validated envelope.
    async fn submit(
        &self,
        envelope: &RelayEnvelope,
        now_unix_seconds: u64,
    ) -> Result<SubmitResult, RelayError> {
        let encoded_envelope = encode_relay_envelope(envelope)?;
        self.submit_encoded(envelope, &encoded_envelope, now_unix_seconds)
            .await
    }

    /// Returns one bounded page after the requested cursor.
    async fn replay(&self, request: ReplayRequest) -> Result<ReplayPage, RelayError>;

    /// Returns one bounded page that embeds each original envelope encoding without
    /// decoding and re-encoding it.
    async fn replay_encoded(&self, request: ReplayRequest) -> Result<Vec<u8>, RelayError>;

    /// Monotonically acknowledges one route cursor for one authenticated principal.
    async fn acknowledge(
        &self,
        principal: RelayPrincipalId,
        request: AcknowledgeRequest,
    ) -> Result<u64, RelayError>;
}
