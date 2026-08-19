use KonclaveDomainCore::{AcknowledgeRequest, RelayEnvelope, ReplayPage, ReplayRequest};
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
    /// Atomically checks idempotency and expected epoch, assigns one cursor, and
    /// stores one opaque envelope.
    async fn submit(
        &self,
        envelope: &RelayEnvelope,
        now_unix_seconds: u64,
    ) -> Result<SubmitResult, RelayError>;

    /// Returns one bounded page after the requested cursor.
    async fn replay(&self, request: ReplayRequest) -> Result<ReplayPage, RelayError>;

    /// Monotonically acknowledges one route cursor for one authenticated principal.
    async fn acknowledge(
        &self,
        principal: RelayPrincipalId,
        request: AcknowledgeRequest,
    ) -> Result<u64, RelayError>;
}
