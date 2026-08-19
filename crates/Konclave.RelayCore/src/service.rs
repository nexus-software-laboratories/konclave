use std::time::{SystemTime, UNIX_EPOCH};

use KonclaveDomainCore::{AcknowledgeRequest, RelayEnvelope, ReplayPage, ReplayRequest, RoutingId};
use async_trait::async_trait;

use crate::{RelayError, RelayPrincipalId, RelayRepository, SubmitResult};

/// Relay action checked independently by the authorization adapter.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum RelayPermission {
    Send,
    Replay,
    Acknowledge,
}

/// Trust-boundary adapter for authenticated route permissions.
#[async_trait]
pub trait RelayAuthorizer: Send + Sync {
    /// Authorizes one principal action for one route.
    ///
    /// # Errors
    ///
    /// Returns [`RelayError::Unauthorized`] for a denied action or a typed
    /// dependency error when authorization cannot be evaluated.
    async fn authorize(
        &self,
        principal: RelayPrincipalId,
        routing_id: RoutingId,
        permission: RelayPermission,
    ) -> Result<(), RelayError>;
}

/// Bounded clock used for expiration validation.
pub trait RelayClock: Send + Sync {
    /// Returns current Unix time in seconds.
    ///
    /// # Errors
    ///
    /// Returns [`RelayError::ClockUnavailable`] when time is before the Unix epoch.
    fn now_unix_seconds(&self) -> Result<u64, RelayError>;
}

/// Operating-system relay clock.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemRelayClock;

impl RelayClock for SystemRelayClock {
    fn now_unix_seconds(&self) -> Result<u64, RelayError> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .map_err(|_| RelayError::ClockUnavailable)
    }
}

/// Authorization-enforcing relay service over one durable repository.
pub struct RelayService<R, A, C = SystemRelayClock> {
    repository: R,
    authorizer: A,
    clock: C,
}

impl<R, A> RelayService<R, A, SystemRelayClock> {
    /// Creates a relay service with the operating-system clock.
    #[must_use]
    pub const fn new(repository: R, authorizer: A) -> Self {
        Self {
            repository,
            authorizer,
            clock: SystemRelayClock,
        }
    }
}

impl<R, A, C> RelayService<R, A, C>
where
    R: RelayRepository,
    A: RelayAuthorizer,
    C: RelayClock,
{
    /// Creates a relay service with an explicit clock.
    #[must_use]
    pub const fn with_clock(repository: R, authorizer: A, clock: C) -> Self {
        Self {
            repository,
            authorizer,
            clock,
        }
    }

    /// Authorizes and durably submits one opaque envelope.
    ///
    /// # Errors
    ///
    /// Returns a typed authorization, expiration, sequencing, idempotency, or
    /// storage error.
    pub async fn submit(
        &self,
        principal: RelayPrincipalId,
        envelope: &RelayEnvelope,
    ) -> Result<SubmitResult, RelayError> {
        self.authorizer
            .authorize(principal, envelope.routing_id(), RelayPermission::Send)
            .await?;
        let now = self.clock.now_unix_seconds()?;
        self.repository.submit(envelope, now).await
    }

    /// Authorizes and returns one bounded replay page.
    ///
    /// # Errors
    ///
    /// Returns a typed authorization or storage error.
    pub async fn replay(
        &self,
        principal: RelayPrincipalId,
        request: ReplayRequest,
    ) -> Result<ReplayPage, RelayError> {
        self.authorizer
            .authorize(principal, request.routing_id(), RelayPermission::Replay)
            .await?;
        self.repository.replay(request).await
    }

    /// Authorizes and records one monotonic cursor acknowledgment.
    ///
    /// # Errors
    ///
    /// Returns a typed authorization, range, or storage error.
    pub async fn acknowledge(
        &self,
        principal: RelayPrincipalId,
        request: AcknowledgeRequest,
    ) -> Result<u64, RelayError> {
        self.authorizer
            .authorize(
                principal,
                request.routing_id(),
                RelayPermission::Acknowledge,
            )
            .await?;
        self.repository.acknowledge(principal, request).await
    }
}
