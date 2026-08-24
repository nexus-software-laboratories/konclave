use std::path::Path;
use std::sync::Arc;

use KonclaveDomainCore::{AcknowledgeRequest, RelayEnvelope, ReplayPage, ReplayRequest, RoutingId};
use KonclaveProtocolContracts::v1::decode_relay_envelope;
use KonclaveRelayAuthentication::{RelayEnrollmentRequest, RelayEnrollmentResponse};
use KonclaveRelayCore::{
    EncodedReplayPage, RelayError, RelayPrincipalId, RelayPrincipalRegistry, RelayService,
    SqliteRelayRepository, SubmitResult,
};

use crate::access::{RelayAccess, StaticRelayAccess};

type AuthorizedRelayService = RelayService<SqliteRelayRepository, RelayAccess>;
const RELAY_EVENT_CAPACITY: usize = 1_024;

/// Composes authenticated relay policy with durable opaque persistence.
#[derive(Clone)]
pub struct RelayApplication {
    service: Arc<AuthorizedRelayService>,
    registry: SqliteRelayRepository,
    events: tokio::sync::broadcast::Sender<RelayEvent>,
}

impl RelayApplication {
    /// Opens the durable relay database and binds the configured authorizer.
    ///
    /// # Errors
    ///
    /// Returns a typed storage error when SQLite cannot open or validate its schema.
    pub async fn connect(
        database_path: &Path,
        access: StaticRelayAccess,
    ) -> Result<Self, RelayError> {
        let repository = SqliteRelayRepository::connect(database_path).await?;
        let authorizer = RelayAccess::new(access, repository.clone());
        let (events, _) = tokio::sync::broadcast::channel(RELAY_EVENT_CAPACITY);
        Ok(Self {
            service: Arc::new(RelayService::new(repository.clone(), authorizer)),
            registry: repository,
            events,
        })
    }

    /// Authorizes and submits one validated opaque envelope.
    ///
    /// # Errors
    ///
    /// Returns the relay service's typed authorization, sequencing, or storage error.
    pub async fn submit(
        &self,
        principal: RelayPrincipalId,
        envelope: &RelayEnvelope,
    ) -> Result<SubmitResult, RelayError> {
        let outcome = self.service.submit(principal, envelope).await?;
        self.publish_if_new(envelope.routing_id(), outcome);
        Ok(outcome)
    }

    /// Decodes, authorizes, and submits exact bounded envelope bytes.
    ///
    /// # Errors
    ///
    /// Returns the relay service's typed protocol, authorization, sequencing, or
    /// storage error.
    pub async fn submit_encoded(
        &self,
        principal: RelayPrincipalId,
        encoded_envelope: &[u8],
    ) -> Result<SubmitResult, RelayError> {
        let route = decode_relay_envelope(encoded_envelope)?.routing_id();
        let outcome = self
            .service
            .submit_encoded(principal, encoded_envelope)
            .await?;
        self.publish_if_new(route, outcome);
        Ok(outcome)
    }

    /// Authorizes and returns one bounded replay page.
    ///
    /// # Errors
    ///
    /// Returns the relay service's typed authorization or storage error.
    pub async fn replay(
        &self,
        principal: RelayPrincipalId,
        request: ReplayRequest,
    ) -> Result<ReplayPage, RelayError> {
        self.service.replay(principal, request).await
    }

    /// Authorizes and returns a bounded page that preserves exact envelope bytes.
    ///
    /// # Errors
    ///
    /// Returns the relay service's typed authorization, protocol, or storage error.
    pub async fn replay_encoded(
        &self,
        principal: RelayPrincipalId,
        request: ReplayRequest,
    ) -> Result<EncodedReplayPage, RelayError> {
        self.service.replay_encoded(principal, request).await
    }

    /// Authorizes and advances one principal's durable acknowledgment.
    ///
    /// # Errors
    ///
    /// Returns the relay service's typed authorization, range, or storage error.
    pub async fn acknowledge(
        &self,
        principal: RelayPrincipalId,
        request: AcknowledgeRequest,
    ) -> Result<u64, RelayError> {
        self.service.acknowledge(principal, request).await
    }

    /// Registers one client-generated dynamic relay principal.
    ///
    /// # Errors
    ///
    /// Returns a version, conflict, revocation, capacity, malformed-data, or storage
    /// error.
    pub async fn register_principal(
        &self,
        request: RelayEnrollmentRequest,
    ) -> Result<RelayEnrollmentResponse, RelayError> {
        self.registry.register_principal(request).await
    }

    /// Idempotently revokes one dynamically registered principal.
    ///
    /// # Errors
    ///
    /// Returns a storage error.
    pub async fn revoke_principal(&self, principal: RelayPrincipalId) -> Result<bool, RelayError> {
        self.registry.revoke_principal(principal).await
    }

    pub(crate) fn registry(&self) -> SqliteRelayRepository {
        self.registry.clone()
    }

    /// Subscribes to best-effort durable-cursor notifications.
    pub(crate) fn subscribe(&self) -> tokio::sync::broadcast::Receiver<RelayEvent> {
        self.events.subscribe()
    }

    fn publish_if_new(&self, routing_id: RoutingId, outcome: SubmitResult) {
        if !outcome.duplicate() {
            let _ = self.events.send(RelayEvent {
                routing_id,
                cursor: outcome.cursor(),
            });
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct RelayEvent {
    /// Route whose durable cursor advanced.
    pub routing_id: RoutingId,
    /// Newly assigned cursor.
    pub cursor: u64,
}
