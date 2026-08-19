use std::path::Path;
use std::sync::Arc;

use KonclaveDomainCore::{AcknowledgeRequest, RelayEnvelope, ReplayPage, ReplayRequest};
use KonclaveRelayCore::{
    RelayError, RelayPrincipalId, RelayService, SqliteRelayRepository, SubmitResult,
};

use crate::access::StaticRelayAccess;

type AuthorizedRelayService = RelayService<SqliteRelayRepository, StaticRelayAccess>;

/// Composes authenticated relay policy with durable opaque persistence.
#[derive(Clone)]
pub struct RelayApplication {
    service: Arc<AuthorizedRelayService>,
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
        Ok(Self {
            service: Arc::new(RelayService::new(repository, access)),
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
        self.service.submit(principal, envelope).await
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
        self.service
            .submit_encoded(principal, encoded_envelope)
            .await
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
    ) -> Result<Vec<u8>, RelayError> {
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
}
