use std::sync::Arc;

use KonclaveA2AContracts::{
    InitialA2AArtifact, MAX_A2A_ARTIFACTS_PER_TASK, decode_initial_artifact_json,
};
use KonclaveA2ADomain::{A2AAgentRoute, A2AArtifactId, A2ATaskId};
use KonclaveA2ATaskStore::{A2ATaskArtifact, A2ATaskKey, A2ATaskStore, AppendA2ATaskRecordOutcome};
use async_trait::async_trait;

use crate::A2AGatewayError;
use crate::application::{A2AGatewayClock, map_store_error};

/// One validated artifact publication targeting an exact task.
pub struct A2AArtifactPublication {
    task_id: A2ATaskId,
    artifact: InitialA2AArtifact,
}

impl A2AArtifactPublication {
    /// Creates a publication from already validated task and artifact values.
    #[must_use]
    pub const fn new(task_id: A2ATaskId, artifact: InitialA2AArtifact) -> Self {
        Self { task_id, artifact }
    }

    /// Validates one bounded harness-authored artifact document.
    ///
    /// # Errors
    ///
    /// Returns an invalid-request error for a malformed task identifier or artifact
    /// outside the canonical A2A profile.
    pub fn from_json(task_id: &str, artifact_json: &[u8]) -> Result<Self, A2AGatewayError> {
        let task_id =
            A2ATaskId::parse(task_id.to_owned()).map_err(|_| A2AGatewayError::InvalidRequest)?;
        let artifact = decode_initial_artifact_json(artifact_json)
            .map_err(|_| A2AGatewayError::InvalidRequest)?;
        Ok(Self::new(task_id, artifact))
    }

    /// Returns the exact task identifier.
    #[must_use]
    pub const fn task_id(&self) -> &A2ATaskId {
        &self.task_id
    }
}

/// Least-privilege publication capability for a harness or gateway host.
#[async_trait]
pub trait A2AArtifactPublisher: Send + Sync {
    /// Publishes one complete validated task artifact.
    ///
    /// Exact retries are idempotent. Reusing an artifact identifier with different
    /// canonical content fails as a conflict.
    ///
    /// # Errors
    ///
    /// Returns route, task-state, storage, capacity, conflict, or clock failures.
    async fn publish(&self, publication: A2AArtifactPublication) -> Result<(), A2AGatewayError>;
}

/// Route-bound artifact publisher extracted from one gateway application.
#[derive(Clone)]
pub struct A2AGatewayArtifactPublisher {
    route: A2AAgentRoute,
    store: Arc<dyn A2ATaskStore>,
    clock: Arc<dyn A2AGatewayClock>,
}

impl A2AGatewayArtifactPublisher {
    pub(crate) fn new(
        route: A2AAgentRoute,
        store: Arc<dyn A2ATaskStore>,
        clock: Arc<dyn A2AGatewayClock>,
    ) -> Self {
        Self {
            route,
            store,
            clock,
        }
    }

    /// Validates and publishes one bounded harness-authored artifact document.
    ///
    /// The publisher supplies its immutable agent and tenant route; callers cannot
    /// select another route or infer content from a filename, path, URL, or text.
    ///
    /// # Errors
    ///
    /// Returns request, route, task-state, storage, capacity, conflict, or clock
    /// failures.
    pub async fn publish_json(
        &self,
        task_id: &str,
        artifact_json: &[u8],
    ) -> Result<(), A2AGatewayError> {
        self.publish(A2AArtifactPublication::from_json(task_id, artifact_json)?)
            .await
    }
}

#[async_trait]
impl A2AArtifactPublisher for A2AGatewayArtifactPublisher {
    async fn publish(&self, publication: A2AArtifactPublication) -> Result<(), A2AGatewayError> {
        let A2AArtifactPublication { task_id, artifact } = publication;
        let key = A2ATaskKey::new(
            self.route.agent_id().clone(),
            self.route.tenant().cloned(),
            task_id,
        );
        let artifact_id = A2AArtifactId::parse(artifact.artifact_id().to_owned())
            .map_err(|_| A2AGatewayError::InvalidRequest)?;
        let canonical_artifact = artifact.into_canonical_json();
        let store = Arc::clone(&self.store);
        let clock = Arc::clone(&self.clock);
        let expected_context = self.route.context_id().clone();
        let expected_conversation = self.route.conversation_id();
        let expected_target = self.route.target_device_id();
        tokio::task::spawn_blocking(move || {
            let task = store.get_task(&key).map_err(map_store_error)?;
            if task.context_id() != &expected_context
                || task.conversation_id() != expected_conversation
                || task.target_device_id() != expected_target
            {
                return Err(A2AGatewayError::TaskNotFound);
            }
            let recorded_at = clock
                .now_unix_milliseconds()
                .map_err(|_| A2AGatewayError::ClockUnavailable)?;
            let artifact =
                A2ATaskArtifact::new(key, artifact_id, canonical_artifact, true, recorded_at)
                    .map_err(map_store_error)?;
            match store
                .append_working_artifact(artifact, recorded_at, MAX_A2A_ARTIFACTS_PER_TASK)
                .map_err(map_store_error)?
            {
                AppendA2ATaskRecordOutcome::Appended { .. }
                | AppendA2ATaskRecordOutcome::Existing { .. } => Ok(()),
            }
        })
        .await
        .map_err(|_| A2AGatewayError::StorageUnavailable)?
    }
}
