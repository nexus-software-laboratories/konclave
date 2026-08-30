use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use KonclaveA2AContracts::wire::TaskState;
use KonclaveA2AContracts::{
    InitialA2AAgentCard, InitialA2ATaskResponse, InitialGetTaskRequest, InitialSendMessageRequest,
};
use KonclaveA2ADiscovery::CompiledA2AAgentPublication;
use KonclaveA2ADomain::{
    A2AAgentRoute, A2AMessageId, map_initial_get_task, map_initial_send_message,
};
use KonclaveA2ATaskStore::{
    A2ATaskCreation, A2ATaskKey, A2ATaskRecord, A2ATaskStore, A2ATaskStoreError,
    CreateA2ATaskOutcome,
};
use KonclaveA2ATaskStoreSqlite::{A2ASqliteTaskStore, A2ASqliteTaskStoreConfig};
use KonclaveDomainCore::{ConversationId, DeviceId, MessageId};
use async_trait::async_trait;
use tokio::time::{Instant, sleep, timeout_at};

use crate::A2AGatewayError;
use crate::projection::project_task;

const MAX_RESPONSE_WAIT: Duration = Duration::from_secs(5 * 60);
const MAX_RESPONSE_POLL: Duration = Duration::from_secs(1);

/// Bounded wait behavior for non-immediate `SendMessage` requests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct A2AGatewayWaitConfig {
    timeout: Duration,
    poll_interval: Duration,
}

impl A2AGatewayWaitConfig {
    /// Creates one finite response-wait configuration.
    ///
    /// # Errors
    ///
    /// Returns a configuration error when either duration is zero, exceeds its hard
    /// bound, or the poll interval exceeds the wait timeout.
    pub fn new(timeout: Duration, poll_interval: Duration) -> Result<Self, A2AGatewayError> {
        if timeout.is_zero()
            || timeout > MAX_RESPONSE_WAIT
            || poll_interval.is_zero()
            || poll_interval > MAX_RESPONSE_POLL
            || poll_interval > timeout
        {
            return Err(A2AGatewayError::InvalidConfiguration);
        }
        Ok(Self {
            timeout,
            poll_interval,
        })
    }
}

impl Default for A2AGatewayWaitConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            poll_interval: Duration::from_millis(250),
        }
    }
}

/// Clock boundary used for durable first-accepted task timestamps.
pub trait A2AGatewayClock: Send + Sync {
    /// Returns current Unix time in milliseconds.
    ///
    /// # Errors
    ///
    /// Returns a clock error when a nonnegative bounded Unix timestamp is unavailable.
    fn now_unix_milliseconds(&self) -> Result<u64, A2AGatewayClockError>;
}

/// Opaque clock failure that carries no environment details.
#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("A2A gateway clock is unavailable")]
pub struct A2AGatewayClockError;

/// System clock implementation used by a composed gateway process.
pub struct SystemA2AGatewayClock;

impl A2AGatewayClock for SystemA2AGatewayClock {
    fn now_unix_milliseconds(&self) -> Result<u64, A2AGatewayClockError> {
        let milliseconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| A2AGatewayClockError)?
            .as_millis();
        u64::try_from(milliseconds).map_err(|_| A2AGatewayClockError)
    }
}

/// One idempotent task submission emitted after durable task creation.
///
/// Implementations use `request_message_id` as the stable downstream idempotency
/// identity. The submission intentionally does not implement `Clone` or `Debug`
/// because it contains request plaintext.
pub struct A2ATaskSubmission {
    key: A2ATaskKey,
    source_message_id: A2AMessageId,
    conversation_id: ConversationId,
    target_device_id: DeviceId,
    request_message_id: MessageId,
    text: String,
}

impl A2ATaskSubmission {
    /// Returns the exact durable task key.
    #[must_use]
    pub const fn key(&self) -> &A2ATaskKey {
        &self.key
    }

    /// Returns the caller's source A2A message identifier.
    #[must_use]
    pub const fn source_message_id(&self) -> &A2AMessageId {
        &self.source_message_id
    }

    /// Returns the configured Konclave conversation.
    #[must_use]
    pub const fn conversation_id(&self) -> ConversationId {
        self.conversation_id
    }

    /// Returns the exact configured responder.
    #[must_use]
    pub const fn target_device_id(&self) -> DeviceId {
        self.target_device_id
    }

    /// Returns the stable downstream idempotency identifier.
    #[must_use]
    pub const fn request_message_id(&self) -> MessageId {
        self.request_message_id
    }

    /// Returns the bounded request plaintext.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Returns the request plaintext and consumes the submission.
    #[must_use]
    pub fn into_text(self) -> String {
        self.text
    }
}

/// Opaque downstream submission failure.
#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("A2A task submission failed")]
pub struct A2ATaskSubmissionError;

/// Idempotent boundary implemented by the later Konclave bridge.
#[async_trait]
pub trait A2ATaskSubmitter: Send + Sync {
    /// Ensures one durably created task is submitted downstream.
    ///
    /// Repeated calls for the same `request_message_id` are expected after retries or
    /// process recovery and must not duplicate the downstream side effect.
    async fn submit(&self, submission: A2ATaskSubmission) -> Result<(), A2ATaskSubmissionError>;
}

/// Single-publication application core shared by HTTP handlers and tests.
#[derive(Clone)]
pub struct A2AGatewayApplication {
    route: A2AAgentRoute,
    publication: Arc<CompiledA2AAgentPublication>,
    store: Arc<dyn A2ATaskStore>,
    submitter: Arc<dyn A2ATaskSubmitter>,
    clock: Arc<dyn A2AGatewayClock>,
    wait: A2AGatewayWaitConfig,
}

impl A2AGatewayApplication {
    /// Creates one gateway application for an exact publication and Konclave route.
    ///
    /// # Errors
    ///
    /// Returns a configuration error when publication identity or interface tenant
    /// differs from the selected route.
    pub fn new(
        route: A2AAgentRoute,
        publication: CompiledA2AAgentPublication,
        store: Arc<dyn A2ATaskStore>,
        submitter: Arc<dyn A2ATaskSubmitter>,
        clock: Arc<dyn A2AGatewayClock>,
        wait: A2AGatewayWaitConfig,
    ) -> Result<Self, A2AGatewayError> {
        if publication.id() != route.agent_id()
            || publication
                .card()
                .interfaces()
                .iter()
                .any(|interface| interface.tenant() != route.tenant().map(|tenant| tenant.as_str()))
        {
            return Err(A2AGatewayError::InvalidConfiguration);
        }
        Ok(Self {
            route,
            publication: Arc::new(publication),
            store,
            submitter,
            clock,
            wait,
        })
    }

    /// Opens the complete public SQLite reference store and creates one gateway
    /// application.
    ///
    /// # Errors
    ///
    /// Returns a configuration, schema, storage, publication-route, or wait-policy
    /// failure.
    pub fn open_sqlite(
        route: A2AAgentRoute,
        publication: CompiledA2AAgentPublication,
        database_path: impl AsRef<Path>,
        store_config: A2ASqliteTaskStoreConfig,
        submitter: Arc<dyn A2ATaskSubmitter>,
        clock: Arc<dyn A2AGatewayClock>,
        wait: A2AGatewayWaitConfig,
    ) -> Result<Self, A2AGatewayError> {
        let store =
            A2ASqliteTaskStore::open(database_path, store_config).map_err(map_store_error)?;
        Self::new(route, publication, Arc::new(store), submitter, clock, wait)
    }

    /// Returns the configured base card for direct composition.
    #[must_use]
    pub fn card(&self) -> &InitialA2AAgentCard {
        self.publication.card()
    }

    /// Returns the configured opaque A2A tenant routing value.
    #[must_use]
    pub fn tenant(&self) -> Option<&str> {
        self.route.tenant().map(|tenant| tenant.as_str())
    }

    /// Returns the card only when public well-known discovery is enabled.
    #[must_use]
    pub fn public_card(&self) -> Option<&InitialA2AAgentCard> {
        self.publication
            .publicly_discoverable()
            .then(|| self.publication.card())
    }

    /// Returns the fixed authenticated extended card when configured.
    #[must_use]
    pub fn extended_card(&self) -> Option<&InitialA2AAgentCard> {
        self.publication.extended_card()
    }

    /// Creates or reconciles one task, submits new or recoverable work idempotently,
    /// and returns according to the request's immediate/wait preference.
    ///
    /// # Errors
    ///
    /// Returns typed route, storage, conflict, capacity, submission, projection, or
    /// response-wait failures.
    pub async fn send_message(
        &self,
        request: InitialSendMessageRequest,
    ) -> Result<InitialA2ATaskResponse, A2AGatewayError> {
        let return_immediately = request.return_immediately();
        let history_length = request.history_length();
        let mapping = map_initial_send_message(&self.route, request)
            .map_err(|_| A2AGatewayError::RouteMismatch)?;
        let created_at = self
            .clock
            .now_unix_milliseconds()
            .map_err(|_| A2AGatewayError::ClockUnavailable)?;
        let creation = A2ATaskCreation::from_mapping(mapping, created_at);
        let store = Arc::clone(&self.store);
        let outcome = tokio::task::spawn_blocking(move || store.create_task(creation))
            .await
            .map_err(|_| A2AGatewayError::StorageUnavailable)?
            .map_err(map_store_error)?;
        let record = match outcome {
            CreateA2ATaskOutcome::Created(record) | CreateA2ATaskOutcome::Existing(record) => {
                record
            }
        };
        let key = record.key().clone();
        let deadline = Instant::now() + self.wait.timeout;
        if matches!(
            record.state(),
            KonclaveA2ADomain::A2ATaskState::Submitted | KonclaveA2ADomain::A2ATaskState::Working
        ) {
            let submission = submission_from_record(record)?;
            timeout_at(deadline, self.submitter.submit(submission))
                .await
                .map_err(|_| A2AGatewayError::ResponseWaitExpired)?
                .map_err(|_| A2AGatewayError::SubmissionUnavailable)?;
        }
        if return_immediately {
            return timeout_at(deadline, self.project_current(key, history_length))
                .await
                .map_err(|_| A2AGatewayError::ResponseWaitExpired)?;
        }
        let wait = async {
            loop {
                let task = self.project_current(key.clone(), history_length).await?;
                if response_ready(task.state()) {
                    return Ok(task);
                }
                sleep(self.wait.poll_interval).await;
            }
        };
        timeout_at(deadline, wait)
            .await
            .map_err(|_| A2AGatewayError::ResponseWaitExpired)?
    }

    /// Loads one exact task with the requested initial-profile history window.
    ///
    /// # Errors
    ///
    /// Returns route, not-found, storage, or projection failures.
    pub async fn get_task(
        &self,
        request: InitialGetTaskRequest,
    ) -> Result<InitialA2ATaskResponse, A2AGatewayError> {
        let lookup = map_initial_get_task(&self.route, request)
            .map_err(|_| A2AGatewayError::RouteMismatch)?;
        let history_length = lookup.history_length();
        let key = A2ATaskKey::new(
            lookup.agent_id().clone(),
            lookup.tenant().cloned(),
            lookup.task_id().clone(),
        );
        self.project_current(key, history_length).await
    }

    async fn project_current(
        &self,
        key: A2ATaskKey,
        history_length: Option<u32>,
    ) -> Result<InitialA2ATaskResponse, A2AGatewayError> {
        let store = Arc::clone(&self.store);
        tokio::task::spawn_blocking(move || {
            let (record, messages) = store.task_with_messages(&key, 2).map_err(map_store_error)?;
            project_task(record, messages, history_length)
        })
        .await
        .map_err(|_| A2AGatewayError::StorageUnavailable)?
    }
}

fn submission_from_record(record: A2ATaskRecord) -> Result<A2ATaskSubmission, A2AGatewayError> {
    let key = record.key().clone();
    let source_message_id = record.source_message_id().clone();
    let conversation_id = record.conversation_id();
    let target_device_id = record.target_device_id();
    let request_message_id = record.request_message_id();
    let text = record
        .into_request_text()
        .ok_or(A2AGatewayError::InvalidTaskProjection)?;
    Ok(A2ATaskSubmission {
        key,
        source_message_id,
        conversation_id,
        target_device_id,
        request_message_id,
        text,
    })
}

fn response_ready(state: TaskState) -> bool {
    matches!(
        state,
        TaskState::Completed
            | TaskState::Failed
            | TaskState::Canceled
            | TaskState::InputRequired
            | TaskState::Rejected
            | TaskState::AuthRequired
    )
}

fn map_store_error(error: A2ATaskStoreError) -> A2AGatewayError {
    match error {
        A2ATaskStoreError::InvalidConfiguration | A2ATaskStoreError::InvalidTransition => {
            A2AGatewayError::InvalidTaskProjection
        }
        A2ATaskStoreError::NotFound => A2AGatewayError::TaskNotFound,
        A2ATaskStoreError::Conflict => A2AGatewayError::Conflict,
        A2ATaskStoreError::CapacityExceeded => A2AGatewayError::CapacityExceeded,
        A2ATaskStoreError::CorruptData => A2AGatewayError::InvalidTaskProjection,
        A2ATaskStoreError::Storage => A2AGatewayError::StorageUnavailable,
    }
}
