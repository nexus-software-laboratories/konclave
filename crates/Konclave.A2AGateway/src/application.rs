use std::collections::VecDeque;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use KonclaveA2AContracts::wire::TaskState;
use KonclaveA2AContracts::{
    InitialA2AAgentCard, InitialA2AArtifact, InitialA2AStreamResponse, InitialA2ATaskListResponse,
    InitialA2ATaskResponse, InitialGetTaskRequest, InitialListTasksRequest,
    InitialSendMessageRequest, InitialSubscribeToTaskRequest,
};
use KonclaveA2ADiscovery::CompiledA2AAgentPublication;
use KonclaveA2ADomain::{
    A2AAgentRoute, A2AArtifactId, A2AMessageId, A2ATaskId, A2ATaskState, map_initial_get_task,
    map_initial_list_tasks, map_initial_send_message, map_initial_streaming_message,
    map_initial_subscribe_to_task,
};
use KonclaveA2ATaskStore::{
    A2ATaskArtifact, A2ATaskCreation, A2ATaskKey, A2ATaskListCursor, A2ATaskListQuery,
    A2ATaskRecord, A2ATaskStore, A2ATaskStoreError, AppendA2ATaskRecordOutcome,
    CreateA2ATaskOutcome,
};
use KonclaveA2ATaskStoreSqlite::{A2ASqliteTaskStore, A2ASqliteTaskStoreConfig};
use KonclaveDomainCore::{ConversationId, DeviceId, MessageId};
use async_trait::async_trait;
use futures_util::StreamExt as _;
use futures_util::stream::{self, BoxStream};
use tokio::time::{Instant, sleep, sleep_until, timeout_at};

use crate::A2AGatewayError;
use crate::projection::{
    project_artifact_update, project_get_task, project_list_tasks, project_status_update,
    project_stream_task,
};

const MAX_RESPONSE_WAIT: Duration = Duration::from_secs(5 * 60);
const MAX_RESPONSE_POLL: Duration = Duration::from_secs(1);
const PAGE_TOKEN_PREFIX: &str = "v1";

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

/// Finite ordered stream of validated A2A task snapshots and status updates.
pub type A2AGatewayTaskStream =
    BoxStream<'static, Result<InitialA2AStreamResponse, A2AGatewayError>>;

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
        let prepared = self.prepare_task(request, false).await?;
        if return_immediately {
            return timeout_at(
                prepared.deadline,
                self.project_current(prepared.key, prepared.history_length),
            )
            .await
            .map_err(|_| A2AGatewayError::ResponseWaitExpired)?;
        }
        let wait = async {
            loop {
                let task = self
                    .project_current(prepared.key.clone(), prepared.history_length)
                    .await?;
                if response_ready(task.state()) {
                    return Ok(task);
                }
                sleep(self.wait.poll_interval).await;
            }
        };
        timeout_at(prepared.deadline, wait)
            .await
            .map_err(|_| A2AGatewayError::ResponseWaitExpired)?
    }

    /// Creates or reconciles one task and returns an ordered finite streaming response.
    ///
    /// `returnImmediately` has no effect on streaming behavior, as required by A2A.
    ///
    /// # Errors
    ///
    /// Returns typed route, storage, conflict, capacity, submission, projection, or
    /// response-wait failures before the stream begins.
    pub async fn send_streaming_message(
        &self,
        request: InitialSendMessageRequest,
    ) -> Result<A2AGatewayTaskStream, A2AGatewayError> {
        let prepared = self.prepare_task(request, true).await?;
        self.stream_task(
            prepared.key,
            prepared.history_length,
            prepared.deadline,
            false,
        )
        .await
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
        self.prune_visible_tasks().await?;
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

    /// Lists visible tasks in the configured route scope.
    ///
    /// # Errors
    ///
    /// Returns route, invalid-request, storage, or projection failures.
    pub async fn list_tasks(
        &self,
        request: InitialListTasksRequest,
    ) -> Result<InitialA2ATaskListResponse, A2AGatewayError> {
        self.prune_visible_tasks().await?;
        let lookup = map_initial_list_tasks(&self.route, request)
            .map_err(|_| A2AGatewayError::RouteMismatch)?;
        let cursor = decode_page_token(lookup.page_token())?;
        let query = A2ATaskListQuery::new(
            lookup.agent_id().clone(),
            lookup.tenant().cloned(),
            lookup.context_id().clone(),
            usize::try_from(lookup.page_size()).map_err(|_| A2AGatewayError::InvalidRequest)?,
            cursor,
        )
        .map_err(|_| A2AGatewayError::InvalidRequest)?;
        let store = Arc::clone(&self.store);
        let (tasks, next_cursor, page_size, total_size) = if lookup.include_artifacts() {
            let page = tokio::task::spawn_blocking(move || store.list_tasks_with_artifacts(&query))
                .await
                .map_err(|_| A2AGatewayError::StorageUnavailable)?
                .map_err(map_store_error)?;
            let (tasks, next_cursor, page_size, total_size) = page.into_parts();
            (
                tasks
                    .into_iter()
                    .map(KonclaveA2ATaskStore::A2ATaskWithArtifacts::into_parts)
                    .collect(),
                next_cursor,
                page_size,
                total_size,
            )
        } else {
            let page = tokio::task::spawn_blocking(move || store.list_tasks(&query))
                .await
                .map_err(|_| A2AGatewayError::StorageUnavailable)?
                .map_err(map_store_error)?;
            let (tasks, next_cursor, page_size, total_size) = page.into_parts();
            (
                tasks.into_iter().map(|task| (task, Vec::new())).collect(),
                next_cursor,
                page_size,
                total_size,
            )
        };
        project_list_tasks(
            tasks,
            next_cursor.as_ref().map(encode_page_token),
            page_size,
            total_size,
        )
    }

    /// Subscribes to one active task with a current Task snapshot as the first event.
    ///
    /// # Errors
    ///
    /// Returns route, not-found, unsupported-terminal-state, storage, or projection
    /// failures before the stream begins.
    pub async fn subscribe_to_task(
        &self,
        request: InitialSubscribeToTaskRequest,
    ) -> Result<A2AGatewayTaskStream, A2AGatewayError> {
        self.prune_visible_tasks().await?;
        let lookup = map_initial_subscribe_to_task(&self.route, request)
            .map_err(|_| A2AGatewayError::RouteMismatch)?;
        let key = A2ATaskKey::new(
            lookup.agent_id().clone(),
            lookup.tenant().cloned(),
            lookup.task_id().clone(),
        );
        self.stream_task(key, Some(1), Instant::now() + self.wait.timeout, true)
            .await
    }

    /// Publishes one complete validated artifact for an active task.
    ///
    /// The task must already be `WORKING`. This operation does not transition task
    /// state; orchestration publishes terminal state separately after all outputs are
    /// durable.
    ///
    /// # Errors
    ///
    /// Returns route, task-state, storage, capacity, conflict, or clock failures.
    pub async fn publish_artifact(
        &self,
        task_id: &A2ATaskId,
        artifact: InitialA2AArtifact,
    ) -> Result<(), A2AGatewayError> {
        let key = A2ATaskKey::new(
            self.route.agent_id().clone(),
            self.route.tenant().cloned(),
            task_id.clone(),
        );
        let artifact_id = A2AArtifactId::parse(artifact.artifact_id().to_owned())
            .map_err(|_| A2AGatewayError::InvalidRequest)?;
        let recorded_at = self
            .clock
            .now_unix_milliseconds()
            .map_err(|_| A2AGatewayError::ClockUnavailable)?;
        let artifact = A2ATaskArtifact::new(
            key.clone(),
            artifact_id,
            artifact.into_canonical_json(),
            true,
            recorded_at,
        )
        .map_err(map_store_error)?;
        let store = Arc::clone(&self.store);
        tokio::task::spawn_blocking(move || {
            match store
                .append_working_artifact(artifact, recorded_at)
                .map_err(map_store_error)?
            {
                AppendA2ATaskRecordOutcome::Appended { .. }
                | AppendA2ATaskRecordOutcome::Existing { .. } => Ok(()),
            }
        })
        .await
        .map_err(|_| A2AGatewayError::StorageUnavailable)?
    }

    async fn prepare_task(
        &self,
        request: InitialSendMessageRequest,
        streaming: bool,
    ) -> Result<PreparedTask, A2AGatewayError> {
        let history_length = request.history_length();
        let mapping = if streaming {
            map_initial_streaming_message(&self.route, request)
        } else {
            map_initial_send_message(&self.route, request)
        }
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
            A2ATaskState::Submitted | A2ATaskState::Working
        ) {
            let submission = submission_from_record(record)?;
            timeout_at(deadline, self.submitter.submit(submission))
                .await
                .map_err(|_| A2AGatewayError::ResponseWaitExpired)?
                .map_err(|_| A2AGatewayError::SubmissionUnavailable)?;
        }
        Ok(PreparedTask {
            key,
            history_length,
            deadline,
        })
    }

    async fn stream_task(
        &self,
        key: A2ATaskKey,
        history_length: Option<u32>,
        deadline: Instant,
        reject_terminal: bool,
    ) -> Result<A2AGatewayTaskStream, A2AGatewayError> {
        let (initial, generation, artifact_sequence) =
            self.stream_snapshot(key.clone(), history_length).await?;
        if reject_terminal && terminal_state(initial.state()) {
            return Err(A2AGatewayError::UnsupportedOperation);
        }
        let state = TaskStreamState {
            application: self.clone(),
            key,
            task_id: initial.task_id().to_owned(),
            context_id: initial.context_id().to_owned(),
            generation,
            artifact_sequence,
            has_complete_artifact: initial
                .as_wire()
                .payload
                .as_ref()
                .and_then(|payload| match payload {
                    KonclaveA2AContracts::wire::stream_response::Payload::Task(task) => {
                        Some(!task.artifacts.is_empty())
                    }
                    _ => None,
                })
                .unwrap_or(false),
            deadline,
            finished: response_ready(initial.state()),
            pending: VecDeque::from([initial]),
        };
        Ok(stream::try_unfold(state, |mut state| async move {
            loop {
                if let Some(event) = state.pending.pop_front() {
                    return Ok(Some((event, state)));
                }
                if state.finished || Instant::now() >= state.deadline {
                    return Ok(None);
                }
                let next_poll =
                    (Instant::now() + state.application.wait.poll_interval).min(state.deadline);
                sleep_until(next_poll).await;
                if Instant::now() >= state.deadline {
                    return Ok(None);
                }
                let (status_updates, artifact_updates, messages) = state
                    .application
                    .stream_updates(state.key.clone(), state.generation, state.artifact_sequence)
                    .await?;
                for artifact in artifact_updates {
                    state.artifact_sequence = artifact.sequence();
                    state.has_complete_artifact = true;
                    state.pending.push_back(project_artifact_update(
                        &state.task_id,
                        &state.context_id,
                        artifact,
                    )?);
                }
                for update in status_updates {
                    state.generation = update.generation();
                    let event = project_status_update(
                        &state.task_id,
                        &state.context_id,
                        update,
                        &messages,
                        state.has_complete_artifact,
                    )?;
                    if response_ready(event.state()) {
                        state.finished = true;
                    }
                    state.pending.push_back(event);
                }
            }
        })
        .boxed())
    }

    async fn stream_snapshot(
        &self,
        key: A2ATaskKey,
        history_length: Option<u32>,
    ) -> Result<(InitialA2AStreamResponse, u64, u64), A2AGatewayError> {
        let store = Arc::clone(&self.store);
        tokio::task::spawn_blocking(move || {
            let snapshot = store.task_snapshot(&key, 2).map_err(map_store_error)?;
            let (record, messages, artifacts) = snapshot.into_parts();
            if record.content_pruned() {
                return Err(A2AGatewayError::TaskNotFound);
            }
            let generation = record.generation();
            let artifact_sequence = artifacts.last().map_or(0, |artifact| artifact.sequence());
            Ok((
                project_stream_task(record, messages, artifacts, history_length)?,
                generation,
                artifact_sequence,
            ))
        })
        .await
        .map_err(|_| A2AGatewayError::StorageUnavailable)?
    }

    async fn stream_updates(
        &self,
        key: A2ATaskKey,
        after_generation: u64,
        after_artifact_sequence: u64,
    ) -> Result<
        (
            Vec<KonclaveA2ATaskStore::StoredA2ATaskStatus>,
            Vec<KonclaveA2ATaskStore::StoredA2ATaskArtifact>,
            Vec<KonclaveA2ATaskStore::StoredA2ATaskMessage>,
        ),
        A2AGatewayError,
    > {
        let store = Arc::clone(&self.store);
        tokio::task::spawn_blocking(move || {
            let updates = store
                .stream_updates(&key, after_generation, after_artifact_sequence, 2)
                .map_err(map_store_error)?;
            let (task, statuses, artifacts, messages) = updates.into_parts();
            if task.content_pruned() {
                return Err(A2AGatewayError::TaskNotFound);
            }
            Ok((statuses, artifacts, messages))
        })
        .await
        .map_err(|_| A2AGatewayError::StorageUnavailable)?
    }

    async fn project_current(
        &self,
        key: A2ATaskKey,
        history_length: Option<u32>,
    ) -> Result<InitialA2ATaskResponse, A2AGatewayError> {
        let store = Arc::clone(&self.store);
        tokio::task::spawn_blocking(move || {
            let snapshot = store.task_snapshot(&key, 2).map_err(map_store_error)?;
            let (record, messages, artifacts) = snapshot.into_parts();
            if record.content_pruned() {
                return Err(A2AGatewayError::TaskNotFound);
            }
            project_get_task(record, messages, artifacts, history_length)
        })
        .await
        .map_err(|_| A2AGatewayError::StorageUnavailable)?
    }

    async fn prune_visible_tasks(&self) -> Result<(), A2AGatewayError> {
        let now = self
            .clock
            .now_unix_milliseconds()
            .map_err(|_| A2AGatewayError::ClockUnavailable)?;
        let store = Arc::clone(&self.store);
        tokio::task::spawn_blocking(move || store.prune(now))
            .await
            .map_err(|_| A2AGatewayError::StorageUnavailable)?
            .map_err(map_store_error)?;
        Ok(())
    }
}

struct PreparedTask {
    key: A2ATaskKey,
    history_length: Option<u32>,
    deadline: Instant,
}

struct TaskStreamState {
    application: A2AGatewayApplication,
    key: A2ATaskKey,
    task_id: String,
    context_id: String,
    generation: u64,
    artifact_sequence: u64,
    has_complete_artifact: bool,
    deadline: Instant,
    finished: bool,
    pending: VecDeque<InitialA2AStreamResponse>,
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

fn terminal_state(state: TaskState) -> bool {
    matches!(
        state,
        TaskState::Completed | TaskState::Failed | TaskState::Canceled | TaskState::Rejected
    )
}

fn encode_page_token(cursor: &A2ATaskListCursor) -> String {
    format!(
        "{PAGE_TOKEN_PREFIX}.{}.{}",
        cursor.created_at_unix_milliseconds(),
        cursor.task_id().as_str()
    )
}

fn decode_page_token(value: Option<&str>) -> Result<Option<A2ATaskListCursor>, A2AGatewayError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let mut segments = value.split('.');
    let Some(prefix) = segments.next() else {
        return Err(A2AGatewayError::InvalidRequest);
    };
    if prefix != PAGE_TOKEN_PREFIX {
        return Err(A2AGatewayError::InvalidRequest);
    }
    let Some(created_at) = segments.next() else {
        return Err(A2AGatewayError::InvalidRequest);
    };
    let Some(task_id) = segments.next() else {
        return Err(A2AGatewayError::InvalidRequest);
    };
    if segments.next().is_some() {
        return Err(A2AGatewayError::InvalidRequest);
    }
    Ok(Some(A2ATaskListCursor::new(
        created_at
            .parse::<u64>()
            .map_err(|_| A2AGatewayError::InvalidRequest)?,
        A2ATaskId::parse(task_id.to_owned()).map_err(|_| A2AGatewayError::InvalidRequest)?,
    )))
}

fn map_store_error(error: A2ATaskStoreError) -> A2AGatewayError {
    match error {
        A2ATaskStoreError::InvalidConfiguration => A2AGatewayError::InvalidConfiguration,
        A2ATaskStoreError::InvalidTransition => A2AGatewayError::InvalidTaskProjection,
        A2ATaskStoreError::NotFound => A2AGatewayError::TaskNotFound,
        A2ATaskStoreError::Conflict => A2AGatewayError::Conflict,
        A2ATaskStoreError::CapacityExceeded => A2AGatewayError::CapacityExceeded,
        A2ATaskStoreError::CorruptData => A2AGatewayError::InvalidTaskProjection,
        A2ATaskStoreError::Storage => A2AGatewayError::StorageUnavailable,
    }
}
