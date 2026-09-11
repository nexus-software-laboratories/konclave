use crate::{
    A2ATaskArtifact, A2ATaskCreation, A2ATaskKey, A2ATaskMessage, A2ATaskRecord, A2ATaskStoreError,
    A2ATaskTransition, StoredA2ATaskArtifact, StoredA2ATaskMessage, StoredA2ATaskStatus,
};
use KonclaveA2ADomain::{A2AAgentId, A2AContextId, A2ATaskId, A2ATenantId};

/// Outcome of creating one deterministic task.
pub enum CreateA2ATaskOutcome {
    /// No prior task existed and one was created.
    Created(A2ATaskRecord),
    /// An exact task already existed.
    Existing(A2ATaskRecord),
}

/// Outcome of one expected-generation transition.
pub enum TransitionA2ATaskOutcome {
    /// The state and generation changed.
    Applied(A2ATaskRecord),
    /// The exact state transition had already been recorded.
    Existing(A2ATaskRecord),
}

/// Outcome of appending one idempotent history record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppendA2ATaskRecordOutcome {
    /// A new ordered record was appended.
    Appended {
        /// Store-assigned sequence.
        sequence: u64,
    },
    /// The exact record was already present.
    Existing {
        /// Existing store-assigned sequence.
        sequence: u64,
    },
}

/// Counts returned by one deterministic retention sweep.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct A2ATaskPruneOutcome {
    /// Terminal tasks whose retained payload rows were removed.
    pub pruned_task_payloads: usize,
    /// Expired task tombstones removed completely.
    pub removed_tombstones: usize,
}

/// One task, message window, and artifact page read from one persistence snapshot.
pub struct A2ATaskSnapshot {
    task: A2ATaskRecord,
    messages: Vec<StoredA2ATaskMessage>,
    artifacts: Vec<StoredA2ATaskArtifact>,
}

impl A2ATaskSnapshot {
    /// Creates one persistence-owned snapshot.
    #[must_use]
    pub fn new(
        task: A2ATaskRecord,
        messages: Vec<StoredA2ATaskMessage>,
        artifacts: Vec<StoredA2ATaskArtifact>,
    ) -> Self {
        Self {
            task,
            messages,
            artifacts,
        }
    }

    /// Consumes the snapshot into its task, messages, and artifacts.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        A2ATaskRecord,
        Vec<StoredA2ATaskMessage>,
        Vec<StoredA2ATaskArtifact>,
    ) {
        (self.task, self.messages, self.artifacts)
    }
}

/// Ordered stream deltas observed from one persistence snapshot.
pub struct A2ATaskStreamUpdates {
    task: A2ATaskRecord,
    statuses: Vec<StoredA2ATaskStatus>,
    artifacts: Vec<StoredA2ATaskArtifact>,
    messages: Vec<StoredA2ATaskMessage>,
}

impl A2ATaskStreamUpdates {
    /// Creates one persistence-owned stream update set.
    #[must_use]
    pub fn new(
        task: A2ATaskRecord,
        statuses: Vec<StoredA2ATaskStatus>,
        artifacts: Vec<StoredA2ATaskArtifact>,
        messages: Vec<StoredA2ATaskMessage>,
    ) -> Self {
        Self {
            task,
            statuses,
            artifacts,
            messages,
        }
    }

    /// Consumes the update set into its current task and ordered deltas.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        A2ATaskRecord,
        Vec<StoredA2ATaskStatus>,
        Vec<StoredA2ATaskArtifact>,
        Vec<StoredA2ATaskMessage>,
    ) {
        (self.task, self.statuses, self.artifacts, self.messages)
    }
}

/// Opaque cursor for deterministic task pagination.
#[derive(Clone, PartialEq, Eq)]
pub struct A2ATaskListCursor {
    created_at_unix_milliseconds: u64,
    task_id: A2ATaskId,
}

impl A2ATaskListCursor {
    /// Creates one cursor from the last visible task on a page.
    #[must_use]
    pub const fn new(created_at_unix_milliseconds: u64, task_id: A2ATaskId) -> Self {
        Self {
            created_at_unix_milliseconds,
            task_id,
        }
    }

    /// Returns the anchor creation timestamp.
    #[must_use]
    pub const fn created_at_unix_milliseconds(&self) -> u64 {
        self.created_at_unix_milliseconds
    }

    /// Returns the anchor task identifier.
    #[must_use]
    pub const fn task_id(&self) -> &A2ATaskId {
        &self.task_id
    }
}

/// Exact scoped task-list query.
#[derive(Clone, PartialEq, Eq)]
pub struct A2ATaskListQuery {
    agent_id: A2AAgentId,
    tenant: Option<A2ATenantId>,
    context_id: A2AContextId,
    page_size: usize,
    cursor: Option<A2ATaskListCursor>,
}

impl A2ATaskListQuery {
    /// Creates one exact route-scoped task-list query.
    ///
    /// # Errors
    ///
    /// Returns a configuration error when `page_size` is zero or exceeds the store
    /// hard bound.
    pub fn new(
        agent_id: A2AAgentId,
        tenant: Option<A2ATenantId>,
        context_id: A2AContextId,
        page_size: usize,
        cursor: Option<A2ATaskListCursor>,
    ) -> Result<Self, A2ATaskStoreError> {
        if page_size == 0 || page_size > 256 {
            return Err(A2ATaskStoreError::InvalidConfiguration);
        }
        Ok(Self {
            agent_id,
            tenant,
            context_id,
            page_size,
            cursor,
        })
    }

    /// Returns the scoped published agent.
    #[must_use]
    pub const fn agent_id(&self) -> &A2AAgentId {
        &self.agent_id
    }

    /// Returns the scoped tenant.
    #[must_use]
    pub const fn tenant(&self) -> Option<&A2ATenantId> {
        self.tenant.as_ref()
    }

    /// Returns the scoped public context.
    #[must_use]
    pub const fn context_id(&self) -> &A2AContextId {
        &self.context_id
    }

    /// Returns the bounded requested page size.
    #[must_use]
    pub const fn page_size(&self) -> usize {
        self.page_size
    }

    /// Returns the optional pagination cursor.
    #[must_use]
    pub const fn cursor(&self) -> Option<&A2ATaskListCursor> {
        self.cursor.as_ref()
    }
}

/// One deterministic visible task page.
pub struct A2ATaskListPage {
    tasks: Vec<A2ATaskRecord>,
    next_cursor: Option<A2ATaskListCursor>,
    page_size: usize,
    total_size: usize,
}

/// One listed task and its complete retained artifact set.
pub struct A2ATaskWithArtifacts {
    task: A2ATaskRecord,
    artifacts: Vec<StoredA2ATaskArtifact>,
}

impl A2ATaskWithArtifacts {
    /// Creates one persistence-owned listed task projection.
    #[must_use]
    pub fn new(task: A2ATaskRecord, artifacts: Vec<StoredA2ATaskArtifact>) -> Self {
        Self { task, artifacts }
    }

    /// Consumes the projection into its task and artifacts.
    #[must_use]
    pub fn into_parts(self) -> (A2ATaskRecord, Vec<StoredA2ATaskArtifact>) {
        (self.task, self.artifacts)
    }
}

/// Deterministic task page with atomically observed artifacts.
pub struct A2ATaskArtifactListPage {
    tasks: Vec<A2ATaskWithArtifacts>,
    next_cursor: Option<A2ATaskListCursor>,
    page_size: usize,
    total_size: usize,
}

impl A2ATaskArtifactListPage {
    /// Creates one persistence-owned artifact-inclusive page.
    #[must_use]
    pub fn new(
        tasks: Vec<A2ATaskWithArtifacts>,
        next_cursor: Option<A2ATaskListCursor>,
        page_size: usize,
        total_size: usize,
    ) -> Self {
        Self {
            tasks,
            next_cursor,
            page_size,
            total_size,
        }
    }

    /// Consumes the page into its records and pagination metadata.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        Vec<A2ATaskWithArtifacts>,
        Option<A2ATaskListCursor>,
        usize,
        usize,
    ) {
        (
            self.tasks,
            self.next_cursor,
            self.page_size,
            self.total_size,
        )
    }
}

impl A2ATaskListPage {
    /// Creates one visible page.
    #[must_use]
    pub fn new(
        tasks: Vec<A2ATaskRecord>,
        next_cursor: Option<A2ATaskListCursor>,
        page_size: usize,
        total_size: usize,
    ) -> Self {
        Self {
            tasks,
            next_cursor,
            page_size,
            total_size,
        }
    }

    /// Returns the visible tasks.
    #[must_use]
    pub fn tasks(&self) -> &[A2ATaskRecord] {
        &self.tasks
    }

    /// Returns the next cursor, when another page exists.
    #[must_use]
    pub const fn next_cursor(&self) -> Option<&A2ATaskListCursor> {
        self.next_cursor.as_ref()
    }

    /// Returns the effective page size.
    #[must_use]
    pub const fn page_size(&self) -> usize {
        self.page_size
    }

    /// Returns the number of visible tasks in this scope before pagination.
    #[must_use]
    pub const fn total_size(&self) -> usize {
        self.total_size
    }

    /// Consumes the page and returns its tasks.
    #[must_use]
    pub fn into_tasks(self) -> Vec<A2ATaskRecord> {
        self.tasks
    }

    /// Consumes the page and returns every owned component.
    #[must_use]
    pub fn into_parts(self) -> (Vec<A2ATaskRecord>, Option<A2ATaskListCursor>, usize, usize) {
        (
            self.tasks,
            self.next_cursor,
            self.page_size,
            self.total_size,
        )
    }
}

/// Portable semantic contract implemented by public and managed A2A task stores.
pub trait A2ATaskStore: Send + Sync {
    /// Creates one deterministic task or reconciles an exact retry.
    ///
    /// # Errors
    ///
    /// Returns conflict, capacity, corruption, configuration, or storage errors.
    fn create_task(
        &self,
        creation: A2ATaskCreation,
    ) -> Result<CreateA2ATaskOutcome, A2ATaskStoreError>;

    /// Loads one exact agent- and tenant-scoped task.
    ///
    /// # Errors
    ///
    /// Returns not-found, corruption, or storage errors.
    fn get_task(&self, key: &A2ATaskKey) -> Result<A2ATaskRecord, A2ATaskStoreError>;

    /// Lists visible tasks for one exact agent, tenant, and context scope.
    ///
    /// Content-pruned tombstones remain internal idempotency state and are therefore
    /// excluded from the caller-visible page.
    ///
    /// # Errors
    ///
    /// Returns invalid-query, corruption, or storage errors.
    fn list_tasks(&self, query: &A2ATaskListQuery) -> Result<A2ATaskListPage, A2ATaskStoreError>;

    /// Lists visible tasks with each retained artifact set from one snapshot.
    ///
    /// # Errors
    ///
    /// Returns invalid-query, corruption, or storage errors.
    fn list_tasks_with_artifacts(
        &self,
        query: &A2ATaskListQuery,
    ) -> Result<A2ATaskArtifactListPage, A2ATaskStoreError>;

    /// Applies one expected-generation state transition.
    ///
    /// # Errors
    ///
    /// Returns not-found, conflict, invalid-transition, corruption, or storage errors.
    fn transition_task(
        &self,
        transition: A2ATaskTransition,
    ) -> Result<TransitionA2ATaskOutcome, A2ATaskStoreError>;

    /// Reads all durable status records after one previously observed generation.
    ///
    /// The returned records are consecutive and ordered by generation. An empty
    /// result means the task has not transitioned since the supplied cursor.
    ///
    /// # Errors
    ///
    /// Returns not-found, corruption, or storage errors.
    fn status_updates(
        &self,
        key: &A2ATaskKey,
        after_generation: u64,
    ) -> Result<Vec<StoredA2ATaskStatus>, A2ATaskStoreError>;

    /// Appends one ordered idempotent task message.
    ///
    /// `now_unix_milliseconds` drives retention eligibility and is independent from
    /// the message's first accepted display timestamp.
    ///
    /// # Errors
    ///
    /// Returns not-found, conflict, capacity, corruption, or storage errors.
    fn append_message(
        &self,
        message: A2ATaskMessage,
        now_unix_milliseconds: u64,
    ) -> Result<AppendA2ATaskRecordOutcome, A2ATaskStoreError>;

    /// Appends one ordered idempotent canonical artifact record.
    ///
    /// `now_unix_milliseconds` drives retention eligibility and is independent from
    /// the artifact's first accepted display timestamp.
    ///
    /// # Errors
    ///
    /// Returns not-found, conflict, capacity, corruption, or storage errors.
    fn append_artifact(
        &self,
        artifact: A2ATaskArtifact,
        now_unix_milliseconds: u64,
    ) -> Result<AppendA2ATaskRecordOutcome, A2ATaskStoreError>;

    /// Appends one artifact only when new content targets a `WORKING` task.
    ///
    /// An exact existing artifact remains idempotent after terminal transition.
    ///
    /// # Errors
    ///
    /// Returns not-found, invalid-transition, conflict, capacity, corruption, or
    /// storage errors.
    fn append_working_artifact(
        &self,
        artifact: A2ATaskArtifact,
        now_unix_milliseconds: u64,
    ) -> Result<AppendA2ATaskRecordOutcome, A2ATaskStoreError>;

    /// Reads the most recent bounded message window in chronological order.
    ///
    /// # Errors
    ///
    /// Returns bounds, not-found, corruption, or storage errors.
    fn messages(
        &self,
        key: &A2ATaskKey,
        limit: usize,
    ) -> Result<Vec<StoredA2ATaskMessage>, A2ATaskStoreError>;

    /// Reads one task and its most recent bounded message window from the same
    /// persistence snapshot.
    ///
    /// # Errors
    ///
    /// Returns bounds, not-found, corruption, or storage errors.
    fn task_with_messages(
        &self,
        key: &A2ATaskKey,
        limit: usize,
    ) -> Result<(A2ATaskRecord, Vec<StoredA2ATaskMessage>), A2ATaskStoreError>;

    /// Reads one task, message window, and artifact page from the same snapshot.
    ///
    /// # Errors
    ///
    /// Returns bounds, not-found, corruption, or storage errors.
    fn task_snapshot(
        &self,
        key: &A2ATaskKey,
        message_limit: usize,
    ) -> Result<A2ATaskSnapshot, A2ATaskStoreError>;

    /// Reads status and artifact deltas after durable internal cursors.
    ///
    /// Artifacts precede terminal status transitions within the returned snapshot
    /// because terminal tasks reject later artifact appends.
    ///
    /// # Errors
    ///
    /// Returns bounds, not-found, corruption, or storage errors.
    fn stream_updates(
        &self,
        key: &A2ATaskKey,
        after_generation: u64,
        after_artifact_sequence: u64,
        message_limit: usize,
    ) -> Result<A2ATaskStreamUpdates, A2ATaskStoreError>;

    /// Reads a bounded ordered artifact page from sequence zero.
    ///
    /// # Errors
    ///
    /// Returns bounds, not-found, corruption, or storage errors.
    fn artifacts(
        &self,
        key: &A2ATaskKey,
        limit: usize,
    ) -> Result<Vec<StoredA2ATaskArtifact>, A2ATaskStoreError>;

    /// Removes eligible expired terminal payloads and tombstones.
    ///
    /// # Errors
    ///
    /// Returns corruption or storage errors.
    fn prune(&self, now_unix_milliseconds: u64) -> Result<A2ATaskPruneOutcome, A2ATaskStoreError>;
}
