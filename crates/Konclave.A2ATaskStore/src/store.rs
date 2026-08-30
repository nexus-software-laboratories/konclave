use crate::{
    A2ATaskArtifact, A2ATaskCreation, A2ATaskKey, A2ATaskMessage, A2ATaskRecord, A2ATaskStoreError,
    A2ATaskTransition, StoredA2ATaskArtifact, StoredA2ATaskMessage,
};

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

    /// Applies one expected-generation state transition.
    ///
    /// # Errors
    ///
    /// Returns not-found, conflict, invalid-transition, corruption, or storage errors.
    fn transition_task(
        &self,
        transition: A2ATaskTransition,
    ) -> Result<TransitionA2ATaskOutcome, A2ATaskStoreError>;

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
