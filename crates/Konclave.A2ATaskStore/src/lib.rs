#![forbid(unsafe_code)]
#![allow(non_snake_case)]

mod error;
mod model;
mod policy;
mod record;
mod store;

pub use error::A2ATaskStoreError;
pub use model::{
    A2ATaskArtifact, A2ATaskCreation, A2ATaskKey, A2ATaskMessage, A2ATaskMessageRole,
    A2ATaskTransition, A2ATerminalReason, MAX_A2A_STORED_ARTIFACT_BYTES,
    MAX_A2A_TERMINAL_REASON_BYTES,
};
pub use policy::{
    A2ATaskTransitionPlan, a2a_task_state_is_terminal, a2a_task_state_transition_is_allowed,
    a2a_task_status_reason_is_valid, plan_a2a_task_transition, validate_a2a_task_shape,
    validate_a2a_task_status_history,
};
pub use record::{A2ATaskRecord, StoredA2ATaskArtifact, StoredA2ATaskMessage, StoredA2ATaskStatus};
pub use store::{
    A2ATaskArtifactListPage, A2ATaskListCursor, A2ATaskListPage, A2ATaskListQuery,
    A2ATaskPruneOutcome, A2ATaskSnapshot, A2ATaskStore, A2ATaskStreamUpdates, A2ATaskWithArtifacts,
    AppendA2ATaskRecordOutcome, CreateA2ATaskOutcome, TransitionA2ATaskOutcome,
};
