#![forbid(unsafe_code)]
#![allow(non_snake_case)]

mod error;
mod model;
mod record;
mod store;

pub use error::A2ATaskStoreError;
pub use model::{
    A2ATaskArtifact, A2ATaskCreation, A2ATaskKey, A2ATaskMessage, A2ATaskMessageRole,
    A2ATaskTransition, A2ATerminalReason, MAX_A2A_STORED_ARTIFACT_BYTES,
    MAX_A2A_TERMINAL_REASON_BYTES,
};
pub use record::{A2ATaskRecord, StoredA2ATaskArtifact, StoredA2ATaskMessage};
pub use store::{
    A2ATaskPruneOutcome, A2ATaskStore, AppendA2ATaskRecordOutcome, CreateA2ATaskOutcome,
    TransitionA2ATaskOutcome,
};
