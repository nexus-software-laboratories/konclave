#![forbid(unsafe_code)]
#![allow(non_snake_case)]

mod error;
mod identifiers;
mod mapping;
mod task_state;

pub use error::A2ADomainError;
pub use identifiers::{
    A2AAgentId, A2AArtifactId, A2AContextId, A2AMessageId, A2APartIndex, A2ATaskId, A2ATenantId,
};
pub use mapping::{
    A2AAgentRoute, A2ADirectedRequestMapping, A2ATaskLookup, map_initial_get_task,
    map_initial_send_message,
};
pub use task_state::A2ATaskState;
