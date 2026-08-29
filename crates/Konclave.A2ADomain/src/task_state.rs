use KonclaveA2AContracts::wire::TaskState;

use crate::A2ADomainError;

/// A2A task lifecycle state, separate from Konclave delivery and request-handling state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum A2ATaskState {
    /// The gateway durably accepted the task.
    Submitted,
    /// The mapped directed request is being processed.
    Working,
    /// The exact target produced the authoritative terminal response.
    Completed,
    /// Processing ended with an error.
    Failed,
    /// Cancellation completed before task completion.
    Canceled,
    /// The agent requires explicit new input.
    InputRequired,
    /// The task was deliberately refused.
    Rejected,
    /// Additional web-layer authentication is required.
    AuthRequired,
}

impl A2ATaskState {
    /// Returns the generated A2A wire state.
    #[must_use]
    pub const fn to_wire(self) -> TaskState {
        match self {
            Self::Submitted => TaskState::Submitted,
            Self::Working => TaskState::Working,
            Self::Completed => TaskState::Completed,
            Self::Failed => TaskState::Failed,
            Self::Canceled => TaskState::Canceled,
            Self::InputRequired => TaskState::InputRequired,
            Self::Rejected => TaskState::Rejected,
            Self::AuthRequired => TaskState::AuthRequired,
        }
    }

    /// Narrows one generated A2A wire state.
    ///
    /// # Errors
    ///
    /// Returns an unsupported-state error for the unspecified value.
    pub fn from_wire(value: i32) -> Result<Self, A2ADomainError> {
        match TaskState::try_from(value).ok() {
            Some(TaskState::Submitted) => Ok(Self::Submitted),
            Some(TaskState::Working) => Ok(Self::Working),
            Some(TaskState::Completed) => Ok(Self::Completed),
            Some(TaskState::Failed) => Ok(Self::Failed),
            Some(TaskState::Canceled) => Ok(Self::Canceled),
            Some(TaskState::InputRequired) => Ok(Self::InputRequired),
            Some(TaskState::Rejected) => Ok(Self::Rejected),
            Some(TaskState::AuthRequired) => Ok(Self::AuthRequired),
            Some(TaskState::Unspecified) | None => Err(A2ADomainError::UnsupportedTaskState),
        }
    }
}
