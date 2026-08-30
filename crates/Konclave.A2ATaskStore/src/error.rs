use thiserror::Error;

/// Stable failures returned by an A2A task store.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum A2ATaskStoreError {
    /// The supplied configuration is internally inconsistent.
    #[error("A2A task store configuration is invalid")]
    InvalidConfiguration,
    /// No task exists under the exact agent, tenant, and task identifier.
    #[error("A2A task was not found")]
    NotFound,
    /// An idempotency key or expected generation was reused with different content.
    #[error("A2A task operation conflicts with durable state")]
    Conflict,
    /// The requested state change is not allowed.
    #[error("A2A task transition is invalid")]
    InvalidTransition,
    /// A hard row or byte capacity was reached with no eligible retention candidate.
    #[error("A2A task store capacity is exhausted")]
    CapacityExceeded,
    /// Durable data failed its declared shape or relationship checks.
    #[error("A2A task store data is corrupt")]
    CorruptData,
    /// The persistence implementation could not complete the operation.
    #[error("A2A task store operation failed")]
    Storage,
}
