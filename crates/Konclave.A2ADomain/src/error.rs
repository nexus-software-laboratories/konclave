use thiserror::Error;

/// Stable failures returned while mapping validated A2A values.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum A2ADomainError {
    /// A deployment or request identifier was not canonical.
    #[error("A2A mapping identifier is invalid: {kind}")]
    InvalidIdentifier {
        /// Stable identifier kind.
        kind: &'static str,
    },
    /// The validated request tenant did not match the selected agent route.
    #[error("A2A request tenant does not match the selected agent route")]
    TenantMismatch,
    /// The caller context did not match the deployment-owned conversation binding.
    #[error("A2A request context does not match the selected agent route")]
    ContextMismatch,
    /// The wire task state has no valid domain meaning.
    #[error("A2A task state is unsupported")]
    UnsupportedTaskState,
    /// An A2A part position could not fit the bounded domain index.
    #[error("A2A part position is outside its domain bound")]
    PartIndexOutOfRange,
}
