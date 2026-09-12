use KonclaveLocalServiceClient::LocalServiceJsonClientError;
use KonclaveLocalServiceTransport::LocalServiceErrorCode;
use thiserror::Error;

/// Stable failures exposed to harness adapters.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum AdapterSdkError {
    /// An SDK request or local configuration is outside the versioned contract.
    #[error("adapter SDK configuration is invalid")]
    InvalidConfiguration,
    /// The owner-restricted local transport is unavailable.
    #[error("adapter SDK transport is unavailable")]
    Transport,
    /// The expected local service or exact-profile grant could not be authenticated.
    #[error("adapter SDK authentication failed")]
    Authentication,
    /// A bounded local operation exceeded its deadline.
    #[error("adapter SDK deadline exceeded")]
    DeadlineExceeded,
    /// The authenticated service returned one stable operation failure.
    #[error("adapter SDK operation failed: {0:?}")]
    Service(LocalServiceErrorCode),
    /// An authenticated response violated the adapter contract.
    #[error("adapter SDK response is invalid")]
    InvalidResponse,
}

impl From<LocalServiceJsonClientError> for AdapterSdkError {
    fn from(error: LocalServiceJsonClientError) -> Self {
        match error {
            LocalServiceJsonClientError::InvalidConfiguration => Self::InvalidConfiguration,
            LocalServiceJsonClientError::Transport => Self::Transport,
            LocalServiceJsonClientError::Authentication => Self::Authentication,
            LocalServiceJsonClientError::DeadlineExceeded => Self::DeadlineExceeded,
            LocalServiceJsonClientError::Service(code) => Self::Service(code),
            LocalServiceJsonClientError::InvalidResponse => Self::InvalidResponse,
        }
    }
}
