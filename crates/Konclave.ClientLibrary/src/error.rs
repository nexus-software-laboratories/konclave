use KonclaveProtocolContracts::KonclaveProtocolError;
use thiserror::Error;

/// Stable failures produced by the outbound relay client.
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum KonclaveClientError {
    /// The relay endpoint is malformed or violates TLS-or-loopback policy.
    #[error("relay endpoint is invalid")]
    InvalidEndpoint,

    /// A bearer credential is malformed or has the wrong size.
    #[error("relay access credential is invalid")]
    InvalidCredential,

    /// An outbound operation exceeded its deadline.
    #[error("relay operation timed out")]
    Timeout,

    /// The network or remote service was unavailable.
    #[error("relay transport is unavailable")]
    TransportUnavailable,

    /// A response exceeded the selected protocol bound.
    #[error("relay response exceeds {maximum} bytes")]
    ResponseTooLarge { maximum: usize },

    /// A successful response used an unexpected status, media type, or message kind.
    #[error("relay response is invalid")]
    InvalidResponse,

    /// The relay rejected an authenticated operation with a stable code.
    #[error("relay rejected the operation with status {status}: {relay_code}")]
    RelayRejected { status: u16, relay_code: String },

    /// A WebSocket watch ended before the caller closed it.
    #[error("relay watch closed")]
    WatchClosed,

    /// The relay closed a watch with a stable rejection code.
    #[error("relay rejected the watch with close code {close_code}: {relay_code}")]
    WatchRejected { close_code: u16, relay_code: String },

    /// Protocol encoding or decoding rejected a bounded message.
    #[error(transparent)]
    Protocol(#[from] KonclaveProtocolError),
}

impl KonclaveClientError {
    /// Returns the stable machine-readable client or relay failure code.
    #[must_use]
    pub fn code(&self) -> &str {
        match self {
            Self::InvalidEndpoint => "client_invalid_endpoint",
            Self::InvalidCredential => "client_invalid_credential",
            Self::Timeout => "client_timeout",
            Self::TransportUnavailable => "client_transport_unavailable",
            Self::ResponseTooLarge { .. } => "client_response_too_large",
            Self::InvalidResponse => "client_invalid_response",
            Self::RelayRejected { relay_code, .. } => relay_code,
            Self::WatchClosed => "client_watch_closed",
            Self::WatchRejected { relay_code, .. } => relay_code,
            Self::Protocol(error) => error.code(),
        }
    }
}

pub(crate) fn stable_relay_code(value: &str) -> String {
    if !value.is_empty()
        && value.len() <= 64
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        })
    {
        value.to_string()
    } else {
        "relay_rejected".to_string()
    }
}
