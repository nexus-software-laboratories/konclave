use thiserror::Error;

/// Stable failures from the reference A2A gateway and outbound client.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum A2AGatewayError {
    /// Gateway configuration is inconsistent or outside its hard bounds.
    #[error("A2A gateway configuration is invalid")]
    InvalidConfiguration,
    /// An inbound or outbound A2A body violates the initial profile.
    #[error("A2A gateway contract validation failed")]
    Contract,
    /// A request does not match the configured agent route.
    #[error("A2A gateway route does not match the request")]
    RouteMismatch,
    /// No exact task exists for the configured publication.
    #[error("A2A gateway task was not found")]
    TaskNotFound,
    /// A deterministic task identity was reused with different content.
    #[error("A2A gateway idempotency conflict")]
    Conflict,
    /// Durable task capacity is exhausted.
    #[error("A2A gateway task capacity is exhausted")]
    CapacityExceeded,
    /// Durable task data or a generated response violates required invariants.
    #[error("A2A gateway task projection is invalid")]
    InvalidTaskProjection,
    /// Durable task storage is unavailable.
    #[error("A2A gateway task storage is unavailable")]
    StorageUnavailable,
    /// The configured clock cannot produce a valid Unix timestamp.
    #[error("A2A gateway clock is unavailable")]
    ClockUnavailable,
    /// The idempotent downstream submission boundary is unavailable.
    #[error("A2A gateway submission is unavailable")]
    SubmissionUnavailable,
    /// A non-immediate request did not reach a response state within the configured bound.
    #[error("A2A gateway response wait expired")]
    ResponseWaitExpired,
    /// HTTP authentication is missing or invalid.
    #[error("A2A gateway authentication failed")]
    Unauthenticated,
    /// HTTP identity is valid but not authorized for the requested operation.
    #[error("A2A gateway operation is forbidden")]
    Forbidden,
    /// The deployment authorization dependency is unavailable.
    #[error("A2A gateway authorization is unavailable")]
    AuthorizationUnavailable,
    /// The requested extended card is not configured.
    #[error("A2A gateway extended Agent Card is not configured")]
    ExtendedCardNotConfigured,
    /// The configured card authentication cannot be used by the built-in client.
    #[error("A2A client authentication is unsupported")]
    UnsupportedAuthentication,
    /// Outbound HTTP transport failed before a valid response was received.
    #[error("A2A client transport failed")]
    Transport,
    /// The reference HTTP server could not bind or serve.
    #[error("A2A gateway HTTP server is unavailable")]
    ServerUnavailable,
    /// The remote server returned a bounded A2A error response.
    #[error("A2A remote operation failed with HTTP {status}")]
    Remote {
        /// HTTP status code.
        status: u16,
        /// Optional stable A2A reason value.
        reason: Option<String>,
    },
}
