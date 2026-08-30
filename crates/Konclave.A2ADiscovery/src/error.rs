use thiserror::Error;

/// Stable failures while compiling or resolving A2A discovery publications.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum A2ADiscoveryError {
    /// An explicitly selected source or catalog file is unavailable.
    #[error("A2A discovery document is unavailable: {document}")]
    DocumentUnavailable {
        /// Stable document kind.
        document: &'static str,
    },
    /// A source or catalog exceeded its byte bound.
    #[error("A2A discovery document exceeds {maximum} bytes: {document}")]
    DocumentTooLarge {
        /// Stable document kind.
        document: &'static str,
        /// Largest accepted byte length.
        maximum: usize,
    },
    /// A source or catalog is not one strict JSON document.
    #[error("A2A discovery JSON is invalid: {document}")]
    InvalidJson {
        /// Stable document kind.
        document: &'static str,
    },
    /// The publication source uses an unsupported API version.
    #[error("A2A discovery source API version is unsupported")]
    UnsupportedApiVersion,
    /// The publication source uses an unsupported kind.
    #[error("A2A discovery source kind is unsupported")]
    UnsupportedKind,
    /// A catalog uses an unsupported schema version.
    #[error("A2A discovery catalog version is unsupported")]
    UnsupportedCatalogVersion,
    /// The publication identifier is not canonical.
    #[error("A2A discovery agent identifier is invalid")]
    InvalidAgentId,
    /// Generated Agent Card content violates the initial profile.
    #[error("A2A discovery Agent Card is invalid")]
    InvalidAgentCard,
    /// A production publication omitted supported web authentication.
    #[error("A2A production publication requires Bearer or mutual TLS authentication")]
    AuthenticationRequired,
    /// An unauthenticated development publication is not loopback-only.
    #[error("unauthenticated A2A publication must use loopback interfaces")]
    UnauthenticatedInterface,
    /// OASF projection metadata is incomplete, unsupported, or noncanonical.
    #[error("A2A OASF projection configuration is invalid")]
    InvalidOasfProjection,
    /// A catalog source path is unsafe.
    #[error("A2A discovery catalog path is unsafe")]
    UnsafeCatalogPath,
    /// A catalog repeats an identifier or physical source.
    #[error("A2A discovery catalog duplicates {field}")]
    DuplicateCatalogEntry {
        /// Stable duplicate field.
        field: &'static str,
    },
    /// A catalog entry name differs from its compiled source identity.
    #[error("A2A discovery catalog name does not match its source")]
    CatalogNameMismatch,
    /// The requested private publication does not exist.
    #[error("A2A discovery publication was not found")]
    PublicationNotFound,
    /// The requested publication has no extended card.
    #[error("A2A extended Agent Card is not configured")]
    ExtendedCardNotConfigured,
    /// The requested publication has no OASF projection.
    #[error("A2A OASF projection is not configured")]
    OasfProjectionNotConfigured,
    /// Deployment authorization explicitly denied the operation.
    #[error("A2A discovery operation is unauthorized")]
    Unauthorized,
    /// Deployment authorization could not make a decision.
    #[error("A2A discovery authorization is unavailable")]
    AuthorizationUnavailable,
}
