use KonclaveDomainCore::KonclaveDomainError;
use thiserror::Error;

/// Stable failures produced while loading or compiling collaboration-policy sources.
#[non_exhaustive]
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CollaborationPolicySourceError {
    /// A source or catalog exceeds its pre-allocation byte bound.
    #[error("{document} exceeds {maximum} bytes")]
    DocumentTooLarge {
        document: &'static str,
        maximum: usize,
    },

    /// A source or catalog is not valid strict JSON.
    #[error("{document} is not valid collaboration-policy JSON")]
    InvalidJson { document: &'static str },

    /// A source uses an unsupported authoring API version.
    #[error("collaboration-policy source API version is unsupported")]
    UnsupportedApiVersion,

    /// A source uses an unsupported document kind.
    #[error("collaboration-policy source kind is unsupported")]
    UnsupportedKind,

    /// A catalog uses an unsupported schema version.
    #[error("collaboration-policy catalog schema version is unsupported")]
    UnsupportedCatalogVersion,

    /// An explicit policy source or catalog cannot be opened as a regular file.
    #[error("collaboration-policy {document} file is unavailable")]
    FileUnavailable { document: &'static str },

    /// A catalog source path is nonportable, absolute, linked, or escapes its root.
    #[error("collaboration-policy catalog source path is unsafe")]
    UnsafeCatalogPath,

    /// A catalog repeats one name or source path.
    #[error("collaboration-policy catalog contains a duplicate {field}")]
    DuplicateCatalogEntry { field: &'static str },

    /// A requested policy does not exist in the explicit catalog.
    #[error("collaboration policy is absent from the catalog")]
    PolicyNotFound,

    /// A catalog entry name differs from the compiled source name.
    #[error("collaboration-policy catalog entry does not match its source name")]
    CatalogNameMismatch,

    /// Canonical bundle encoding failed after source validation.
    #[error("collaboration-policy bundle encoding failed")]
    ProtocolContract,

    /// Content digest derivation failed after source validation.
    #[error("collaboration-policy digest derivation failed")]
    Digest,

    /// A source value violates the canonical domain contract.
    #[error(transparent)]
    Domain(#[from] KonclaveDomainError),
}

impl CollaborationPolicySourceError {
    /// Returns the stable machine-readable error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::DocumentTooLarge { .. } => "policy_document_too_large",
            Self::InvalidJson { .. } => "invalid_policy_json",
            Self::UnsupportedApiVersion => "unsupported_policy_api_version",
            Self::UnsupportedKind => "unsupported_policy_kind",
            Self::UnsupportedCatalogVersion => "unsupported_policy_catalog_version",
            Self::FileUnavailable { .. } => "policy_file_unavailable",
            Self::UnsafeCatalogPath => "unsafe_policy_catalog_path",
            Self::DuplicateCatalogEntry { .. } => "duplicate_policy_catalog_entry",
            Self::PolicyNotFound => "policy_not_found",
            Self::CatalogNameMismatch => "policy_catalog_name_mismatch",
            Self::ProtocolContract => "policy_protocol_contract_failure",
            Self::Digest => "policy_digest_failure",
            Self::Domain(error) => error.code(),
        }
    }
}
