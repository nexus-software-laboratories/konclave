use thiserror::Error;

/// Stable non-sensitive failures from the durable local authorization store.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum LocalAuthorizationStoreError {
    /// A caller supplied an invalid timestamp, limit, or store location.
    #[error("local authorization store input is invalid")]
    InvalidInput,
    /// The store could not be opened or an atomic storage operation failed.
    #[error("local authorization storage is unavailable")]
    StorageUnavailable,
    /// Stored metadata or a persisted row violates the authorization schema.
    #[error("local authorization storage is invalid")]
    InvalidStorage,
    /// SQLite reported database corruption or a non-database file.
    #[error("local authorization storage is corrupt")]
    CorruptStorage,
    /// The database file or containing directory is linked or not owner-protected.
    #[error("local authorization storage is unsafe")]
    UnsafeStorage,
    /// The database uses a schema version this build does not understand.
    #[error("local authorization storage schema is unsupported")]
    UnsupportedSchema,
    /// The database belongs to another immutable local-service installation.
    #[error("local authorization storage installation does not match")]
    InstallationMismatch,
    /// The durable generation is below the caller's process high-water mark.
    #[error("local authorization storage generation rolled back")]
    GenerationRollback,
    /// An exact identifier or monotonic version conflicts with retained state.
    #[error("local authorization state conflicts with the requested operation")]
    Conflict,
    /// The requested exact issuer, grant, or profile state does not exist.
    #[error("local authorization state was not found")]
    NotFound,
    /// New grant issuance is blocked for the exact profile.
    #[error("local authorization profile is suspended")]
    ProfileSuspended,
    /// New grant issuance is blocked for the exact issuer key version.
    #[error("local authorization issuer is disabled")]
    IssuerDisabled,
    /// The effective policy does not accept the candidate grant's evidence.
    #[error("required authorization evidence is unavailable")]
    RequiredEvidenceUnavailable,
    /// A bounded issuer, grant, profile, audit, or generation limit was reached.
    #[error("local authorization capacity is exhausted")]
    Capacity,
}

impl LocalAuthorizationStoreError {
    /// Returns the stable machine-readable outcome code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidInput => "invalid_input",
            Self::StorageUnavailable => "storage_unavailable",
            Self::InvalidStorage => "invalid_storage",
            Self::CorruptStorage => "corrupt_storage",
            Self::UnsafeStorage => "unsafe_storage",
            Self::UnsupportedSchema => "unsupported_schema",
            Self::InstallationMismatch => "installation_mismatch",
            Self::GenerationRollback => "generation_rollback",
            Self::Conflict => "conflict",
            Self::NotFound => "not_found",
            Self::ProfileSuspended => "profile_suspended",
            Self::IssuerDisabled => "issuer_disabled",
            Self::RequiredEvidenceUnavailable => "required_evidence_unavailable",
            Self::Capacity => "capacity",
        }
    }
}
