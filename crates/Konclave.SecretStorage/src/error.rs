use thiserror::Error;

/// Stable failures from wrapping-key custody and sealed secret operations.
#[non_exhaustive]
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SecretStorageError {
    /// A record identifier is empty or exceeds its hard limit.
    #[error("secret record identifier must contain from 1 through {maximum} bytes")]
    InvalidRecordIdentifier { maximum: usize },

    /// Plaintext exceeds the sealed-record hard limit.
    #[error("secret plaintext exceeds {maximum} bytes (actual: {actual})")]
    PlaintextTooLarge { maximum: usize, actual: usize },

    /// Ciphertext exceeds the sealed-record hard limit.
    #[error("sealed blob exceeds {maximum} bytes (actual: {actual})")]
    SealedBlobTooLarge { maximum: usize, actual: usize },

    /// The sealed blob header or framing is malformed or unsupported.
    #[error("sealed blob format is invalid or unsupported")]
    InvalidSealedBlob,

    /// Authenticated decryption rejected the key, context, or ciphertext.
    #[error("sealed secret authentication failed")]
    AuthenticationFailed,

    /// Secure randomness was unavailable.
    #[error("secure random generation failed")]
    RandomGenerationFailed,

    /// Externally supplied wrapping-key material is not exactly 32 bytes.
    #[error("external wrapping key must contain exactly 32 bytes")]
    InvalidExternalKey,

    /// The configured native credential store is unavailable or rejected an operation.
    #[error("native wrapping-key custody is unavailable")]
    NativeCustodyUnavailable,

    /// A native credential exists but does not contain a valid wrapping key.
    #[error("native wrapping-key credential is invalid")]
    InvalidNativeCredential,
}

impl SecretStorageError {
    /// Returns the stable machine-readable error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidRecordIdentifier { .. } => "invalid_record_identifier",
            Self::PlaintextTooLarge { .. } => "secret_plaintext_too_large",
            Self::SealedBlobTooLarge { .. } => "sealed_blob_too_large",
            Self::InvalidSealedBlob => "invalid_sealed_blob",
            Self::AuthenticationFailed => "sealed_secret_authentication_failed",
            Self::RandomGenerationFailed => "secure_random_generation_failed",
            Self::InvalidExternalKey => "invalid_external_wrapping_key",
            Self::NativeCustodyUnavailable => "native_key_custody_unavailable",
            Self::InvalidNativeCredential => "invalid_native_key_credential",
        }
    }
}
