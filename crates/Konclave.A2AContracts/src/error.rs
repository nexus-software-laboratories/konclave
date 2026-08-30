use thiserror::Error;

/// Stable failures returned while narrowing untrusted A2A wire values.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum A2AContractError {
    /// The encoded request exceeded the public A2A profile bound.
    #[error("encoded A2A request exceeds its bound")]
    EncodedMessageTooLarge {
        /// Largest accepted byte length.
        maximum: usize,
        /// Observed byte length.
        actual: usize,
    },
    /// The encoded request was not valid A2A protobuf or ProtoJSON.
    #[error("A2A request encoding is malformed")]
    MalformedEncoding,
    /// A field required by the initial profile was absent.
    #[error("required A2A field is missing: {field}")]
    MissingField {
        /// Stable field name.
        field: &'static str,
    },
    /// A field used an unsupported A2A feature or content form.
    #[error("A2A field is unsupported by the initial profile: {field}")]
    UnsupportedField {
        /// Stable field name.
        field: &'static str,
    },
    /// An identifier was empty, oversized, or noncanonical.
    #[error("A2A identifier is invalid: {field}")]
    InvalidIdentifier {
        /// Stable field name.
        field: &'static str,
    },
    /// A text or metadata field violated its byte bound.
    #[error("A2A text field is invalid: {field}")]
    InvalidText {
        /// Stable field name.
        field: &'static str,
    },
    /// A collection repeated a value that must be unique.
    #[error("A2A value is duplicated: {field}")]
    DuplicateValue {
        /// Stable field name.
        field: &'static str,
    },
    /// A numeric field exceeded the initial profile range.
    #[error("A2A numeric field is outside its supported range: {field}")]
    OutOfRange {
        /// Stable field name.
        field: &'static str,
    },
    /// The request named a tenant other than the deployment-selected tenant.
    #[error("A2A tenant does not match the selected interface")]
    TenantMismatch,
    /// An advertised interface URL was malformed or insecure for its environment.
    #[error("A2A interface URL is invalid")]
    InvalidInterfaceUrl,
}
