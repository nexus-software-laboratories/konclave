#![forbid(unsafe_code)]
#![allow(non_snake_case)]

//! Shared relay principal derivation and enrollment-domain contracts.

use KonclaveDomainCore::ProtocolVersion;
use sha2::{Digest, Sha256};
use thiserror::Error;

const RELAY_PRINCIPAL_DOMAIN: &[u8] = b"konclave-relay-principal-v1\0";

macro_rules! define_fixed_bytes {
    ($(#[$meta:meta])* $name:ident, $length:expr, $field:literal) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; $length]);

        impl $name {
            /// Required byte length.
            pub const LENGTH: usize = $length;

            /// Creates a value from exact-size bytes.
            #[must_use]
            pub const fn from_bytes(value: [u8; $length]) -> Self {
                Self(value)
            }

            /// Parses an exact-size byte slice.
            ///
            /// # Errors
            ///
            /// Returns an invalid-length error for any other size.
            pub fn from_slice(value: &[u8]) -> Result<Self, RelayAuthenticationError> {
                let bytes =
                    value
                        .try_into()
                        .map_err(|_| RelayAuthenticationError::InvalidLength {
                            field: $field,
                            expected: $length,
                            actual: value.len(),
                        })?;
                Ok(Self(bytes))
            }

            /// Returns the canonical bytes.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; $length] {
                &self.0
            }

            /// Consumes the value and returns its canonical bytes.
            #[must_use]
            pub const fn into_bytes(self) -> [u8; $length] {
                self.0
            }
        }
    };
}

define_fixed_bytes!(
    /// Pseudonymous identifier derived from one high-entropy relay access token.
    RelayPrincipalId,
    32,
    "relay_principal_id"
);

impl RelayPrincipalId {
    /// Derives a non-secret principal identifier from one 256-bit access token.
    ///
    /// The caller retains ownership of the token and remains responsible for clearing
    /// every additional byte copy.
    #[must_use]
    pub fn from_access_token(token: &[u8; Self::LENGTH]) -> Self {
        let mut digest = Sha256::new();
        digest.update(RELAY_PRINCIPAL_DOMAIN);
        digest.update(token);
        Self(digest.finalize().into())
    }
}

define_fixed_bytes!(
    /// Stable identifier for one idempotent relay enrollment request.
    EnrollmentRequestId,
    16,
    "enrollment_request_id"
);

/// Registration requested for one client-generated relay principal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RelayEnrollmentRequest {
    version: ProtocolVersion,
    request_id: EnrollmentRequestId,
    principal_id: RelayPrincipalId,
}

impl RelayEnrollmentRequest {
    /// Creates a request whose grants remain selected by the deployment.
    #[must_use]
    pub const fn new(
        version: ProtocolVersion,
        request_id: EnrollmentRequestId,
        principal_id: RelayPrincipalId,
    ) -> Self {
        Self {
            version,
            request_id,
            principal_id,
        }
    }

    /// Returns the protocol version for this request.
    #[must_use]
    pub const fn version(&self) -> ProtocolVersion {
        self.version
    }

    /// Returns the stable idempotency identifier.
    #[must_use]
    pub const fn request_id(&self) -> EnrollmentRequestId {
        self.request_id
    }

    /// Returns the client-generated pseudonymous principal.
    #[must_use]
    pub const fn principal_id(&self) -> RelayPrincipalId {
        self.principal_id
    }
}

/// Finite result of an authenticated principal registration.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelayEnrollmentOutcome {
    /// A new principal registration was committed.
    Registered,
    /// The same principal was already registered under equivalent policy.
    AlreadyRegistered,
}

/// Authenticated result echoing the exact enrollment identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RelayEnrollmentResponse {
    version: ProtocolVersion,
    request_id: EnrollmentRequestId,
    principal_id: RelayPrincipalId,
    outcome: RelayEnrollmentOutcome,
}

impl RelayEnrollmentResponse {
    /// Creates an authenticated response for one exact request identity.
    #[must_use]
    pub const fn new(
        version: ProtocolVersion,
        request_id: EnrollmentRequestId,
        principal_id: RelayPrincipalId,
        outcome: RelayEnrollmentOutcome,
    ) -> Self {
        Self {
            version,
            request_id,
            principal_id,
            outcome,
        }
    }

    /// Returns the protocol version for this response.
    #[must_use]
    pub const fn version(&self) -> ProtocolVersion {
        self.version
    }

    /// Returns the request identifier this response answers.
    #[must_use]
    pub const fn request_id(&self) -> EnrollmentRequestId {
        self.request_id
    }

    /// Returns the principal whose registration was resolved.
    #[must_use]
    pub const fn principal_id(&self) -> RelayPrincipalId {
        self.principal_id
    }

    /// Returns whether registration was newly committed or already present.
    #[must_use]
    pub const fn outcome(&self) -> RelayEnrollmentOutcome {
        self.outcome
    }
}

/// Stable validation failures for relay-authentication values.
#[non_exhaustive]
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RelayAuthenticationError {
    /// A fixed-width identifier used another byte length.
    #[error("{field} must contain {expected} bytes (actual: {actual})")]
    InvalidLength {
        field: &'static str,
        expected: usize,
        actual: usize,
    },
}

impl RelayAuthenticationError {
    /// Returns the stable machine-readable validation code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidLength { .. } => "invalid_length",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_token_principal_derivation_preserves_the_v1_vector() {
        assert_eq!(
            RelayPrincipalId::from_access_token(&[0x42; RelayPrincipalId::LENGTH]).into_bytes(),
            [
                0x6e, 0x56, 0xaa, 0xd1, 0xf9, 0xfe, 0x6f, 0x80, 0x53, 0x63, 0x95, 0xb7, 0x0d, 0xf8,
                0xb9, 0x98, 0x7c, 0x03, 0x5f, 0x7c, 0x03, 0x15, 0x0e, 0xba, 0xae, 0x96, 0xb7, 0x22,
                0xcf, 0x54, 0x51, 0xcb,
            ]
        );
    }

    #[test]
    fn enrollment_contract_echoes_only_non_secret_identity() {
        let request = RelayEnrollmentRequest::new(
            ProtocolVersion::application_v1(),
            EnrollmentRequestId::from_bytes([1; EnrollmentRequestId::LENGTH]),
            RelayPrincipalId::from_bytes([2; RelayPrincipalId::LENGTH]),
        );
        let response = RelayEnrollmentResponse::new(
            request.version(),
            request.request_id(),
            request.principal_id(),
            RelayEnrollmentOutcome::Registered,
        );
        assert_eq!(response.request_id(), request.request_id());
        assert_eq!(response.principal_id(), request.principal_id());
        assert_eq!(response.outcome(), RelayEnrollmentOutcome::Registered);
    }
}
