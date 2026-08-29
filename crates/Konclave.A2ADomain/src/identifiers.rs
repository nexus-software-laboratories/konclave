use KonclaveA2AContracts::A2AIdentifier;

use crate::A2ADomainError;

macro_rules! define_identifier {
    ($(#[$meta:meta])* $name:ident, $kind:literal) => {
        $(#[$meta])*
        #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(A2AIdentifier);

        impl $name {
            /// Parses one canonical identifier.
            ///
            /// # Errors
            ///
            /// Returns an invalid-identifier error for an empty, oversized, or
            /// noncanonical value.
            pub fn parse(value: impl Into<String>) -> Result<Self, A2ADomainError> {
                A2AIdentifier::parse(value)
                    .map(Self)
                    .map_err(|_| A2ADomainError::InvalidIdentifier { kind: $kind })
            }

            /// Returns the canonical identifier without transferring ownership.
            #[must_use]
            pub fn as_str(&self) -> &str {
                self.0.as_str()
            }
        }
    };
}

define_identifier!(
    /// Deployment-owned identifier for one published A2A agent.
    A2AAgentId,
    "agent"
);
define_identifier!(
    /// Deployment-owned identifier for one A2A interaction context.
    A2AContextId,
    "context"
);
define_identifier!(
    /// Gateway-owned identifier for one A2A task.
    A2ATaskId,
    "task"
);
define_identifier!(
    /// Caller-owned identifier for one A2A message.
    A2AMessageId,
    "message"
);
define_identifier!(
    /// Task-scoped identifier for one A2A artifact.
    A2AArtifactId,
    "artifact"
);
define_identifier!(
    /// Optional deployment-owned tenant routing identifier.
    A2ATenantId,
    "tenant"
);

/// Positional identity for an A2A part, which has no wire identifier field.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct A2APartIndex(u16);

impl A2APartIndex {
    /// Creates a bounded part position.
    ///
    /// # Errors
    ///
    /// Returns an out-of-range error when the position does not fit the domain index.
    pub fn from_position(position: usize) -> Result<Self, A2ADomainError> {
        u16::try_from(position)
            .map(Self)
            .map_err(|_| A2ADomainError::PartIndexOutOfRange)
    }

    /// Returns the zero-based part position.
    #[must_use]
    pub const fn position(self) -> u16 {
        self.0
    }
}
