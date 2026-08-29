use KonclaveA2AContracts::A2AIdentifier;
use KonclaveDomainCore::MessageId;

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

/// Gateway-owned lowercase hexadecimal identifier for one A2A task.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct A2ATaskId(A2AIdentifier);

impl A2ATaskId {
    /// Parses the exact 16-byte lowercase hexadecimal task representation.
    ///
    /// # Errors
    ///
    /// Returns an invalid-identifier error for any alternate length or spelling.
    pub fn parse(value: impl Into<String>) -> Result<Self, A2ADomainError> {
        let value = value.into();
        if value.len() != 32
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            return Err(A2ADomainError::InvalidIdentifier { kind: "task" });
        }
        A2AIdentifier::parse(value)
            .map(Self)
            .map_err(|_| A2ADomainError::InvalidIdentifier { kind: "task" })
    }

    /// Returns the canonical task identifier without transferring ownership.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    pub(crate) fn from_request_message_id(value: MessageId) -> Result<Self, A2ADomainError> {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(MessageId::LENGTH * 2);
        for byte in value.as_bytes() {
            output.push(char::from(HEX[usize::from(byte >> 4)]));
            output.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        Self::parse(output)
    }

    /// Returns the exact Konclave request identifier represented by this task.
    #[must_use]
    pub fn request_message_id(&self) -> MessageId {
        let mut bytes = [0_u8; MessageId::LENGTH];
        for (index, pair) in self.0.as_str().as_bytes().chunks_exact(2).enumerate() {
            bytes[index] = (decode_nibble(pair[0]) << 4) | decode_nibble(pair[1]);
        }
        MessageId::from_bytes(bytes)
    }
}

const fn decode_nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        _ => unreachable!(),
    }
}

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
