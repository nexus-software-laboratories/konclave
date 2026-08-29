use crate::A2AContractError;

/// Maximum byte length of an A2A task, context, message, agent, artifact, or tenant identifier.
pub const MAX_A2A_IDENTIFIER_BYTES: usize = 128;

/// Canonical bounded A2A identifier retained without transport or storage semantics.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct A2AIdentifier(String);

impl A2AIdentifier {
    /// Parses one portable ASCII identifier.
    ///
    /// # Errors
    ///
    /// Returns an invalid-identifier error for an empty, oversized, or noncanonical
    /// value.
    pub fn parse(value: impl Into<String>) -> Result<Self, A2AContractError> {
        Self::parse_for_field(value.into(), "a2a_identifier")
    }

    pub(crate) fn parse_for_field(
        value: String,
        field: &'static str,
    ) -> Result<Self, A2AContractError> {
        if value.is_empty()
            || value.len() > MAX_A2A_IDENTIFIER_BYTES
            || !value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
            })
        {
            Err(A2AContractError::InvalidIdentifier { field })
        } else {
            Ok(Self(value))
        }
    }

    /// Returns the canonical identifier without transferring ownership.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the canonical identifier and consumes the wrapper.
    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }
}
