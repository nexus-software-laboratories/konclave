use crate::RelayError;

/// Opaque identifier for one authenticated relay principal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RelayPrincipalId([u8; 32]);

impl RelayPrincipalId {
    /// Required principal identifier byte length.
    pub const LENGTH: usize = 32;

    /// Creates a principal identifier from an exact-size array.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; Self::LENGTH]) -> Self {
        Self(bytes)
    }

    /// Parses an exact-size principal identifier.
    ///
    /// # Errors
    ///
    /// Returns a stored-data error for any other length.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, RelayError> {
        Ok(Self(
            bytes
                .try_into()
                .map_err(|_| RelayError::InvalidStoredData)?,
        ))
    }

    /// Returns the opaque principal bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LENGTH] {
        &self.0
    }
}
