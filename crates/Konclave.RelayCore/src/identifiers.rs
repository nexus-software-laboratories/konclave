use crate::RelayError;
use sha2::{Digest, Sha256};

const RELAY_PRINCIPAL_DOMAIN: &[u8] = b"konclave-relay-principal-v1\0";

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

    /// Derives a non-secret principal identifier from one high-entropy access token.
    ///
    /// The caller retains ownership of the token and remains responsible for
    /// clearing its bytes after this operation.
    #[must_use]
    pub fn from_access_token(token: &[u8; Self::LENGTH]) -> Self {
        let mut digest = Sha256::new();
        digest.update(RELAY_PRINCIPAL_DOMAIN);
        digest.update(token);
        Self(digest.finalize().into())
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

    /// Returns the principal bytes and consumes the identifier.
    #[must_use]
    pub const fn into_bytes(self) -> [u8; Self::LENGTH] {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::RelayPrincipalId;

    #[test]
    fn access_token_principal_derivation_is_domain_separated() {
        assert_eq!(
            RelayPrincipalId::from_access_token(&[0x42; RelayPrincipalId::LENGTH]).into_bytes(),
            [
                0x6e, 0x56, 0xaa, 0xd1, 0xf9, 0xfe, 0x6f, 0x80, 0x53, 0x63, 0x95, 0xb7, 0x0d, 0xf8,
                0xb9, 0x98, 0x7c, 0x03, 0x5f, 0x7c, 0x03, 0x15, 0x0e, 0xba, 0xae, 0x96, 0xb7, 0x22,
                0xcf, 0x54, 0x51, 0xcb,
            ]
        );
    }
}
