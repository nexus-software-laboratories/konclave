use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use reqwest::header::HeaderValue;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::KonclaveClientError;

/// Exact-size relay bearer credential retained only by trusted endpoint code.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RelayAccessCredential([u8; Self::LENGTH]);

impl RelayAccessCredential {
    /// Required bearer-token byte length.
    pub const LENGTH: usize = 32;

    /// Constructs from one already generated high-entropy credential.
    ///
    /// The caller remains responsible for clearing any additional byte copies.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; Self::LENGTH]) -> Self {
        Self(bytes)
    }

    /// Decodes one canonical unpadded base64url credential.
    ///
    /// # Errors
    ///
    /// Returns [`KonclaveClientError::InvalidCredential`] for a non-canonical or
    /// incorrectly sized value. The caller remains responsible for clearing the
    /// source string.
    pub fn from_base64(value: &str) -> Result<Self, KonclaveClientError> {
        if value.len() != 43 {
            return Err(KonclaveClientError::InvalidCredential);
        }
        let decoded = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(value)
                .map_err(|_| KonclaveClientError::InvalidCredential)?,
        );
        let canonical = Zeroizing::new(URL_SAFE_NO_PAD.encode(decoded.as_slice()));
        if canonical.as_str() != value {
            return Err(KonclaveClientError::InvalidCredential);
        }
        let bytes = decoded
            .as_slice()
            .try_into()
            .map_err(|_| KonclaveClientError::InvalidCredential)?;
        Ok(Self(bytes))
    }

    pub(crate) fn authorization_header(&self) -> Result<HeaderValue, KonclaveClientError> {
        let encoded = Zeroizing::new(URL_SAFE_NO_PAD.encode(self.0));
        let mut value = Zeroizing::new(Vec::with_capacity(7 + encoded.len()));
        value.extend_from_slice(b"Bearer ");
        value.extend_from_slice(encoded.as_bytes());
        let mut header =
            HeaderValue::from_bytes(&value).map_err(|_| KonclaveClientError::InvalidCredential)?;
        header.set_sensitive(true);
        Ok(header)
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    use super::RelayAccessCredential;

    #[test]
    fn credential_requires_canonical_exact_size_base64url() {
        let encoded = URL_SAFE_NO_PAD.encode([7; RelayAccessCredential::LENGTH]);
        let credential = RelayAccessCredential::from_base64(&encoded).unwrap();
        assert!(credential.authorization_header().unwrap().is_sensitive());
        assert!(RelayAccessCredential::from_base64("short").is_err());
        assert!(RelayAccessCredential::from_base64(&format!("{encoded}=")).is_err());
    }
}
