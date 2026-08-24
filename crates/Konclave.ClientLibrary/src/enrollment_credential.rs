use KonclaveRelayAuthentication::RelayEnrollmentAuthorityId;
use reqwest::header::HeaderValue;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::KonclaveClientError;
use crate::protected_http::{authorization_header, decode_canonical_credential};

/// Exact-size enrollment bearer credential retained only by trusted endpoint code.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RelayEnrollmentCredential([u8; Self::LENGTH]);

impl RelayEnrollmentCredential {
    /// Required bearer-token byte length.
    pub const LENGTH: usize = 32;

    /// Constructs from one already generated high-entropy credential.
    ///
    /// The caller remains responsible for clearing any additional byte copies.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; Self::LENGTH]) -> Self {
        Self(bytes)
    }

    /// Returns the non-secret verifier derived from this credential.
    #[must_use]
    pub fn authority_id(&self) -> RelayEnrollmentAuthorityId {
        RelayEnrollmentAuthorityId::from_enrollment_token(&self.0)
    }

    /// Decodes one canonical unpadded base64url credential.
    ///
    /// # Errors
    ///
    /// Returns [`KonclaveClientError::InvalidEnrollmentCredential`] for a
    /// non-canonical or incorrectly sized value. The caller remains responsible for
    /// clearing the source string.
    pub fn from_base64(value: &str) -> Result<Self, KonclaveClientError> {
        decode_canonical_credential(value)
            .map(Self)
            .ok_or(KonclaveClientError::InvalidEnrollmentCredential)
    }

    pub(crate) fn authorization_header(&self) -> Result<HeaderValue, KonclaveClientError> {
        authorization_header(&self.0).ok_or(KonclaveClientError::InvalidEnrollmentCredential)
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    use super::RelayEnrollmentCredential;

    #[test]
    fn credential_requires_canonical_exact_size_base64url() {
        let encoded = URL_SAFE_NO_PAD.encode([7; RelayEnrollmentCredential::LENGTH]);
        let credential = RelayEnrollmentCredential::from_base64(&encoded).unwrap();
        assert!(credential.authorization_header().unwrap().is_sensitive());
        assert_eq!(
            credential.authority_id(),
            KonclaveRelayAuthentication::RelayEnrollmentAuthorityId::from_enrollment_token(
                &[7; RelayEnrollmentCredential::LENGTH]
            )
        );
        assert!(RelayEnrollmentCredential::from_base64("short").is_err());
        assert!(RelayEnrollmentCredential::from_base64(&format!("{encoded}=")).is_err());
    }
}
