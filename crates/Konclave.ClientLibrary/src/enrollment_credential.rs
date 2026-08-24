use std::io::Read;

use KonclaveRelayAuthentication::RelayEnrollmentAuthorityId;
use reqwest::header::HeaderValue;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::protected_http::{authorization_header, decode_canonical_credential};
use crate::{KonclaveClientError, RelayEndpoint};

const BOUND_CREDENTIAL_MAGIC: &[u8; 4] = b"KEC1";
const MAX_BOUND_ENDPOINT_BYTES: usize = 2 * 1024;
const MAX_BOUND_CREDENTIAL_BYTES: usize =
    BOUND_CREDENTIAL_MAGIC.len() + 2 + MAX_BOUND_ENDPOINT_BYTES + RelayEnrollmentCredential::LENGTH;

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

    /// Encodes an endpoint-bound credential record for protected installation custody.
    ///
    /// The returned secret-bearing buffer zeroizes on drop.
    ///
    /// # Errors
    ///
    /// Returns [`KonclaveClientError::InvalidEnrollmentCredential`] when the
    /// normalized endpoint exceeds its installation-record bound.
    pub fn encode_bound(
        &self,
        endpoint: &RelayEndpoint,
    ) -> Result<Zeroizing<Vec<u8>>, KonclaveClientError> {
        let endpoint = endpoint.as_str().as_bytes();
        if endpoint.is_empty() || endpoint.len() > MAX_BOUND_ENDPOINT_BYTES {
            return Err(KonclaveClientError::InvalidEnrollmentCredential);
        }
        let endpoint_length = u16::try_from(endpoint.len())
            .map_err(|_| KonclaveClientError::InvalidEnrollmentCredential)?;
        let mut record = Zeroizing::new(Vec::with_capacity(
            BOUND_CREDENTIAL_MAGIC.len() + 2 + endpoint.len() + Self::LENGTH,
        ));
        record.extend_from_slice(BOUND_CREDENTIAL_MAGIC);
        record.extend_from_slice(&endpoint_length.to_be_bytes());
        record.extend_from_slice(endpoint);
        record.extend_from_slice(&self.0);
        Ok(record)
    }

    /// Reads one bounded installation record and verifies its exact endpoint binding.
    ///
    /// # Errors
    ///
    /// Returns [`KonclaveClientError::InvalidEnrollmentCredential`] for I/O,
    /// framing, trailing-data, endpoint-binding, or exact-length failure.
    pub fn from_bound_reader(
        reader: impl Read,
        endpoint: &RelayEndpoint,
    ) -> Result<Self, KonclaveClientError> {
        let mut record = Zeroizing::new(Vec::new());
        reader
            .take((MAX_BOUND_CREDENTIAL_BYTES + 1) as u64)
            .read_to_end(&mut record)
            .map_err(|_| KonclaveClientError::InvalidEnrollmentCredential)?;
        if record.len() > MAX_BOUND_CREDENTIAL_BYTES
            || record.len() < BOUND_CREDENTIAL_MAGIC.len() + 2 + Self::LENGTH
            || &record[..4] != BOUND_CREDENTIAL_MAGIC
        {
            return Err(KonclaveClientError::InvalidEnrollmentCredential);
        }
        let endpoint_length = usize::from(u16::from_be_bytes(
            record[4..6]
                .try_into()
                .map_err(|_| KonclaveClientError::InvalidEnrollmentCredential)?,
        ));
        let credential_offset = 6_usize
            .checked_add(endpoint_length)
            .ok_or(KonclaveClientError::InvalidEnrollmentCredential)?;
        if credential_offset.checked_add(Self::LENGTH) != Some(record.len())
            || &record[6..credential_offset] != endpoint.as_str().as_bytes()
        {
            return Err(KonclaveClientError::InvalidEnrollmentCredential);
        }
        let bytes = record[credential_offset..]
            .try_into()
            .map_err(|_| KonclaveClientError::InvalidEnrollmentCredential)?;
        Ok(Self(bytes))
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
    use crate::RelayEndpoint;

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
        let endpoint = RelayEndpoint::parse("https://relay.example.com/base").unwrap();
        let record = credential.encode_bound(&endpoint).unwrap();
        assert!(
            RelayEnrollmentCredential::from_bound_reader(std::io::Cursor::new(&record), &endpoint,)
                .is_ok()
        );
        assert!(
            RelayEnrollmentCredential::from_bound_reader(
                std::io::Cursor::new(&record),
                &RelayEndpoint::parse("https://other.example.com/base").unwrap(),
            )
            .is_err()
        );
        let mut trailing = record.to_vec();
        trailing.push(0);
        assert!(
            RelayEnrollmentCredential::from_bound_reader(
                std::io::Cursor::new(trailing),
                &endpoint,
            )
            .is_err()
        );
    }
}
