use KonclaveSecretStorage::{SealedBlob, SecretRecordContext, SecretRecordKind, SecretSealer};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use reqwest::header::HeaderValue;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::KonclaveClientError;
use crate::RelayEndpoint;

const RELAY_CREDENTIAL_MAGIC: &[u8; 4] = b"KRC1";
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

    /// Seals this credential for one non-empty local profile identifier.
    ///
    /// # Errors
    ///
    /// Returns a credential error when context construction or sealing fails.
    pub fn seal(
        &self,
        sealer: &SecretSealer,
        profile_id: &[u8],
        endpoint: &RelayEndpoint,
    ) -> Result<SealedBlob, KonclaveClientError> {
        let context = Self::credential_context(profile_id)?;
        let endpoint_bytes = endpoint.as_str().as_bytes();
        let endpoint_length = u16::try_from(endpoint_bytes.len())
            .map_err(|_| KonclaveClientError::InvalidEndpoint)?;
        let mut plaintext = Zeroizing::new(Vec::with_capacity(
            RELAY_CREDENTIAL_MAGIC.len() + 2 + endpoint_bytes.len() + Self::LENGTH,
        ));
        plaintext.extend_from_slice(RELAY_CREDENTIAL_MAGIC);
        plaintext.extend_from_slice(&endpoint_length.to_be_bytes());
        plaintext.extend_from_slice(endpoint_bytes);
        plaintext.extend_from_slice(&self.0);
        sealer
            .seal(&context, &plaintext)
            .map_err(|_| KonclaveClientError::InvalidCredential)
    }

    /// Reopens one sealed relay credential.
    ///
    /// # Errors
    ///
    /// Returns a credential error when authentication or exact-size validation
    /// fails.
    pub fn open(
        sealer: &SecretSealer,
        profile_id: &[u8],
        endpoint: &RelayEndpoint,
        blob: &SealedBlob,
    ) -> Result<Self, KonclaveClientError> {
        let context = Self::credential_context(profile_id)?;
        let plaintext = sealer
            .open(&context, blob)
            .map_err(|_| KonclaveClientError::InvalidCredential)?;
        if plaintext.len() < RELAY_CREDENTIAL_MAGIC.len() + 2 + Self::LENGTH
            || &plaintext[..4] != RELAY_CREDENTIAL_MAGIC
        {
            return Err(KonclaveClientError::InvalidCredential);
        }
        let endpoint_length = usize::from(u16::from_be_bytes(
            plaintext[4..6]
                .try_into()
                .map_err(|_| KonclaveClientError::InvalidCredential)?,
        ));
        let token_offset = 6_usize
            .checked_add(endpoint_length)
            .ok_or(KonclaveClientError::InvalidCredential)?;
        let expected_length = token_offset
            .checked_add(Self::LENGTH)
            .ok_or(KonclaveClientError::InvalidCredential)?;
        if plaintext.len() != expected_length
            || &plaintext[6..token_offset] != endpoint.as_str().as_bytes()
        {
            return Err(KonclaveClientError::InvalidCredential);
        }
        let bytes = plaintext[token_offset..]
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

    fn credential_context(profile_id: &[u8]) -> Result<SecretRecordContext, KonclaveClientError> {
        if profile_id.is_empty() {
            return Err(KonclaveClientError::InvalidCredential);
        }
        SecretRecordContext::new(SecretRecordKind::RelayAccessCredential, profile_id.to_vec())
            .map_err(|_| KonclaveClientError::InvalidCredential)
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    use crate::RelayEndpoint;

    use super::RelayAccessCredential;

    #[test]
    fn credential_requires_canonical_exact_size_base64url() {
        let encoded = URL_SAFE_NO_PAD.encode([7; RelayAccessCredential::LENGTH]);
        let credential = RelayAccessCredential::from_base64(&encoded).unwrap();
        assert!(credential.authorization_header().unwrap().is_sensitive());
        assert!(RelayAccessCredential::from_base64("short").is_err());
        assert!(RelayAccessCredential::from_base64(&format!("{encoded}=")).is_err());
    }

    #[test]
    fn credential_sealing_is_profile_bound() {
        let sealer = KonclaveSecretStorage::SecretSealer::from_provider(
            KonclaveSecretStorage::ExternalWrappingKeyProvider::from_bytes([3; 32]),
        )
        .unwrap();
        let credential = RelayAccessCredential::from_bytes([4; RelayAccessCredential::LENGTH]);
        let endpoint = RelayEndpoint::parse("https://relay.example.com").unwrap();
        let blob = credential.seal(&sealer, b"profile-a", &endpoint).unwrap();
        assert!(RelayAccessCredential::open(&sealer, b"profile-a", &endpoint, &blob).is_ok());
        assert!(RelayAccessCredential::open(&sealer, b"profile-b", &endpoint, &blob).is_err());
        assert!(
            RelayAccessCredential::open(
                &sealer,
                b"profile-a",
                &RelayEndpoint::parse("https://other.example.com").unwrap(),
                &blob,
            )
            .is_err()
        );
        assert!(credential.seal(&sealer, b"", &endpoint).is_err());
    }
}
