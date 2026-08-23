use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use aws_lc_rs::{constant_time, hmac};
use zeroize::Zeroize;

use crate::KonclaveCryptographicError;

/// Length in bytes of an HMAC-SHA-256 authentication tag.
pub const HMAC_SHA256_TAG_LENGTH: usize = 32;

/// Fills `buffer` with operating-system random bytes from the vetted provider.
///
/// # Errors
///
/// Returns [`KonclaveCryptographicError::ProviderFailure`] when the system random
/// source is unavailable.
pub fn fill_random(buffer: &mut [u8]) -> Result<(), KonclaveCryptographicError> {
    SystemRandom::new()
        .fill(buffer)
        .map_err(|_| KonclaveCryptographicError::ProviderFailure {
            operation: "system random",
        })
}

/// A keyed HMAC-SHA-256 authenticator over the project's vetted provider.
///
/// Local channel authentication needs a keyed proof that both a Rust daemon and a
/// non-Rust adapter can reproduce byte for byte. Routing it through this type keeps
/// every caller on one audited primitive instead of introducing a second
/// implementation beside the MLS provider.
pub struct HmacSha256Key {
    key: hmac::Key,
    material: Vec<u8>,
}

impl HmacSha256Key {
    /// Creates an authenticator from raw key material.
    ///
    /// # Errors
    ///
    /// Returns [`KonclaveCryptographicError::InvalidInput`] when the material is
    /// empty.
    pub fn new(material: &[u8]) -> Result<Self, KonclaveCryptographicError> {
        if material.is_empty() {
            return Err(KonclaveCryptographicError::InvalidKeyMaterial);
        }
        Ok(Self {
            key: hmac::Key::new(hmac::HMAC_SHA256, material),
            material: material.to_vec(),
        })
    }

    /// Computes the authentication tag over `message`.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> [u8; HMAC_SHA256_TAG_LENGTH] {
        let tag = hmac::sign(&self.key, message);
        let mut output = [0_u8; HMAC_SHA256_TAG_LENGTH];
        output.copy_from_slice(tag.as_ref());
        output
    }

    /// Reports whether `tag` authenticates `message` under this key.
    ///
    /// The comparison is constant time, so a mismatched tag reveals nothing about how
    /// many leading bytes were correct.
    #[must_use]
    pub fn verify(&self, message: &[u8], tag: &[u8]) -> bool {
        if tag.len() != HMAC_SHA256_TAG_LENGTH {
            return false;
        }
        let expected = self.sign(message);
        constant_time::verify_slices_are_equal(&expected, tag).is_ok()
    }
}

impl Drop for HmacSha256Key {
    fn drop(&mut self) {
        self.material.zeroize();
    }
}

impl core::fmt::Debug for HmacSha256Key {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("HmacSha256Key")
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::HmacSha256Key;

    #[test]
    fn rejects_empty_key_material() {
        assert!(HmacSha256Key::new(&[]).is_err());
    }

    #[test]
    fn matches_rfc_4231_test_case_two() {
        let key = HmacSha256Key::new(b"Jefe").unwrap();
        let tag = key.sign(b"what do ya want for nothing?");
        let expected =
            hex_bytes("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
        assert_eq!(tag.as_slice(), expected.as_slice());
        assert!(key.verify(b"what do ya want for nothing?", &expected));
    }

    #[test]
    fn rejects_a_wrong_tag_and_a_wrong_length() {
        let key = HmacSha256Key::new(b"key").unwrap();
        let mut tag = key.sign(b"message");
        assert!(key.verify(b"message", &tag));
        tag[31] ^= 1;
        assert!(!key.verify(b"message", &tag));
        assert!(!key.verify(b"message", &tag[..31]));
        assert!(!key.verify(b"other", &key.sign(b"message")));
    }

    #[test]
    fn distinct_keys_produce_distinct_tags() {
        let first = HmacSha256Key::new(b"first").unwrap();
        let second = HmacSha256Key::new(b"second").unwrap();
        assert_ne!(first.sign(b"message"), second.sign(b"message"));
    }

    fn hex_bytes(value: &str) -> Vec<u8> {
        (0..value.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
            .collect()
    }
}
