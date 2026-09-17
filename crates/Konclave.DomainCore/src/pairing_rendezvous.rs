use crate::{KonclaveDomainError, PairingRendezvousId, PairingRendezvousNonce, ProtocolVersion};

/// Maximum authenticated ciphertext bytes stored in one pairing rendezvous.
pub const MAX_PAIRING_RENDEZVOUS_CIPHERTEXT_BYTES: usize = 8 * 1024 + 16;
/// Maximum protobuf bytes for one pairing rendezvous record.
pub const MAX_PAIRING_RENDEZVOUS_RECORD_BYTES: usize = 9 * 1024;

/// Validated opaque capability ciphertext stored by the relay.
///
/// The ciphertext is intentionally not `Debug`; relay diagnostics must report only
/// bounded identifiers, sizes, and finite outcomes.
#[derive(PartialEq, Eq)]
pub struct PairingRendezvousRecord {
    version: ProtocolVersion,
    lookup_id: PairingRendezvousId,
    expires_at_unix_seconds: u64,
    nonce: PairingRendezvousNonce,
    ciphertext: Vec<u8>,
}

impl PairingRendezvousRecord {
    /// Validates and owns one encrypted rendezvous record.
    ///
    /// # Errors
    ///
    /// Returns a domain error when expiry is zero or ciphertext is shorter than one
    /// authentication tag or exceeds the rendezvous bound.
    pub fn new(
        version: ProtocolVersion,
        lookup_id: PairingRendezvousId,
        expires_at_unix_seconds: u64,
        nonce: PairingRendezvousNonce,
        ciphertext: Vec<u8>,
    ) -> Result<Self, KonclaveDomainError> {
        if expires_at_unix_seconds == 0 {
            return Err(KonclaveDomainError::ZeroValue {
                field: "pairing_rendezvous_expiry",
            });
        }
        if !(16..=MAX_PAIRING_RENDEZVOUS_CIPHERTEXT_BYTES).contains(&ciphertext.len()) {
            return Err(KonclaveDomainError::OutOfRange {
                field: "pairing_rendezvous_ciphertext",
                minimum: 16,
                maximum: MAX_PAIRING_RENDEZVOUS_CIPHERTEXT_BYTES,
                actual: ciphertext.len(),
            });
        }
        Ok(Self {
            version,
            lookup_id,
            expires_at_unix_seconds,
            nonce,
            ciphertext,
        })
    }

    /// Returns the protocol version.
    #[must_use]
    pub const fn version(&self) -> ProtocolVersion {
        self.version
    }

    /// Returns the opaque relay lookup identifier.
    #[must_use]
    pub const fn lookup_id(&self) -> PairingRendezvousId {
        self.lookup_id
    }

    /// Returns the capability authorization deadline.
    #[must_use]
    pub const fn expires_at_unix_seconds(&self) -> u64 {
        self.expires_at_unix_seconds
    }

    /// Returns the authenticated-encryption nonce.
    #[must_use]
    pub const fn nonce(&self) -> PairingRendezvousNonce {
        self.nonce
    }

    /// Returns the opaque ciphertext and appended authentication tag.
    #[must_use]
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// Consumes the record into its opaque ciphertext.
    #[must_use]
    pub fn into_ciphertext(self) -> Vec<u8> {
        self.ciphertext
    }
}

/// Bounded request for atomically taking one pairing rendezvous.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PairingRendezvousTakeRequest {
    version: ProtocolVersion,
    lookup_id: PairingRendezvousId,
}

impl PairingRendezvousTakeRequest {
    /// Creates one take request.
    #[must_use]
    pub const fn new(version: ProtocolVersion, lookup_id: PairingRendezvousId) -> Self {
        Self { version, lookup_id }
    }

    /// Returns the protocol version.
    #[must_use]
    pub const fn version(self) -> ProtocolVersion {
        self.version
    }

    /// Returns the opaque lookup identifier.
    #[must_use]
    pub const fn lookup_id(self) -> PairingRendezvousId {
        self.lookup_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_enforces_expiry_and_ciphertext_bounds() {
        let identifier = PairingRendezvousId::from_bytes([1; 32]);
        let nonce = PairingRendezvousNonce::from_bytes([2; 12]);
        assert!(
            PairingRendezvousRecord::new(
                ProtocolVersion::application_v1(),
                identifier,
                1,
                nonce,
                vec![3; 16],
            )
            .is_ok()
        );
        assert!(
            PairingRendezvousRecord::new(
                ProtocolVersion::application_v1(),
                identifier,
                0,
                nonce,
                vec![3; 16],
            )
            .is_err()
        );
        assert!(
            PairingRendezvousRecord::new(
                ProtocolVersion::application_v1(),
                identifier,
                1,
                nonce,
                vec![3; 15],
            )
            .is_err()
        );
    }
}
