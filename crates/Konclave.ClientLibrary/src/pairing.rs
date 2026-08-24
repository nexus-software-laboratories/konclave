use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use KonclaveCryptographicCore::{
    DeviceIdentity, PAIRING_SECRET_BYTES, PairingKeySchedule, PairingSecret, fill_random,
    verify_pairing_offer,
};
use KonclaveDomainCore::{
    ConversationRole, MAX_PAIRING_RELAY_ENDPOINT_BYTES, PairingId, PairingOffer,
};
use KonclaveProtocolContracts::v1::{decode_pairing_offer, encode_pairing_offer};

use crate::{KonclaveClientError, RelayEndpoint};

const MAGIC: &[u8; 4] = b"KPC1";
const FORMAT_VERSION: u8 = 1;
const HEADER_BYTES: usize = MAGIC.len() + 1 + PAIRING_SECRET_BYTES + 2 + 2;
const MAX_PAIRING_CAPABILITY_BYTES: usize = 4 * 1024;

/// Maximum UTF-8 bytes accepted for one unpadded base64url pairing capability.
pub const MAX_PAIRING_CAPABILITY_TEXT_BYTES: usize = MAX_PAIRING_CAPABILITY_BYTES.div_ceil(3) * 4;

/// One transferable, secret-bearing pairing capability.
///
/// This type intentionally implements neither `Clone`, `Debug`, nor general-purpose
/// serialization. It owns the one bearer secret and exposes it only through
/// [`PairingCapability::encode`] or key-schedule derivation.
pub struct PairingCapability {
    offer: PairingOffer,
    secret: PairingSecret,
    relay_endpoint: RelayEndpoint,
}

impl PairingCapability {
    /// Issues a short-lived capability for this device to join a conversation.
    ///
    /// The deadline must be strictly later than `now_unix_seconds`. The inviter still
    /// chooses the role it grants; `requested_role` is the joiner's signed request.
    ///
    /// # Errors
    ///
    /// Returns a typed client or provider error for an invalid deadline, unavailable
    /// randomness, or offer-signing failure.
    pub fn issue(
        identity: &DeviceIdentity,
        relay_endpoint: RelayEndpoint,
        requested_role: ConversationRole,
        expires_at_unix_seconds: u64,
        now_unix_seconds: u64,
    ) -> Result<Self, KonclaveClientError> {
        if expires_at_unix_seconds <= now_unix_seconds {
            return Err(KonclaveClientError::InvalidPairingCapability);
        }
        let mut pairing_id = [0_u8; PairingId::LENGTH];
        fill_random(&mut pairing_id)?;
        let pairing_id = PairingId::from_bytes(pairing_id);
        let secret = PairingSecret::generate()?;
        let schedule = PairingKeySchedule::derive(pairing_id, &secret)?;
        let context_hash = PairingKeySchedule::pairing_context_hash(
            pairing_id,
            schedule.routing_id(),
            relay_endpoint.as_str(),
        )?;
        let offer = identity.offer_pairing(
            pairing_id,
            requested_role,
            expires_at_unix_seconds,
            context_hash,
        )?;
        Ok(Self {
            offer,
            secret,
            relay_endpoint,
        })
    }

    /// Decodes, shape-validates, and authenticates one capability.
    ///
    /// Decoding verifies canonical unpadded base64url, the root-signed offer, its
    /// claimed device identity, its deadline, and TLS-or-loopback relay policy before
    /// returning any usable secret state.
    ///
    /// # Errors
    ///
    /// Returns an opaque invalid-capability error for malformed, non-canonical,
    /// expired, unauthentic, or trailing input, and a size error before base64
    /// allocation for oversized input.
    pub fn decode(encoded: &str, now_unix_seconds: u64) -> Result<Self, KonclaveClientError> {
        if encoded.len() > MAX_PAIRING_CAPABILITY_TEXT_BYTES {
            return Err(KonclaveClientError::PairingCapabilityTooLarge {
                maximum: MAX_PAIRING_CAPABILITY_TEXT_BYTES,
                actual: encoded.len(),
            });
        }
        if encoded.is_empty() || !encoded.is_ascii() {
            return Err(KonclaveClientError::InvalidPairingCapability);
        }
        let decoded = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(encoded)
                .map_err(|_| KonclaveClientError::InvalidPairingCapability)?,
        );
        if decoded.len() < HEADER_BYTES || decoded.len() > MAX_PAIRING_CAPABILITY_BYTES {
            return Err(KonclaveClientError::InvalidPairingCapability);
        }
        let canonical = Zeroizing::new(URL_SAFE_NO_PAD.encode(decoded.as_slice()));
        if canonical.as_str() != encoded {
            return Err(KonclaveClientError::InvalidPairingCapability);
        }
        if &decoded[..MAGIC.len()] != MAGIC || decoded[MAGIC.len()] != FORMAT_VERSION {
            return Err(KonclaveClientError::InvalidPairingCapability);
        }

        let mut cursor = MAGIC.len() + 1;
        let secret_end = cursor + PAIRING_SECRET_BYTES;
        let secret = PairingSecret::from_bytes(
            decoded[cursor..secret_end]
                .try_into()
                .map_err(|_| KonclaveClientError::InvalidPairingCapability)?,
        );
        cursor = secret_end;
        let offer_length = read_u16(&decoded, &mut cursor)?;
        let endpoint_length = read_u16(&decoded, &mut cursor)?;
        if endpoint_length == 0 || endpoint_length > MAX_PAIRING_RELAY_ENDPOINT_BYTES {
            return Err(KonclaveClientError::InvalidPairingCapability);
        }
        let offer_end = cursor
            .checked_add(offer_length)
            .ok_or(KonclaveClientError::InvalidPairingCapability)?;
        let endpoint_end = offer_end
            .checked_add(endpoint_length)
            .ok_or(KonclaveClientError::InvalidPairingCapability)?;
        if endpoint_end != decoded.len() {
            return Err(KonclaveClientError::InvalidPairingCapability);
        }

        let offer = decode_pairing_offer(&decoded[cursor..offer_end])
            .map_err(|_| KonclaveClientError::InvalidPairingCapability)?;
        verify_pairing_offer(&offer, now_unix_seconds)
            .map_err(|_| KonclaveClientError::InvalidPairingCapability)?;
        let endpoint = std::str::from_utf8(&decoded[offer_end..endpoint_end])
            .map_err(|_| KonclaveClientError::InvalidPairingCapability)?;
        let relay_endpoint = RelayEndpoint::parse(endpoint)
            .map_err(|_| KonclaveClientError::InvalidPairingCapability)?;
        if relay_endpoint.as_str() != endpoint {
            return Err(KonclaveClientError::InvalidPairingCapability);
        }
        let schedule = PairingKeySchedule::derive(offer.pairing_id(), &secret)
            .map_err(|_| KonclaveClientError::InvalidPairingCapability)?;
        let expected_context = PairingKeySchedule::pairing_context_hash(
            offer.pairing_id(),
            schedule.routing_id(),
            relay_endpoint.as_str(),
        )
        .map_err(|_| KonclaveClientError::InvalidPairingCapability)?;
        if offer.context_hash() != expected_context {
            return Err(KonclaveClientError::InvalidPairingCapability);
        }
        Ok(Self {
            offer,
            secret,
            relay_endpoint,
        })
    }

    /// Encodes the canonical unpadded base64url capability.
    ///
    /// The returned wrapper zeroizes its text on drop. Callers must still avoid logs,
    /// telemetry, diagnostics, shell arguments, and long-lived clipboard history.
    ///
    /// # Errors
    ///
    /// Returns a protocol or size error when the offer or normalized relay endpoint
    /// cannot fit the capability contract.
    pub fn encode(&self) -> Result<PairingCapabilityText, KonclaveClientError> {
        let offer = encode_pairing_offer(&self.offer)?;
        let endpoint = self.relay_endpoint.as_str().as_bytes();
        if offer.len() > usize::from(u16::MAX)
            || endpoint.is_empty()
            || endpoint.len() > MAX_PAIRING_RELAY_ENDPOINT_BYTES
            || endpoint.len() > usize::from(u16::MAX)
        {
            return Err(KonclaveClientError::InvalidPairingCapability);
        }
        let total = HEADER_BYTES
            .checked_add(offer.len())
            .and_then(|value| value.checked_add(endpoint.len()))
            .ok_or(KonclaveClientError::InvalidPairingCapability)?;
        if total > MAX_PAIRING_CAPABILITY_BYTES {
            return Err(KonclaveClientError::PairingCapabilityTooLarge {
                maximum: MAX_PAIRING_CAPABILITY_BYTES,
                actual: total,
            });
        }

        let mut bytes = Zeroizing::new(Vec::with_capacity(total));
        bytes.extend_from_slice(MAGIC);
        bytes.push(FORMAT_VERSION);
        self.secret.write_capability_bytes(&mut bytes);
        bytes.extend_from_slice(
            &u16::try_from(offer.len())
                .map_err(|_| KonclaveClientError::InvalidPairingCapability)?
                .to_be_bytes(),
        );
        bytes.extend_from_slice(
            &u16::try_from(endpoint.len())
                .map_err(|_| KonclaveClientError::InvalidPairingCapability)?
                .to_be_bytes(),
        );
        bytes.extend_from_slice(&offer);
        bytes.extend_from_slice(endpoint);
        Ok(PairingCapabilityText(Zeroizing::new(
            URL_SAFE_NO_PAD.encode(bytes.as_slice()),
        )))
    }

    /// Returns the authenticated public offer an inviter decides on.
    #[must_use]
    pub const fn offer(&self) -> &PairingOffer {
        &self.offer
    }

    /// Returns the validated non-secret relay endpoint.
    #[must_use]
    pub const fn relay_endpoint(&self) -> &RelayEndpoint {
        &self.relay_endpoint
    }

    /// Derives the relay route and direction-specific encryption keys.
    ///
    /// # Errors
    ///
    /// Returns a provider error if key derivation fails.
    pub fn key_schedule(&self) -> Result<PairingKeySchedule, KonclaveClientError> {
        Ok(PairingKeySchedule::derive(
            self.offer.pairing_id(),
            &self.secret,
        )?)
    }
}

/// Canonical secret-bearing capability text.
///
/// The value is zeroized on drop and intentionally implements neither `Clone` nor
/// `Debug`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PairingCapabilityText(Zeroizing<String>);

impl PairingCapabilityText {
    /// Returns the capability for the explicit transfer operation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

fn read_u16(bytes: &[u8], cursor: &mut usize) -> Result<usize, KonclaveClientError> {
    let end = cursor
        .checked_add(2)
        .ok_or(KonclaveClientError::InvalidPairingCapability)?;
    let value = bytes
        .get(*cursor..end)
        .ok_or(KonclaveClientError::InvalidPairingCapability)?;
    *cursor = end;
    Ok(usize::from(u16::from_be_bytes(value.try_into().map_err(
        |_| KonclaveClientError::InvalidPairingCapability,
    )?)))
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_700_000_000;
    const EXPIRY: u64 = NOW + 300;

    fn capability() -> PairingCapability {
        PairingCapability::issue(
            &DeviceIdentity::generate().unwrap(),
            RelayEndpoint::parse("https://relay.example.com/base").unwrap(),
            ConversationRole::Member,
            EXPIRY,
            NOW,
        )
        .unwrap()
    }

    #[test]
    fn capability_round_trips_as_one_canonical_bounded_string() {
        let issued = capability();
        let text = issued.encode().unwrap();
        assert!(text.as_str().len() <= MAX_PAIRING_CAPABILITY_TEXT_BYTES);
        assert!(!text.as_str().contains('='));

        let decoded = PairingCapability::decode(text.as_str(), NOW).unwrap();
        assert_eq!(decoded.offer(), issued.offer());
        assert_eq!(
            decoded.relay_endpoint().as_str(),
            "https://relay.example.com/base/"
        );
        assert_eq!(
            decoded.key_schedule().unwrap().routing_id(),
            issued.key_schedule().unwrap().routing_id()
        );
    }

    #[test]
    fn expired_or_non_future_capabilities_fail_closed() {
        assert!(
            PairingCapability::decode(capability().encode().unwrap().as_str(), EXPIRY).is_err()
        );
        assert!(
            PairingCapability::issue(
                &DeviceIdentity::generate().unwrap(),
                RelayEndpoint::parse("https://relay.example.com").unwrap(),
                ConversationRole::Member,
                NOW,
                NOW,
            )
            .is_err()
        );
    }

    #[test]
    fn modified_noncanonical_oversized_and_trailing_input_fail_closed() {
        let text = capability().encode().unwrap();
        assert!(PairingCapability::decode(&format!("{}=", text.as_str()), NOW).is_err());
        assert!(
            PairingCapability::decode(&"A".repeat(MAX_PAIRING_CAPABILITY_TEXT_BYTES + 1), NOW)
                .is_err()
        );

        let mut bytes = Zeroizing::new(URL_SAFE_NO_PAD.decode(text.as_str()).unwrap());
        bytes.push(0);
        let trailing = Zeroizing::new(URL_SAFE_NO_PAD.encode(bytes.as_slice()));
        assert!(PairingCapability::decode(trailing.as_str(), NOW).is_err());
    }

    #[test]
    fn signed_context_rejects_secret_or_endpoint_substitution() {
        let text = capability().encode().unwrap();
        let mut secret_changed = Zeroizing::new(URL_SAFE_NO_PAD.decode(text.as_str()).unwrap());
        secret_changed[MAGIC.len() + 1] ^= 1;
        let secret_changed = Zeroizing::new(URL_SAFE_NO_PAD.encode(secret_changed.as_slice()));
        assert!(PairingCapability::decode(secret_changed.as_str(), NOW).is_err());

        let mut endpoint_changed = Zeroizing::new(URL_SAFE_NO_PAD.decode(text.as_str()).unwrap());
        let last = endpoint_changed.len() - 1;
        endpoint_changed[last] = if endpoint_changed[last] == b'/' {
            b'x'
        } else {
            b'/'
        };
        let endpoint_changed = Zeroizing::new(URL_SAFE_NO_PAD.encode(endpoint_changed.as_slice()));
        assert!(PairingCapability::decode(endpoint_changed.as_str(), NOW).is_err());
    }

    #[test]
    fn endpoint_must_use_its_normalized_wire_form() {
        let text = capability().encode().unwrap();
        let mut bytes = Zeroizing::new(URL_SAFE_NO_PAD.decode(text.as_str()).unwrap());
        let endpoint_length_offset = MAGIC.len() + 1 + PAIRING_SECRET_BYTES + 2;
        let endpoint_length = u16::from_be_bytes(
            bytes[endpoint_length_offset..endpoint_length_offset + 2]
                .try_into()
                .unwrap(),
        );
        assert_eq!(bytes.last(), Some(&b'/'));
        bytes.pop();
        bytes[endpoint_length_offset..endpoint_length_offset + 2]
            .copy_from_slice(&(endpoint_length - 1).to_be_bytes());
        let noncanonical = Zeroizing::new(URL_SAFE_NO_PAD.encode(bytes.as_slice()));

        // RelayEndpoint would normalize this to the same endpoint. The capability
        // still rejects it so one semantic capability has one transferable string.
        assert!(PairingCapability::decode(noncanonical.as_str(), NOW).is_err());
    }

    #[test]
    fn capability_cannot_smuggle_a_relay_credential_in_the_endpoint() {
        assert!(RelayEndpoint::parse("https://token@relay.example.com").is_err());
        assert!(RelayEndpoint::parse("https://relay.example.com?token=secret").is_err());
        assert!(RelayEndpoint::parse("http://relay.example.com").is_err());
    }
}
