use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use KonclaveCryptographicCore::{
    MAX_PAIRING_RENDEZVOUS_PLAINTEXT_BYTES, PAIRING_RENDEZVOUS_LOOKUP_BYTES,
    PAIRING_RENDEZVOUS_TOKEN_BYTES, PairingRendezvousKeySchedule, PairingRendezvousSecret,
};
use KonclaveSecretStorage::{
    AUTHENTICATED_CIPHER_NONCE_BYTES, AuthenticatedCiphertext,
};

use crate::{KonclaveClientError, PairingCapability};

const TOKEN_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/// Character length of one canonical compact pairing rendezvous token.
pub const PAIRING_RENDEZVOUS_TOKEN_CHARACTERS: usize = 26;
/// Maximum ciphertext bytes stored by one compact pairing rendezvous.
pub const MAX_PAIRING_RENDEZVOUS_CIPHERTEXT_BYTES: usize =
    MAX_PAIRING_RENDEZVOUS_PLAINTEXT_BYTES + KonclaveSecretStorage::AUTHENTICATED_CIPHER_TAG_BYTES;

/// Canonical case-insensitive Crockford Base32 pairing rendezvous token.
///
/// The text implements neither `Clone` nor `Debug` and zeroizes on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PairingRendezvousTokenText(Zeroizing<String>);

impl PairingRendezvousTokenText {
    /// Returns the token for one explicit handoff operation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// Opaque capability ciphertext stored under one non-secret relay lookup identifier.
pub struct PairingRendezvousRecord {
    lookup_id: [u8; PAIRING_RENDEZVOUS_LOOKUP_BYTES],
    expires_at_unix_seconds: u64,
    ciphertext: AuthenticatedCiphertext,
}

impl PairingRendezvousRecord {
    /// Validates and owns one relay-returned rendezvous record.
    ///
    /// # Errors
    ///
    /// Returns an invalid-rendezvous error for malformed lookup, expiry, nonce, or
    /// ciphertext bounds.
    pub fn new(
        lookup_id: &[u8],
        expires_at_unix_seconds: u64,
        nonce: &[u8],
        ciphertext: Vec<u8>,
    ) -> Result<Self, KonclaveClientError> {
        if expires_at_unix_seconds == 0 {
            return Err(KonclaveClientError::InvalidPairingRendezvous);
        }
        let lookup_id = lookup_id
            .try_into()
            .map_err(|_| KonclaveClientError::InvalidPairingRendezvous)?;
        let ciphertext = AuthenticatedCiphertext::from_parts(
            nonce,
            ciphertext,
            MAX_PAIRING_RENDEZVOUS_PLAINTEXT_BYTES,
        )
        .map_err(|_| KonclaveClientError::InvalidPairingRendezvous)?;
        Ok(Self {
            lookup_id,
            expires_at_unix_seconds,
            ciphertext,
        })
    }

    /// Returns the opaque relay lookup identifier.
    #[must_use]
    pub const fn lookup_id(&self) -> &[u8; PAIRING_RENDEZVOUS_LOOKUP_BYTES] {
        &self.lookup_id
    }

    /// Returns the capability authorization deadline.
    #[must_use]
    pub const fn expires_at_unix_seconds(&self) -> u64 {
        self.expires_at_unix_seconds
    }

    /// Returns the authenticated-encryption nonce.
    #[must_use]
    pub const fn nonce(&self) -> &[u8; AUTHENTICATED_CIPHER_NONCE_BYTES] {
        self.ciphertext.nonce()
    }

    /// Returns the opaque capability ciphertext and appended tag.
    #[must_use]
    pub fn ciphertext(&self) -> &[u8] {
        self.ciphertext.as_bytes()
    }
}

/// Encrypts one complete pairing capability behind a compact token.
///
/// # Errors
///
/// Returns a capability, randomness, key-derivation, or encryption error.
pub fn create_pairing_rendezvous(
    capability: &PairingCapability,
    now_unix_seconds: u64,
) -> Result<(PairingRendezvousTokenText, PairingRendezvousRecord), KonclaveClientError> {
    if capability.offer().expires_at_unix_seconds() <= now_unix_seconds {
        return Err(KonclaveClientError::InvalidPairingRendezvous);
    }
    let secret = PairingRendezvousSecret::generate()?;
    let schedule = PairingRendezvousKeySchedule::derive(&secret)?;
    let capability_text = capability.encode()?;
    let expires_at_unix_seconds = capability.offer().expires_at_unix_seconds();
    let ciphertext = schedule.seal(
        expires_at_unix_seconds,
        capability_text.as_str().as_bytes(),
    )?;
    let record = PairingRendezvousRecord {
        lookup_id: *schedule.lookup_id(),
        expires_at_unix_seconds,
        ciphertext,
    };
    let mut token_bytes = Zeroizing::new(Vec::with_capacity(PAIRING_RENDEZVOUS_TOKEN_BYTES));
    secret.write_token_bytes(&mut token_bytes);
    let token = encode_token(
        token_bytes
            .as_slice()
            .try_into()
            .map_err(|_| KonclaveClientError::InvalidPairingRendezvous)?,
    );
    Ok((
        PairingRendezvousTokenText(Zeroizing::new(token)),
        record,
    ))
}

/// Decrypts and authenticates one relay-returned capability with a compact token.
///
/// # Errors
///
/// Returns one opaque invalid-rendezvous or capability error for malformed,
/// expired, mismatched, modified, or unauthentic input.
pub fn open_pairing_rendezvous(
    token: &str,
    record: &PairingRendezvousRecord,
    now_unix_seconds: u64,
) -> Result<PairingCapability, KonclaveClientError> {
    if record.expires_at_unix_seconds <= now_unix_seconds {
        return Err(KonclaveClientError::InvalidPairingRendezvous);
    }
    let token_bytes = Zeroizing::new(decode_token(token)?);
    let secret = PairingRendezvousSecret::from_bytes(*token_bytes);
    let schedule = PairingRendezvousKeySchedule::derive(&secret)?;
    if schedule.lookup_id() != record.lookup_id() {
        return Err(KonclaveClientError::InvalidPairingRendezvous);
    }
    let plaintext = schedule
        .open(record.expires_at_unix_seconds, &record.ciphertext)
        .map_err(|_| KonclaveClientError::InvalidPairingRendezvous)?;
    let capability_text = std::str::from_utf8(&plaintext)
        .map_err(|_| KonclaveClientError::InvalidPairingRendezvous)?;
    let capability = PairingCapability::decode(capability_text, now_unix_seconds)
        .map_err(|_| KonclaveClientError::InvalidPairingRendezvous)?;
    if capability.offer().expires_at_unix_seconds() != record.expires_at_unix_seconds {
        return Err(KonclaveClientError::InvalidPairingRendezvous);
    }
    Ok(capability)
}

fn encode_token(bytes: &[u8; PAIRING_RENDEZVOUS_TOKEN_BYTES]) -> String {
    let mut output = String::with_capacity(PAIRING_RENDEZVOUS_TOKEN_CHARACTERS);
    let mut buffer = 0_u32;
    let mut bits = 0_u32;
    for byte in bytes {
        buffer = (buffer << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            output.push(char::from(TOKEN_ALPHABET[((buffer >> bits) & 31) as usize]));
            buffer &= (1_u32 << bits).wrapping_sub(1);
        }
    }
    if bits > 0 {
        output.push(char::from(TOKEN_ALPHABET[((buffer << (5 - bits)) & 31) as usize]));
    }
    debug_assert_eq!(output.len(), PAIRING_RENDEZVOUS_TOKEN_CHARACTERS);
    output
}

fn decode_token(
    value: &str,
) -> Result<[u8; PAIRING_RENDEZVOUS_TOKEN_BYTES], KonclaveClientError> {
    if value.len() != PAIRING_RENDEZVOUS_TOKEN_CHARACTERS || !value.is_ascii() {
        return Err(KonclaveClientError::InvalidPairingRendezvous);
    }
    let mut output = [0_u8; PAIRING_RENDEZVOUS_TOKEN_BYTES];
    let mut output_length = 0_usize;
    let mut buffer = 0_u32;
    let mut bits = 0_u32;
    for byte in value.bytes() {
        let value = decode_character(byte).ok_or(KonclaveClientError::InvalidPairingRendezvous)?;
        buffer = (buffer << 5) | u32::from(value);
        bits += 5;
        while bits >= 8 {
            bits -= 8;
            if output_length >= output.len() {
                return Err(KonclaveClientError::InvalidPairingRendezvous);
            }
            output[output_length] = ((buffer >> bits) & 255) as u8;
            output_length += 1;
            buffer &= (1_u32 << bits).wrapping_sub(1);
        }
    }
    if output_length != output.len() || bits != 2 || buffer != 0 {
        return Err(KonclaveClientError::InvalidPairingRendezvous);
    }
    Ok(output)
}

fn decode_character(value: u8) -> Option<u8> {
    let value = value.to_ascii_uppercase();
    TOKEN_ALPHABET
        .iter()
        .position(|candidate| *candidate == value)
        .and_then(|index| u8::try_from(index).ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use KonclaveCryptographicCore::DeviceIdentity;
    use KonclaveDomainCore::ConversationRole;
    use crate::RelayEndpoint;

    const NOW: u64 = 1_700_000_000;
    const EXPIRY: u64 = NOW + 300;

    fn capability() -> PairingCapability {
        PairingCapability::issue(
            &DeviceIdentity::generate().unwrap(),
            RelayEndpoint::parse("https://relay.example.com").unwrap(),
            ConversationRole::Member,
            EXPIRY,
            NOW,
        )
        .unwrap()
    }

    #[test]
    fn compact_token_round_trips_one_encrypted_capability() {
        let capability = capability();
        let capability_text = capability.encode().unwrap();
        let (token, record) = create_pairing_rendezvous(&capability, NOW).unwrap();
        assert_eq!(token.as_str().len(), PAIRING_RENDEZVOUS_TOKEN_CHARACTERS);
        assert!(
            token
                .as_str()
                .bytes()
                .all(|byte| TOKEN_ALPHABET.contains(&byte))
        );
        let opened = open_pairing_rendezvous(token.as_str(), &record, NOW).unwrap();
        assert_eq!(opened.offer(), capability.offer());
        assert_eq!(
            opened.relay_endpoint().as_str(),
            capability.relay_endpoint().as_str()
        );
        assert!(
            !record
                .ciphertext()
                .windows(capability_text.as_str().len())
                .any(|window| window == capability_text.as_str().as_bytes())
        );
    }

    #[test]
    fn token_is_case_insensitive_and_canonical() {
        let vector = std::array::from_fn(|index| u8::try_from(index).unwrap());
        assert_eq!(encode_token(&vector), "000G40R40M30E209185GR38E1W");
        assert_eq!(
            decode_token("000g40r40m30e209185gr38e1w").unwrap(),
            vector
        );

        let bytes = [0xabu8; PAIRING_RENDEZVOUS_TOKEN_BYTES];
        let encoded = encode_token(&bytes);
        assert_eq!(encoded.len(), PAIRING_RENDEZVOUS_TOKEN_CHARACTERS);
        assert_eq!(decode_token(&encoded).unwrap(), bytes);
        assert_eq!(decode_token(&encoded.to_ascii_lowercase()).unwrap(), bytes);
        assert!(decode_token(&format!("{}D", &encoded[..25])).is_err());
        assert!(decode_token("0000000000000000000000000O").is_err());
    }

    #[test]
    fn wrong_modified_and_expired_rendezvous_fail_closed() {
        let capability = capability();
        let (token, record) = create_pairing_rendezvous(&capability, NOW).unwrap();
        let (other_token, _) = create_pairing_rendezvous(&capability, NOW).unwrap();
        assert!(open_pairing_rendezvous(other_token.as_str(), &record, NOW).is_err());
        assert!(open_pairing_rendezvous(token.as_str(), &record, EXPIRY).is_err());
        assert!(create_pairing_rendezvous(&capability, EXPIRY).is_err());

        let mut modified = record.ciphertext().to_vec();
        modified[0] ^= 1;
        let modified = PairingRendezvousRecord::new(
            record.lookup_id(),
            record.expires_at_unix_seconds(),
            record.nonce(),
            modified,
        )
        .unwrap();
        assert!(open_pairing_rendezvous(token.as_str(), &modified, NOW).is_err());
    }
}
