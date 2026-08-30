/// Encodes bytes as canonical lowercase hexadecimal text.
#[must_use]
pub fn encode_lowercase_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

/// Decodes an exact-length canonical lowercase hexadecimal value.
#[must_use]
pub fn decode_lowercase_hex<const N: usize>(value: &str) -> Option<[u8; N]> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    let mut output = [0_u8; N];
    for (index, byte) in output.iter_mut().enumerate() {
        let high = hex_nibble(value.as_bytes()[index * 2])?;
        let low = hex_nibble(value.as_bytes()[index * 2 + 1])?;
        *byte = (high << 4) | low;
    }
    Some(output)
}

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{decode_lowercase_hex, encode_lowercase_hex};

    #[test]
    fn canonical_hex_round_trips_and_rejects_alternate_spelling() {
        assert_eq!(encode_lowercase_hex(&[0x00, 0xaf, 0xff]), "00afff");
        assert_eq!(
            decode_lowercase_hex::<3>("00afff").unwrap(),
            [0x00, 0xaf, 0xff]
        );
        assert!(decode_lowercase_hex::<3>("00AFFF").is_none());
        assert!(decode_lowercase_hex::<3>("00aff").is_none());
        assert!(decode_lowercase_hex::<3>("00afgg").is_none());
    }
}
