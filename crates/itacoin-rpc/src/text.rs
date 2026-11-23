//! Text forms of protocol values (section 3 of
//! `docs/PROTOCOL_REQUIREMENTS.md`, section 4.3 of `docs/NODE_PROPOSAL.md`).
//!
//! Every value has exactly one accepted text form, and sizes are checked
//! before anything is decoded.

use base64::{
    Engine,
    alphabet::URL_SAFE,
    engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig},
};
use itacoin_primitives::{Amount, Hash256, MAX_SUPPLY};

/// base64url without padding that refuses padding and non-zero trailing
/// bits, so each byte string has one encoding.
const STRICT_BASE64URL: GeneralPurpose = GeneralPurpose::new(
    &URL_SAFE,
    GeneralPurposeConfig::new()
        .with_encode_padding(false)
        .with_decode_padding_mode(DecodePaddingMode::RequireNone)
        .with_decode_allow_trailing_bits(false),
);

/// Why a text value was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TextError {
    /// Wrong length.
    Length,
    /// A character outside the alphabet, a prefix or padding.
    Encoding,
    /// The value is out of range.
    Range,
}

/// Encodes bytes as base64url without padding.
#[must_use]
pub fn encode_base64url(bytes: &[u8]) -> String {
    STRICT_BASE64URL.encode(bytes)
}

/// Longest base64url text for `max_bytes` bytes: `ceil(4n / 3)`.
#[must_use]
pub const fn base64url_len(max_bytes: usize) -> usize {
    (max_bytes * 4).div_ceil(3)
}

/// Decodes strict base64url, refusing text longer than `max_bytes` encodes
/// to before decoding anything.
pub fn decode_base64url(text: &str, max_bytes: usize) -> Result<Vec<u8>, TextError> {
    if text.len() > base64url_len(max_bytes) {
        return Err(TextError::Length);
    }
    let bytes = STRICT_BASE64URL
        .decode(text)
        .map_err(|_| TextError::Encoding)?;
    if bytes.len() > max_bytes {
        return Err(TextError::Length);
    }
    Ok(bytes)
}

/// Encodes bytes as lowercase hex.
#[must_use]
pub fn encode_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(char::from(DIGITS[usize::from(byte >> 4)]));
        text.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    text
}

/// Decodes exactly `N` bytes from `2N` hex digits. Uppercase is accepted,
/// a `0x` prefix is not.
pub fn decode_hex<const N: usize>(text: &str) -> Result<[u8; N], TextError> {
    if text.len() != 2 * N {
        return Err(TextError::Length);
    }
    let mut bytes = [0_u8; N];
    for (index, pair) in text.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_digit(pair[0]).ok_or(TextError::Encoding)?;
        let low = hex_digit(pair[1]).ok_or(TextError::Encoding)?;
        bytes[index] = (high << 4) | low;
    }
    Ok(bytes)
}

/// Decodes a 32-byte hash from 64 hex digits.
pub fn decode_hash(text: &str) -> Result<Hash256, TextError> {
    decode_hex::<32>(text).map(Hash256::new)
}

const fn hex_digit(character: u8) -> Option<u8> {
    match character {
        b'0'..=b'9' => Some(character - b'0'),
        b'a'..=b'f' => Some(character - b'a' + 10),
        b'A'..=b'F' => Some(character - b'A' + 10),
        _ => None,
    }
}

/// Formats an amount as a string of satoshis.
#[must_use]
pub fn format_sat(amount: Amount) -> String {
    amount.as_satoshis().to_string()
}

/// Formats a satoshi total kept in `u128` as a string.
#[must_use]
pub fn format_sat_u128(satoshis: u128) -> String {
    satoshis.to_string()
}

/// Parses a string of satoshis: digits only, no sign, no leading zero, at
/// most [`MAX_SUPPLY`].
pub fn parse_sat(text: &str) -> Result<Amount, TextError> {
    // MAX_SUPPLY has 17 digits.
    if text.is_empty() || text.len() > 17 {
        return Err(TextError::Length);
    }
    if !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(TextError::Encoding);
    }
    if text.len() > 1 && text.starts_with('0') {
        return Err(TextError::Encoding);
    }
    let value: u64 = text.parse().map_err(|_| TextError::Range)?;
    if value > MAX_SUPPLY {
        return Err(TextError::Range);
    }
    Amount::from_satoshis(value).map_err(|_| TextError::Range)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64url_is_strict() {
        let bytes = [0xfb_u8, 0xff, 0x01];
        let text = encode_base64url(&bytes);
        assert_eq!(text, "-_8B");
        assert_eq!(decode_base64url(&text, 3).unwrap(), bytes);
        // Padding, the standard alphabet and spaces are refused.
        assert_eq!(decode_base64url("AQ==", 3), Err(TextError::Encoding));
        assert_eq!(decode_base64url("+/8B", 3), Err(TextError::Encoding));
        assert_eq!(decode_base64url("-_8 B", 3), Err(TextError::Length));
        assert_eq!(decode_base64url("-_ 8B", 4), Err(TextError::Encoding));
        // Non-zero trailing bits would give a second encoding of 0x01.
        assert_eq!(decode_base64url("AQ", 1).unwrap(), [1]);
        assert_eq!(decode_base64url("AR", 1), Err(TextError::Encoding));
        // The size is checked before decoding.
        assert_eq!(decode_base64url("AAAAAA", 3), Err(TextError::Length));
        assert_eq!(base64url_len(100_000), 133_334);
        assert_eq!(base64url_len(1_000_000), 1_333_334);
    }

    #[test]
    fn hashes_are_lowercase_hex_without_prefix() {
        let hash = Hash256::new([0xab; 32]);
        let text = encode_hex(hash.as_bytes());
        assert_eq!(text, "ab".repeat(32));
        assert_eq!(text, hash.to_string());
        assert_eq!(decode_hash(&text).unwrap(), hash);
        assert_eq!(decode_hash(&"AB".repeat(32)).unwrap(), hash);
        assert_eq!(
            decode_hash(&format!("0x{}", "ab".repeat(31))),
            Err(TextError::Encoding)
        );
        assert_eq!(decode_hash("ab"), Err(TextError::Length));
        assert_eq!(decode_hash(&"g0".repeat(32)), Err(TextError::Encoding));
    }

    #[test]
    fn satoshi_strings_round_trip_without_loss() {
        // Above 2^53, where a JavaScript number would round.
        let text = "10000000000000000";
        assert_eq!(format_sat(parse_sat(text).unwrap()), text);
        assert_eq!(
            format_sat(parse_sat("9007199254740993").unwrap()),
            "9007199254740993"
        );
        assert_eq!(parse_sat("0").unwrap(), Amount::ZERO);
        for bad in ["", "01", "-1", "+1", "1.0", " 1", "1e3", "0x10"] {
            assert!(parse_sat(bad).is_err(), "{bad:?} must be refused");
        }
        assert_eq!(parse_sat("10000000000000001"), Err(TextError::Range));
        assert_eq!(parse_sat("99999999999999999"), Err(TextError::Range));
        assert_eq!(parse_sat("100000000000000000"), Err(TextError::Length));
    }
}
