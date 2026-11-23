//! Canonical binary encoding for ITACOIN, as specified in
//! `docs/CODEC_PROPOSAL.md`.
//!
//! Every field has a fixed width and integers are big-endian, so each value
//! has exactly one accepted encoding. Decoding is strict: it refuses trailing
//! bytes, out-of-range counts and invalid values, never panics, and never
//! allocates a list before confirming the input is long enough to hold it.

use core::{fmt, ops::RangeInclusive};

use itacoin_crypto::{
    CryptoError, ML_DSA_65_PUBLIC_KEY_BYTES, ML_DSA_65_SIGNATURE_BYTES, PublicKey, Signature,
};
use itacoin_primitives::{Amount, AmountError, BlockId, Hash256, TransactionId, WalletId};

/// A bounds-checked cursor over untrusted input.
#[derive(Debug)]
pub struct Reader<'a> {
    input: &'a [u8],
}

impl<'a> Reader<'a> {
    /// Starts reading `input` from the beginning.
    #[must_use]
    pub const fn new(input: &'a [u8]) -> Self {
        Self { input }
    }

    /// Returns the number of unread bytes.
    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.input.len()
    }

    /// Fails unless at least `length` bytes remain, without consuming them.
    pub fn ensure(&self, length: usize) -> Result<(), CodecError> {
        if length <= self.input.len() {
            Ok(())
        } else {
            Err(CodecError::UnexpectedEnd)
        }
    }

    /// Consumes and returns the next `length` bytes.
    pub fn take(&mut self, length: usize) -> Result<&'a [u8], CodecError> {
        self.ensure(length)?;
        let (head, tail) = self.input.split_at(length);
        self.input = tail;
        Ok(head)
    }

    /// Consumes a fixed-size byte array.
    pub fn array<const N: usize>(&mut self) -> Result<[u8; N], CodecError> {
        let mut array = [0_u8; N];
        array.copy_from_slice(self.take(N)?);
        Ok(array)
    }

    /// Reads a `u8`.
    pub fn u8(&mut self) -> Result<u8, CodecError> {
        Ok(self.array::<1>()?[0])
    }

    /// Reads a big-endian `u16`.
    pub fn u16(&mut self) -> Result<u16, CodecError> {
        self.array().map(u16::from_be_bytes)
    }

    /// Reads a big-endian `u32`.
    pub fn u32(&mut self) -> Result<u32, CodecError> {
        self.array().map(u32::from_be_bytes)
    }

    /// Reads a big-endian `u64`.
    pub fn u64(&mut self) -> Result<u64, CodecError> {
        self.array().map(u64::from_be_bytes)
    }

    /// Reads a `u16` list count, requires it to be in `allowed`, and checks
    /// that the rest of the input can hold that many elements of at least
    /// `min_element_bytes` each before the caller allocates anything.
    pub fn count_u16(
        &mut self,
        allowed: RangeInclusive<usize>,
        min_element_bytes: usize,
    ) -> Result<usize, CodecError> {
        let count = usize::from(self.u16()?);
        self.check_count(count, allowed, min_element_bytes)
    }

    /// Like [`Reader::count_u16`] for a `u32` count.
    pub fn count_u32(
        &mut self,
        allowed: RangeInclusive<usize>,
        min_element_bytes: usize,
    ) -> Result<usize, CodecError> {
        let count = usize::try_from(self.u32()?).map_err(|_| CodecError::UnexpectedEnd)?;
        self.check_count(count, allowed, min_element_bytes)
    }

    fn check_count(
        &self,
        count: usize,
        allowed: RangeInclusive<usize>,
        min_element_bytes: usize,
    ) -> Result<usize, CodecError> {
        if !allowed.contains(&count) {
            return Err(CodecError::CountOutOfRange {
                minimum: *allowed.start(),
                maximum: *allowed.end(),
                actual: count,
            });
        }
        self.ensure(
            count
                .checked_mul(min_element_bytes)
                .ok_or(CodecError::UnexpectedEnd)?,
        )?;
        Ok(count)
    }

    /// Finishes decoding, refusing any unread bytes.
    pub fn finish(self) -> Result<(), CodecError> {
        if self.input.is_empty() {
            Ok(())
        } else {
            Err(CodecError::TrailingBytes {
                count: self.input.len(),
            })
        }
    }
}

/// An append-only output buffer.
#[derive(Debug, Default)]
pub struct Writer {
    bytes: Vec<u8>,
}

impl Writer {
    /// Creates a writer with room for `capacity` bytes.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(capacity),
        }
    }

    /// Appends raw bytes.
    pub fn bytes(&mut self, bytes: &[u8]) {
        self.bytes.extend_from_slice(bytes);
    }

    /// Appends a `u8`.
    pub fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    /// Appends a big-endian `u16`.
    pub fn u16(&mut self, value: u16) {
        self.bytes(&value.to_be_bytes());
    }

    /// Appends a big-endian `u32`.
    pub fn u32(&mut self, value: u32) {
        self.bytes(&value.to_be_bytes());
    }

    /// Appends a big-endian `u64`.
    pub fn u64(&mut self, value: u64) {
        self.bytes(&value.to_be_bytes());
    }

    /// Appends a `u16` list count.
    ///
    /// # Panics
    ///
    /// Panics if `count` exceeds `u16::MAX`. Protocol types validate their
    /// list lengths on construction, far below that bound, so this indicates a
    /// bug rather than bad input.
    pub fn count_u16(&mut self, count: usize) {
        self.u16(u16::try_from(count).expect("validated list length fits in u16"));
    }

    /// Appends a `u32` list count.
    ///
    /// # Panics
    ///
    /// Panics if `count` exceeds `u32::MAX`; see [`Writer::count_u16`].
    pub fn count_u32(&mut self, count: usize) {
        self.u32(u32::try_from(count).expect("validated list length fits in u32"));
    }

    /// Returns the encoded bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

/// A value with a canonical binary encoding.
pub trait Encode {
    /// Appends the canonical encoding to `writer`.
    fn encode(&self, writer: &mut Writer);

    /// Returns the exact length of the canonical encoding.
    fn encoded_len(&self) -> usize;

    /// Returns the canonical encoding.
    fn to_bytes(&self) -> Vec<u8> {
        let mut writer = Writer::with_capacity(self.encoded_len());
        self.encode(&mut writer);
        debug_assert_eq!(writer.bytes.len(), self.encoded_len());
        writer.into_bytes()
    }
}

/// A value that can be strictly decoded from untrusted bytes.
pub trait Decode: Sized {
    /// The error returned for invalid input.
    type Error: From<CodecError>;

    /// Decodes one value from the front of `reader`.
    fn decode(reader: &mut Reader<'_>) -> Result<Self, Self::Error>;
}

/// Decodes exactly one value occupying all of `bytes`.
///
/// The length is checked against `maximum` before anything is parsed.
pub fn decode_exact<T: Decode>(bytes: &[u8], maximum: usize) -> Result<T, T::Error> {
    if bytes.len() > maximum {
        return Err(CodecError::TooLarge {
            maximum,
            actual: bytes.len(),
        }
        .into());
    }
    let mut reader = Reader::new(bytes);
    let value = T::decode(&mut reader)?;
    reader.finish()?;
    Ok(value)
}

impl Encode for Hash256 {
    fn encode(&self, writer: &mut Writer) {
        writer.bytes(self.as_bytes());
    }

    fn encoded_len(&self) -> usize {
        32
    }
}

impl Decode for Hash256 {
    type Error = CodecError;

    fn decode(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        reader.array().map(Self::new)
    }
}

macro_rules! identifier_codec {
    ($($name:ident),*) => {$(
        impl Encode for $name {
            fn encode(&self, writer: &mut Writer) {
                writer.bytes(self.as_bytes());
            }

            fn encoded_len(&self) -> usize {
                32
            }
        }

        impl Decode for $name {
            type Error = CodecError;

            fn decode(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
                Hash256::decode(reader).map(Self::new)
            }
        }
    )*};
}

identifier_codec!(BlockId, TransactionId, WalletId);

impl Encode for Amount {
    fn encode(&self, writer: &mut Writer) {
        writer.u64(self.as_satoshis());
    }

    fn encoded_len(&self) -> usize {
        8
    }
}

impl Decode for Amount {
    type Error = CodecError;

    /// Accepts `0..=MAX_SUPPLY`; whether zero is allowed is up to the caller.
    fn decode(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        Self::from_satoshis(reader.u64()?).map_err(CodecError::InvalidAmount)
    }
}

impl Encode for PublicKey {
    fn encode(&self, writer: &mut Writer) {
        writer.bytes(self.as_bytes());
    }

    fn encoded_len(&self) -> usize {
        ML_DSA_65_PUBLIC_KEY_BYTES
    }
}

impl Decode for PublicKey {
    type Error = CodecError;

    fn decode(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        Self::from_bytes(reader.take(ML_DSA_65_PUBLIC_KEY_BYTES)?).map_err(CodecError::Crypto)
    }
}

impl Encode for Signature {
    fn encode(&self, writer: &mut Writer) {
        writer.bytes(self.as_bytes());
    }

    fn encoded_len(&self) -> usize {
        ML_DSA_65_SIGNATURE_BYTES
    }
}

impl Decode for Signature {
    type Error = CodecError;

    fn decode(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        Self::from_bytes(reader.take(ML_DSA_65_SIGNATURE_BYTES)?).map_err(CodecError::Crypto)
    }
}

/// Errors produced by strict decoding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CodecError {
    /// The input ended before the value was complete.
    UnexpectedEnd,
    /// Bytes remained after the value was decoded.
    TrailingBytes {
        /// Number of unread bytes.
        count: usize,
    },
    /// The input is longer than the limit for this value.
    TooLarge {
        /// Maximum accepted length in bytes.
        maximum: usize,
        /// Provided length in bytes.
        actual: usize,
    },
    /// A list count is outside its allowed range.
    CountOutOfRange {
        /// Smallest allowed count.
        minimum: usize,
        /// Largest allowed count.
        maximum: usize,
        /// Decoded count.
        actual: usize,
    },
    /// A monetary value exceeds the maximum supply.
    InvalidAmount(AmountError),
    /// A key or signature is not a valid ML-DSA-65 encoding.
    Crypto(CryptoError),
}

impl fmt::Display for CodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEnd => formatter.write_str("input ended unexpectedly"),
            Self::TrailingBytes { count } => write!(formatter, "{count} trailing bytes"),
            Self::TooLarge { maximum, actual } => {
                write!(formatter, "input of {actual} bytes exceeds {maximum}")
            }
            Self::CountOutOfRange {
                minimum,
                maximum,
                actual,
            } => write!(
                formatter,
                "list count {actual} outside {minimum}..={maximum}"
            ),
            Self::InvalidAmount(error) => write!(formatter, "invalid amount: {error}"),
            Self::Crypto(error) => write!(formatter, "invalid encoding: {error}"),
        }
    }
}

impl std::error::Error for CodecError {}

#[cfg(test)]
mod tests {
    use itacoin_primitives::MAX_SUPPLY;

    use super::*;

    #[test]
    fn integers_are_big_endian_and_round_trip() {
        let mut writer = Writer::default();
        writer.u8(0xab);
        writer.u16(0x0102);
        writer.u32(0x0304_0506);
        writer.u64(0x0708_090a_0b0c_0d0e);
        let bytes = writer.into_bytes();
        assert_eq!(bytes, [0xab, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]);
        let mut reader = Reader::new(&bytes);
        assert_eq!(reader.u8().unwrap(), 0xab);
        assert_eq!(reader.u16().unwrap(), 0x0102);
        assert_eq!(reader.u32().unwrap(), 0x0304_0506);
        assert_eq!(reader.u64().unwrap(), 0x0708_090a_0b0c_0d0e);
        reader.finish().unwrap();
    }

    #[test]
    fn refuses_truncated_and_trailing_input() {
        assert_eq!(Reader::new(&[1]).u16(), Err(CodecError::UnexpectedEnd));
        let mut reader = Reader::new(&[0, 1, 2]);
        reader.u16().unwrap();
        assert_eq!(reader.finish(), Err(CodecError::TrailingBytes { count: 1 }));
        assert_eq!(
            decode_exact::<Hash256>(&[0; 33], 32),
            Err(CodecError::TooLarge {
                maximum: 32,
                actual: 33
            })
        );
        assert_eq!(
            decode_exact::<Hash256>(&[0; 33], 64),
            Err(CodecError::TrailingBytes { count: 1 })
        );
    }

    #[test]
    fn counts_are_range_checked_before_allocation() {
        // A count of 1000 elements of 36 bytes with only 4 bytes of input
        // must fail before any list is allocated.
        let mut input = vec![0x03, 0xe8];
        input.extend_from_slice(&[0; 4]);
        assert_eq!(
            Reader::new(&input).count_u16(1..=1000, 36),
            Err(CodecError::UnexpectedEnd)
        );
        assert_eq!(
            Reader::new(&[0, 0]).count_u16(1..=1000, 36),
            Err(CodecError::CountOutOfRange {
                minimum: 1,
                maximum: 1000,
                actual: 0
            })
        );
        assert_eq!(
            Reader::new(&[0xff, 0xff, 0xff, 0xff]).count_u32(0..=10, 1),
            Err(CodecError::CountOutOfRange {
                minimum: 0,
                maximum: 10,
                actual: u32::MAX as usize
            })
        );
        let mut input = vec![0, 2];
        input.extend_from_slice(&[0; 72]);
        assert_eq!(Reader::new(&input).count_u16(1..=1000, 36), Ok(2));
    }

    #[test]
    fn amounts_above_max_supply_are_refused() {
        let max = Amount::from_satoshis(MAX_SUPPLY).unwrap();
        assert_eq!(decode_exact::<Amount>(&max.to_bytes(), 8), Ok(max));
        assert!(matches!(
            decode_exact::<Amount>(&(MAX_SUPPLY + 1).to_be_bytes(), 8),
            Err(CodecError::InvalidAmount(_))
        ));
    }

    #[test]
    fn keys_and_signatures_are_validated() {
        let pair = itacoin_crypto::KeyPair::generate().unwrap();
        let encoded = pair.public_key.to_bytes();
        assert_eq!(
            decode_exact::<PublicKey>(&encoded, encoded.len()).unwrap(),
            pair.public_key
        );
        assert!(matches!(
            decode_exact::<Signature>(&[0; ML_DSA_65_SIGNATURE_BYTES], usize::MAX),
            Err(CodecError::Crypto(_))
        ));
    }
}
