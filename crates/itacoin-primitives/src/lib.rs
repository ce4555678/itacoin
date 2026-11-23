//! Fundamental monetary and fixed-width identifier types for ITACOIN.
//!
//! Monetary values are always represented by [`Amount`] in atomic ITC units.
//! Floating-point conversion is intentionally not provided.

use core::{fmt, str::FromStr};

mod address;

pub use address::{ADDRESS_VERSION, Address, AddressError, Network};

/// Atomic units in one whole ITC.
pub const COIN: u64 = 100_000_000;

/// Maximum number of ITC that may ever be emitted, in atomic units.
pub const MAX_SUPPLY: u64 = 100_000_000 * COIN;

/// A non-negative ITC amount in atomic units, bounded by [`MAX_SUPPLY`].
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct Amount(u64);

impl Amount {
    /// Zero ITC.
    pub const ZERO: Self = Self(0);

    /// The protocol's total maximum supply.
    pub const MAX: Self = Self(MAX_SUPPLY);

    /// Creates an amount from atomic ITC units.
    pub const fn from_satoshis(satoshis: u64) -> Result<Self, AmountError> {
        if satoshis > MAX_SUPPLY {
            return Err(AmountError::ExceedsMaxSupply { satoshis });
        }
        Ok(Self(satoshis))
    }

    /// Creates an amount from a whole number of ITC.
    pub const fn from_whole_itc(itc: u64) -> Result<Self, AmountError> {
        let satoshis = match itc.checked_mul(COIN) {
            Some(value) => value,
            None => return Err(AmountError::ArithmeticOverflow),
        };
        Self::from_satoshis(satoshis)
    }

    /// Returns the amount in atomic ITC units.
    #[must_use]
    pub const fn as_satoshis(self) -> u64 {
        self.0
    }

    /// Adds two amounts without allowing overflow or issuance beyond the cap.
    pub const fn checked_add(self, rhs: Self) -> Result<Self, AmountError> {
        let sum = match self.0.checked_add(rhs.0) {
            Some(value) => value,
            None => return Err(AmountError::ArithmeticOverflow),
        };
        Self::from_satoshis(sum)
    }

    /// Subtracts two amounts without allowing underflow.
    pub const fn checked_sub(self, rhs: Self) -> Result<Self, AmountError> {
        let difference = match self.0.checked_sub(rhs.0) {
            Some(value) => value,
            None => return Err(AmountError::InsufficientAmount),
        };
        Ok(Self(difference))
    }

    /// Parses a decimal ITC value with at most eight fractional digits.
    ///
    /// Exponent notation, signs, whitespace, and floating-point inputs are not
    /// accepted. Use this at human-input boundaries; consensus code should use
    /// atomic units directly.
    pub fn from_itc_str(input: &str) -> Result<Self, AmountError> {
        if input.is_empty() || input.starts_with('-') || input.starts_with('+') {
            return Err(AmountError::InvalidDecimal);
        }

        let mut parts = input.split('.');
        let whole = parts.next().ok_or(AmountError::InvalidDecimal)?;
        let fractional = parts.next();
        if parts.next().is_some() || whole.is_empty() || !whole.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(AmountError::InvalidDecimal);
        }

        let whole = whole
            .parse::<u64>()
            .map_err(|_| AmountError::InvalidDecimal)?;
        let fractional_satoshis = match fractional {
            None => 0,
            Some(value) => {
                if value.is_empty() || value.len() > 8 || !value.bytes().all(|b| b.is_ascii_digit())
                {
                    return Err(AmountError::InvalidDecimal);
                }
                let digits = value
                    .parse::<u64>()
                    .map_err(|_| AmountError::InvalidDecimal)?;
                let scale =
                    8_u32 - u32::try_from(value.len()).map_err(|_| AmountError::InvalidDecimal)?;
                digits
                    .checked_mul(10_u64.pow(scale))
                    .ok_or(AmountError::ArithmeticOverflow)?
            }
        };

        let integral = whole
            .checked_mul(COIN)
            .ok_or(AmountError::ArithmeticOverflow)?;
        let satoshis = integral
            .checked_add(fractional_satoshis)
            .ok_or(AmountError::ArithmeticOverflow)?;
        Self::from_satoshis(satoshis)
    }
}

impl fmt::Display for Amount {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let whole = self.0 / COIN;
        let fractional = self.0 % COIN;
        write!(formatter, "{whole}.{fractional:08}")
    }
}

impl FromStr for Amount {
    type Err = AmountError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::from_itc_str(input)
    }
}

/// Errors raised by checked monetary operations and decimal parsing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AmountError {
    /// A calculation exceeded `u64`.
    ArithmeticOverflow,
    /// The resulting amount would exceed [`MAX_SUPPLY`].
    ExceedsMaxSupply {
        /// The rejected number of atomic units.
        satoshis: u64,
    },
    /// Subtraction would create a negative amount.
    InsufficientAmount,
    /// The input is not a precise decimal ITC string.
    InvalidDecimal,
}

impl fmt::Display for AmountError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ArithmeticOverflow => formatter.write_str("monetary arithmetic overflow"),
            Self::ExceedsMaxSupply { .. } => {
                formatter.write_str("amount exceeds ITACOIN maximum supply")
            }
            Self::InsufficientAmount => formatter.write_str("monetary subtraction underflow"),
            Self::InvalidDecimal => formatter.write_str("invalid decimal ITC amount"),
        }
    }
}

impl std::error::Error for AmountError {}

/// A 256-bit value used as the common representation for protocol digests.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct Hash256([u8; 32]);

impl Hash256 {
    /// Creates a hash from exactly 32 bytes.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrows the canonical bytes of this hash.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns the canonical bytes of this hash.
    #[must_use]
    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl From<[u8; 32]> for Hash256 {
    fn from(bytes: [u8; 32]) -> Self {
        Self::new(bytes)
    }
}

impl fmt::Debug for Hash256 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Hash256(")?;
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        formatter.write_str(")")
    }
}

impl fmt::Display for Hash256 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

macro_rules! identifier {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        #[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
        #[repr(transparent)]
        pub struct $name(Hash256);

        impl $name {
            /// Creates an identifier from a hash digest.
            #[must_use]
            pub const fn new(hash: Hash256) -> Self {
                Self(hash)
            }

            /// Borrows the 32-byte identifier.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 32] {
                self.0.as_bytes()
            }

            /// Returns its hash representation.
            #[must_use]
            pub const fn into_hash(self) -> Hash256 {
                self.0
            }
        }

        impl From<Hash256> for $name {
            fn from(hash: Hash256) -> Self {
                Self::new(hash)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&self.0)
                    .finish()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }
    };
}

identifier!(BlockId, "Identifier of a block header.");
identifier!(TransactionId, "Identifier of a transaction.");
identifier!(WalletId, "Identifier derived from a wallet public key.");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_precise_itc_decimals() {
        assert_eq!(
            Amount::from_itc_str("1.00000001").unwrap().as_satoshis(),
            COIN + 1
        );
        assert_eq!(Amount::from_itc_str("100000000").unwrap(), Amount::MAX);
        assert_eq!(
            Amount::from_itc_str("42").unwrap().to_string(),
            "42.00000000"
        );
        assert_eq!(
            Amount::from_itc_str("0.1").unwrap().to_string(),
            "0.10000000"
        );
    }

    #[test]
    fn rejects_imprecise_or_out_of_range_decimals() {
        for invalid in ["", "-1", "+1", "1.", ".1", "1.000000001", "1e2", " 1"] {
            assert_eq!(
                Amount::from_itc_str(invalid),
                Err(AmountError::InvalidDecimal)
            );
        }
        assert!(matches!(
            Amount::from_itc_str("100000000.00000001"),
            Err(AmountError::ExceedsMaxSupply { .. })
        ));
    }

    #[test]
    fn monetary_operations_are_checked() {
        assert_eq!(
            Amount::MAX.checked_add(Amount::from_satoshis(1).unwrap()),
            Err(AmountError::ExceedsMaxSupply {
                satoshis: MAX_SUPPLY + 1
            })
        );
        assert_eq!(
            Amount::ZERO.checked_sub(Amount::from_satoshis(1).unwrap()),
            Err(AmountError::InsufficientAmount)
        );
        assert_eq!(
            Amount::from_whole_itc(u64::MAX),
            Err(AmountError::ArithmeticOverflow)
        );
    }
}
