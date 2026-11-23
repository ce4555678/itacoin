//! A minimal unsigned 256-bit integer for targets and chain work.
//!
//! Only the operations consensus needs are implemented, each with explicit
//! overflow behavior. Limbs are little-endian: `limbs[0]` is least significant.

use core::{
    cmp::Ordering,
    fmt,
    ops::{Not, Shl, Shr},
};

use itacoin_primitives::Hash256;

/// An unsigned 256-bit integer.
#[derive(Clone, Copy, Default, Eq, Hash, PartialEq)]
pub struct U256([u64; 4]);

impl U256 {
    /// Zero.
    pub const ZERO: Self = Self([0; 4]);
    /// One.
    pub const ONE: Self = Self([1, 0, 0, 0]);
    /// `2^256 - 1`.
    pub const MAX: Self = Self([u64::MAX; 4]);

    /// Converts a `u64`.
    #[must_use]
    pub const fn from_u64(value: u64) -> Self {
        Self([value, 0, 0, 0])
    }

    /// Parses 32 big-endian bytes.
    #[must_use]
    pub fn from_be_bytes(bytes: [u8; 32]) -> Self {
        let mut limbs = [0_u64; 4];
        for (index, limb) in limbs.iter_mut().enumerate() {
            let start = 32 - 8 * (index + 1);
            *limb = u64::from_be_bytes(bytes[start..start + 8].try_into().expect("8 bytes"));
        }
        Self(limbs)
    }

    /// Returns 32 big-endian bytes.
    #[must_use]
    pub fn to_be_bytes(self) -> [u8; 32] {
        let mut bytes = [0_u8; 32];
        for (index, limb) in self.0.iter().enumerate() {
            let start = 32 - 8 * (index + 1);
            bytes[start..start + 8].copy_from_slice(&limb.to_be_bytes());
        }
        bytes
    }

    /// Interprets a hash as a big-endian integer.
    #[must_use]
    pub fn from_hash(hash: &Hash256) -> Self {
        Self::from_be_bytes(*hash.as_bytes())
    }

    /// Returns the value as a big-endian hash.
    #[must_use]
    pub fn to_hash(self) -> Hash256 {
        Hash256::new(self.to_be_bytes())
    }

    /// Returns whether the value is zero.
    #[must_use]
    pub fn is_zero(self) -> bool {
        self == Self::ZERO
    }

    /// Returns the number of significant bits (0 for zero).
    #[must_use]
    pub fn bits(self) -> u32 {
        for index in (0..4).rev() {
            if self.0[index] != 0 {
                return 64 * index as u32 + 64 - self.0[index].leading_zeros();
            }
        }
        0
    }

    /// Returns the low 64 bits.
    #[must_use]
    pub const fn low_u64(self) -> u64 {
        self.0[0]
    }

    /// Adds, returning `None` on overflow.
    #[must_use]
    pub fn checked_add(self, rhs: Self) -> Option<Self> {
        let mut out = [0_u64; 4];
        let mut carry = false;
        for (index, limb) in out.iter_mut().enumerate() {
            let (sum, first) = self.0[index].overflowing_add(rhs.0[index]);
            let (sum, second) = sum.overflowing_add(u64::from(carry));
            *limb = sum;
            carry = first || second;
        }
        (!carry).then_some(Self(out))
    }

    /// Subtracts, returning `None` on underflow.
    #[must_use]
    pub fn checked_sub(self, rhs: Self) -> Option<Self> {
        let mut out = [0_u64; 4];
        let mut borrow = false;
        for (index, limb) in out.iter_mut().enumerate() {
            let (difference, first) = self.0[index].overflowing_sub(rhs.0[index]);
            let (difference, second) = difference.overflowing_sub(u64::from(borrow));
            *limb = difference;
            borrow = first || second;
        }
        (!borrow).then_some(Self(out))
    }

    /// Divides, returning `None` for a zero divisor.
    #[must_use]
    pub fn checked_div(self, divisor: Self) -> Option<Self> {
        if divisor.is_zero() {
            return None;
        }
        // Restoring long division, one bit at a time. Not performance critical.
        let mut quotient = Self::ZERO;
        let mut remainder = Self::ZERO;
        for bit in (0..self.bits()).rev() {
            let top = remainder.0[3] >> 63;
            remainder = remainder << 1;
            remainder.0[0] |= (self.0[(bit / 64) as usize] >> (bit % 64)) & 1;
            if top == 1 || remainder >= divisor {
                remainder = remainder.wrapping_sub(divisor);
                quotient.0[(bit / 64) as usize] |= 1 << (bit % 64);
            }
        }
        Some(quotient)
    }

    fn wrapping_sub(self, rhs: Self) -> Self {
        let mut out = [0_u64; 4];
        let mut borrow = false;
        for (index, limb) in out.iter_mut().enumerate() {
            let (difference, first) = self.0[index].overflowing_sub(rhs.0[index]);
            let (difference, second) = difference.overflowing_sub(u64::from(borrow));
            *limb = difference;
            borrow = first || second;
        }
        Self(out)
    }

    /// Multiplies by `factor` and shifts by `shift` (left if positive),
    /// computed exactly in 320 bits. Returns `None` if the result does not fit
    /// in 256 bits.
    #[must_use]
    pub fn mul_u64_shift(self, factor: u64, shift: i64) -> Option<Self> {
        let mut wide = [0_u64; 5];
        let mut carry = 0_u128;
        for (slot, &limb) in wide.iter_mut().zip(&self.0) {
            let product = u128::from(limb) * u128::from(factor) + carry;
            *slot = product as u64;
            carry = product >> 64;
        }
        wide[4] = carry as u64;

        let shifted = if shift >= 0 {
            let shift = u32::try_from(shift).unwrap_or(u32::MAX);
            // Any bit pushed past 320 bits, or left above 256, overflows.
            if shift >= 320 {
                if wide.iter().any(|&limb| limb != 0) {
                    return None;
                }
                [0; 5]
            } else {
                let result = wide_shl(wide, shift);
                if wide_shr(result, shift) != wide {
                    return None;
                }
                result
            }
        } else {
            wide_shr(
                wide,
                u32::try_from(shift.unsigned_abs()).unwrap_or(u32::MAX),
            )
        };
        (shifted[4] == 0).then_some(Self([shifted[0], shifted[1], shifted[2], shifted[3]]))
    }
}

fn wide_shl(value: [u64; 5], shift: u32) -> [u64; 5] {
    let mut out = [0_u64; 5];
    if shift >= 320 {
        return out;
    }
    let limbs = (shift / 64) as usize;
    let bits = shift % 64;
    for index in (limbs..5).rev() {
        let source = index - limbs;
        out[index] = value[source] << bits;
        if bits > 0 && source > 0 {
            out[index] |= value[source - 1] >> (64 - bits);
        }
    }
    out
}

fn wide_shr(value: [u64; 5], shift: u32) -> [u64; 5] {
    let mut out = [0_u64; 5];
    if shift >= 320 {
        return out;
    }
    let limbs = (shift / 64) as usize;
    let bits = shift % 64;
    for (index, slot) in out.iter_mut().enumerate().take(5 - limbs) {
        let source = index + limbs;
        *slot = value[source] >> bits;
        if bits > 0 && source + 1 < 5 {
            *slot |= value[source + 1] << (64 - bits);
        }
    }
    out
}

impl Shl<u32> for U256 {
    type Output = Self;

    /// Shifts left, discarding bits shifted out; zero for `shift >= 256`.
    fn shl(self, shift: u32) -> Self {
        let mut wide = [0_u64; 5];
        wide[..4].copy_from_slice(&self.0);
        let shifted = wide_shl(wide, shift);
        Self([shifted[0], shifted[1], shifted[2], shifted[3]])
    }
}

impl Shr<u32> for U256 {
    type Output = Self;

    /// Shifts right; zero for `shift >= 256`.
    fn shr(self, shift: u32) -> Self {
        let mut wide = [0_u64; 5];
        wide[..4].copy_from_slice(&self.0);
        let shifted = wide_shr(wide, shift);
        Self([shifted[0], shifted[1], shifted[2], shifted[3]])
    }
}

impl Not for U256 {
    type Output = Self;

    fn not(self) -> Self {
        Self(self.0.map(|limb| !limb))
    }
}

impl Ord for U256 {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.iter().rev().cmp(other.0.iter().rev())
    }
}

impl PartialOrd for U256 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Debug for U256 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "U256(0x{})", self.to_hash())
    }
}

impl fmt::Display for U256 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "0x{}", self.to_hash())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn from_u128(value: u128) -> U256 {
        U256([value as u64, (value >> 64) as u64, 0, 0])
    }

    /// Deterministic xorshift64.
    fn next(state: &mut u64) -> u64 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *state
    }

    #[test]
    fn bytes_round_trip_big_endian() {
        let mut bytes = [0_u8; 32];
        bytes[31] = 1;
        assert_eq!(U256::from_be_bytes(bytes), U256::ONE);
        bytes[0] = 0x80;
        let value = U256::from_be_bytes(bytes);
        assert_eq!(value.bits(), 256);
        assert_eq!(value.to_be_bytes(), bytes);
        assert_eq!(U256::ZERO.bits(), 0);
    }

    #[test]
    fn arithmetic_matches_u128() {
        let mut state = 0x9e37_79b9_7f4a_7c15;
        for _ in 0..2_000 {
            let a = u128::from(next(&mut state)) << (next(&mut state) % 64);
            let b = u128::from(next(&mut state) >> (next(&mut state) % 64)).max(1);
            let (wa, wb) = (from_u128(a), from_u128(b));
            assert_eq!(wa.checked_div(wb), Some(from_u128(a / b)));
            assert_eq!(wa.cmp(&wb), a.cmp(&b));
            if let Some(sum) = a.checked_add(b) {
                assert_eq!(wa.checked_add(wb), Some(from_u128(sum)));
            }
            if let Some(difference) = a.checked_sub(b) {
                assert_eq!(wa.checked_sub(wb), Some(from_u128(difference)));
            }
            let shift = (next(&mut state) % 64) as u32;
            assert_eq!(wa >> shift, from_u128(a >> shift));
        }
    }

    #[test]
    fn overflow_is_explicit() {
        assert_eq!(U256::MAX.checked_add(U256::ONE), None);
        assert_eq!(U256::ZERO.checked_sub(U256::ONE), None);
        assert_eq!(U256::ONE.checked_div(U256::ZERO), None);
        assert_eq!(U256::ONE << 256, U256::ZERO);
        assert_eq!((U256::ONE << 255) >> 255, U256::ONE);
        assert_eq!(U256::MAX.mul_u64_shift(2, 0), None);
        assert_eq!(U256::MAX.mul_u64_shift(2, -1), Some(U256::MAX));
        assert_eq!(U256::ONE.mul_u64_shift(1, 255), Some(U256::ONE << 255));
        assert_eq!(U256::ONE.mul_u64_shift(1, 256), None);
        assert_eq!(U256::ONE.mul_u64_shift(1, -1000), Some(U256::ZERO));
        assert_eq!(U256::ZERO.mul_u64_shift(5, 10_000), Some(U256::ZERO));
    }

    #[test]
    fn division_of_full_width_values() {
        assert_eq!(U256::MAX.checked_div(U256::MAX), Some(U256::ONE));
        assert_eq!(U256::MAX.checked_div(U256::ONE), Some(U256::MAX));
        let half = U256::ONE << 255;
        assert_eq!(U256::MAX.checked_div(half), Some(U256::ONE));
        assert_eq!(half.checked_div(U256::from_u64(2)), Some(U256::ONE << 254));
    }
}
