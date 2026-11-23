//! The `itcseed1…` backup of a master secret (section 4 of
//! `docs/WALLET_PROPOSAL.md`).
//!
//! ```text
//! itcseed1 ‖ Bech32m(version = 0 (1 byte) ‖ master secret (32 bytes))
//! ```
//!
//! Bech32m detects any error in up to four characters. The prefix keeps the
//! backup from being mistaken for a Bitcoin recovery phrase, and the version
//! byte lets a future derivation be told apart instead of misread.

use core::fmt;

use bech32::{Bech32m, Hrp, primitives::decode::CheckedHrpstring};
use zeroize::Zeroizing;

use crate::MasterSecret;

/// Human-readable prefix of a backup.
pub const BACKUP_HRP: &str = "itcseed";
/// The only backup version this release reads and writes.
pub const BACKUP_VERSION: u8 = 0;
/// Length of an encoded backup.
pub const BACKUP_LEN: usize = 67;

/// Why a backup was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackupError {
    /// Not valid Bech32m, a wrong checksum or mixed case.
    Encoding,
    /// The prefix is not `itcseed`.
    WrongPrefix,
    /// The payload is not one version byte and 32 secret bytes.
    Length,
    /// A version this release does not know.
    UnknownVersion(u8),
}

impl fmt::Display for BackupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Encoding => formatter.write_str("the backup is mistyped or damaged"),
            Self::WrongPrefix => formatter.write_str("this is not an itcseed backup"),
            Self::Length => formatter.write_str("the backup has the wrong length"),
            Self::UnknownVersion(version) => {
                write!(formatter, "backup version {version} is not supported")
            }
        }
    }
}

impl std::error::Error for BackupError {}

/// Encodes `master` as an `itcseed1…` backup.
#[must_use]
pub fn encode(master: &MasterSecret) -> Zeroizing<String> {
    let mut payload = Zeroizing::new([0_u8; 33]);
    payload[0] = BACKUP_VERSION;
    payload[1..].copy_from_slice(master.as_bytes());
    let hrp = Hrp::parse_unchecked(BACKUP_HRP);
    let mut text = Zeroizing::new(String::with_capacity(BACKUP_LEN));
    // Writing into a String cannot fail.
    let _ = bech32::encode_lower_to_fmt::<Bech32m, _>(&mut *text, hrp, payload.as_ref());
    text
}

/// Decodes an `itcseed1…` backup. Surrounding spaces are ignored; the text
/// must be all lowercase or all uppercase.
pub fn decode(text: &str) -> Result<MasterSecret, BackupError> {
    let text = text.trim();
    if text.len() != BACKUP_LEN {
        return Err(BackupError::Length);
    }
    let checked = CheckedHrpstring::new::<Bech32m>(text).map_err(|_| BackupError::Encoding)?;
    if !checked.hrp().as_str().eq_ignore_ascii_case(BACKUP_HRP) {
        return Err(BackupError::WrongPrefix);
    }
    let mut payload = Zeroizing::new([0_u8; 33]);
    let mut length = 0_usize;
    for byte in checked.byte_iter() {
        if length == payload.len() {
            return Err(BackupError::Length);
        }
        payload[length] = byte;
        length += 1;
    }
    if length != payload.len() {
        return Err(BackupError::Length);
    }
    if payload[0] != BACKUP_VERSION {
        return Err(BackupError::UnknownVersion(payload[0]));
    }
    let mut secret = [0_u8; 32];
    secret.copy_from_slice(&payload[1..]);
    let master = MasterSecret::from_bytes(secret);
    zeroize::Zeroize::zeroize(&mut secret);
    Ok(master)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALPHABET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

    fn fixed() -> MasterSecret {
        MasterSecret::from_bytes(core::array::from_fn(|index| index as u8))
    }

    #[test]
    fn backups_round_trip() {
        let master = fixed();
        let text = encode(&master);
        assert_eq!(text.len(), BACKUP_LEN);
        assert!(text.starts_with("itcseed1"));
        assert_eq!(decode(&text).unwrap().as_bytes(), master.as_bytes());
        // All uppercase is the same backup (QR alphanumeric mode).
        assert_eq!(
            decode(&text.to_ascii_uppercase()).unwrap().as_bytes(),
            master.as_bytes()
        );
        assert_eq!(
            decode(&format!("  {}\n", text.as_str()))
                .unwrap()
                .as_bytes(),
            master.as_bytes()
        );
        let random = MasterSecret::generate();
        assert_eq!(
            decode(&encode(&random)).unwrap().as_bytes(),
            random.as_bytes()
        );
    }

    #[test]
    fn every_error_in_up_to_four_characters_is_detected() {
        let text = encode(&fixed());
        let data_start = BACKUP_HRP.len() + 1;
        let bytes = text.as_bytes();
        // Every single substitution in the data part.
        for position in data_start..bytes.len() {
            for &replacement in ALPHABET {
                if replacement == bytes[position] {
                    continue;
                }
                let mut changed = bytes.to_vec();
                changed[position] = replacement;
                let changed = String::from_utf8(changed).unwrap();
                assert!(decode(&changed).is_err(), "missed an error at {position}");
            }
        }
        // Pseudo-random substitutions of 2, 3 and 4 characters.
        let mut state = 0x2545_f491_4f6c_dd1d_u64;
        let mut next = |bound: usize| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state % bound as u64) as usize
        };
        for errors in 2..=4 {
            for _ in 0..3_000 {
                let mut changed = bytes.to_vec();
                let mut positions = Vec::new();
                while positions.len() < errors {
                    let position = data_start + next(bytes.len() - data_start);
                    if !positions.contains(&position) {
                        positions.push(position);
                    }
                }
                for position in positions {
                    let mut replacement = ALPHABET[next(ALPHABET.len())];
                    while replacement == bytes[position] {
                        replacement = ALPHABET[next(ALPHABET.len())];
                    }
                    changed[position] = replacement;
                }
                assert!(decode(&String::from_utf8(changed).unwrap()).is_err());
            }
        }
    }

    #[test]
    fn foreign_and_malformed_backups_are_refused() {
        let text = encode(&fixed());
        // Mixed case.
        let mut mixed = text.to_string();
        mixed.replace_range(10..11, &mixed[10..11].to_ascii_uppercase());
        assert!(matches!(decode(&mixed), Err(BackupError::Encoding)));
        // Another prefix with a valid checksum.
        let payload = [0_u8; 33];
        let other = bech32::encode::<Bech32m>(Hrp::parse("itcseex").unwrap(), &payload).unwrap();
        assert!(matches!(decode(&other), Err(BackupError::WrongPrefix)));
        // A future version.
        let mut future = [0_u8; 33];
        future[0] = 1;
        let future = bech32::encode::<Bech32m>(Hrp::parse(BACKUP_HRP).unwrap(), &future).unwrap();
        assert!(matches!(
            decode(&future),
            Err(BackupError::UnknownVersion(1))
        ));
        // Wrong lengths and plain Bech32.
        assert!(matches!(decode("itcseed1"), Err(BackupError::Length)));
        let legacy =
            bech32::encode::<bech32::Bech32>(Hrp::parse(BACKUP_HRP).unwrap(), &payload).unwrap();
        assert!(decode(&legacy).is_err());
    }
}
