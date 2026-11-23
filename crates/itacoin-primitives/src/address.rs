//! Human-readable ITACOIN addresses.
//!
//! An address is the Bech32m (BIP 350) encoding of
//! `address_version (1 byte) || wallet_id (32 bytes)` under a network-specific
//! human-readable prefix. The checksum detects typing errors; the version byte
//! lets a future address format coexist with version 0 without ambiguity.
//!
//! An address identifies a wallet. It is not a public key, and verifying a
//! signature always requires the full ML-DSA-65 public key.

use core::{fmt, str::FromStr};

use bech32::{Bech32m, Hrp, primitives::decode::CheckedHrpstring};

use crate::{Hash256, WalletId};

/// The only address version currently defined.
pub const ADDRESS_VERSION: u8 = 0;

const PAYLOAD_BYTES: usize = 1 + 32;

/// The network an address belongs to. Each network uses a distinct prefix so
/// test-network addresses can never be mistaken for main-network ones.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Network {
    /// Main network, prefix `itc`.
    Mainnet,
    /// Public test network, prefix `titc`.
    Testnet,
    /// Local regression-test network, prefix `ritc`.
    Regtest,
}

impl Network {
    /// Returns this network's Bech32m human-readable prefix.
    #[must_use]
    pub const fn hrp(self) -> &'static str {
        match self {
            Self::Mainnet => "itc",
            Self::Testnet => "titc",
            Self::Regtest => "ritc",
        }
    }

    fn from_hrp(hrp: &Hrp) -> Option<Self> {
        [Self::Mainnet, Self::Testnet, Self::Regtest]
            .into_iter()
            .find(|network| hrp.as_str().eq_ignore_ascii_case(network.hrp()))
    }
}

/// A checksummed, network-bound wallet address.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Address {
    network: Network,
    wallet_id: WalletId,
}

impl Address {
    /// Creates a version-0 address for a wallet on a network.
    #[must_use]
    pub const fn new(network: Network, wallet_id: WalletId) -> Self {
        Self { network, wallet_id }
    }

    /// Returns the network encoded in the address prefix.
    #[must_use]
    pub const fn network(&self) -> Network {
        self.network
    }

    /// Returns the wallet identifier carried by the address.
    #[must_use]
    pub const fn wallet_id(&self) -> WalletId {
        self.wallet_id
    }

    /// Parses an address, requiring it to belong to `expected`.
    ///
    /// Use this at every user-input boundary so that an address for another
    /// network is rejected instead of silently accepted.
    pub fn parse_for_network(input: &str, expected: Network) -> Result<Self, AddressError> {
        let address = input.parse::<Self>()?;
        if address.network == expected {
            Ok(address)
        } else {
            Err(AddressError::WrongNetwork {
                expected,
                found: address.network,
            })
        }
    }
}

impl fmt::Display for Address {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hrp = Hrp::parse(self.network.hrp()).map_err(|_| fmt::Error)?;
        let mut payload = [0_u8; PAYLOAD_BYTES];
        payload[0] = ADDRESS_VERSION;
        payload[1..].copy_from_slice(self.wallet_id.as_bytes());
        bech32::encode_lower_to_fmt::<Bech32m, _>(formatter, hrp, &payload).map_err(|_| fmt::Error)
    }
}

impl FromStr for Address {
    type Err = AddressError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let checked =
            CheckedHrpstring::new::<Bech32m>(input).map_err(|_| AddressError::InvalidEncoding)?;
        checked
            .validate_segwit_padding()
            .map_err(|_| AddressError::InvalidEncoding)?;
        let network = Network::from_hrp(&checked.hrp()).ok_or(AddressError::UnknownNetwork)?;

        let mut payload = [0_u8; PAYLOAD_BYTES];
        let mut length = 0_usize;
        for byte in checked.byte_iter() {
            if length == PAYLOAD_BYTES {
                return Err(AddressError::InvalidLength);
            }
            payload[length] = byte;
            length += 1;
        }
        if length != PAYLOAD_BYTES {
            return Err(AddressError::InvalidLength);
        }
        if payload[0] != ADDRESS_VERSION {
            return Err(AddressError::UnsupportedVersion(payload[0]));
        }

        let mut wallet_id = [0_u8; 32];
        wallet_id.copy_from_slice(&payload[1..]);
        Ok(Self::new(network, WalletId::new(Hash256::new(wallet_id))))
    }
}

/// Errors raised while parsing an [`Address`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressError {
    /// The string is not valid Bech32m, or its checksum does not match.
    InvalidEncoding,
    /// The prefix does not name a known ITACOIN network.
    UnknownNetwork,
    /// The address belongs to a different network than required.
    WrongNetwork {
        /// The network the caller required.
        expected: Network,
        /// The network encoded in the address.
        found: Network,
    },
    /// The decoded payload does not have the version-0 length.
    InvalidLength,
    /// The address version is not supported by this implementation.
    UnsupportedVersion(u8),
}

impl fmt::Display for AddressError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEncoding => formatter.write_str("invalid address encoding or checksum"),
            Self::UnknownNetwork => formatter.write_str("unknown address network prefix"),
            Self::WrongNetwork { expected, found } => write!(
                formatter,
                "address is for {found:?}, but {expected:?} was required"
            ),
            Self::InvalidLength => formatter.write_str("invalid address payload length"),
            Self::UnsupportedVersion(version) => {
                write!(formatter, "unsupported address version {version}")
            }
        }
    }
}

impl std::error::Error for AddressError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Address {
        Address::new(Network::Mainnet, WalletId::new(Hash256::new([7; 32])))
    }

    #[test]
    fn round_trips_and_is_lowercase_with_prefix() {
        let address = sample();
        let encoded = address.to_string();
        assert!(encoded.starts_with("itc1"));
        assert_eq!(encoded, encoded.to_ascii_lowercase());
        assert_eq!(encoded.parse::<Address>().unwrap(), address);
        assert_eq!(
            encoded.to_ascii_uppercase().parse::<Address>().unwrap(),
            address
        );
    }

    #[test]
    fn detects_every_single_character_substitution() {
        let encoded = sample().to_string();
        let separator = encoded.rfind('1').unwrap();
        let charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
        for position in separator + 1..encoded.len() {
            for replacement in charset.chars() {
                let mut altered: Vec<char> = encoded.chars().collect();
                if altered[position] == replacement {
                    continue;
                }
                altered[position] = replacement;
                let altered: String = altered.into_iter().collect();
                assert!(altered.parse::<Address>().is_err(), "{altered}");
            }
        }
    }

    #[test]
    fn networks_are_separated() {
        let testnet = Address::new(Network::Testnet, sample().wallet_id());
        let encoded = testnet.to_string();
        assert!(encoded.starts_with("titc1"));
        assert_eq!(
            Address::parse_for_network(&encoded, Network::Mainnet),
            Err(AddressError::WrongNetwork {
                expected: Network::Mainnet,
                found: Network::Testnet,
            })
        );
        assert_ne!(encoded, sample().to_string());
    }

    #[test]
    fn rejects_bech32_checksum_mixed_case_unknown_prefix_and_bad_payloads() {
        let hrp = Hrp::parse("itc").unwrap();
        let mut payload = [0_u8; PAYLOAD_BYTES];
        payload[1..].copy_from_slice(&[7; 32]);

        let legacy = bech32::encode::<bech32::Bech32>(hrp, &payload).unwrap();
        assert_eq!(
            legacy.parse::<Address>(),
            Err(AddressError::InvalidEncoding)
        );

        let mut mixed = sample().to_string();
        mixed.replace_range(0..1, "I");
        assert_eq!(mixed.parse::<Address>(), Err(AddressError::InvalidEncoding));

        let foreign = bech32::encode::<Bech32m>(Hrp::parse("btc").unwrap(), &payload).unwrap();
        assert_eq!(
            foreign.parse::<Address>(),
            Err(AddressError::UnknownNetwork)
        );

        let short = bech32::encode::<Bech32m>(hrp, &payload[..32]).unwrap();
        assert_eq!(short.parse::<Address>(), Err(AddressError::InvalidLength));

        let mut long = payload.to_vec();
        long.push(0);
        let long = bech32::encode::<Bech32m>(hrp, &long).unwrap();
        assert_eq!(long.parse::<Address>(), Err(AddressError::InvalidLength));

        payload[0] = 1;
        let future = bech32::encode::<Bech32m>(hrp, &payload).unwrap();
        assert_eq!(
            future.parse::<Address>(),
            Err(AddressError::UnsupportedVersion(1))
        );
    }
}
