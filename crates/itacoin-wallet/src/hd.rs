//! The master secret and deterministic key derivation (section 3 of
//! `docs/WALLET_PROPOSAL.md`).
//!
//! ```text
//! ξ(network, branch, i) = BLAKE3-keyed(key = master secret,
//!     "ITACOIN:wallet:key:v1" ‖ network (u8) ‖ branch (u8) ‖ i (u32 BE))
//! ```
//!
//! ξ is the FIPS 204 key-generation seed of key `i`. Derivation is private
//! only: ML-DSA has no equivalent of a BIP 32 extended public key.

use core::fmt;

use itacoin_crypto::{KeyPair, PrivateKey, internal_hash};
use itacoin_primitives::{Hash256, Network};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

use crate::WalletError;

const DERIVATION_LABEL: &[u8] = b"ITACOIN:wallet:key:v1";
const FINGERPRINT_LABEL: &[u8] = b"itacoin:wallet:fingerprint:v1";

/// Which chain of addresses a key belongs to.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Branch {
    /// Addresses handed out to receive payments.
    Receive,
    /// Addresses that receive the wallet's own change.
    Change,
}

impl Branch {
    /// The byte that enters the derivation.
    #[must_use]
    pub const fn to_byte(self) -> u8 {
        match self {
            Self::Receive => 0,
            Self::Change => 1,
        }
    }

    /// The branch for a derivation byte.
    #[must_use]
    pub const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Self::Receive),
            1 => Some(Self::Change),
            _ => None,
        }
    }
}

/// The byte that identifies `network` in the derivation.
#[must_use]
pub const fn network_byte(network: Network) -> u8 {
    match network {
        Network::Mainnet => 0,
        Network::Testnet => 1,
        Network::Regtest => 2,
    }
}

/// The 32-byte secret every key of a wallet derives from. Wiped on drop;
/// `Debug` never prints it.
pub struct MasterSecret(Zeroizing<[u8; 32]>);

impl MasterSecret {
    /// Draws a new secret from the operating system CSPRNG.
    #[must_use]
    pub fn generate() -> Self {
        let mut bytes = Zeroizing::new([0_u8; 32]);
        OsRng.fill_bytes(bytes.as_mut());
        Self(bytes)
    }

    /// Wraps existing secret bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// The raw secret.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Identifies the wallet without revealing any address.
    #[must_use]
    pub fn fingerprint(&self) -> Hash256 {
        internal_hash(FINGERPRINT_LABEL, self.0.as_ref())
    }

    /// The key-generation seed of key `index` on `branch` of `network`.
    #[must_use]
    pub fn seed(&self, network: Network, branch: Branch, index: u32) -> Zeroizing<[u8; 32]> {
        let mut message = Vec::with_capacity(DERIVATION_LABEL.len() + 6);
        message.extend_from_slice(DERIVATION_LABEL);
        message.push(network_byte(network));
        message.push(branch.to_byte());
        message.extend_from_slice(&index.to_be_bytes());
        Zeroizing::new(*blake3::keyed_hash(&self.0, &message).as_bytes())
    }

    /// Derives key `index` on `branch` of `network`.
    pub fn derive(
        &self,
        network: Network,
        branch: Branch,
        index: u32,
    ) -> Result<KeyPair, WalletError> {
        let seed = self.seed(network, branch, index);
        let private_key = PrivateKey::from_seed(seed.as_ref()).map_err(WalletError::Crypto)?;
        let public_key = private_key.public_key().map_err(WalletError::Crypto)?;
        Ok(KeyPair {
            private_key,
            public_key,
        })
    }
}

impl fmt::Debug for MasterSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MasterSecret(REDACTED)")
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    fn fixed() -> MasterSecret {
        MasterSecret::from_bytes(core::array::from_fn(|index| index as u8))
    }

    /// Golden values: a change to the derivation must break this test.
    #[test]
    fn derivation_vectors() {
        let master = fixed();
        assert_eq!(
            master.fingerprint().to_string(),
            "d1f92f0d7694359cc61181f09f48fb9b1a9eaf262acbc0618f6ad9fafc8641a6"
        );
        let vectors = [
            (Network::Testnet, Branch::Receive, 0),
            (Network::Testnet, Branch::Receive, 1),
            (Network::Testnet, Branch::Change, 0),
            (Network::Mainnet, Branch::Receive, 0),
            (Network::Regtest, Branch::Receive, 0),
        ];
        let seeds: Vec<String> = vectors
            .iter()
            .map(|(network, branch, index)| {
                Hash256::new(*master.seed(*network, *branch, *index)).to_string()
            })
            .collect();
        assert_eq!(seeds, GOLDEN_SEEDS);
        let wallet_id = master
            .derive(Network::Testnet, Branch::Receive, 0)
            .unwrap()
            .public_key
            .wallet_id();
        assert_eq!(wallet_id.to_string(), GOLDEN_WALLET_ID);
    }

    /// Checked against the reference BLAKE3 implementation.
    const GOLDEN_SEEDS: [&str; 5] = [
        "fc28596568c0892417b25ac0b0c6382b261f004e92836ce565b28033d35407de",
        "f98c0ece9b1f95e1bbb8248874e564faab5f92dc11c9f53253348d8311710075",
        "9369bfc425d480762f342ee31f5d64bdafb8c67ce713217b461631e230ad4338",
        "2d1b97ea012ad6565a60548c3fda7869cb4ca5504681e08e5ebc694741567963",
        "512c30bcbb04aeaa8b982835fb9966a7093337750e22262dbe849ae1764509f9",
    ];
    const GOLDEN_WALLET_ID: &str =
        "bed9c8b7f81c1296fa079eae3b9131f0188aa285ed4845d189efc4f295f8e644";

    #[test]
    fn networks_branches_and_indices_never_share_keys() {
        let master = fixed();
        let mut seen = HashSet::new();
        for network in [Network::Mainnet, Network::Testnet, Network::Regtest] {
            for branch in [Branch::Receive, Branch::Change] {
                for index in 0..20 {
                    assert!(seen.insert(*master.seed(network, branch, index)));
                }
            }
        }
        let other = MasterSecret::from_bytes([9; 32]);
        assert!(!seen.contains(&*other.seed(Network::Testnet, Branch::Receive, 0)));
        assert_ne!(other.fingerprint(), master.fingerprint());
    }

    #[test]
    fn derived_keys_sign_and_match_their_seed() {
        let master = MasterSecret::generate();
        let pair = master.derive(Network::Regtest, Branch::Change, 7).unwrap();
        assert_eq!(
            *pair.private_key.to_seed(),
            *master.seed(Network::Regtest, Branch::Change, 7)
        );
        let again = master.derive(Network::Regtest, Branch::Change, 7).unwrap();
        assert_eq!(again.public_key, pair.public_key);
        assert_eq!(format!("{master:?}"), "MasterSecret(REDACTED)");
        assert_eq!(Branch::from_byte(1), Some(Branch::Change));
        assert_eq!(Branch::from_byte(2), None);
    }
}
