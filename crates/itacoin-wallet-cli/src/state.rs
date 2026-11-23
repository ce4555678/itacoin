//! The public wallet state, one JSON file per network (section 5.3 of
//! `docs/WALLET_PROPOSAL.md`). No secrets, but private: it links every
//! address of the wallet.

use std::path::Path;

use itacoin_primitives::{Hash256, WalletId};
use itacoin_rpc::text::decode_hash;
use itacoin_wallet::Branch;
use serde::{Deserialize, Serialize};

/// Addresses kept derived ahead of the next one handed out, per branch.
pub const POOL: u32 = 100;
const STATE_VERSION: u32 = 1;

/// What the wallet file holds.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    /// A master secret (`ITCW` v3).
    Master,
    /// One key (`ITCW` v2).
    Single,
}

/// One derived key.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct KeyRecord {
    /// Hex wallet id.
    pub wallet_id: String,
    /// 0 receive, 1 change.
    pub branch: u8,
    /// Derivation index.
    pub index: u32,
    /// User label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

/// One payment of a sent transaction.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PaymentRecord {
    /// Destination address.
    pub address: String,
    /// Satoshis.
    pub amount_sat: String,
}

/// Status of a sent transaction.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Status {
    /// Waiting in the node's mempool.
    Mempool,
    /// Its inputs are spent and it left the mempool: confirmed.
    Confirmed,
    /// Left the mempool with its inputs unspent; it can be sent again.
    Dropped,
    /// Replaced by a fee bump.
    Replaced,
}

/// A transaction this wallet sent.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SentRecord {
    /// Hex txid.
    pub txid: String,
    /// The signed transaction, base64url.
    pub transaction: String,
    /// Spent coins as `txid:index`.
    pub inputs: Vec<String>,
    /// Payments, without the change.
    pub payments: Vec<PaymentRecord>,
    /// Hex wallet id of the change output, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change_wallet_id: Option<String>,
    /// Fee in satoshis.
    pub fee_sat: String,
    /// Encoded size.
    pub size: usize,
    /// Seconds since the Unix epoch.
    pub time: u64,
    /// Current status.
    pub status: Status,
    /// The replacement, after a fee bump.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replaced_by: Option<String>,
}

/// The state file.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    /// Format version.
    pub version: u32,
    /// Network name.
    pub network: String,
    /// What the wallet file holds.
    pub kind: Kind,
    /// Hex identity of the wallet file (fingerprint or wallet id).
    pub fingerprint: String,
    /// Highest wallet file generation seen (finding V-04).
    pub generation: u64,
    /// Derived keys.
    pub keys: Vec<KeyRecord>,
    /// Next index handed out, per branch.
    pub next: [u32; 2],
    /// Keys derived so far, per branch.
    pub derived: [u32; 2],
    /// Sent transactions.
    #[serde(default)]
    pub sent: Vec<SentRecord>,
}

impl State {
    /// A fresh state.
    #[must_use]
    pub fn new(network: &str, kind: Kind, identity: Hash256, generation: u64) -> Self {
        Self {
            version: STATE_VERSION,
            network: network.to_owned(),
            kind,
            fingerprint: identity.to_string(),
            generation,
            keys: Vec::new(),
            next: [0, 0],
            derived: [0, 0],
            sent: Vec::new(),
        }
    }

    /// Reads a state file, or `None` if it does not exist.
    pub fn load(path: &Path) -> Result<Option<Self>, String> {
        match std::fs::read(path) {
            Ok(bytes) => {
                let state: Self = serde_json::from_slice(&bytes)
                    .map_err(|error| format!("{} is damaged: {error}", path.display()))?;
                if state.version != STATE_VERSION {
                    return Err(format!("{} has an unknown version", path.display()));
                }
                Ok(Some(state))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(format!("could not read {}: {error}", path.display())),
        }
    }

    /// Writes the state atomically with permission 0600.
    pub fn save(&self, path: &Path) -> Result<(), String> {
        let bytes = serde_json::to_vec_pretty(self).map_err(|error| error.to_string())?;
        itacoin_process::write_private(path, &bytes)
            .map_err(|error| format!("could not write {}: {error}", path.display()))
    }

    /// The record of `wallet_id`.
    #[must_use]
    pub fn key(&self, wallet_id: &WalletId) -> Option<&KeyRecord> {
        let text = wallet_id.to_string();
        self.keys.iter().find(|key| key.wallet_id == text)
    }

    /// The key at `index` of `branch`.
    #[must_use]
    pub fn key_at(&self, branch: Branch, index: u32) -> Option<&KeyRecord> {
        self.keys
            .iter()
            .find(|key| key.branch == branch.to_byte() && key.index == index)
    }

    /// Every wallet id, in derivation order.
    #[must_use]
    pub fn wallet_ids(&self) -> Vec<WalletId> {
        self.keys
            .iter()
            .filter_map(|key| parse_wallet_id(&key.wallet_id))
            .collect()
    }

    /// Records a derived key.
    pub fn add_key(&mut self, wallet_id: WalletId, branch: Branch, index: u32) {
        if self.key_at(branch, index).is_none() {
            self.keys.push(KeyRecord {
                wallet_id: wallet_id.to_string(),
                branch: branch.to_byte(),
                index,
                label: None,
            });
        }
    }
}

/// Parses a hex wallet id.
#[must_use]
pub fn parse_wallet_id(text: &str) -> Option<WalletId> {
    decode_hash(text).ok().map(WalletId::new)
}

/// Index into `next` and `derived` for `branch`.
#[must_use]
pub const fn slot(branch: Branch) -> usize {
    branch.to_byte() as usize
}
