//! Compact blocks (section 9 of `docs/NETWORK_PROPOSAL.md`).
//!
//! A block is announced as its header, the coinbase, and a 6-byte short id
//! per other transaction. Short ids are SipHash-2-4 of `txid ‖ witness_hash`
//! under a key derived from the header and a per-announcement nonce, so an
//! attacker cannot prepare colliding transactions in advance.

use std::{collections::HashMap, hash::Hasher};

use itacoin_blockchain::{Block, BlockHeader};
use itacoin_codec::Encode;
use itacoin_primitives::Hash256;
use itacoin_transaction::{NormalTransaction, Transaction};
use siphasher::sip::SipHasher24;

use crate::message::{CmpctBlock, SHORT_ID_BYTES};

/// The SipHash key for a compact block.
#[must_use]
pub fn short_id_key(header: &BlockHeader, nonce: u64) -> (u64, u64) {
    let mut hasher = blake3::Hasher::new_derive_key("ITACOIN p2p v1 compact block");
    hasher.update(&header.to_bytes());
    hasher.update(&nonce.to_be_bytes());
    let digest = hasher.finalize();
    let bytes = digest.as_bytes();
    (
        u64::from_le_bytes(bytes[..8].try_into().expect("8 bytes")),
        u64::from_le_bytes(bytes[8..16].try_into().expect("8 bytes")),
    )
}

/// The short id of a transaction under `key`.
#[must_use]
pub fn short_id(key: (u64, u64), txid: &Hash256, witness_hash: &Hash256) -> [u8; SHORT_ID_BYTES] {
    let mut hasher = SipHasher24::new_with_keys(key.0, key.1);
    hasher.write(txid.as_bytes());
    hasher.write(witness_hash.as_bytes());
    let value = hasher.finish().to_le_bytes();
    let mut id = [0_u8; SHORT_ID_BYTES];
    id.copy_from_slice(&value[..SHORT_ID_BYTES]);
    id
}

/// Builds the compact form of `block`, prefilling only the coinbase.
#[must_use]
pub fn build(block: &Block, nonce: u64) -> CmpctBlock {
    let key = short_id_key(block.header(), nonce);
    let transactions = block.transactions();
    CmpctBlock {
        header: *block.header(),
        nonce,
        short_ids: transactions[1..]
            .iter()
            .map(|transaction| {
                short_id(
                    key,
                    &transaction.txid().into_hash(),
                    &transaction.witness_hash(),
                )
            })
            .collect(),
        prefilled: vec![(0, transactions[0].clone())],
    }
}

/// A compact block being reconstructed.
#[derive(Clone, Debug)]
pub struct Partial {
    header: BlockHeader,
    slots: Vec<Option<Transaction>>,
}

/// The outcome of reconstruction.
#[derive(Debug)]
pub enum Reconstruction {
    /// Every transaction was found.
    Complete(Partial),
    /// These positions must be requested with `getblocktxn`.
    Missing(Partial, Vec<u32>),
    /// Two candidate transactions share a short id, or the announcement
    /// repeats one: request the full block instead.
    Collision,
}

impl Partial {
    /// The block header.
    #[must_use]
    pub const fn header(&self) -> &BlockHeader {
        &self.header
    }

    /// Positions still missing.
    #[must_use]
    pub fn missing(&self) -> Vec<u32> {
        self.slots
            .iter()
            .enumerate()
            .filter(|(_, slot)| slot.is_none())
            .map(|(index, _)| index as u32)
            .collect()
    }

    /// Fills the positions answered by `blocktxn`, in requested order.
    /// Returns `false` if the counts do not match.
    pub fn fill(&mut self, transactions: Vec<Transaction>) -> bool {
        let missing = self.missing();
        if missing.len() != transactions.len() {
            return false;
        }
        for (index, transaction) in missing.into_iter().zip(transactions) {
            self.slots[index as usize] = Some(transaction);
        }
        true
    }

    /// The full block, if complete. Fails if the result does not match the
    /// header (wrong transactions, or a short-id collision with a different
    /// transaction).
    #[must_use]
    pub fn finish(self) -> Option<Block> {
        let transactions: Option<Vec<Transaction>> = self.slots.into_iter().collect();
        Block::new(self.header, transactions?).ok()
    }
}

/// Reconstructs `compact` from candidate transactions (the mempool), given as
/// `(txid, witness_hash, transaction)`.
pub fn reconstruct<'a>(
    compact: &CmpctBlock,
    candidates: impl IntoIterator<Item = (Hash256, Hash256, &'a NormalTransaction)>,
) -> Reconstruction {
    let total = compact.short_ids.len() + compact.prefilled.len();
    let mut slots: Vec<Option<Transaction>> = vec![None; total];
    for (index, transaction) in &compact.prefilled {
        slots[*index as usize] = Some(transaction.clone());
    }

    // Positions not prefilled, in order, take the short ids in order.
    let open: Vec<usize> = (0..total).filter(|index| slots[*index].is_none()).collect();
    let mut wanted: HashMap<[u8; SHORT_ID_BYTES], usize> = HashMap::new();
    for (position, id) in open.iter().zip(&compact.short_ids) {
        if wanted.insert(*id, *position).is_some() {
            return Reconstruction::Collision;
        }
    }

    let key = short_id_key(&compact.header, compact.nonce);
    let mut found: HashMap<usize, &NormalTransaction> = HashMap::new();
    for (txid, witness_hash, transaction) in candidates {
        if let Some(position) = wanted.get(&short_id(key, &txid, &witness_hash))
            && found.insert(*position, transaction).is_some()
        {
            return Reconstruction::Collision;
        }
    }
    for (position, transaction) in found {
        slots[position] = Some(Transaction::Normal(transaction.clone()));
    }

    let partial = Partial {
        header: compact.header,
        slots,
    };
    let missing = partial.missing();
    if missing.is_empty() {
        Reconstruction::Complete(partial)
    } else {
        Reconstruction::Missing(partial, missing)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn siphash_matches_the_reference_vector() {
        // SipHash-2-4 reference: key 00..0f, message 00..0e → a129ca6149be45e5.
        let key = (
            u64::from_le_bytes([0, 1, 2, 3, 4, 5, 6, 7]),
            u64::from_le_bytes([8, 9, 10, 11, 12, 13, 14, 15]),
        );
        let mut hasher = SipHasher24::new_with_keys(key.0, key.1);
        hasher.write(&(0..15).collect::<Vec<u8>>());
        assert_eq!(hasher.finish(), 0xa129_ca61_49be_45e5);
    }

    #[test]
    fn short_ids_depend_on_the_announcement() {
        let header = BlockHeader {
            prev_block: itacoin_primitives::BlockId::new(Hash256::new([0; 32])),
            tx_root: Hash256::new([1; 32]),
            witness_root: Hash256::new([2; 32]),
            timestamp: 0,
            target: Hash256::new([0xff; 32]),
            nonce: 0,
        };
        let txid = Hash256::new([3; 32]);
        let witness = Hash256::new([4; 32]);
        let a = short_id(short_id_key(&header, 1), &txid, &witness);
        let b = short_id(short_id_key(&header, 2), &txid, &witness);
        let c = short_id(short_id_key(&header, 1), &txid, &Hash256::new([5; 32]));
        assert_ne!(a, b);
        assert_ne!(a, c);
    }
}
