//! Blocks whose witnesses were pruned (section 5.2 of
//! `docs/STORAGE_PROPOSAL.md`, requirement 1.9).
//!
//! A pruned block keeps the header, every transaction without its witnesses
//! and the hash of each transaction's witnesses. It stays verifiable on its
//! own: the transaction root is recomputed from the txids and the witness
//! root from the stored hashes, so corruption on disk is detected on read.

use itacoin_codec::{Decode, Encode, Reader, Writer};
use itacoin_crypto::merkle_root;
use itacoin_primitives::{BlockId, Hash256};
use itacoin_transaction::{MIN_TX_BYTES, StrippedTransaction};

use crate::{
    Block, BlockError, BlockHeader, HEADER_BYTES, MAX_BLOCK_TRANSACTIONS,
    utxo::{BlockShape, created_outpoints_of},
};

/// A block stored without witnesses.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrunedBlock {
    header: BlockHeader,
    transactions: Vec<StrippedTransaction>,
    witness_hashes: Vec<Hash256>,
}

impl PrunedBlock {
    /// Prunes a full block.
    #[must_use]
    pub fn from_block(block: &Block) -> Self {
        Self {
            header: *block.header(),
            transactions: block
                .transactions()
                .iter()
                .map(itacoin_transaction::Transaction::stripped)
                .collect(),
            witness_hashes: block
                .transactions()
                .iter()
                .map(itacoin_transaction::Transaction::witness_hash)
                .collect(),
        }
    }

    /// Builds a pruned block, checking it against its header.
    pub fn new(
        header: BlockHeader,
        transactions: Vec<StrippedTransaction>,
        witness_hashes: Vec<Hash256>,
    ) -> Result<Self, BlockError> {
        let block = Self {
            header,
            transactions,
            witness_hashes,
        };
        block.verify()?;
        Ok(block)
    }

    /// Checks the shape and both Merkle roots against the header.
    pub fn verify(&self) -> Result<(), BlockError> {
        if self.transactions.is_empty() || self.transactions.len() != self.witness_hashes.len() {
            return Err(BlockError::NoTransactions);
        }
        if !self.transactions[0].is_coinbase() {
            return Err(BlockError::MissingCoinbase);
        }
        if let Some(position) = self.transactions[1..]
            .iter()
            .position(StrippedTransaction::is_coinbase)
        {
            return Err(BlockError::ExtraCoinbase {
                transaction: position + 1,
            });
        }
        let txids: Vec<Hash256> = self
            .transactions
            .iter()
            .map(|transaction| transaction.txid().into_hash())
            .collect();
        if merkle_root(&txids).map_err(BlockError::Crypto)? != self.header.tx_root {
            return Err(BlockError::TxRootMismatch);
        }
        if merkle_root(&self.witness_hashes).map_err(BlockError::Crypto)?
            != self.header.witness_root
        {
            return Err(BlockError::WitnessRootMismatch);
        }
        Ok(())
    }

    /// The header.
    #[must_use]
    pub const fn header(&self) -> &BlockHeader {
        &self.header
    }

    /// The transactions without witnesses, coinbase first.
    #[must_use]
    pub fn transactions(&self) -> &[StrippedTransaction] {
        &self.transactions
    }

    /// The witness hash of each transaction.
    #[must_use]
    pub fn witness_hashes(&self) -> &[Hash256] {
        &self.witness_hashes
    }

    /// The block id.
    #[must_use]
    pub fn id(&self) -> BlockId {
        self.header.id()
    }

    /// The height recorded in the coinbase.
    #[must_use]
    pub fn height(&self) -> u64 {
        match &self.transactions[0] {
            StrippedTransaction::Coinbase(coinbase) => coinbase.height(),
            StrippedTransaction::Normal(_) => 0,
        }
    }

    /// What validation needs besides the transactions.
    #[must_use]
    pub fn shape(&self) -> BlockShape {
        BlockShape {
            block_id: self.id(),
            prev_block: self.header.prev_block,
            height: self.height(),
        }
    }

    /// The outputs this block adds to the set.
    #[must_use]
    pub fn created_outpoints(&self) -> Vec<itacoin_transaction::OutPoint> {
        created_outpoints_of(&self.transactions)
    }
}

impl Encode for PrunedBlock {
    fn encode(&self, writer: &mut Writer) {
        self.header.encode(writer);
        writer.count_u32(self.transactions.len());
        for (transaction, witness_hash) in self.transactions.iter().zip(&self.witness_hashes) {
            transaction.encode(writer);
            witness_hash.encode(writer);
        }
    }

    fn encoded_len(&self) -> usize {
        HEADER_BYTES
            + 4
            + self
                .transactions
                .iter()
                .map(|transaction| transaction.encoded_len() + 32)
                .sum::<usize>()
    }
}

impl Decode for PrunedBlock {
    type Error = BlockError;

    fn decode(reader: &mut Reader<'_>) -> Result<Self, BlockError> {
        let header = BlockHeader::decode(reader)?;
        let count = reader.count_u32(1..=MAX_BLOCK_TRANSACTIONS, MIN_TX_BYTES + 32)?;
        let mut transactions = Vec::with_capacity(count);
        let mut witness_hashes = Vec::with_capacity(count);
        for _ in 0..count {
            transactions
                .push(StrippedTransaction::decode(reader).map_err(BlockError::Transaction)?);
            witness_hashes.push(Hash256::decode(reader)?);
        }
        Self::new(header, transactions, witness_hashes)
    }
}

#[cfg(test)]
mod tests {
    use itacoin_codec::decode_exact;
    use itacoin_primitives::{Amount, WalletId};
    use itacoin_transaction::{CoinbaseTransaction, Output, Transaction};

    use super::*;

    fn block() -> Block {
        let coinbase = Transaction::Coinbase(
            CoinbaseTransaction::new(
                3,
                vec![Output {
                    amount: Amount::from_satoshis(50).unwrap(),
                    wallet_id: WalletId::new(Hash256::new([1; 32])),
                }],
            )
            .unwrap(),
        );
        let transactions = vec![coinbase];
        let (tx_root, witness_root) = Block::roots(&transactions).unwrap();
        let header = BlockHeader {
            prev_block: BlockId::new(Hash256::new([2; 32])),
            tx_root,
            witness_root,
            timestamp: 1,
            target: Hash256::new([0xff; 32]),
            nonce: 0,
        };
        Block::new(header, transactions).unwrap()
    }

    #[test]
    fn pruned_blocks_round_trip_and_verify() {
        let full = block();
        let pruned = PrunedBlock::from_block(&full);
        assert_eq!(pruned.id(), full.id());
        assert_eq!(pruned.height(), 3);
        let bytes = pruned.to_bytes();
        assert_eq!(bytes.len(), pruned.encoded_len());
        let decoded: PrunedBlock = decode_exact(&bytes, usize::MAX).unwrap();
        assert_eq!(decoded, pruned);
        assert_eq!(pruned.created_outpoints(), crate::created_outpoints(&full));

        // Any change to a stored witness hash or transaction is caught.
        let mut tampered = bytes.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(matches!(
            decode_exact::<PrunedBlock>(&tampered, usize::MAX),
            Err(BlockError::WitnessRootMismatch)
        ));
        let mut tampered = bytes;
        tampered[HEADER_BYTES + 4 + 20] ^= 1;
        assert!(decode_exact::<PrunedBlock>(&tampered, usize::MAX).is_err());
    }
}
