//! ITACOIN blocks, as specified in `docs/CODEC_PROPOSAL.md`.
//!
//! This crate holds the block format and the rules that need no chain state.
//! Chain state, proof of work, timestamps and the coinbase value are checked
//! by later stages. Every [`Block`] value satisfies the stateless rules: the
//! constructor and the decoder enforce them.

use core::fmt;
use std::collections::HashSet;

use itacoin_codec::{CodecError, Decode, Encode, Reader, Writer, decode_exact};
use itacoin_crypto::{CryptoError, block_hash, merkle_root};
use itacoin_primitives::{BlockId, Hash256};
use itacoin_transaction::{MIN_TX_BYTES, Transaction, TransactionError};

/// The only block version this release accepts.
pub const BLOCK_VERSION: u16 = 1;
/// Encoded size of a [`BlockHeader`].
pub const HEADER_BYTES: usize = 2 + 32 + 32 + 32 + 8 + 32 + 8;
/// Maximum encoded size of a block, header included.
///
/// Provisional: to be recalculated once the block interval is approved.
pub const MAX_BLOCK_BYTES: usize = 2_000_000;
/// Maximum number of ML-DSA verifications a block may require.
///
/// Provisional: to be recalculated once the block interval is approved.
pub const MAX_BLOCK_SIG_VERIFICATIONS: usize = 400;
/// Largest transaction count that can fit in [`MAX_BLOCK_BYTES`].
pub const MAX_BLOCK_TRANSACTIONS: usize = (MAX_BLOCK_BYTES - HEADER_BYTES - 4) / MIN_TX_BYTES;

/// A block header (146 bytes).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct BlockHeader {
    /// The previous block, or all zero for the genesis block.
    pub prev_block: BlockId,
    /// Merkle root of the transaction ids.
    pub tx_root: Hash256,
    /// Merkle root of the transactions' witness hashes.
    pub witness_root: Hash256,
    /// Seconds since the Unix epoch.
    pub timestamp: u64,
    /// Full 256-bit proof-of-work target, big-endian.
    pub target: Hash256,
    /// Proof-of-work nonce.
    pub nonce: u64,
}

impl BlockHeader {
    /// Returns the block id, the hash of the encoded header.
    #[must_use]
    pub fn id(&self) -> BlockId {
        block_hash(&self.to_bytes())
    }
}

/// A header and its transactions; the first transaction is the coinbase.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Block {
    header: BlockHeader,
    transactions: Vec<Transaction>,
}

impl Block {
    /// Validates the stateless block rules.
    pub fn new(header: BlockHeader, transactions: Vec<Transaction>) -> Result<Self, BlockError> {
        match transactions.first() {
            None => return Err(BlockError::NoTransactions),
            Some(first) if !first.is_coinbase() => return Err(BlockError::MissingCoinbase),
            Some(_) => {}
        }
        let mut signatures = 0_usize;
        let mut spent = HashSet::new();
        for (index, transaction) in transactions.iter().enumerate().skip(1) {
            if transaction.is_coinbase() {
                return Err(BlockError::ExtraCoinbase { transaction: index });
            }
            signatures += transaction.signature_count();
            for input in transaction.inputs() {
                if !spent.insert(input.previous_output) {
                    return Err(BlockError::DuplicateSpend { transaction: index });
                }
            }
        }
        if signatures > MAX_BLOCK_SIG_VERIFICATIONS {
            return Err(BlockError::TooManySignatures(signatures));
        }

        let block = Self {
            header,
            transactions,
        };
        let size = block.encoded_len();
        if size > MAX_BLOCK_BYTES {
            return Err(CodecError::TooLarge {
                maximum: MAX_BLOCK_BYTES,
                actual: size,
            }
            .into());
        }
        let (tx_root, witness_root) = Self::roots(&block.transactions)?;
        if tx_root != header.tx_root {
            return Err(BlockError::TxRootMismatch);
        }
        if witness_root != header.witness_root {
            return Err(BlockError::WitnessRootMismatch);
        }
        Ok(block)
    }

    /// Computes the transaction and witness Merkle roots for a header.
    pub fn roots(transactions: &[Transaction]) -> Result<(Hash256, Hash256), BlockError> {
        let txids: Vec<Hash256> = transactions
            .iter()
            .map(|transaction| transaction.txid().into_hash())
            .collect();
        let witnesses: Vec<Hash256> = transactions.iter().map(Transaction::witness_hash).collect();
        Ok((
            merkle_root(&txids).map_err(BlockError::Crypto)?,
            merkle_root(&witnesses).map_err(BlockError::Crypto)?,
        ))
    }

    /// Decodes one block that occupies all of `bytes`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BlockError> {
        decode_exact(bytes, MAX_BLOCK_BYTES)
    }

    /// Returns the header.
    #[must_use]
    pub const fn header(&self) -> &BlockHeader {
        &self.header
    }

    /// Returns the transactions, coinbase first.
    #[must_use]
    pub fn transactions(&self) -> &[Transaction] {
        &self.transactions
    }

    /// Returns the block id.
    #[must_use]
    pub fn id(&self) -> BlockId {
        self.header.id()
    }

    /// Returns the height recorded in the coinbase.
    #[must_use]
    pub fn height(&self) -> u64 {
        match &self.transactions[0] {
            Transaction::Coinbase(coinbase) => coinbase.height(),
            Transaction::Normal(_) => unreachable!("constructor requires a coinbase first"),
        }
    }
}

impl Encode for BlockHeader {
    fn encode(&self, writer: &mut Writer) {
        writer.u16(BLOCK_VERSION);
        self.prev_block.encode(writer);
        self.tx_root.encode(writer);
        self.witness_root.encode(writer);
        writer.u64(self.timestamp);
        self.target.encode(writer);
        writer.u64(self.nonce);
    }

    fn encoded_len(&self) -> usize {
        HEADER_BYTES
    }
}

impl Decode for BlockHeader {
    type Error = BlockError;

    fn decode(reader: &mut Reader<'_>) -> Result<Self, BlockError> {
        let version = reader.u16()?;
        if version != BLOCK_VERSION {
            return Err(BlockError::UnsupportedVersion(version));
        }
        Ok(Self {
            prev_block: BlockId::decode(reader)?,
            tx_root: Hash256::decode(reader)?,
            witness_root: Hash256::decode(reader)?,
            timestamp: reader.u64()?,
            target: Hash256::decode(reader)?,
            nonce: reader.u64()?,
        })
    }
}

impl Encode for Block {
    fn encode(&self, writer: &mut Writer) {
        self.header.encode(writer);
        writer.count_u32(self.transactions.len());
        for transaction in &self.transactions {
            transaction.encode(writer);
        }
    }

    fn encoded_len(&self) -> usize {
        HEADER_BYTES
            + 4
            + self
                .transactions
                .iter()
                .map(Encode::encoded_len)
                .sum::<usize>()
    }
}

impl Decode for Block {
    type Error = BlockError;

    fn decode(reader: &mut Reader<'_>) -> Result<Self, BlockError> {
        let header = BlockHeader::decode(reader)?;
        let count = reader.count_u32(1..=MAX_BLOCK_TRANSACTIONS, MIN_TX_BYTES)?;
        let transactions = (0..count)
            .map(|_| Transaction::decode(reader))
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(header, transactions)
    }
}

/// Errors from building or decoding a block.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BlockError {
    /// The bytes are not a canonical encoding, or the block is too large.
    Codec(CodecError),
    /// A transaction is invalid.
    Transaction(TransactionError),
    /// The version is not [`BLOCK_VERSION`].
    UnsupportedVersion(u16),
    /// The block has no transactions.
    NoTransactions,
    /// The first transaction is not a coinbase.
    MissingCoinbase,
    /// A coinbase appears after the first position.
    ExtraCoinbase {
        /// Position of the extra coinbase.
        transaction: usize,
    },
    /// Two inputs in the block spend the same output.
    DuplicateSpend {
        /// Position of the transaction with the repeated spend.
        transaction: usize,
    },
    /// The block needs more than [`MAX_BLOCK_SIG_VERIFICATIONS`] verifications.
    TooManySignatures(usize),
    /// The header's transaction root does not match the transactions.
    TxRootMismatch,
    /// The header's witness root does not match the witnesses.
    WitnessRootMismatch,
    /// A Merkle root could not be computed.
    Crypto(CryptoError),
}

impl From<CodecError> for BlockError {
    fn from(error: CodecError) -> Self {
        Self::Codec(error)
    }
}

impl From<TransactionError> for BlockError {
    fn from(error: TransactionError) -> Self {
        Self::Transaction(error)
    }
}

impl fmt::Display for BlockError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Codec(error) => write!(formatter, "invalid block encoding: {error}"),
            Self::Transaction(error) => write!(formatter, "invalid transaction in block: {error}"),
            Self::UnsupportedVersion(version) => {
                write!(formatter, "unsupported block version {version}")
            }
            Self::NoTransactions => formatter.write_str("block has no transactions"),
            Self::MissingCoinbase => formatter.write_str("first transaction is not a coinbase"),
            Self::ExtraCoinbase { transaction } => {
                write!(formatter, "transaction {transaction} is an extra coinbase")
            }
            Self::DuplicateSpend { transaction } => {
                write!(
                    formatter,
                    "transaction {transaction} spends an output twice"
                )
            }
            Self::TooManySignatures(count) => {
                write!(formatter, "block requires {count} signature verifications")
            }
            Self::TxRootMismatch => formatter.write_str("transaction root mismatch"),
            Self::WitnessRootMismatch => formatter.write_str("witness root mismatch"),
            Self::Crypto(error) => write!(formatter, "merkle root failed: {error}"),
        }
    }
}

impl std::error::Error for BlockError {}

#[cfg(test)]
mod tests;
