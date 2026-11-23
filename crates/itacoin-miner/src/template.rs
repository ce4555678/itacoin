//! Block templates: the next block on the active tip, filled from the
//! mempool (section 3 of `docs/NODE_PROPOSAL.md`).
//!
//! Nothing here panics on chain or mempool state: a template is requested
//! over RPC, and a panic would take the node down.

use core::fmt;

use itacoin_blockchain::{
    Block, BlockError, BlockHeader, MAX_BLOCK_BYTES, MAX_BLOCK_SIG_VERIFICATIONS,
};
use itacoin_consensus::{MEDIAN_TIME_SPAN, check_pow, median_time_past, subsidy};
use itacoin_mempool::Mempool;
use itacoin_primitives::{Amount, AmountError, BlockId, Hash256, WalletId};
use itacoin_storage::{Chain, ChainError};
use itacoin_transaction::{CoinbaseTransaction, Output, Transaction, TransactionError};

/// Room left in a template for the header, the count and the coinbase.
const RESERVED_BYTES: usize = 10_000;

/// An unmined block and what a miner needs to know about it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Template {
    /// The block, with nonce zero.
    pub block: Block,
    /// Its height.
    pub height: u64,
    /// Fees paid by its transactions, included in the coinbase.
    pub fees: Amount,
    /// The smallest timestamp the block may carry: median time past plus one.
    pub min_timestamp: u64,
}

/// Builds an unmined block on the active tip paying subsidy and fees to
/// `payout`. The nonce is zero.
pub fn build_template(
    chain: &Chain,
    mempool: &Mempool,
    payout: WalletId,
    now: u64,
) -> Result<Template, TemplateError> {
    let tip = chain.tip().ok_or(TemplateError::NoTip)?;
    let height = tip.height.checked_add(1).ok_or(TemplateError::NoTip)?;
    let min_timestamp = median_time_past_of(chain, tip.block_id)
        .checked_add(1)
        .ok_or(TemplateError::NoTip)?;

    let selected = mempool.select(
        MAX_BLOCK_BYTES - RESERVED_BYTES,
        MAX_BLOCK_SIG_VERIFICATIONS,
    );
    let fees = total_fees(selected.iter().map(|transaction| {
        mempool
            .get(&transaction.unsigned().txid())
            .map(itacoin_mempool::Entry::fee)
    }))?;
    let reward = subsidy(height, chain.params())
        .checked_add(fees)
        .map_err(TemplateError::Fees)?;
    let coinbase = CoinbaseTransaction::new(
        height,
        vec![Output {
            amount: reward,
            wallet_id: payout,
        }],
    )
    .map_err(TemplateError::Coinbase)?;

    let mut transactions = vec![Transaction::Coinbase(coinbase)];
    transactions.extend(selected.into_iter().map(Transaction::Normal));
    let (tx_root, witness_root) = Block::roots(&transactions).map_err(TemplateError::Block)?;
    let header = BlockHeader {
        prev_block: tip.block_id,
        tx_root,
        witness_root,
        timestamp: now.max(min_timestamp),
        target: chain
            .next_target(&tip.block_id)
            .map_err(TemplateError::Chain)?
            .to_hash(),
        nonce: 0,
    };
    let block = Block::new(header, transactions).map_err(TemplateError::Block)?;
    Ok(Template {
        block,
        height,
        fees,
        min_timestamp,
    })
}

/// [`build_template`], keeping only the block.
pub fn build_block(
    chain: &Chain,
    mempool: &Mempool,
    payout: WalletId,
    now: u64,
) -> Result<Block, TemplateError> {
    build_template(chain, mempool, payout, now).map(|template| template.block)
}

/// Sums fees with [`Amount::checked_add`] (requirement 2.1). `None` marks a
/// selected transaction that is missing from the pool.
pub fn total_fees(fees: impl IntoIterator<Item = Option<Amount>>) -> Result<Amount, TemplateError> {
    fees.into_iter().try_fold(Amount::ZERO, |total, fee| {
        total
            .checked_add(fee.ok_or(TemplateError::MissingEntry)?)
            .map_err(TemplateError::Fees)
    })
}

/// The median timestamp of the [`MEDIAN_TIME_SPAN`] blocks ending at `tip`.
#[must_use]
pub fn median_time_past_of(chain: &Chain, tip: BlockId) -> u64 {
    let mut timestamps = Vec::with_capacity(MEDIAN_TIME_SPAN);
    let mut current = Some(tip);
    while let Some(id) = current {
        if timestamps.len() == MEDIAN_TIME_SPAN {
            break;
        }
        let Some(entry) = chain.entry(&id) else {
            break;
        };
        timestamps.push(entry.header.timestamp);
        current = (entry.height > 0).then_some(entry.header.prev_block);
    }
    median_time_past(&timestamps)
}

/// Searches nonces from zero for a valid proof of work, trying at most
/// `max_tries`. Single-threaded; for tests and regtest. Real mining uses
/// [`crate::Miner`].
#[must_use]
pub fn mine(block: &Block, chain_id: &Hash256, max_tries: u64) -> Option<Block> {
    let mut header = *block.header();
    for nonce in 0..max_tries {
        header.nonce = nonce;
        if check_pow(&header, chain_id) {
            return Block::new(header, block.transactions().to_vec()).ok();
        }
    }
    None
}

/// Why a template could not be built.
#[derive(Debug)]
pub enum TemplateError {
    /// The chain has no tip, or the next height overflows.
    NoTip,
    /// A selected transaction vanished from the pool.
    MissingEntry,
    /// Subsidy plus fees overflowed or exceeded the supply.
    Fees(AmountError),
    /// The coinbase is invalid.
    Coinbase(TransactionError),
    /// The block is invalid.
    Block(BlockError),
    /// The chain could not compute the next target.
    Chain(ChainError),
}

impl fmt::Display for TemplateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoTip => formatter.write_str("the chain has no usable tip"),
            Self::MissingEntry => formatter.write_str("a selected transaction left the mempool"),
            Self::Fees(error) => write!(formatter, "fees do not fit the supply: {error}"),
            Self::Coinbase(error) => write!(formatter, "invalid coinbase: {error}"),
            Self::Block(error) => write!(formatter, "invalid template: {error}"),
            Self::Chain(error) => write!(formatter, "chain error: {error}"),
        }
    }
}

impl std::error::Error for TemplateError {}
