//! Block templates: the next block on the active tip, filled from the
//! mempool. Used by local mining and by tests.

use itacoin_blockchain::{Block, BlockHeader, MAX_BLOCK_BYTES, MAX_BLOCK_SIG_VERIFICATIONS};
use itacoin_codec::Encode;
use itacoin_consensus::{check_pow, subsidy};
use itacoin_mempool::Mempool;
use itacoin_primitives::{Amount, WalletId};
use itacoin_storage::Chain;
use itacoin_transaction::{CoinbaseTransaction, Output, Transaction};

/// Room left in a template for the header, the count and the coinbase.
const RESERVED_BYTES: usize = 10_000;

/// Builds an unmined block on the active tip paying subsidy and fees to
/// `payout`. The nonce is zero; see [`mine`].
///
/// # Panics
///
/// Panics if the chain has no tip, which [`Chain::open`] rules out.
#[must_use]
pub fn build_block(chain: &Chain, mempool: &Mempool, payout: WalletId, now: u64) -> Block {
    let tip = chain.tip().expect("the chain always has a genesis tip");
    let parent = chain.entry(&tip.block_id).expect("tip is indexed");
    let height = tip.height + 1;

    let selected = mempool.select(
        MAX_BLOCK_BYTES - RESERVED_BYTES,
        MAX_BLOCK_SIG_VERIFICATIONS,
    );
    let fees: u64 = selected
        .iter()
        .filter_map(|transaction| mempool.get(&transaction.unsigned().txid()))
        .map(|entry| entry.fee().as_satoshis())
        .sum();
    let reward = subsidy(height, chain.params()).as_satoshis() + fees;
    let coinbase = CoinbaseTransaction::new(
        height,
        vec![Output {
            amount: Amount::from_satoshis(reward).expect("subsidy plus fees fits the supply"),
            wallet_id: payout,
        }],
    )
    .expect("a one-output coinbase is valid");

    let mut transactions = vec![Transaction::Coinbase(coinbase)];
    transactions.extend(selected.into_iter().map(Transaction::Normal));
    let (tx_root, witness_root) = Block::roots(&transactions).expect("bounded leaf count");
    let header = BlockHeader {
        prev_block: tip.block_id,
        tx_root,
        witness_root,
        // Strictly after the parent keeps it above the median time past.
        timestamp: now.max(parent.header.timestamp + 1),
        target: chain
            .next_target(&tip.block_id)
            .expect("tip is indexed")
            .to_hash(),
        nonce: 0,
    };
    Block::new(header, transactions).expect("template respects the block limits")
}

/// Searches nonces for a valid proof of work, trying at most `max_tries`.
#[must_use]
pub fn mine(block: &Block, chain: &Chain, max_tries: u64) -> Option<Block> {
    let mut header = *block.header();
    for nonce in 0..max_tries {
        header.nonce = nonce;
        if check_pow(&header, &chain.chain_id()) {
            return Block::new(header, block.transactions().to_vec()).ok();
        }
    }
    None
}

/// The encoded size of a block, for diagnostics.
#[must_use]
pub fn block_size(block: &Block) -> usize {
    block.encoded_len()
}
