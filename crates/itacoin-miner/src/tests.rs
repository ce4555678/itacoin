use std::collections::HashSet;

use itacoin_consensus::ConsensusParams;
use itacoin_mempool::{Mempool, Policy};
use itacoin_primitives::{Amount, MAX_SUPPLY, WalletId};
use itacoin_storage::{Chain, SubmitOutcome};
use tokio::sync::mpsc;

use super::*;
use crate::template::total_fees;

fn payout() -> WalletId {
    WalletId::new(Hash256::new([7; 32]))
}

fn regtest_chain(directory: &tempfile::TempDir) -> Chain {
    Chain::open(
        &directory.path().join("chain.redb"),
        ConsensusParams::regtest(),
    )
    .unwrap()
}

fn with_target(block: &Block, target: Hash256) -> Block {
    let mut header = *block.header();
    header.target = target;
    Block::new(header, block.transactions().to_vec()).unwrap()
}

#[test]
fn templates_are_accepted_by_the_chain() {
    let directory = tempfile::tempdir().unwrap();
    let mut chain = regtest_chain(&directory);
    let mempool = Mempool::new(Policy::default());
    for height in 1..=3 {
        let template = build_template(&chain, &mempool, payout(), unix_now()).unwrap();
        assert_eq!(template.height, height);
        assert_eq!(template.fees, Amount::ZERO);
        assert!(template.block.header().timestamp >= template.min_timestamp);
        assert_eq!(
            chain.submit_block(&template.block, unix_now()).unwrap(),
            SubmitOutcome::NewTip
        );
    }
    assert_eq!(chain.tip().unwrap().height, 3);
}

#[test]
fn fee_sums_refuse_overflow_and_missing_entries() {
    let max = Amount::from_satoshis(MAX_SUPPLY).unwrap();
    let one = Amount::from_satoshis(1).unwrap();
    assert!(matches!(
        total_fees([Some(max), Some(one)]),
        Err(TemplateError::Fees(_))
    ));
    assert!(matches!(
        total_fees([Some(one), None]),
        Err(TemplateError::MissingEntry)
    ));
    assert_eq!(
        total_fees([Some(one), Some(one)]).unwrap(),
        Amount::from_satoshis(2).unwrap()
    );
}

#[test]
fn workers_never_repeat_nonces() {
    let count = 5;
    let mut seen = HashSet::new();
    for index in 0..count {
        for k in 0..1_000 {
            assert!(seen.insert(nonce_for(index, count, k)));
        }
    }
    assert_eq!(seen.len(), 5_000);
    // Together the workers cover a contiguous range.
    assert!((0..5_000).all(|nonce| seen.contains(&nonce)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_pool_solves_work_once() {
    let directory = tempfile::tempdir().unwrap();
    let chain = regtest_chain(&directory);
    let mempool = Mempool::new(Policy::default());
    let block = build_block(&chain, &mempool, payout(), unix_now()).unwrap();

    let (found, mut solved) = mpsc::unbounded_channel();
    let miner = Miner::new(found);
    miner.set_threads(3);
    assert_eq!(miner.threads(), 3);
    // The regtest target accepts every hash.
    miner.set_work(&block, chain.chain_id());
    let mined = tokio::time::timeout(Duration::from_secs(30), solved.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(mined.header().prev_block, block.header().prev_block);
    assert_eq!(mined.transactions(), block.transactions());
    assert!(check_pow(mined.header(), &chain.chain_id()));
    // Only one block per generation, even with three workers.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(solved.try_recv().is_err());
    assert!(!miner.has_work());
    assert!(miner.hashes() >= 1);
    miner.shutdown();
    assert_eq!(miner.threads(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn new_work_replaces_stale_work() {
    let directory = tempfile::tempdir().unwrap();
    let chain = regtest_chain(&directory);
    let mempool = Mempool::new(Policy::default());
    let block = build_block(&chain, &mempool, payout(), unix_now()).unwrap();
    // A zero target is practically never met.
    let impossible = with_target(&block, Hash256::new([0; 32]));
    let mut easy_header = *block.header();
    easy_header.timestamp += 1;
    let easy = Block::new(easy_header, block.transactions().to_vec()).unwrap();

    let (found, mut solved) = mpsc::unbounded_channel();
    let miner = Miner::new(found);
    miner.set_threads(2);
    miner.set_work(&impossible, chain.chain_id());
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(solved.try_recv().is_err());
    miner.set_work(&easy, chain.chain_id());
    let mined = tokio::time::timeout(Duration::from_secs(30), solved.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(mined.header().target, easy.header().target);
    assert!(mined.header().timestamp >= easy.header().timestamp);

    // Withdrawn work is not mined.
    miner.set_work(&impossible, chain.chain_id());
    miner.clear_work();
    assert!(!miner.has_work());
    miner.shutdown();
}

#[test]
fn single_threaded_mining_finds_regtest_blocks() {
    let directory = tempfile::tempdir().unwrap();
    let chain = regtest_chain(&directory);
    let mempool = Mempool::new(Policy::default());
    let block = build_block(&chain, &mempool, payout(), unix_now()).unwrap();
    let mined = template::mine(&block, &chain.chain_id(), 1).unwrap();
    assert_eq!(mined.header().nonce, 0);
    let impossible = with_target(&block, Hash256::new([0; 32]));
    assert!(template::mine(&impossible, &chain.chain_id(), 3).is_none());
}
