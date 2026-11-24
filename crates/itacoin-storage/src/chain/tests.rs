use itacoin_crypto::{KeyPair, SigningDomain};
use itacoin_primitives::{Amount, WalletId};
use itacoin_transaction::{
    CoinbaseTransaction, Input, OutPoint, Output, Transaction, UnsignedTransaction, Witness,
};

use super::*;

const NOW: u64 = 4_000_000_000;

struct Fixture {
    _directory: tempfile::TempDir,
    path: std::path::PathBuf,
    key: KeyPair,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("chain.redb");
        Self {
            _directory: directory,
            path,
            key: KeyPair::generate().unwrap(),
        }
    }

    fn open(&self) -> Chain {
        Chain::open(&self.path, ConsensusParams::regtest()).unwrap()
    }
}

/// Options for a test block.
#[derive(Clone, Copy)]
struct Shape {
    /// Coinbase claims `subsidy + extra` satoshis.
    extra: u64,
    /// Distinguishes sibling blocks.
    tag: u8,
}

const PLAIN: Shape = Shape { extra: 0, tag: 0 };

/// A block on `parent`, paying the coinbase to `key` (or to a tag-specific
/// wallet), with the given transactions.
fn block_on(
    chain: &Chain,
    key: &KeyPair,
    parent: BlockId,
    shape: Shape,
    transactions: Vec<Transaction>,
) -> Block {
    let parent_entry = chain.entry(&parent).unwrap();
    let height = parent_entry.height + 1;
    let wallet = if shape.tag == 0 {
        key.public_key.wallet_id()
    } else {
        WalletId::new(Hash256::new([shape.tag; 32]))
    };
    let reward = itacoin_consensus::subsidy(height, chain.params()).as_satoshis() + shape.extra;
    let mut all = vec![Transaction::Coinbase(
        CoinbaseTransaction::new(
            height,
            vec![Output {
                amount: Amount::from_satoshis(reward).unwrap(),
                wallet_id: wallet,
            }],
        )
        .unwrap(),
    )];
    all.extend(transactions);
    let (tx_root, witness_root) = Block::roots(&all).unwrap();
    let header = BlockHeader {
        prev_block: parent,
        tx_root,
        witness_root,
        timestamp: parent_entry.header.timestamp + 120,
        target: chain.next_target(&parent).unwrap().to_hash(),
        nonce: u64::from(shape.tag),
    };
    Block::new(header, all).unwrap()
}

fn spend(chain: &Chain, key: &KeyPair, coin: OutPoint, to: WalletId) -> Transaction {
    let output = chain.coin(&coin).unwrap().unwrap().output;
    let unsigned = UnsignedTransaction::new(
        vec![Input {
            previous_output: coin,
            witness_index: 0,
        }],
        vec![Output {
            amount: output.amount,
            wallet_id: to,
        }],
    )
    .unwrap();
    let message = unsigned.sighash(&chain.chain_id(), &[output]).unwrap();
    let signature = key
        .private_key
        .sign(SigningDomain::Transaction, message.as_bytes())
        .unwrap();
    Transaction::Normal(
        unsigned
            .with_witnesses(vec![Witness {
                public_key: key.public_key.clone(),
                signature,
            }])
            .unwrap(),
    )
}

fn coinbase_outpoint(block: &Block) -> OutPoint {
    OutPoint {
        txid: block.transactions()[0].txid(),
        index: 0,
    }
}

fn genesis_id(chain: &Chain) -> BlockId {
    chain.store().block_id_at(0).unwrap().unwrap()
}

/// Extends `parent` with `count` plain blocks, submitting each.
fn extend(
    chain: &mut Chain,
    key: &KeyPair,
    mut parent: BlockId,
    count: usize,
    tag: u8,
) -> Vec<Block> {
    let mut blocks = Vec::new();
    for _ in 0..count {
        let block = block_on(chain, key, parent, Shape { extra: 0, tag }, vec![]);
        chain.submit_block(&block, NOW).unwrap();
        parent = block.id();
        blocks.push(block);
    }
    blocks
}

/// Replays the active chain from genesis into a fresh set.
fn replay(chain: &Chain) -> UtxoSet {
    let mut set = UtxoSet::new();
    for height in 0..=chain.tip().unwrap().height {
        let id = chain.store().block_id_at(height).unwrap().unwrap();
        let block = chain.store().block(&id).unwrap().unwrap();
        set.apply_block(&block, &chain.rules(height)).unwrap();
    }
    set
}

#[test]
fn opening_creates_the_genesis_block() {
    let fixture = Fixture::new();
    let chain = fixture.open();
    let tip = chain.tip().unwrap();
    assert_eq!(tip.height, 0);
    assert_eq!(tip.block_id.into_hash(), chain.chain_id());
    assert_eq!(chain.utxo_stats().coins, 1);
    assert_eq!(
        chain.utxo_stats().total_value,
        itacoin_consensus::subsidy(0, chain.params())
    );
    drop(chain);
    assert_eq!(fixture.open().tip(), Some(tip));
}

#[test]
fn blocks_extend_the_chain_and_persist() {
    let fixture = Fixture::new();
    let mut chain = fixture.open();
    let genesis = genesis_id(&chain);
    let blocks = extend(&mut chain, &fixture.key, genesis, 5, 0);
    let tip = chain.tip().unwrap();
    assert_eq!(tip.height, 5);
    assert_eq!(tip.block_id, blocks[4].id());
    let utxo = chain.snapshot().unwrap();
    drop(chain);

    let mut chain = fixture.open();
    assert_eq!(chain.tip(), Some(tip));
    assert_eq!(chain.snapshot().unwrap(), utxo);
    assert_eq!(
        chain.submit_block(&blocks[2], NOW).unwrap(),
        SubmitOutcome::Duplicate
    );
}

#[test]
fn the_chain_with_more_work_wins_and_reorganizes() {
    let fixture = Fixture::new();
    let mut chain = fixture.open();
    let genesis = genesis_id(&chain);
    let a = extend(&mut chain, &fixture.key, genesis, 2, 1);
    assert_eq!(chain.tip().unwrap().block_id, a[1].id());

    // A longer branch with a spend of its own coinbase.
    let b1 = block_on(&chain, &fixture.key, genesis, PLAIN, vec![]);
    assert_eq!(
        chain.submit_block(&b1, NOW).unwrap(),
        SubmitOutcome::SideChain
    );
    let b2 = block_on(&chain, &fixture.key, b1.id(), PLAIN, vec![]);
    assert_eq!(
        chain.submit_block(&b2, NOW).unwrap(),
        SubmitOutcome::SideChain
    );
    // `spend` reads the active set, which is still branch A: look the coin up
    // after switching instead.
    let b3 = block_on(&chain, &fixture.key, b2.id(), PLAIN, vec![]);
    assert_eq!(chain.submit_block(&b3, NOW).unwrap(), SubmitOutcome::NewTip);
    assert!(chain.coin(&coinbase_outpoint(&b1)).unwrap().is_some());
    assert!(chain.coin(&coinbase_outpoint(&a[0])).unwrap().is_none());

    let payment = spend(
        &chain,
        &fixture.key,
        coinbase_outpoint(&b1),
        WalletId::new(Hash256::new([7; 32])),
    );
    let b4 = block_on(&chain, &fixture.key, b3.id(), PLAIN, vec![payment]);
    assert_eq!(chain.submit_block(&b4, NOW).unwrap(), SubmitOutcome::NewTip);
    assert_eq!(replay(&chain), chain.snapshot().unwrap());

    // Branch A overtakes again: the spend is undone.
    extend(&mut chain, &fixture.key, a[1].id(), 3, 1);
    assert_eq!(chain.tip().unwrap().height, 5);
    assert!(chain.coin(&coinbase_outpoint(&b1)).unwrap().is_none());
    assert_eq!(replay(&chain), chain.snapshot().unwrap());
}

#[test]
fn equal_work_keeps_the_first_seen_chain() {
    let fixture = Fixture::new();
    let mut chain = fixture.open();
    let genesis = genesis_id(&chain);
    let first = extend(&mut chain, &fixture.key, genesis, 1, 1);
    let second = block_on(
        &chain,
        &fixture.key,
        genesis,
        Shape { extra: 0, tag: 2 },
        vec![],
    );
    assert_eq!(
        chain.submit_block(&second, NOW).unwrap(),
        SubmitOutcome::SideChain
    );
    assert_eq!(chain.tip().unwrap().block_id, first[0].id());
}

#[test]
fn an_invalid_block_on_a_heavier_branch_is_rejected_with_its_descendants() {
    let fixture = Fixture::new();
    let mut chain = fixture.open();
    let genesis = genesis_id(&chain);
    let a = extend(&mut chain, &fixture.key, genesis, 2, 1);

    let b1 = block_on(&chain, &fixture.key, genesis, PLAIN, vec![]);
    chain.submit_block(&b1, NOW).unwrap();
    // Claims one satoshi more than the subsidy: the header is fine, the block
    // is not. With equal work it is only stored, not validated.
    let b2 = block_on(
        &chain,
        &fixture.key,
        b1.id(),
        Shape { extra: 1, tag: 0 },
        vec![],
    );
    assert_eq!(
        chain.submit_block(&b2, NOW).unwrap(),
        SubmitOutcome::SideChain
    );
    let b3 = block_on(&chain, &fixture.key, b2.id(), PLAIN, vec![]);
    assert!(matches!(
        chain.submit_block(&b3, NOW),
        Err(ChainError::InvalidAncestor(id)) if id == b3.id()
    ));

    assert_eq!(chain.tip().unwrap().block_id, a[1].id());
    assert!(!chain.entry(&b1.id()).unwrap().invalid);
    assert!(chain.entry(&b2.id()).unwrap().invalid);
    assert!(chain.entry(&b3.id()).unwrap().invalid);
    assert_eq!(replay(&chain), chain.snapshot().unwrap());

    let b4 = block_on(&chain, &fixture.key, b3.id(), PLAIN, vec![]);
    assert!(matches!(
        chain.submit_block(&b4, NOW),
        Err(ChainError::InvalidParent(_))
    ));
    drop(chain);
    let chain = fixture.open();
    assert!(chain.entry(&b2.id()).unwrap().invalid);
    assert_eq!(chain.tip().unwrap().block_id, a[1].id());
}

#[test]
fn a_directly_invalid_tip_is_reported() {
    let fixture = Fixture::new();
    let mut chain = fixture.open();
    let genesis = genesis_id(&chain);
    let greedy = block_on(
        &chain,
        &fixture.key,
        genesis,
        Shape { extra: 1, tag: 0 },
        vec![],
    );
    assert!(matches!(
        chain.submit_block(&greedy, NOW),
        Err(ChainError::InvalidBlock {
            error: UtxoError::CoinbaseTooLarge { .. },
            ..
        })
    ));
    assert_eq!(chain.tip().unwrap().height, 0);
}

#[test]
fn header_rules_reject_without_storing() {
    let fixture = Fixture::new();
    let mut chain = fixture.open();
    let genesis = genesis_id(&chain);
    let valid = block_on(&chain, &fixture.key, genesis, PLAIN, vec![]);

    let rebuild = |header: BlockHeader| Block::new(header, valid.transactions().to_vec()).unwrap();

    let mut header = *valid.header();
    header.target = (U256::MAX >> 1).to_hash();
    assert!(matches!(
        chain.submit_block(&rebuild(header), NOW),
        Err(ChainError::Consensus(ConsensusError::WrongTarget))
    ));

    let mut header = *valid.header();
    header.timestamp = chain.entry(&genesis).unwrap().header.timestamp;
    assert!(matches!(
        chain.submit_block(&rebuild(header), NOW),
        Err(ChainError::Consensus(ConsensusError::TimestampTooOld))
    ));

    let early_clock = valid.header().timestamp - 601;
    assert!(matches!(
        chain.submit_block(&valid, early_clock),
        Err(ChainError::Consensus(ConsensusError::TimestampInFuture))
    ));

    let mut header = *valid.header();
    header.prev_block = BlockId::new(Hash256::new([9; 32]));
    assert!(matches!(
        chain.submit_block(&rebuild(header), NOW),
        Err(ChainError::UnknownParent(_))
    ));

    let coinbase = vec![Transaction::Coinbase(
        CoinbaseTransaction::new(2, valid.transactions()[0].outputs().to_vec()).unwrap(),
    )];
    let (tx_root, witness_root) = Block::roots(&coinbase).unwrap();
    let skipping = Block::new(
        BlockHeader {
            tx_root,
            witness_root,
            ..*valid.header()
        },
        coinbase,
    )
    .unwrap();
    assert!(matches!(
        chain.submit_block(&skipping, NOW),
        Err(ChainError::WrongHeight {
            expected: 1,
            actual: 2
        })
    ));

    // None of the rejected blocks were stored; the valid one still applies.
    assert_eq!(
        chain.submit_block(&valid, NOW).unwrap(),
        SubmitOutcome::NewTip
    );
}

#[test]
fn proof_of_work_is_enforced() {
    let directory = tempfile::tempdir().unwrap();
    let params = ConsensusParams {
        pow_limit: U256::ONE,
        ..ConsensusParams::regtest()
    };
    let mut chain = Chain::open(&directory.path().join("chain.redb"), params).unwrap();
    let key = KeyPair::generate().unwrap();
    let genesis = genesis_id(&chain);
    let block = block_on(&chain, &key, genesis, PLAIN, vec![]);
    assert!(matches!(
        chain.submit_block(&block, NOW),
        Err(ChainError::Consensus(ConsensusError::InsufficientWork))
    ));
}

#[test]
fn an_interrupted_reorganization_finishes_on_reopen() {
    let fixture = Fixture::new();
    let mut chain = fixture.open();
    let genesis = genesis_id(&chain);
    extend(&mut chain, &fixture.key, genesis, 2, 1);
    let b = extend(&mut chain, &fixture.key, genesis, 2, 0);
    let b3 = block_on(&chain, &fixture.key, b[1].id(), PLAIN, vec![]);

    // Commits for b3: store it (0), revert a2 (1), revert a1 (2), then fail
    // applying b1, as if the process died mid-reorganization.
    chain.store.fail_commit_in = Some(3);
    assert!(matches!(
        chain.submit_block(&b3, NOW),
        Err(ChainError::Storage(_))
    ));
    drop(chain);

    let chain = fixture.open();
    assert_eq!(chain.tip().unwrap().block_id, b3.id());
    assert_eq!(replay(&chain), chain.snapshot().unwrap());
    chain.store().verify().unwrap();
}

#[test]
fn arrival_order_does_not_change_the_result() {
    let first = Fixture::new();
    let mut builder = first.open();
    let genesis = genesis_id(&builder);
    let a = extend(&mut builder, &first.key, genesis, 2, 1);
    let b = extend(&mut builder, &first.key, genesis, 3, 2);
    let mut expected_tip = builder.tip();
    let expected_utxo = builder.snapshot().unwrap();

    let second = Fixture::new();
    let mut other = second.open();
    for block in b.iter().chain(a.iter()) {
        other.submit_block(block, NOW).unwrap();
    }
    assert_eq!(other.tip(), expected_tip.take());
    assert_eq!(other.snapshot().unwrap(), expected_utxo);
}

#[test]
fn a_branch_above_a_flagged_block_is_never_activated() {
    let fixture = Fixture::new();
    let mut chain = fixture.open();
    let genesis = genesis_id(&chain);
    let a = extend(&mut chain, &fixture.key, genesis, 2, 1);
    // An equal-work side branch: stored, not yet validated.
    let b = extend(&mut chain, &fixture.key, genesis, 2, 2);
    assert_eq!(chain.tip().unwrap().block_id, a[1].id());

    // Simulate an index where b1 is flagged invalid but b2 was never flagged
    // (a bug or damage). A heavier child of b2 must not activate the branch,
    // and activation must not loop forever retrying it.
    chain.index.get_mut(&b[0].id()).unwrap().invalid = true;
    let b3 = block_on(
        &chain,
        &fixture.key,
        b[1].id(),
        Shape { extra: 0, tag: 2 },
        vec![],
    );
    assert!(matches!(
        chain.submit_block(&b3, NOW),
        Err(ChainError::InvalidAncestor(id)) if id == b3.id()
    ));
    assert!(chain.entry(&b3.id()).unwrap().invalid);
    assert_eq!(chain.tip().unwrap().block_id, a[1].id());
    assert_eq!(replay(&chain), chain.snapshot().unwrap());
}

fn pruning() -> StoreOptions {
    StoreOptions {
        prune_depth: Some(crate::MIN_PRUNE_DEPTH),
        ..StoreOptions::default()
    }
}

/// Extends `parent` with `count` blocks on every chain, built on the first.
fn extend_all(
    chains: &mut [&mut Chain],
    key: &KeyPair,
    mut parent: BlockId,
    count: usize,
    tag: u8,
) -> BlockId {
    for _ in 0..count {
        let block = block_on(chains[0], key, parent, Shape { extra: 0, tag }, vec![]);
        for chain in chains.iter_mut() {
            chain.submit_block(&block, NOW).unwrap();
        }
        parent = block.id();
    }
    parent
}

#[test]
fn a_pruned_node_reorganizes_like_an_archive_node() {
    let (archive_fixture, pruned_fixture) = (Fixture::new(), Fixture::new());
    let mut archive = archive_fixture.open();
    let mut pruned =
        Chain::open_with(&pruned_fixture.path, ConsensusParams::regtest(), pruning()).unwrap();
    archive.set_bulk(true).unwrap();
    pruned.set_bulk(true).unwrap();
    let key = &archive_fixture.key;
    let genesis = genesis_id(&archive);

    // Branch A: 300 blocks. The pruned node drops the witnesses of the
    // deepest ones.
    let a_tip = extend_all(&mut [&mut archive, &mut pruned], key, genesis, 300, 1);
    assert_eq!(pruned.tip().unwrap().block_id, a_tip);
    assert_eq!(pruned.store.pruned_height(), Some(12));

    // Branch B from genesis overtakes with 310 blocks: a reorganization
    // that reverts all of A, pruned blocks included.
    let b_tip = extend_all(&mut [&mut archive, &mut pruned], key, genesis, 310, 2);
    for chain in [&archive, &pruned] {
        assert_eq!(chain.tip().unwrap().block_id, b_tip);
    }
    assert_eq!(archive.snapshot().unwrap(), pruned.snapshot().unwrap());

    // A comes back: its pruned blocks are applied again from storage,
    // without their witnesses, since this node validated them before.
    let a_tip = extend_all(&mut [&mut archive, &mut pruned], key, a_tip, 20, 1);
    for chain in [&archive, &pruned] {
        assert_eq!(chain.tip().unwrap().block_id, a_tip);
        assert_eq!(chain.tip().unwrap().height, 320);
    }
    assert_eq!(archive.snapshot().unwrap(), pruned.snapshot().unwrap());
    pruned.store.check_utxo().unwrap();
    pruned.store.check_blocks(u64::MAX).unwrap();
    pruned.flush().unwrap();
    drop(pruned);
    // Reopening keeps the same state.
    let reopened =
        Chain::open_with(&pruned_fixture.path, ConsensusParams::regtest(), pruning()).unwrap();
    assert_eq!(reopened.snapshot().unwrap(), archive.snapshot().unwrap());
}

#[test]
fn reindexing_rebuilds_the_same_state() {
    for options in [StoreOptions::default(), pruning()] {
        let fixture = Fixture::new();
        let mut chain =
            Chain::open_with(&fixture.path, ConsensusParams::regtest(), options).unwrap();
        chain.set_bulk(true).unwrap();
        let genesis = genesis_id(&chain);
        let a = extend(&mut chain, &fixture.key, genesis, 2, 0);
        let payment = spend(
            &chain,
            &fixture.key,
            coinbase_outpoint(&a[0]),
            WalletId::new(Hash256::new([7; 32])),
        );
        let paid = block_on(&chain, &fixture.key, a[1].id(), PLAIN, vec![payment]);
        chain.submit_block(&paid, NOW).unwrap();
        extend(&mut chain, &fixture.key, paid.id(), 300, 0);
        // A side branch, kept by the reindexation.
        let side = extend(&mut chain, &fixture.key, genesis, 2, 9);
        let tip = chain.tip();
        let before = chain.snapshot().unwrap();
        drop(chain);

        let report = reindex(&fixture.path, ConsensusParams::regtest(), options).unwrap();
        assert_eq!(report.applied, 304);
        assert_eq!(report.side_blocks, 2);
        assert_eq!(report.pruned > 0, options.prune_depth.is_some());

        let chain = Chain::open_with(&fixture.path, ConsensusParams::regtest(), options).unwrap();
        assert_eq!(chain.tip(), tip);
        assert_eq!(chain.snapshot().unwrap(), before);
        assert!(chain.store().block(&side[1].id()).unwrap().is_some());
        chain.store().check_utxo().unwrap();
        chain.store().check_blocks(u64::MAX).unwrap();
        let names: Vec<_> = std::fs::read_dir(fixture.path.parent().unwrap())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from("chain.redb")]);
    }
}
