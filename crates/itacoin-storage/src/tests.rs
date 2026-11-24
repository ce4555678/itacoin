use std::{process::Command, thread, time::Duration};

use itacoin_blockchain::BlockHeader;
use itacoin_crypto::{KeyPair, PrivateKey, SigningDomain};
use itacoin_primitives::{Amount, COIN, WalletId};
use itacoin_transaction::{
    CoinbaseTransaction, Input, Output, Transaction, UnsignedTransaction, Witness,
};

use super::*;

const CHAIN: Hash256 = Hash256::new([0xc4; 32]);
const CRASH_CHILD: &str = "ITACOIN_STORAGE_CRASH_CHILD";
const CRASH_DELAY: &str = "ITACOIN_STORAGE_CRASH_DELAY_MS";
const CRASH_BULK: &str = "ITACOIN_STORAGE_CRASH_BULK";

/// A fixed key, so that every crash-test child can spend the same coins.
fn fixed_key() -> KeyPair {
    let private_key = PrivateKey::from_seed(&[3; 32]).unwrap();
    KeyPair {
        public_key: private_key.public_key().unwrap(),
        private_key,
    }
}

fn rules() -> BlockRules {
    BlockRules {
        chain_id: CHAIN,
        coinbase_maturity: 0,
        subsidy: Amount::from_satoshis(50 * COIN).unwrap(),
    }
}

fn pay(value: u64, wallet_id: WalletId) -> Output {
    Output {
        amount: Amount::from_satoshis(value).unwrap(),
        wallet_id,
    }
}

/// Builds a valid block on the store's tip: a coinbase paying `key`, plus one
/// transaction spending up to `spend` of `key`'s coins back to itself.
fn next_block(store: &ChainStore, key: &KeyPair, spend: usize, nonce: u64) -> Block {
    let owner = key.public_key.wallet_id();
    let (prev_block, height) = match store.tip() {
        Some(tip) => (tip.block_id, tip.height + 1),
        None => (BlockId::new(Hash256::new([0; 32])), 0),
    };
    let snapshot = store.snapshot().unwrap();
    let mut coins: Vec<(OutPoint, Output)> = snapshot
        .coins()
        .map(|(outpoint, coin)| (*outpoint, coin.output))
        .collect();
    coins.sort_by_key(|(outpoint, _)| *outpoint);
    coins.truncate(spend);

    let mut transactions = vec![Transaction::Coinbase(
        CoinbaseTransaction::new(height, vec![pay(50 * COIN, owner)]).unwrap(),
    )];
    if !coins.is_empty() {
        let value: u64 = coins.iter().map(|(_, o)| o.amount.as_satoshis()).sum();
        let inputs = coins
            .iter()
            .map(|(previous_output, _)| Input {
                previous_output: *previous_output,
                witness_index: 0,
            })
            .collect();
        let spent: Vec<Output> = coins.iter().map(|(_, output)| *output).collect();
        let unsigned = UnsignedTransaction::new(
            inputs,
            vec![pay(value / 2, owner), pay(value - value / 2, owner)],
        )
        .unwrap();
        let message = unsigned.sighash(&CHAIN, &spent).unwrap();
        let signature = key
            .private_key
            .sign(SigningDomain::Transaction, message.as_bytes())
            .unwrap();
        transactions.push(Transaction::Normal(
            unsigned
                .with_witnesses(vec![Witness {
                    public_key: key.public_key.clone(),
                    signature,
                }])
                .unwrap(),
        ));
    }
    let (tx_root, witness_root) = Block::roots(&transactions).unwrap();
    let header = BlockHeader {
        prev_block,
        tx_root,
        witness_root,
        timestamp: 1_800_000_000 + height,
        target: Hash256::new([0xff; 32]),
        nonce,
    };
    Block::new(header, transactions).unwrap()
}

/// Replays the stored chain from genesis into a fresh set.
fn replay(store: &ChainStore) -> UtxoSet {
    let mut set = UtxoSet::new();
    let Some(tip) = store.tip() else {
        return set;
    };
    for height in 0..=tip.height {
        let id = store.block_id_at(height).unwrap().unwrap();
        let block = store.block(&id).unwrap().unwrap();
        set.apply_block(&block, &rules()).unwrap();
    }
    set
}

#[test]
fn new_store_is_empty_and_bound_to_its_chain() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("chain.redb");
    let store = ChainStore::open(&path, CHAIN).unwrap();
    assert_eq!(store.tip(), None);
    assert_eq!(store.utxo_stats().coins, 0);
    drop(store);

    assert!(matches!(
        ChainStore::open(&path, Hash256::new([1; 32])),
        Err(StorageError::WrongChain { .. })
    ));
    ChainStore::open(&path, CHAIN).unwrap();
}

#[test]
fn creation_is_atomic_and_ignores_stale_temporaries() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("chain.redb");
    // A crash during an earlier creation left garbage under the temporary
    // name; nothing was published at `path`.
    std::fs::write(directory.path().join(".chain.redb.creating"), b"garbage").unwrap();
    let store = ChainStore::open(&path, CHAIN).unwrap();
    assert_eq!(store.tip(), None);
    drop(store);
    let names: Vec<_> = std::fs::read_dir(directory.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(names, vec![std::ffi::OsString::from("chain.redb")]);
}

#[test]
fn only_one_handle_can_open_the_store() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("chain.redb");
    let _store = ChainStore::open(&path, CHAIN).unwrap();
    assert!(matches!(
        ChainStore::open(&path, CHAIN),
        Err(StorageError::Database(_))
    ));
}

#[test]
fn applied_blocks_survive_reopening() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("chain.redb");
    let key = KeyPair::generate().unwrap();
    let mut store = ChainStore::open(&path, CHAIN).unwrap();
    let mut ids = Vec::new();
    for nonce in 0..6 {
        let block = next_block(&store, &key, 2, nonce);
        store.apply_block(&block, &rules()).unwrap();
        ids.push(block.id());
    }
    store.verify().unwrap();
    let before = store.snapshot().unwrap();
    drop(store);

    let store = ChainStore::open(&path, CHAIN).unwrap();
    assert_eq!(store.snapshot().unwrap(), before);
    assert_eq!(store.tip().unwrap().height, 5);
    for (height, id) in ids.iter().enumerate() {
        assert_eq!(store.block_id_at(height as u64).unwrap(), Some(*id));
        assert_eq!(store.block(id).unwrap().unwrap().id(), *id);
    }
    assert_eq!(replay(&store), before);
}

#[test]
fn reverted_blocks_survive_reopening() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("chain.redb");
    let key = KeyPair::generate().unwrap();
    let mut store = ChainStore::open(&path, CHAIN).unwrap();
    let mut states = vec![store.snapshot().unwrap()];
    for nonce in 0..4 {
        let block = next_block(&store, &key, 3, nonce);
        store.apply_block(&block, &rules()).unwrap();
        states.push(store.snapshot().unwrap());
    }

    for _ in 0..4 {
        let reverted = store.revert_tip().unwrap();
        states.pop();
        assert_eq!(&store.snapshot().unwrap(), states.last().unwrap());
        // The block stays available for a later reorganization.
        assert!(store.block(&reverted.id()).unwrap().is_some());
        drop(store);
        store = ChainStore::open(&path, CHAIN).unwrap();
        assert_eq!(&store.snapshot().unwrap(), states.last().unwrap());
        store.verify().unwrap();
    }
    assert_eq!(store.tip(), None);
    assert!(matches!(store.revert_tip(), Err(StorageError::NoTip)));
}

#[test]
fn invalid_blocks_write_nothing() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("chain.redb");
    let key = KeyPair::generate().unwrap();
    let mut store = ChainStore::open(&path, CHAIN).unwrap();
    store
        .apply_block(&next_block(&store, &key, 0, 0), &rules())
        .unwrap();
    let before = store.snapshot().unwrap();

    let block = next_block(&store, &key, 1, 1);
    let stingy = BlockRules {
        subsidy: Amount::ZERO,
        ..rules()
    };
    assert!(matches!(
        store.apply_block(&block, &stingy),
        Err(StorageError::Utxo(UtxoError::CoinbaseTooLarge { .. }))
    ));
    let other_chain = BlockRules {
        chain_id: Hash256::new([1; 32]),
        ..rules()
    };
    assert!(matches!(
        store.apply_block(&block, &other_chain),
        Err(StorageError::WrongChain { .. })
    ));
    assert_eq!(store.snapshot().unwrap(), before);
    drop(store);
    assert_eq!(
        ChainStore::open(&path, CHAIN).unwrap().snapshot().unwrap(),
        before
    );
}

#[test]
fn failed_commits_leave_disk_and_memory_consistent() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("chain.redb");
    let key = KeyPair::generate().unwrap();
    let mut store = ChainStore::open(&path, CHAIN).unwrap();
    store
        .apply_block(&next_block(&store, &key, 0, 0), &rules())
        .unwrap();
    let block = next_block(&store, &key, 1, 1);
    let before = store.snapshot().unwrap();

    store.fail_commit_in = Some(0);
    assert!(store.apply_block(&block, &rules()).is_err());
    assert_eq!(store.snapshot().unwrap(), before);
    store.verify().unwrap();

    store.apply_block(&block, &rules()).unwrap();
    let after = store.snapshot().unwrap();
    store.fail_commit_in = Some(0);
    assert!(store.revert_tip().is_err());
    assert_eq!(store.snapshot().unwrap(), after);
    store.verify().unwrap();
}

#[test]
fn inconsistent_tip_is_detected_on_open() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("chain.redb");
    let key = KeyPair::generate().unwrap();
    let mut store = ChainStore::open(&path, CHAIN).unwrap();
    store
        .apply_block(&next_block(&store, &key, 0, 0), &rules())
        .unwrap();
    drop(store);

    let db = Database::create(&path).unwrap();
    let write = db.begin_write().unwrap();
    set_tip(
        &write,
        Some(Tip {
            block_id: BlockId::new(Hash256::new([9; 32])),
            height: 0,
        }),
    )
    .unwrap();
    write.commit().unwrap();
    drop(db);

    assert!(matches!(
        ChainStore::open(&path, CHAIN),
        Err(StorageError::Corrupt(_))
    ));
}

/// Child side of the crash test: applies (and sometimes reverts) blocks
/// forever until a timer thread aborts the process mid-flight.
fn crash_child(path: &str) -> ! {
    let delay: u64 = std::env::var(CRASH_DELAY).unwrap().parse().unwrap();
    thread::spawn(move || {
        thread::sleep(Duration::from_millis(delay));
        std::process::abort();
    });
    let key = fixed_key();
    let mut store = ChainStore::open(Path::new(path), CHAIN).unwrap();
    if std::env::var_os(CRASH_BULK).is_some() {
        store.set_bulk(true).unwrap();
        store.set_durable_every(3);
    }
    for nonce in 0.. {
        if nonce % 5 == 4 && store.tip().is_some() {
            store.revert_tip().unwrap();
        } else {
            let block = next_block(&store, &key, 3, nonce);
            store.apply_block(&block, &rules()).unwrap();
        }
    }
    unreachable!()
}

#[cfg(unix)]
#[test]
fn survives_process_abort_mid_write() {
    abort_children("tests::survives_process_abort_mid_write", false);
}

/// Batched, non-durable commits during initial sync: an abort rolls back to
/// the last durable commit, which is still a whole block.
#[cfg(unix)]
#[test]
fn survives_process_abort_in_bulk_mode() {
    abort_children("tests::survives_process_abort_in_bulk_mode", true);
}

#[cfg(unix)]
fn abort_children(test: &str, bulk: bool) {
    use std::os::unix::process::ExitStatusExt;

    if let Ok(path) = std::env::var(CRASH_CHILD) {
        crash_child(&path);
    }
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("chain.redb");
    let mut heights = Vec::new();
    let delays: &[u64] = if bulk {
        &[2, 300, 700, 1_100, 1_500, 1_900, 2_300]
    } else {
        &[2, 10, 150, 300, 450, 600, 750, 900]
    };
    for &delay in delays {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", test, "--nocapture"])
            .env(CRASH_CHILD, &path)
            .env(CRASH_DELAY, delay.to_string());
        if bulk {
            command.env(CRASH_BULK, "1");
        }
        let status = command.status().unwrap();
        // SIGABRT (6), not a panic: the child must die mid-flight.
        assert_eq!(status.signal(), Some(6), "child did not abort: {status}");

        // The file reopens, matches a replay of its own chain, and keeps
        // accepting blocks.
        let store = ChainStore::open(&path, CHAIN).unwrap();
        store.check_utxo().unwrap();
        store.check_blocks(u64::MAX).unwrap();
        assert_eq!(replay(&store), store.snapshot().unwrap());
        heights.push(store.tip().map(|tip| tip.height));
    }
    // Several aborts must actually have landed after some committed blocks.
    assert!(heights.iter().flatten().count() >= 3, "{heights:?}");
}

#[test]
fn the_cache_evicts_by_generation() {
    let coin = |value: u64| Coin {
        output: pay(value, WalletId::new(Hash256::new([1; 32]))),
        height: 0,
        is_coinbase: false,
    };
    let outpoint = |index: u16| OutPoint {
        txid: itacoin_primitives::TransactionId::new(Hash256::new([2; 32])),
        index,
    };
    let mut cache = CoinCache::new(MIN_COIN_CACHE_BYTES);
    cache.half = 2;
    cache.insert(outpoint(0), coin(1));
    cache.insert(outpoint(1), coin(2));
    // The hot generation filled up and became cold.
    assert_eq!(cache.len(), 2);
    assert_eq!(cache.get(&outpoint(0)), Some(coin(1)));
    cache.insert(outpoint(2), coin(3));
    // 1 was cold and never read: it is the one dropped.
    assert_eq!(cache.get(&outpoint(1)), None);
    assert_eq!(cache.get(&outpoint(0)), Some(coin(1)));
    cache.remove(&outpoint(0));
    assert_eq!(cache.get(&outpoint(0)), None);
    assert!(cache.len() <= 4);
    assert!(cache.hits >= 2 && cache.misses >= 2);
}

/// The proof that splitting validation into `validate_block` and the store
/// did not change consensus: the same blocks, applied and reverted at
/// random, give the same coins in memory and on disk.
#[test]
fn the_store_matches_the_in_memory_set() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("chain.redb");
    let key = KeyPair::generate().unwrap();
    let owner = key.public_key.wallet_id();
    let mut store = ChainStore::open(&path, CHAIN).unwrap();
    store.set_cache_half(4);
    let mut set = UtxoSet::new();
    let mut undo: Vec<(Block, BlockUndo)> = Vec::new();
    let mut state = 0x5eed_u64;
    let mut next = |bound: u64| {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state % bound
    };
    for nonce in 0..60 {
        if next(4) == 0 && !undo.is_empty() {
            let (block, block_undo) = undo.pop().unwrap();
            let reverted = store.revert_tip().unwrap();
            assert_eq!(reverted.id(), block.id());
            set.revert_block(&block, &block_undo).unwrap();
        } else {
            let block = next_block(&store, &key, next(5) as usize, nonce);
            store.apply_block(&block, &rules()).unwrap();
            let block_undo = set.apply_block(&block, &rules()).unwrap();
            undo.push((block, block_undo));
        }
        let snapshot = store.snapshot().unwrap();
        assert_eq!(snapshot, set);
        assert_eq!(store.tip(), set.tip());
        assert_eq!(store.utxo_stats().coins, set.len() as u64);
        assert_eq!(store.utxo_stats().total_value, set.total_value());
        let mut expected: Vec<OutPoint> = set.outpoints_of(&owner).copied().collect();
        expected.sort();
        let listed: Vec<OutPoint> = store
            .coins_of(&owner, None, usize::MAX)
            .unwrap()
            .into_iter()
            .map(|(outpoint, _)| outpoint)
            .collect();
        assert_eq!(listed, expected);
        for (outpoint, coin) in set.coins() {
            assert_eq!(store.coin(outpoint).unwrap(), Some(*coin));
        }
    }
    store.check_utxo().unwrap();
    store.check_blocks(u64::MAX).unwrap();
    // Pagination by outpoint.
    let all = store.coins_of(&owner, None, usize::MAX).unwrap();
    if all.len() > 2 {
        let first = store.coins_of(&owner, None, 2).unwrap();
        let rest = store
            .coins_of(&owner, Some(first[1].0), usize::MAX)
            .unwrap();
        assert_eq!([first, rest].concat(), all);
    }
}

#[test]
fn version_1_files_are_upgraded() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("chain.redb");
    let key = KeyPair::generate().unwrap();
    let owner = key.public_key.wallet_id();
    let mut store = ChainStore::open(&path, CHAIN).unwrap();
    for nonce in 0..5 {
        let block = next_block(&store, &key, 2, nonce);
        store.apply_block(&block, &rules()).unwrap();
    }
    let before = store.snapshot().unwrap();
    drop(store);

    // Turn the file back into the version 1 layout.
    let db = Database::open(&path).unwrap();
    let write = db.begin_write().unwrap();
    {
        let mut meta = write.open_table(META).unwrap();
        meta.insert(META_SCHEMA, 1_u32.to_be_bytes().as_slice())
            .unwrap();
        meta.remove(META_SUPPLY).unwrap();
        meta.remove(META_COINS).unwrap();
        meta.remove(META_WALLET_INDEX).unwrap();
    }
    write.delete_table(WALLET_COINS).unwrap();
    write.delete_table(PRUNED).unwrap();
    write.commit().unwrap();
    drop(db);

    let store = ChainStore::open(&path, CHAIN).unwrap();
    assert_eq!(store.snapshot().unwrap(), before);
    assert_eq!(store.utxo_stats().total_value, before.total_value());
    assert_eq!(
        store.coins_of(&owner, None, usize::MAX).unwrap().len(),
        before.len()
    );
    store.check_utxo().unwrap();
    drop(store);

    // A newer schema is refused.
    let db = Database::open(&path).unwrap();
    let write = db.begin_write().unwrap();
    write
        .open_table(META)
        .unwrap()
        .insert(META_SCHEMA, 9_u32.to_be_bytes().as_slice())
        .unwrap();
    write.commit().unwrap();
    drop(db);
    assert!(matches!(
        ChainStore::open(&path, CHAIN),
        Err(StorageError::UnsupportedSchema(9))
    ));
}

#[test]
fn audits_catch_tampering() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("chain.redb");
    let key = KeyPair::generate().unwrap();
    let mut store = ChainStore::open(&path, CHAIN).unwrap();
    for nonce in 0..4 {
        let block = next_block(&store, &key, 1, nonce);
        store.apply_block(&block, &rules()).unwrap();
    }
    store.check_utxo().unwrap();
    assert_eq!(store.check_blocks(10).unwrap(), 4);
    drop(store);

    // Drop one wallet-index entry behind the store's back.
    let db = Database::open(&path).unwrap();
    let write = db.begin_write().unwrap();
    {
        let mut index = write.open_table(WALLET_COINS).unwrap();
        let first = index
            .first()
            .unwrap()
            .map(|(key, _)| key.value().to_vec())
            .unwrap();
        index.remove(first.as_slice()).unwrap();
    }
    write.commit().unwrap();
    drop(db);
    let store = ChainStore::open(&path, CHAIN).unwrap();
    assert!(store.check_utxo().is_err());
    drop(store);

    // Turning the index off and on again rebuilds it.
    let off = StoreOptions {
        wallet_index: false,
        ..StoreOptions::default()
    };
    let store = ChainStore::open_with(&path, CHAIN, off).unwrap();
    assert!(matches!(
        store.coins_of(&key.public_key.wallet_id(), None, 10),
        Err(StorageError::NoWalletIndex)
    ));
    store.check_utxo().unwrap();
    drop(store);
    let store = ChainStore::open(&path, CHAIN).unwrap();
    store.check_utxo().unwrap();
}

#[test]
fn pruning_is_one_way_and_bounded() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("chain.redb");
    let shallow = StoreOptions {
        prune_depth: Some(MIN_PRUNE_DEPTH - 1),
        ..StoreOptions::default()
    };
    assert!(matches!(
        ChainStore::open_with(&path, CHAIN, shallow),
        Err(StorageError::PruneDepth(_))
    ));
    let pruning = StoreOptions {
        prune_depth: Some(MIN_PRUNE_DEPTH),
        ..StoreOptions::default()
    };
    let key = KeyPair::generate().unwrap();
    let mut store = ChainStore::open_with(&path, CHAIN, pruning).unwrap();
    store.set_bulk(true).unwrap();
    let mut ids = Vec::new();
    for nonce in 0..300 {
        let block = next_block(&store, &key, 1, nonce);
        store.apply_block(&block, &rules()).unwrap();
        store.prune().unwrap();
        ids.push(block.id());
    }
    store.set_bulk(false).unwrap();
    // Heights 0..=11 are deeper than 288 below the tip at 299.
    assert_eq!(store.pruned_height(), Some(11));
    assert!(store.block(&ids[11]).unwrap().is_none());
    assert!(matches!(
        store.stored_block(&ids[11]).unwrap(),
        Some(StoredBlock::Pruned(_))
    ));
    assert!(store.block(&ids[12]).unwrap().is_some());
    store.check_blocks(u64::MAX).unwrap();

    // Reverting through pruned blocks works from the undo data alone, and
    // a pruned block of the old active chain can be applied again.
    let before = store.snapshot().unwrap();
    let mut reverted = Vec::new();
    for _ in 0..295 {
        reverted.push(store.revert_tip().unwrap());
    }
    assert_eq!(store.tip().unwrap().height, 4);
    for block in reverted.iter().rev() {
        store.apply_stored(block, &rules()).unwrap();
    }
    assert_eq!(store.snapshot().unwrap(), before);
    store.check_utxo().unwrap();
    drop(store);

    assert!(matches!(
        ChainStore::open(&path, CHAIN),
        Err(StorageError::PrunedStore)
    ));
}
