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
    let mut coins: Vec<(OutPoint, Output)> = store
        .utxo()
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
    assert!(store.utxo().is_empty());
    drop(store);

    assert!(matches!(
        ChainStore::open(&path, Hash256::new([1; 32])),
        Err(StorageError::WrongChain { .. })
    ));
    ChainStore::open(&path, CHAIN).unwrap();
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
    let before = store.utxo().clone();
    drop(store);

    let store = ChainStore::open(&path, CHAIN).unwrap();
    assert_eq!(store.utxo(), &before);
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
    let mut states = vec![store.utxo().clone()];
    for nonce in 0..4 {
        let block = next_block(&store, &key, 3, nonce);
        store.apply_block(&block, &rules()).unwrap();
        states.push(store.utxo().clone());
    }

    for _ in 0..4 {
        let reverted = store.revert_tip().unwrap();
        states.pop();
        assert_eq!(store.utxo(), states.last().unwrap());
        // The block stays available for a later reorganization.
        assert!(store.block(&reverted.id()).unwrap().is_some());
        drop(store);
        store = ChainStore::open(&path, CHAIN).unwrap();
        assert_eq!(store.utxo(), states.last().unwrap());
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
    let before = store.utxo().clone();

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
    assert_eq!(store.utxo(), &before);
    drop(store);
    assert_eq!(ChainStore::open(&path, CHAIN).unwrap().utxo(), &before);
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
    let before = store.utxo().clone();

    store.fail_next_commit = true;
    assert!(store.apply_block(&block, &rules()).is_err());
    assert_eq!(store.utxo(), &before);
    store.verify().unwrap();

    store.apply_block(&block, &rules()).unwrap();
    let after = store.utxo().clone();
    store.fail_next_commit = true;
    assert!(store.revert_tip().is_err());
    assert_eq!(store.utxo(), &after);
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
    use std::os::unix::process::ExitStatusExt;

    if let Ok(path) = std::env::var(CRASH_CHILD) {
        crash_child(&path);
    }
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("chain.redb");
    let mut heights = Vec::new();
    for delay in [150, 300, 450, 600, 750, 900] {
        let status = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "tests::survives_process_abort_mid_write",
                "--nocapture",
            ])
            .env(CRASH_CHILD, &path)
            .env(CRASH_DELAY, delay.to_string())
            .status()
            .unwrap();
        // SIGABRT (6), not a panic: the child must die mid-flight.
        assert_eq!(status.signal(), Some(6), "child did not abort: {status}");

        // The file reopens, matches a replay of its own chain, and keeps
        // accepting blocks.
        let store = ChainStore::open(&path, CHAIN).unwrap();
        store.verify().unwrap();
        assert_eq!(&replay(&store), store.utxo());
        heights.push(store.tip().map(|tip| tip.height));
    }
    // Several aborts must actually have landed after some committed blocks.
    assert!(heights.iter().flatten().count() >= 3, "{heights:?}");
}
