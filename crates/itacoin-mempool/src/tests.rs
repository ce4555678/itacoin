use itacoin_blockchain::{BlockHeader, Coin, Tip, UtxoSet};
use itacoin_crypto::{KeyPair, SigningDomain};
use itacoin_primitives::{BlockId, COIN, WalletId};
use itacoin_transaction::{CoinbaseTransaction, Input, Output, UnsignedTransaction, Witness};

use super::*;

const CHAIN: Hash256 = Hash256::new([0xc4; 32]);
const NOW: u64 = 1_000_000;

fn sats(value: u64) -> Amount {
    Amount::from_satoshis(value).unwrap()
}

fn outpoint(byte: u8, index: u16) -> OutPoint {
    OutPoint {
        txid: TransactionId::new(Hash256::new([byte; 32])),
        index,
    }
}

/// A set with `count` confirmed, non-coinbase coins of 1 ITC owned by `key`,
/// plus one fresh coinbase coin at height 10.
fn utxo(key: &KeyPair, count: u8) -> UtxoSet {
    let owner = key.public_key.wallet_id();
    let mut coins: Vec<(OutPoint, Coin)> = (1..=count)
        .map(|byte| {
            (
                outpoint(byte, 0),
                Coin {
                    output: Output {
                        amount: sats(COIN),
                        wallet_id: owner,
                    },
                    height: 1,
                    is_coinbase: false,
                },
            )
        })
        .collect();
    coins.push((
        outpoint(0xcb, 0),
        Coin {
            output: Output {
                amount: sats(COIN),
                wallet_id: owner,
            },
            height: 10,
            is_coinbase: true,
        },
    ));
    let tip = Tip {
        block_id: BlockId::new(Hash256::new([1; 32])),
        height: 10,
    };
    UtxoSet::from_parts(coins, Some(tip)).unwrap()
}

fn view(utxo: &UtxoSet) -> ChainView<'_> {
    ChainView {
        coins: utxo,
        chain_id: CHAIN,
        next_height: 11,
        coinbase_maturity: 100,
    }
}

/// Spends `coins` (all owned by `key`), paying `value - fee` to `to`.
fn spend(key: &KeyPair, coins: &[(OutPoint, Output)], fee: u64, to: WalletId) -> Transaction {
    let inputs = coins
        .iter()
        .map(|(previous_output, _)| Input {
            previous_output: *previous_output,
            witness_index: 0,
        })
        .collect();
    let value: u64 = coins
        .iter()
        .map(|(_, output)| output.amount.as_satoshis())
        .sum();
    let outputs = vec![Output {
        amount: sats(value - fee),
        wallet_id: to,
    }];
    let spent: Vec<Output> = coins.iter().map(|(_, output)| *output).collect();
    let unsigned = UnsignedTransaction::new(inputs, outputs).unwrap();
    let message = unsigned.sighash(&CHAIN, &spent).unwrap();
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

fn coin(set: &UtxoSet, outpoint: OutPoint) -> (OutPoint, Output) {
    (outpoint, set.get(&outpoint).unwrap().output)
}

fn first_output(transaction: &Transaction) -> (OutPoint, Output) {
    (
        OutPoint {
            txid: transaction.txid(),
            index: 0,
        },
        transaction.outputs()[0],
    )
}

const FEE: u64 = 10_000;

#[test]
fn accepts_a_valid_transaction_once() {
    let key = KeyPair::generate().unwrap();
    let set = utxo(&key, 1);
    let mut pool = Mempool::new(Policy::default());
    let tx = spend(
        &key,
        &[coin(&set, outpoint(1, 0))],
        FEE,
        key.public_key.wallet_id(),
    );
    let added = pool.add(tx.clone(), &view(&set), NOW).unwrap();
    assert_eq!(added.accepted, vec![tx.txid()]);
    assert_eq!(pool.get(&tx.txid()).unwrap().fee(), sats(FEE));
    assert_eq!(pool.total_bytes(), 5_345);
    assert_eq!(
        pool.add(tx, &view(&set), NOW),
        Err(MempoolError::AlreadyKnown)
    );

    let coinbase = Transaction::Coinbase(
        CoinbaseTransaction::new(
            1,
            vec![Output {
                amount: sats(1),
                wallet_id: key.public_key.wallet_id(),
            }],
        )
        .unwrap(),
    );
    assert_eq!(
        pool.add(coinbase, &view(&set), NOW),
        Err(MempoolError::Coinbase)
    );
}

#[test]
fn enforces_the_minimum_fee_and_validity() {
    let key = KeyPair::generate().unwrap();
    let other = KeyPair::generate().unwrap();
    let set = utxo(&key, 2);
    let mut pool = Mempool::new(Policy::default());
    let cheap = spend(
        &key,
        &[coin(&set, outpoint(1, 0))],
        100,
        key.public_key.wallet_id(),
    );
    assert!(matches!(
        pool.add(cheap, &view(&set), NOW),
        Err(MempoolError::FeeTooLow {
            required: 5_345,
            actual: 100
        })
    ));
    // Signed by a key that does not own the coin.
    let stolen = spend(
        &other,
        &[coin(&set, outpoint(2, 0))],
        FEE,
        other.public_key.wallet_id(),
    );
    assert!(matches!(
        pool.add(stolen, &view(&set), NOW),
        Err(MempoolError::Invalid(TransactionError::WrongKey {
            input: 0
        }))
    ));
    let immature = spend(
        &key,
        &[coin(&set, outpoint(0xcb, 0))],
        FEE,
        key.public_key.wallet_id(),
    );
    assert_eq!(
        pool.add(immature, &view(&set), NOW),
        Err(MempoolError::ImmatureCoinbase)
    );
    assert!(pool.is_empty());
}

#[test]
fn unconfirmed_chains_and_orphans() {
    let key = KeyPair::generate().unwrap();
    let owner = key.public_key.wallet_id();
    let set = utxo(&key, 1);
    let parent = spend(&key, &[coin(&set, outpoint(1, 0))], FEE, owner);
    let child = spend(&key, &[first_output(&parent)], FEE, owner);
    let grandchild = spend(&key, &[first_output(&child)], FEE, owner);

    let mut pool = Mempool::new(Policy::default());
    // Children first: they wait as orphans.
    assert!(
        pool.add(grandchild.clone(), &view(&set), NOW)
            .unwrap()
            .orphaned
    );
    assert!(pool.add(child.clone(), &view(&set), NOW).unwrap().orphaned);
    assert_eq!(pool.orphan_count(), 2);
    let added = pool.add(parent.clone(), &view(&set), NOW).unwrap();
    assert_eq!(
        added.accepted,
        vec![parent.txid(), child.txid(), grandchild.txid()]
    );
    assert_eq!(pool.orphan_count(), 0);

    // A block template always lists parents first.
    let selected: Vec<TransactionId> = pool
        .select(usize::MAX, usize::MAX)
        .iter()
        .map(|tx| tx.unsigned().txid())
        .collect();
    assert_eq!(
        selected,
        vec![parent.txid(), child.txid(), grandchild.txid()]
    );
}

#[test]
fn replacement_requires_a_higher_fee_and_evicts_descendants() {
    let key = KeyPair::generate().unwrap();
    let owner = key.public_key.wallet_id();
    let set = utxo(&key, 1);
    let mut pool = Mempool::new(Policy::default());
    let original = spend(&key, &[coin(&set, outpoint(1, 0))], FEE, owner);
    let child = spend(&key, &[first_output(&original)], FEE, owner);
    pool.add(original.clone(), &view(&set), NOW).unwrap();
    pool.add(child.clone(), &view(&set), NOW).unwrap();

    let stranger = WalletId::new(Hash256::new([7; 32]));
    let same_fee = spend(&key, &[coin(&set, outpoint(1, 0))], FEE, stranger);
    assert_eq!(
        pool.add(same_fee, &view(&set), NOW),
        Err(MempoolError::Replacement("fee rate is not higher"))
    );
    // Higher rate, but not enough to pay for both evicted transactions.
    let not_enough = spend(&key, &[coin(&set, outpoint(1, 0))], FEE + 1_000, stranger);
    assert_eq!(
        pool.add(not_enough, &view(&set), NOW),
        Err(MempoolError::Replacement("absolute fee is not high enough"))
    );
    let replacement = spend(&key, &[coin(&set, outpoint(1, 0))], 3 * FEE, stranger);
    let added = pool.add(replacement.clone(), &view(&set), NOW).unwrap();
    let mut replaced = added.replaced.clone();
    replaced.sort();
    let mut expected = vec![original.txid(), child.txid()];
    expected.sort();
    assert_eq!(replaced, expected);
    assert_eq!(pool.len(), 1);
    assert!(pool.get(&replacement.txid()).is_some());
}

#[test]
fn ancestor_limit_is_enforced() {
    let key = KeyPair::generate().unwrap();
    let owner = key.public_key.wallet_id();
    let set = utxo(&key, 1);
    let mut pool = Mempool::new(Policy {
        max_ancestors: 3,
        ..Policy::default()
    });
    let mut previous = coin(&set, outpoint(1, 0));
    for _ in 0..3 {
        let tx = spend(&key, &[previous], FEE, owner);
        pool.add(tx.clone(), &view(&set), NOW).unwrap();
        previous = first_output(&tx);
    }
    let fourth = spend(&key, &[previous], FEE, owner);
    assert_eq!(
        pool.add(fourth, &view(&set), NOW),
        Err(MempoolError::TooManyAncestors)
    );
}

#[test]
fn a_full_pool_evicts_the_lowest_fee_rate() {
    let key = KeyPair::generate().unwrap();
    let owner = key.public_key.wallet_id();
    let set = utxo(&key, 3);
    let mut pool = Mempool::new(Policy {
        max_bytes: 2 * 5_345,
        ..Policy::default()
    });
    let low = spend(&key, &[coin(&set, outpoint(1, 0))], FEE, owner);
    let high = spend(&key, &[coin(&set, outpoint(2, 0))], 4 * FEE, owner);
    pool.add(low.clone(), &view(&set), NOW).unwrap();
    pool.add(high.clone(), &view(&set), NOW).unwrap();
    let middle = spend(&key, &[coin(&set, outpoint(3, 0))], 2 * FEE, owner);
    pool.add(middle.clone(), &view(&set), NOW).unwrap();
    assert!(pool.get(&low.txid()).is_none());
    assert_eq!(pool.len(), 2);

    // Too cheap to stay: refused rather than evicting better transactions.
    let mut full = pool.clone();
    let key2 = key;
    let set2 = utxo(&key2, 4);
    let cheapest = spend(&key2, &[coin(&set2, outpoint(4, 0))], 6_000, owner);
    assert_eq!(
        full.add(cheapest, &view(&set2), NOW),
        Err(MempoolError::MempoolFull)
    );
}

#[test]
fn expiry_removes_old_transactions() {
    let key = KeyPair::generate().unwrap();
    let set = utxo(&key, 1);
    let mut pool = Mempool::new(Policy::default());
    let tx = spend(
        &key,
        &[coin(&set, outpoint(1, 0))],
        FEE,
        key.public_key.wallet_id(),
    );
    pool.add(tx.clone(), &view(&set), NOW).unwrap();
    assert!(pool.expire(NOW + 14 * 24 * 3600 - 1).is_empty());
    assert_eq!(pool.expire(NOW + 14 * 24 * 3600), vec![tx.txid()]);
    assert!(pool.is_empty());
}

#[test]
fn a_block_confirms_some_transactions_and_invalidates_conflicts() {
    let key = KeyPair::generate().unwrap();
    let owner = key.public_key.wallet_id();
    let set = utxo(&key, 2);
    let mut pool = Mempool::new(Policy::default());
    let confirmed = spend(&key, &[coin(&set, outpoint(1, 0))], FEE, owner);
    let child = spend(&key, &[first_output(&confirmed)], FEE, owner);
    let doomed = spend(&key, &[coin(&set, outpoint(2, 0))], FEE, owner);
    for tx in [&confirmed, &child, &doomed] {
        pool.add(tx.clone(), &view(&set), NOW).unwrap();
    }

    // A block confirms `confirmed` and a double spend of `doomed`'s input.
    let double_spend = spend(&key, &[coin(&set, outpoint(2, 0))], 2 * FEE, owner);
    let block_transactions = vec![
        Transaction::Coinbase(
            CoinbaseTransaction::new(
                11,
                vec![Output {
                    amount: sats(1),
                    wallet_id: owner,
                }],
            )
            .unwrap(),
        ),
        confirmed.clone(),
        double_spend.clone(),
    ];
    let (tx_root, witness_root) = Block::roots(&block_transactions).unwrap();
    let block = Block::new(
        BlockHeader {
            prev_block: set.tip().unwrap().block_id,
            tx_root,
            witness_root,
            timestamp: 0,
            target: Hash256::new([0xff; 32]),
            nonce: 0,
        },
        block_transactions,
    )
    .unwrap();
    let mut after = set.clone();
    after
        .apply_block(
            &block,
            &itacoin_blockchain::BlockRules {
                chain_id: CHAIN,
                coinbase_maturity: 100,
                subsidy: sats(1),
            },
        )
        .unwrap();

    pool.remove_confirmed(&block);
    let next = ChainView {
        next_height: 12,
        ..view(&after)
    };
    pool.resync(&next, NOW);
    assert!(pool.get(&confirmed.txid()).is_none());
    assert!(pool.get(&doomed.txid()).is_none());
    // The child now spends a confirmed output and stays.
    assert!(pool.get(&child.txid()).is_some());
    assert_eq!(pool.len(), 1);
}
