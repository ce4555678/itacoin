use itacoin_crypto::{KeyPair, SigningDomain};
use itacoin_primitives::{COIN, WalletId};
use itacoin_transaction::{CoinbaseTransaction, Input, UnsignedTransaction, Witness};

use super::*;
use crate::BlockHeader;

const CHAIN: Hash256 = Hash256::new([0xc4; 32]);

fn sats(value: u64) -> Amount {
    Amount::from_satoshis(value).unwrap()
}

fn rules(subsidy: u64, coinbase_maturity: u64) -> BlockRules {
    BlockRules {
        chain_id: CHAIN,
        coinbase_maturity,
        subsidy: sats(subsidy),
    }
}

fn pay(value: u64, wallet_id: WalletId) -> Output {
    Output {
        amount: sats(value),
        wallet_id,
    }
}

fn stranger() -> WalletId {
    WalletId::new(Hash256::new([0x5a; 32]))
}

fn outpoint(transaction: &Transaction, index: u16) -> OutPoint {
    OutPoint {
        txid: transaction.txid(),
        index,
    }
}

/// Builds a valid block on top of `set` (or of `parent`, when given).
fn block_on(set: &UtxoSet, coinbase: Vec<Output>, transactions: Vec<Transaction>) -> Block {
    let (prev_block, height) = match set.tip() {
        Some(tip) => (tip.block_id, tip.height + 1),
        None => (BlockId::new(Hash256::new([0; 32])), 0),
    };
    let mut all = vec![Transaction::Coinbase(
        CoinbaseTransaction::new(height, coinbase).unwrap(),
    )];
    all.extend(transactions);
    let (tx_root, witness_root) = Block::roots(&all).unwrap();
    let header = BlockHeader {
        prev_block,
        tx_root,
        witness_root,
        timestamp: 1_800_000_000 + height,
        target: Hash256::new([0xff; 32]),
        nonce: 0,
    };
    Block::new(header, all).unwrap()
}

/// Signs a transaction spending `coins`, all owned by `key`.
fn spend(key: &KeyPair, coins: &[(OutPoint, Output)], outputs: Vec<Output>) -> Transaction {
    let inputs = coins
        .iter()
        .map(|(previous_output, _)| Input {
            previous_output: *previous_output,
            witness_index: 0,
        })
        .collect();
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

/// A set with a genesis block paying 50 ITC to `key`.
fn genesis(key: &KeyPair) -> (UtxoSet, Block, (OutPoint, Output)) {
    let mut set = UtxoSet::new();
    let reward = pay(50 * COIN, key.public_key.wallet_id());
    let block = block_on(&set, vec![reward], vec![]);
    set.apply_block(&block, &rules(50 * COIN, 0)).unwrap();
    let coin = (outpoint(&block.transactions()[0], 0), reward);
    (set, block, coin)
}

#[test]
fn genesis_creates_the_first_coins() {
    let key = KeyPair::generate().unwrap();
    let (set, block, (outpoint, output)) = genesis(&key);
    assert_eq!(set.len(), 1);
    assert_eq!(set.total_value(), sats(50 * COIN));
    assert_eq!(
        set.tip(),
        Some(Tip {
            block_id: block.id(),
            height: 0
        })
    );
    assert_eq!(
        set.get(&outpoint),
        Some(&Coin {
            output,
            height: 0,
            is_coinbase: true
        })
    );
    set.audit().unwrap();
}

#[test]
fn spending_moves_value_and_pays_the_fee_to_the_coinbase() {
    let key = KeyPair::generate().unwrap();
    let owner = key.public_key.wallet_id();
    let (mut set, _, coin) = genesis(&key);

    let payment = spend(
        &key,
        &[coin],
        vec![pay(30 * COIN, stranger()), pay(19 * COIN, owner)],
    );
    // Subsidy 50 plus the 1 ITC fee.
    let block = block_on(&set, vec![pay(51 * COIN, owner)], vec![payment.clone()]);
    let undo = set.apply_block(&block, &rules(50 * COIN, 0)).unwrap();

    assert_eq!(set.get(&coin.0), None);
    assert_eq!(set.len(), 3);
    assert_eq!(set.total_value(), sats(100 * COIN));
    assert_eq!(
        set.get(&outpoint(&payment, 0)).unwrap().output.amount,
        sats(30 * COIN)
    );
    assert_eq!(undo.spent().len(), 1);
    set.audit().unwrap();
}

#[test]
fn failed_blocks_leave_the_set_unchanged() {
    let key = KeyPair::generate().unwrap();
    let owner = key.public_key.wallet_id();
    let (mut set, _, coin) = genesis(&key);
    let before = set.clone();
    let payment = spend(&key, &[coin], vec![pay(49 * COIN, stranger())]);

    // Claims one satoshi more than subsidy plus fees.
    let greedy = block_on(&set, vec![pay(51 * COIN + 1, owner)], vec![payment.clone()]);
    assert_eq!(
        set.apply_block(&greedy, &rules(50 * COIN, 0)),
        Err(UtxoError::CoinbaseTooLarge {
            allowed: sats(51 * COIN),
            claimed: sats(51 * COIN + 1)
        })
    );
    assert_eq!(set, before);

    // Signed for another chain.
    let fine = block_on(&set, vec![pay(COIN, owner)], vec![payment]);
    let other_chain = BlockRules {
        chain_id: Hash256::new([1; 32]),
        ..rules(50 * COIN, 0)
    };
    assert!(matches!(
        set.apply_block(&fine, &other_chain),
        Err(UtxoError::Transaction { transaction: 1, .. })
    ));
    assert_eq!(set, before);
}

#[test]
fn a_coin_cannot_be_spent_twice() {
    let key = KeyPair::generate().unwrap();
    let owner = key.public_key.wallet_id();
    let (mut set, _, coin) = genesis(&key);
    let first = spend(&key, &[coin], vec![pay(50 * COIN, stranger())]);
    let block = block_on(&set, vec![pay(COIN, owner)], vec![first]);
    set.apply_block(&block, &rules(COIN, 0)).unwrap();

    let again = spend(&key, &[coin], vec![pay(50 * COIN, owner)]);
    let block = block_on(&set, vec![pay(COIN, owner)], vec![again]);
    assert_eq!(
        set.apply_block(&block, &rules(COIN, 0)),
        Err(UtxoError::MissingCoin {
            transaction: 1,
            input: 0
        })
    );
}

#[test]
fn coinbase_outputs_must_mature() {
    let key = KeyPair::generate().unwrap();
    let owner = key.public_key.wallet_id();
    let (mut set, _, coin) = genesis(&key);
    let payment = spend(&key, &[coin], vec![pay(50 * COIN, stranger())]);

    let early = block_on(&set, vec![pay(COIN, owner)], vec![payment.clone()]);
    assert_eq!(
        set.apply_block(&early, &rules(COIN, 2)),
        Err(UtxoError::ImmatureCoinbase {
            transaction: 1,
            input: 0
        })
    );
    let empty = block_on(&set, vec![pay(COIN, owner)], vec![]);
    set.apply_block(&empty, &rules(COIN, 2)).unwrap();
    let mature = block_on(&set, vec![pay(COIN, owner)], vec![payment]);
    set.apply_block(&mature, &rules(COIN, 2)).unwrap();
}

#[test]
fn blocks_must_extend_the_tip() {
    let key = KeyPair::generate().unwrap();
    let owner = key.public_key.wallet_id();
    let (mut set, genesis_block, _) = genesis(&key);
    let next = block_on(&set, vec![pay(COIN, owner)], vec![]);

    // Same block again: wrong parent.
    assert_eq!(
        set.apply_block(&genesis_block, &rules(50 * COIN, 0)),
        Err(UtxoError::WrongParent {
            expected: genesis_block.id(),
            actual: genesis_block.header().prev_block
        })
    );

    // Right parent, wrong height.
    let transactions = vec![Transaction::Coinbase(
        CoinbaseTransaction::new(5, vec![pay(COIN, owner)]).unwrap(),
    )];
    let (tx_root, witness_root) = Block::roots(&transactions).unwrap();
    let skipping = Block::new(
        BlockHeader {
            tx_root,
            witness_root,
            ..*next.header()
        },
        transactions,
    )
    .unwrap();
    assert_eq!(
        set.apply_block(&skipping, &rules(COIN, 0)),
        Err(UtxoError::WrongHeight {
            expected: 1,
            actual: 5
        })
    );
    set.apply_block(&next, &rules(COIN, 0)).unwrap();
}

#[test]
fn outputs_can_be_spent_later_in_the_same_block_and_reverted() {
    let key = KeyPair::generate().unwrap();
    let owner = key.public_key.wallet_id();
    let (mut set, _, coin) = genesis(&key);
    let after_genesis = set.clone();

    let first = spend(&key, &[coin], vec![pay(50 * COIN, owner)]);
    let middle = (outpoint(&first, 0), pay(50 * COIN, owner));
    let second = spend(&key, &[middle], vec![pay(49 * COIN, stranger())]);
    let block = block_on(&set, vec![pay(COIN, owner)], vec![first, second.clone()]);
    let undo = set.apply_block(&block, &rules(0, 0)).unwrap();

    // The intermediate output never reaches the set or the undo data.
    assert_eq!(set.get(&middle.0), None);
    assert_eq!(
        undo.spent(),
        &[(coin.0, *after_genesis.get(&coin.0).unwrap())]
    );
    assert!(set.get(&outpoint(&second, 0)).is_some());
    assert_eq!(set.total_value(), sats(50 * COIN));

    set.revert_block(&block, &undo).unwrap();
    assert_eq!(set, after_genesis);
}

#[test]
fn only_the_tip_can_be_reverted() {
    let key = KeyPair::generate().unwrap();
    let owner = key.public_key.wallet_id();
    let (mut set, genesis_block, _) = genesis(&key);
    let first = block_on(&set, vec![pay(COIN, owner)], vec![]);
    let first_undo = set.apply_block(&first, &rules(COIN, 0)).unwrap();
    let second = block_on(&set, vec![pay(COIN, owner)], vec![]);
    let second_undo = set.apply_block(&second, &rules(COIN, 0)).unwrap();

    assert_eq!(
        set.revert_block(&first, &first_undo),
        Err(UtxoError::NotTip(first.id()))
    );
    assert_eq!(
        set.revert_block(&second, &first_undo),
        Err(UtxoError::NotTip(second.id()))
    );
    set.revert_block(&second, &second_undo).unwrap();
    set.revert_block(&first, &first_undo).unwrap();
    assert_eq!(set.tip().unwrap().block_id, genesis_block.id());
}

#[test]
fn unclaimed_fees_and_subsidy_are_burned() {
    let key = KeyPair::generate().unwrap();
    let owner = key.public_key.wallet_id();
    let (mut set, _, coin) = genesis(&key);
    let payment = spend(&key, &[coin], vec![pay(40 * COIN, owner)]);
    // Fee 10, subsidy 50, coinbase claims only 1.
    let block = block_on(&set, vec![pay(COIN, owner)], vec![payment]);
    set.apply_block(&block, &rules(50 * COIN, 0)).unwrap();
    assert_eq!(set.total_value(), sats(41 * COIN));
    set.audit().unwrap();
}

/// Deterministic xorshift64 generator.
struct Rng(u64);

impl Rng {
    fn below(&mut self, bound: u64) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0 % bound
    }
}

#[test]
fn random_chains_apply_and_revert_exactly() {
    let key = KeyPair::generate().unwrap();
    let owner = key.public_key.wallet_id();
    let rules = rules(50 * COIN, 0);
    let mut rng = Rng(0x0dd_c0ff_ee15_600d);
    let mut set = UtxoSet::new();
    let mut history = Vec::new();

    for _ in 0..30 {
        let mut available: Vec<(OutPoint, Output)> = set
            .coins
            .iter()
            .map(|(outpoint, coin)| (*outpoint, coin.output))
            .collect();
        available.sort_by_key(|(outpoint, _)| *outpoint);

        let mut transactions = Vec::new();
        let mut fees = 0;
        for _ in 0..rng.below(4) {
            if available.is_empty() {
                break;
            }
            let count = 1 + rng.below(3.min(available.len() as u64)) as usize;
            let coins: Vec<_> = (0..count)
                .map(|_| available.swap_remove(rng.below(available.len() as u64) as usize))
                .collect();
            let value: u64 = coins
                .iter()
                .map(|(_, output)| output.amount.as_satoshis())
                .sum();
            let fee = rng.below(value);
            let first = 1 + rng.below(value - fee);
            let mut outputs = vec![pay(first, owner)];
            if value - fee - first > 0 {
                outputs.push(pay(value - fee - first, owner));
            }
            fees += fee;
            transactions.push(spend(&key, &coins, outputs));
        }
        let claim = 1 + rng.below(50 * COIN + fees);
        let block = block_on(&set, vec![pay(claim, owner)], transactions);
        let before = set.clone();
        let undo = set.apply_block(&block, &rules).unwrap();
        set.audit().unwrap();
        history.push((before, block, undo));
    }

    while let Some((before, block, undo)) = history.pop() {
        set.revert_block(&block, &undo).unwrap();
        set.audit().unwrap();
        assert_eq!(set, before);
    }
    assert_eq!(set, UtxoSet::new());
}
