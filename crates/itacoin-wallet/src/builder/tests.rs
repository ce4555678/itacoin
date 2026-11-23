use std::collections::HashMap;

use itacoin_codec::Encode;
use itacoin_primitives::{Network, TransactionId};

use super::*;
use crate::{Branch, MasterSecret};

const RATE: u64 = 2;

fn chain_id() -> Hash256 {
    Hash256::new([0xc4; 32])
}

struct Keys {
    pairs: HashMap<WalletId, KeyPair>,
    order: Vec<WalletId>,
}

impl Keys {
    fn new(count: u32) -> Self {
        let master = MasterSecret::from_bytes([3; 32]);
        let mut pairs = HashMap::new();
        let mut order = Vec::new();
        for index in 0..count {
            let pair = master
                .derive(Network::Regtest, Branch::Receive, index)
                .unwrap();
            order.push(pair.public_key.wallet_id());
            pairs.insert(pair.public_key.wallet_id(), pair);
        }
        Self { pairs, order }
    }

    fn sign(&self, plan: &Plan) -> Transaction {
        plan.sign(&chain_id(), |wallet_id| self.pairs.get(wallet_id))
            .unwrap()
    }
}

fn coin(owner: WalletId, value: u64, tag: u8) -> Coin {
    Coin {
        outpoint: OutPoint {
            txid: TransactionId::new(Hash256::new([tag; 32])),
            index: u16::from(tag),
        },
        output: Output {
            amount: Amount::from_satoshis(value).unwrap(),
            wallet_id: owner,
        },
    }
}

fn pay(value: u64) -> Output {
    Output {
        amount: Amount::from_satoshis(value).unwrap(),
        wallet_id: WalletId::new(Hash256::new([0xee; 32])),
    }
}

fn change_wallet() -> WalletId {
    WalletId::new(Hash256::new([0xcc; 32]))
}

fn payment<'a>(coins: &'a [Coin], outputs: &'a [Output]) -> Payment<'a> {
    Payment {
        coins,
        required: &[],
        outputs,
        fee_rate: RATE,
        change: ChangeTo::Wallet(change_wallet()),
    }
}

fn balanced(plan: &Plan) {
    let inputs: u64 = plan
        .inputs
        .iter()
        .map(|coin| coin.output.amount.as_satoshis())
        .sum();
    let outputs: u64 = plan
        .outputs
        .iter()
        .map(|output| output.amount.as_satoshis())
        .sum();
    assert_eq!(inputs, outputs + plan.fee.as_satoshis());
}

#[test]
fn the_size_formula_is_exact() {
    let keys = Keys::new(3);
    let coins = vec![
        coin(keys.order[0], 400_000, 1),
        coin(keys.order[0], 400_000, 2),
        coin(keys.order[1], 400_000, 3),
        coin(keys.order[2], 400_000, 4),
    ];
    let outputs = [pay(1_500_000), pay(5_000)];
    let plan = plan_payment(&payment(&coins, &outputs)).unwrap();
    let signed = keys.sign(&plan);
    assert_eq!(signed.encoded_len(), plan.size);
    assert_eq!(plan.size, transaction_size(4, 3, 3));
    assert_eq!(plan.fee.as_satoshis(), RATE * plan.size as u64);
    // One input and two outputs: the figure quoted in the proposals.
    assert_eq!(transaction_size(1, 2, 1), 5_386);
    balanced(&plan);
}

#[test]
fn the_smallest_covering_group_is_spent_whole() {
    let keys = Keys::new(3);
    let coins = vec![
        coin(keys.order[0], 5_000_000, 1),
        coin(keys.order[1], 300_000, 2),
        coin(keys.order[1], 300_000, 3),
        coin(keys.order[2], 900_000, 4),
    ];
    let outputs = [pay(400_000)];
    let plan = plan_payment(&payment(&coins, &outputs)).unwrap();
    // Key 1 (600 000 in two coins) is the smallest group that covers.
    assert_eq!(plan.keys, vec![keys.order[1]]);
    assert_eq!(plan.inputs.len(), 2);
    let change = plan.outputs[plan.change_index.unwrap()];
    assert_eq!(change.wallet_id, change_wallet());
    balanced(&plan);
    keys.sign(&plan);
}

#[test]
fn large_groups_are_combined_when_no_single_group_covers() {
    let keys = Keys::new(4);
    let coins: Vec<Coin> = (0..4)
        .map(|index| coin(keys.order[index], 100_000 * (index as u64 + 1), index as u8))
        .collect();
    let outputs = [pay(650_000)];
    let plan = plan_payment(&payment(&coins, &outputs)).unwrap();
    // 400 000 alone is short; 400 000 + 300 000 covers 650 000 plus fees.
    assert_eq!(plan.keys, vec![keys.order[3], keys.order[2]]);
    balanced(&plan);
    keys.sign(&plan);
}

#[test]
fn dust_goes_to_the_fee() {
    let keys = Keys::new(1);
    let fee = u64::try_from(transaction_size(1, 1, 1)).unwrap() * RATE;
    let dust = u64::try_from(dust_threshold(RATE)).unwrap() - 1;
    let coins = [coin(keys.order[0], 100_000 + fee + dust, 1)];
    let outputs = [pay(100_000)];
    let plan = plan_payment(&payment(&coins, &outputs)).unwrap();
    assert_eq!(plan.change_index, None);
    assert_eq!(plan.outputs.len(), 1);
    assert_eq!(plan.fee.as_satoshis(), fee + dust);
    balanced(&plan);

    // Enough for change above the threshold.
    let coins = [coin(keys.order[0], 1_000_000, 1)];
    let plan = plan_payment(&payment(&coins, &outputs)).unwrap();
    assert!(plan.change_index.is_some());
    assert_eq!(
        plan.fee.as_satoshis(),
        RATE * transaction_size(1, 2, 1) as u64
    );
    balanced(&plan);
}

#[test]
fn limits_and_shortfalls_are_reported() {
    let keys = Keys::new(19);
    let coins: Vec<Coin> = keys
        .order
        .iter()
        .enumerate()
        .map(|(index, owner)| coin(*owner, 1_000_000, index as u8))
        .collect();
    // Eighteen keys hold 18 000 000; the nineteenth is needed.
    let outputs = [pay(18_500_000)];
    assert_eq!(
        plan_payment(&payment(&coins, &outputs)),
        Err(BuildError::TooManyKeys)
    );
    let outputs = [pay(30_000_000)];
    assert!(matches!(
        plan_payment(&payment(&coins, &outputs)),
        Err(BuildError::Insufficient {
            available: 19_000_000,
            ..
        })
    ));
    assert_eq!(
        plan_payment(&payment(&coins, &[])),
        Err(BuildError::NoOutputs)
    );
}

#[test]
fn required_coins_and_change_to_input() {
    let keys = Keys::new(2);
    let coins = vec![
        coin(keys.order[0], 3_000_000, 1),
        coin(keys.order[1], 200_000, 2),
    ];
    let outputs = [pay(100_000)];
    let required = [coins[1].outpoint];
    let mut request = payment(&coins, &outputs);
    request.required = &required;
    request.change = ChangeTo::LargestInput;
    let plan = plan_payment(&request).unwrap();
    assert_eq!(plan.keys[0], keys.order[1]);
    assert_eq!(
        plan.outputs[plan.change_index.unwrap()].wallet_id,
        keys.order[1]
    );
    keys.sign(&plan);

    let missing = [OutPoint {
        txid: TransactionId::new(Hash256::new([9; 32])),
        index: 0,
    }];
    request.required = &missing;
    assert_eq!(
        plan_payment(&request),
        Err(BuildError::MissingRequired(missing[0]))
    );
}

#[test]
fn sweeps_spend_everything_to_one_output() {
    let keys = Keys::new(3);
    let coins: Vec<Coin> = (0..6)
        .map(|index| coin(keys.order[index % 3], 50_000, index as u8))
        .collect();
    let plan = plan_sweep(&coins, change_wallet(), RATE).unwrap();
    assert_eq!(plan.outputs.len(), 1);
    assert_eq!(plan.keys.len(), 3);
    assert_eq!(plan.size, transaction_size(6, 1, 3));
    balanced(&plan);
    let signed = keys.sign(&plan);
    assert_eq!(signed.encoded_len(), plan.size);
    assert!(matches!(
        plan_sweep(&coins[..1], change_wallet(), 1_000),
        Err(BuildError::Insufficient { .. })
    ));
}

#[test]
fn signing_needs_every_key() {
    let keys = Keys::new(2);
    let coins = [coin(keys.order[0], 1_000_000, 1)];
    let outputs = [pay(10_000)];
    let plan = plan_payment(&payment(&coins, &outputs)).unwrap();
    let wrong = keys.pairs.get(&keys.order[1]).unwrap();
    assert_eq!(
        plan.sign(&chain_id(), |_| Some(wrong)),
        Err(BuildError::MissingKey(keys.order[0]))
    );
    assert_eq!(
        plan.sign(&chain_id(), |_| None),
        Err(BuildError::MissingKey(keys.order[0]))
    );
}

#[test]
fn random_wallets_always_balance() {
    let keys = Keys::new(6);
    let mut state = 0x9e37_79b9_7f4a_7c15_u64;
    let mut next = |bound: u64| {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state % bound
    };
    for round in 0..300 {
        let count = 1 + next(12) as usize;
        let coins: Vec<Coin> = (0..count)
            .map(|index| {
                let owner = keys.order[next(6) as usize];
                coin(owner, 1 + next(3_000_000), (round * 13 + index) as u8)
            })
            .collect();
        let outputs: Vec<Output> = (0..1 + next(3)).map(|_| pay(1 + next(2_000_000))).collect();
        let request = Payment {
            coins: &coins,
            required: &[],
            outputs: &outputs,
            fee_rate: 1 + next(20),
            change: ChangeTo::Wallet(change_wallet()),
        };
        match plan_payment(&request) {
            Ok(plan) => {
                balanced(&plan);
                assert!(plan.fee.as_satoshis() >= request.fee_rate * plan.size as u64);
                assert_eq!(
                    plan.size,
                    transaction_size(plan.inputs.len(), plan.outputs.len(), plan.keys.len())
                );
                // Whole groups: no coin of a selected key is left behind.
                for coin in &coins {
                    if plan.keys.contains(&coin.output.wallet_id) {
                        assert!(
                            plan.inputs
                                .iter()
                                .any(|input| input.outpoint == coin.outpoint)
                        );
                    }
                }
            }
            Err(BuildError::Insufficient { .. } | BuildError::TooManyKeys) => {}
            Err(other) => panic!("unexpected {other:?}"),
        }
    }
}
