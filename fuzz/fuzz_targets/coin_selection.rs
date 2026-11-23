//! Coin selection never panics, and every plan balances: inputs equal
//! outputs plus fee, the fee covers the rate, and keys are spent whole.
#![no_main]

use itacoin_primitives::{Amount, Hash256, TransactionId, WalletId};
use itacoin_transaction::{OutPoint, Output};
use itacoin_wallet::builder::{ChangeTo, Coin, Payment, plan_payment, transaction_size};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut chunks = data.chunks_exact(6);
    let Some(head) = chunks.next() else {
        return;
    };
    let fee_rate = u64::from(head[0]) + 1;
    let outputs: Vec<Output> = (0..1 + head[1] % 3)
        .map(|index| Output {
            amount: Amount::from_satoshis(1 + u64::from(u16::from_be_bytes([head[2], head[3]])) * 1_000 * u64::from(index + 1)).unwrap(),
            wallet_id: WalletId::new(Hash256::new([0xee; 32])),
        })
        .collect();
    let coins: Vec<Coin> = chunks
        .take(200)
        .enumerate()
        .map(|(index, chunk)| Coin {
            outpoint: OutPoint {
                txid: TransactionId::new(Hash256::new([chunk[0]; 32])),
                index: u16::try_from(index).unwrap(),
            },
            output: Output {
                amount: Amount::from_satoshis(1 + u64::from(u32::from_be_bytes([chunk[1], chunk[2], chunk[3], chunk[4]]))).unwrap(),
                wallet_id: WalletId::new(Hash256::new([chunk[5] % 24; 32])),
            },
        })
        .collect();
    let payment = Payment {
        coins: &coins,
        required: &[],
        outputs: &outputs,
        fee_rate,
        change: ChangeTo::Wallet(WalletId::new(Hash256::new([0xcc; 32]))),
    };
    if let Ok(plan) = plan_payment(&payment) {
        let inputs: u128 = plan.inputs.iter().map(|coin| u128::from(coin.output.amount.as_satoshis())).sum();
        let paid: u128 = plan.outputs.iter().map(|output| u128::from(output.amount.as_satoshis())).sum();
        assert_eq!(inputs, paid + u128::from(plan.fee.as_satoshis()));
        assert_eq!(plan.size, transaction_size(plan.inputs.len(), plan.outputs.len(), plan.keys.len()));
        assert!(u128::from(plan.fee.as_satoshis()) >= u128::from(fee_rate) * plan.size as u128);
        for coin in &coins {
            if plan.keys.contains(&coin.output.wallet_id) {
                assert!(plan.inputs.iter().any(|input| input.outpoint == coin.outpoint));
            }
        }
    }
});
