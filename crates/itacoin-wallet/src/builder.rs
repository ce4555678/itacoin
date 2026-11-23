//! Coin selection and transaction building (section 6 of
//! `docs/WALLET_PROPOSAL.md`). No I/O: coins come in, a signed transaction
//! comes out.
//!
//! The size of a transaction is exact before signing, because keys and
//! signatures have fixed sizes:
//!
//! ```text
//! bytes = 7 + 36 × inputs + 41 × outputs + 5 261 × distinct keys
//! ```
//!
//! Each distinct key costs a 5 261-byte witness while each extra input of
//! the same key costs 36 bytes, so coins are selected by whole key groups.

use core::fmt;
use std::collections::{BTreeMap, HashSet};

use itacoin_crypto::{KeyPair, SigningDomain};
use itacoin_primitives::{Amount, Hash256, WalletId};
use itacoin_transaction::{
    INPUT_BYTES, Input, MAX_TX_BYTES, MAX_TX_INPUTS, MAX_TX_OUTPUTS, OUTPUT_BYTES, OutPoint,
    Output, Transaction, TransactionError, UnsignedTransaction, WITNESS_BYTES, Witness,
};
use rand_core::{OsRng, RngCore};

/// Bytes of a normal transaction besides its inputs, outputs and witnesses.
pub const TX_OVERHEAD_BYTES: usize = 7;
/// Most distinct keys that fit in one transaction of [`MAX_TX_BYTES`].
pub const MAX_KEYS_PER_TX: usize = 18;

/// Encoded size of a normal transaction.
#[must_use]
pub const fn transaction_size(inputs: usize, outputs: usize, keys: usize) -> usize {
    TX_OVERHEAD_BYTES + INPUT_BYTES * inputs + OUTPUT_BYTES * outputs + WITNESS_BYTES * keys
}

/// Change smaller than this, at `fee_rate`, costs more to spend later (one
/// input and a new witness) than it is worth, so it goes to the fee.
#[must_use]
pub const fn dust_threshold(fee_rate: u64) -> u128 {
    fee_rate as u128 * (WITNESS_BYTES + INPUT_BYTES) as u128
}

/// A spendable output.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Coin {
    /// Where it is.
    pub outpoint: OutPoint,
    /// What it holds and who owns it.
    pub output: Output,
}

/// Where change goes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChangeTo {
    /// A given wallet id, normally a fresh change address.
    Wallet(WalletId),
    /// Back to the key of the largest selected group, saving a future
    /// witness at the cost of privacy.
    LargestInput,
}

/// A payment to build.
#[derive(Clone, Copy, Debug)]
pub struct Payment<'a> {
    /// Coins that may be spent.
    pub coins: &'a [Coin],
    /// Coins that must be spent, such as those of a transaction being
    /// replaced. Each must be in `coins`.
    pub required: &'a [OutPoint],
    /// Outputs to pay.
    pub outputs: &'a [Output],
    /// Satoshis per byte.
    pub fee_rate: u64,
    /// Where change goes.
    pub change: ChangeTo,
}

/// A transaction ready to sign.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Plan {
    /// Inputs, grouped by key in witness order.
    pub inputs: Vec<Coin>,
    /// The keys that sign, in witness order.
    pub keys: Vec<WalletId>,
    /// Outputs, with the change at a random position.
    pub outputs: Vec<Output>,
    /// Position of the change in `outputs`.
    pub change_index: Option<usize>,
    /// The fee.
    pub fee: Amount,
    /// The exact encoded size.
    pub size: usize,
}

/// Why a transaction could not be built.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BuildError {
    /// Nothing to pay.
    NoOutputs,
    /// Not enough coins.
    Insufficient {
        /// Satoshis needed, fee included.
        needed: u128,
        /// Satoshis available.
        available: u128,
    },
    /// The payment needs more than [`MAX_KEYS_PER_TX`] keys; consolidate
    /// first.
    TooManyKeys,
    /// The transaction would exceed a size or count limit.
    TooLarge,
    /// A required coin is not among the spendable coins.
    MissingRequired(OutPoint),
    /// A signing key is missing.
    MissingKey(WalletId),
    /// An amount is out of range.
    Amount,
    /// The transaction is invalid.
    Transaction(TransactionError),
    /// Signing failed.
    Signing,
}

impl fmt::Display for BuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoOutputs => formatter.write_str("nothing to pay"),
            Self::Insufficient { needed, available } => write!(
                formatter,
                "insufficient funds: {needed} satoshis needed, {available} available"
            ),
            Self::TooManyKeys => write!(
                formatter,
                "the payment needs more than {MAX_KEYS_PER_TX} keys; run consolidate first"
            ),
            Self::TooLarge => formatter.write_str("the transaction would be too large"),
            Self::MissingRequired(outpoint) => write!(
                formatter,
                "coin {}:{} is no longer spendable",
                outpoint.txid, outpoint.index
            ),
            Self::MissingKey(wallet_id) => write!(formatter, "no key for {wallet_id}"),
            Self::Amount => formatter.write_str("amount out of range"),
            Self::Transaction(error) => write!(formatter, "invalid transaction: {error}"),
            Self::Signing => formatter.write_str("signing failed"),
        }
    }
}

impl std::error::Error for BuildError {}

#[derive(Clone, Debug)]
struct Group {
    wallet_id: WalletId,
    coins: Vec<Coin>,
    value: u128,
}

fn groups(coins: &[Coin]) -> Vec<Group> {
    let mut by_key: BTreeMap<WalletId, Vec<Coin>> = BTreeMap::new();
    let mut seen = HashSet::new();
    for coin in coins {
        if seen.insert(coin.outpoint) {
            by_key.entry(coin.output.wallet_id).or_default().push(*coin);
        }
    }
    by_key
        .into_iter()
        .map(|(wallet_id, mut coins)| {
            coins.sort_by_key(|coin| coin.outpoint);
            let value = coins
                .iter()
                .map(|coin| u128::from(coin.output.amount.as_satoshis()))
                .sum();
            Group {
                wallet_id,
                coins,
                value,
            }
        })
        .collect()
}

struct Totals {
    value: u128,
    inputs: usize,
    keys: usize,
}

fn totals(selected: &[&Group]) -> Totals {
    Totals {
        value: selected.iter().map(|group| group.value).sum(),
        inputs: selected.iter().map(|group| group.coins.len()).sum(),
        keys: selected.len(),
    }
}

fn fee(rate: u64, size: usize) -> u128 {
    u128::from(rate) * size as u128
}

fn amount(value: u128) -> Result<Amount, BuildError> {
    u64::try_from(value)
        .ok()
        .and_then(|value| Amount::from_satoshis(value).ok())
        .ok_or(BuildError::Amount)
}

/// Plans a payment: whole key groups, the smallest single group that covers
/// it if one exists, otherwise the largest groups first.
pub fn plan_payment(payment: &Payment<'_>) -> Result<Plan, BuildError> {
    if payment.outputs.is_empty() {
        return Err(BuildError::NoOutputs);
    }
    let outputs = payment.outputs.len();
    let target: u128 = payment
        .outputs
        .iter()
        .map(|output| u128::from(output.amount.as_satoshis()))
        .sum();
    let all = groups(payment.coins);
    let available: u128 = all.iter().map(|group| group.value).sum();
    let needed_with = |selected: &[&Group]| {
        let totals = totals(selected);
        target
            + fee(
                payment.fee_rate,
                transaction_size(totals.inputs, outputs, totals.keys),
            )
    };
    let covers = |selected: &[&Group]| totals(selected).value >= needed_with(selected);

    // Groups that must be spent come first.
    let mut selected: Vec<&Group> = Vec::new();
    for outpoint in payment.required {
        let group = all
            .iter()
            .find(|group| group.coins.iter().any(|coin| coin.outpoint == *outpoint))
            .ok_or(BuildError::MissingRequired(*outpoint))?;
        if !selected
            .iter()
            .any(|chosen| chosen.wallet_id == group.wallet_id)
        {
            selected.push(group);
        }
    }
    let mut rest: Vec<&Group> = all
        .iter()
        .filter(|group| {
            !selected
                .iter()
                .any(|chosen| chosen.wallet_id == group.wallet_id)
        })
        .collect();

    if !covers(&selected) {
        // The smallest single group that completes the payment.
        let single = rest
            .iter()
            .filter(|group| {
                let mut trial = selected.clone();
                trial.push(group);
                covers(&trial)
            })
            .min_by_key(|group| (group.value, group.wallet_id))
            .copied();
        if let Some(group) = single {
            selected.push(group);
        } else {
            rest.sort_by(|a, b| b.value.cmp(&a.value).then(a.wallet_id.cmp(&b.wallet_id)));
            for group in rest {
                selected.push(group);
                if covers(&selected) {
                    break;
                }
            }
        }
    }
    if !covers(&selected) {
        return Err(BuildError::Insufficient {
            needed: needed_with(&selected).max(target),
            available,
        });
    }
    if selected.len() > MAX_KEYS_PER_TX {
        return Err(BuildError::TooManyKeys);
    }

    let totals = totals(&selected);
    let size_without = transaction_size(totals.inputs, outputs, totals.keys);
    let size_with = transaction_size(totals.inputs, outputs + 1, totals.keys);
    let excess = totals
        .value
        .checked_sub(target + fee(payment.fee_rate, size_with));
    let change_value =
        excess.filter(|excess| *excess > 0 && *excess >= dust_threshold(payment.fee_rate));
    let (size, fee_value, change) = match change_value {
        Some(value) => {
            let wallet_id = match payment.change {
                ChangeTo::Wallet(wallet_id) => wallet_id,
                ChangeTo::LargestInput => selected
                    .iter()
                    .max_by_key(|group| (group.value, group.wallet_id))
                    .map(|group| group.wallet_id)
                    .ok_or(BuildError::NoOutputs)?,
            };
            (
                size_with,
                fee(payment.fee_rate, size_with),
                Some(Output {
                    amount: amount(value)?,
                    wallet_id,
                }),
            )
        }
        None => (size_without, totals.value - target, None),
    };
    finish(&selected, payment.outputs.to_vec(), change, fee_value, size)
}

/// Plans a transaction that spends every coin of the given groups to one
/// `destination`, for consolidation.
pub fn plan_sweep(
    coins: &[Coin],
    destination: WalletId,
    fee_rate: u64,
) -> Result<Plan, BuildError> {
    let all = groups(coins);
    if all.is_empty() {
        return Err(BuildError::NoOutputs);
    }
    if all.len() > MAX_KEYS_PER_TX {
        return Err(BuildError::TooManyKeys);
    }
    let selected: Vec<&Group> = all.iter().collect();
    let totals = totals(&selected);
    let size = transaction_size(totals.inputs, 1, totals.keys);
    let fee_value = fee(fee_rate, size);
    let value = totals
        .value
        .checked_sub(fee_value)
        .filter(|value| *value > 0)
        .ok_or(BuildError::Insufficient {
            needed: fee_value + 1,
            available: totals.value,
        })?;
    let output = Output {
        amount: amount(value)?,
        wallet_id: destination,
    };
    let mut plan = finish(&selected, vec![output], None, fee_value, size)?;
    plan.change_index = Some(0);
    Ok(plan)
}

fn finish(
    selected: &[&Group],
    mut outputs: Vec<Output>,
    change: Option<Output>,
    fee_value: u128,
    size: usize,
) -> Result<Plan, BuildError> {
    let inputs: Vec<Coin> = selected
        .iter()
        .flat_map(|group| group.coins.iter().copied())
        .collect();
    let change_index = change.map(|change| {
        let position = (OsRng.next_u64() % (outputs.len() as u64 + 1)) as usize;
        outputs.insert(position, change);
        position
    });
    if inputs.len() > MAX_TX_INPUTS || outputs.len() > MAX_TX_OUTPUTS || size > MAX_TX_BYTES {
        return Err(BuildError::TooLarge);
    }
    Ok(Plan {
        inputs,
        keys: selected.iter().map(|group| group.wallet_id).collect(),
        outputs,
        change_index,
        fee: amount(fee_value)?,
        size,
    })
}

impl Plan {
    /// The outputs being spent, in input order.
    #[must_use]
    pub fn spent(&self) -> Vec<Output> {
        self.inputs.iter().map(|coin| coin.output).collect()
    }

    /// The unsigned transaction.
    pub fn unsigned(&self) -> Result<UnsignedTransaction, BuildError> {
        let inputs = self
            .inputs
            .iter()
            .map(|coin| {
                let index = self
                    .keys
                    .iter()
                    .position(|key| *key == coin.output.wallet_id)
                    .ok_or(BuildError::MissingKey(coin.output.wallet_id))?;
                Ok(Input {
                    previous_output: coin.outpoint,
                    witness_index: u16::try_from(index).map_err(|_| BuildError::TooLarge)?,
                })
            })
            .collect::<Result<Vec<_>, BuildError>>()?;
        UnsignedTransaction::new(inputs, self.outputs.clone()).map_err(BuildError::Transaction)
    }

    /// Signs with one key per entry of `keys`, found by `key_for`, and checks
    /// the result with the consensus rules before returning it.
    pub fn sign<'k>(
        &self,
        chain_id: &Hash256,
        mut key_for: impl FnMut(&WalletId) -> Option<&'k KeyPair>,
    ) -> Result<Transaction, BuildError> {
        let unsigned = self.unsigned()?;
        let spent = self.spent();
        let message = unsigned
            .sighash(chain_id, &spent)
            .map_err(BuildError::Transaction)?;
        let mut witnesses = Vec::with_capacity(self.keys.len());
        for wallet_id in &self.keys {
            let key = key_for(wallet_id).ok_or(BuildError::MissingKey(*wallet_id))?;
            if key.public_key.wallet_id() != *wallet_id {
                return Err(BuildError::MissingKey(*wallet_id));
            }
            let signature = key
                .private_key
                .sign(SigningDomain::Transaction, message.as_bytes())
                .map_err(|_| BuildError::Signing)?;
            witnesses.push(Witness {
                public_key: key.public_key.clone(),
                signature,
            });
        }
        let signed = unsigned
            .with_witnesses(witnesses)
            .map_err(BuildError::Transaction)?;
        signed
            .validate_spend(chain_id, &spent)
            .map_err(BuildError::Transaction)?;
        Ok(Transaction::Normal(signed))
    }
}

#[cfg(test)]
mod tests;
