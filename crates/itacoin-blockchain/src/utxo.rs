//! The unspent-output set and atomic block application.
//!
//! [`UtxoSet::apply_block`] validates a whole block against a staged view and
//! changes nothing unless every rule passes, so a failed block leaves the set
//! exactly as it was. It returns the [`BlockUndo`] needed to revert the block
//! during a reorganization. The set tracks the total value of all unspent
//! outputs, checked against [`MAX_SUPPLY`] after every applied and reverted
//! block (audit finding I-03).
//!
//! The emission schedule is not approved yet, so the subsidy is a parameter:
//! the coinbase may claim at most `subsidy + fees`.
//!
//! [`MAX_SUPPLY`]: itacoin_primitives::MAX_SUPPLY

use core::fmt;
use std::collections::{HashMap, HashSet};

use itacoin_primitives::{Amount, AmountError, BlockId, Hash256};
use itacoin_transaction::{OutPoint, Output, Transaction, TransactionError};

use crate::Block;

/// An unspent output and where it came from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Coin {
    /// The output itself.
    pub output: Output,
    /// Height of the block that created it.
    pub height: u64,
    /// Whether it was created by a coinbase.
    pub is_coinbase: bool,
}

/// Consensus parameters for applying one block.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockRules {
    /// The network's genesis block id, bound into every signature.
    pub chain_id: Hash256,
    /// Blocks a coinbase output must wait before it can be spent.
    ///
    /// Provisional: to be fixed with the block interval.
    pub coinbase_maturity: u64,
    /// New coins the coinbase of this block may create.
    pub subsidy: Amount,
}

/// What [`UtxoSet::revert_block`] needs to undo a block.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockUndo {
    block_id: BlockId,
    spent: Vec<(OutPoint, Coin)>,
}

impl BlockUndo {
    /// Returns the id of the block this undo data belongs to.
    #[must_use]
    pub const fn block_id(&self) -> BlockId {
        self.block_id
    }

    /// Returns the coins the block spent from the earlier set, in spend order.
    #[must_use]
    pub fn spent(&self) -> &[(OutPoint, Coin)] {
        &self.spent
    }
}

/// The tip a [`UtxoSet`] reflects.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Tip {
    /// Id of the last applied block.
    pub block_id: BlockId,
    /// Its height.
    pub height: u64,
}

/// The set of unspent outputs at a chain tip.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct UtxoSet {
    coins: HashMap<OutPoint, Coin>,
    total_value: Amount,
    tip: Option<Tip>,
}

impl UtxoSet {
    /// Creates the empty set that precedes the genesis block.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Looks up an unspent output.
    #[must_use]
    pub fn get(&self, outpoint: &OutPoint) -> Option<&Coin> {
        self.coins.get(outpoint)
    }

    /// Returns the number of unspent outputs.
    #[must_use]
    pub fn len(&self) -> usize {
        self.coins.len()
    }

    /// Returns whether the set has no unspent outputs.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.coins.is_empty()
    }

    /// Returns the total value of all unspent outputs.
    #[must_use]
    pub const fn total_value(&self) -> Amount {
        self.total_value
    }

    /// Returns the last applied block, or `None` before genesis.
    #[must_use]
    pub const fn tip(&self) -> Option<Tip> {
        self.tip
    }

    /// Recounts every coin and checks the tracked total.
    ///
    /// This is O(n) and intended for tests, start-up checks and audits.
    pub fn audit(&self) -> Result<(), UtxoError> {
        let sum: u128 = self
            .coins
            .values()
            .map(|coin| u128::from(coin.output.amount.as_satoshis()))
            .sum();
        if sum == u128::from(self.total_value.as_satoshis()) {
            Ok(())
        } else {
            Err(UtxoError::SupplyMismatch)
        }
    }

    /// Validates `block` against this set and applies it atomically.
    ///
    /// Checks, in order: the block extends the tip at the next height; every
    /// input spends an existing, mature coin; every transaction passes
    /// [`NormalTransaction::validate_spend`]; no output overwrites an existing
    /// coin; and the coinbase claims at most `subsidy + fees`. On any failure
    /// the set is unchanged.
    ///
    /// [`NormalTransaction::validate_spend`]: itacoin_transaction::NormalTransaction::validate_spend
    pub fn apply_block(
        &mut self,
        block: &Block,
        rules: &BlockRules,
    ) -> Result<BlockUndo, UtxoError> {
        let height = block.height();
        let (expected_parent, expected_height) = match self.tip() {
            Some(tip) => (tip.block_id, tip.height + 1),
            None => (BlockId::new(Hash256::new([0; 32])), 0),
        };
        if block.header().prev_block != expected_parent {
            return Err(UtxoError::WrongParent {
                expected: expected_parent,
                actual: block.header().prev_block,
            });
        }
        if height != expected_height {
            return Err(UtxoError::WrongHeight {
                expected: expected_height,
                actual: height,
            });
        }

        // Stage the block: outputs created earlier in the block may be spent
        // later in it, and coins from the set are only marked as spent.
        let mut created: HashMap<OutPoint, Coin> = HashMap::new();
        let mut spent_from_set: Vec<(OutPoint, Coin)> = Vec::new();
        let mut spent_in_set: HashSet<OutPoint> = HashSet::new();
        let mut fees = Amount::ZERO;

        for (index, transaction) in block.transactions().iter().enumerate() {
            if let Transaction::Normal(normal) = transaction {
                let mut spent_outputs = Vec::with_capacity(transaction.inputs().len());
                for (input_index, input) in transaction.inputs().iter().enumerate() {
                    let outpoint = input.previous_output;
                    let coin = if let Some(coin) = created.remove(&outpoint) {
                        coin
                    } else {
                        // `Block` already refuses repeated outpoints, so a
                        // coin from the set is never seen twice here.
                        let coin = *self.coins.get(&outpoint).ok_or(UtxoError::MissingCoin {
                            transaction: index,
                            input: input_index,
                        })?;
                        spent_in_set.insert(outpoint);
                        spent_from_set.push((outpoint, coin));
                        coin
                    };
                    if coin.is_coinbase && height - coin.height < rules.coinbase_maturity {
                        return Err(UtxoError::ImmatureCoinbase {
                            transaction: index,
                            input: input_index,
                        });
                    }
                    spent_outputs.push(coin.output);
                }
                let fee = normal
                    .validate_spend(&rules.chain_id, &spent_outputs)
                    .map_err(|error| UtxoError::Transaction {
                        transaction: index,
                        error,
                    })?;
                fees = fees.checked_add(fee).map_err(UtxoError::Supply)?;
            }

            let txid = transaction.txid();
            for (output_index, output) in transaction.outputs().iter().enumerate() {
                let outpoint = OutPoint {
                    txid,
                    // Outputs are limited to MAX_TX_OUTPUTS, far below u16::MAX.
                    index: u16::try_from(output_index).expect("output count fits in u16"),
                };
                // An output may not overwrite an unspent coin (BIP 30). A
                // coinbase commits to its height, so this needs a collision.
                if (self.coins.contains_key(&outpoint) && !spent_in_set.contains(&outpoint))
                    || created.contains_key(&outpoint)
                {
                    return Err(UtxoError::DuplicateOutput(outpoint));
                }
                created.insert(
                    outpoint,
                    Coin {
                        output: *output,
                        height,
                        is_coinbase: transaction.is_coinbase(),
                    },
                );
            }
        }

        let claimed = match &block.transactions()[0] {
            Transaction::Coinbase(coinbase) => coinbase.output_total(),
            Transaction::Normal(_) => unreachable!("Block requires a coinbase first"),
        };
        let allowed = rules.subsidy.checked_add(fees).map_err(UtxoError::Supply)?;
        if claimed > allowed {
            return Err(UtxoError::CoinbaseTooLarge { allowed, claimed });
        }
        // Inputs equal outputs plus fees, so the supply changes by exactly
        // `claimed - fees`. Computed in u128 so a transient sum cannot overflow.
        let total = u128::from(self.total_value.as_satoshis()) + u128::from(claimed.as_satoshis())
            - u128::from(fees.as_satoshis());
        let total = to_amount(total)?;

        // Commit. Nothing below can fail.
        for (outpoint, _) in &spent_from_set {
            self.coins.remove(outpoint);
        }
        self.coins.extend(created);
        self.total_value = total;
        let block_id = block.id();
        self.tip = Some(Tip { block_id, height });
        debug_assert_eq!(self.audit(), Ok(()));
        Ok(BlockUndo {
            block_id,
            spent: spent_from_set,
        })
    }

    /// Reverts the tip block atomically, using the undo data
    /// [`UtxoSet::apply_block`] returned for it.
    pub fn revert_block(&mut self, block: &Block, undo: &BlockUndo) -> Result<(), UtxoError> {
        let block_id = block.id();
        if self.tip().map(|tip| tip.block_id) != Some(block_id) || undo.block_id != block_id {
            return Err(UtxoError::NotTip(block_id));
        }

        // Outputs the block created and that are still unspent. Outputs both
        // created and spent inside the block never reached the set.
        let spent_inside: HashSet<OutPoint> = block
            .transactions()
            .iter()
            .flat_map(Transaction::inputs)
            .map(|input| input.previous_output)
            .collect();
        let mut created = Vec::new();
        for transaction in block.transactions() {
            let txid = transaction.txid();
            for index in 0..transaction.outputs().len() {
                let outpoint = OutPoint {
                    txid,
                    index: u16::try_from(index).expect("output count fits in u16"),
                };
                if !spent_inside.contains(&outpoint) {
                    created.push(outpoint);
                }
            }
        }

        let mut total = u128::from(self.total_value.as_satoshis());
        for outpoint in &created {
            let coin = self.coins.get(outpoint).ok_or(UtxoError::CorruptUndo)?;
            total -= u128::from(coin.output.amount.as_satoshis());
        }
        for (outpoint, coin) in &undo.spent {
            if self.coins.contains_key(outpoint) {
                return Err(UtxoError::CorruptUndo);
            }
            total += u128::from(coin.output.amount.as_satoshis());
        }
        let total = to_amount(total)?;

        for outpoint in &created {
            self.coins.remove(outpoint);
        }
        self.coins.extend(undo.spent.iter().copied());
        self.total_value = total;
        self.tip = block.height().checked_sub(1).map(|height| Tip {
            block_id: block.header().prev_block,
            height,
        });
        debug_assert_eq!(self.audit(), Ok(()));
        Ok(())
    }
}

fn to_amount(satoshis: u128) -> Result<Amount, UtxoError> {
    let satoshis =
        u64::try_from(satoshis).map_err(|_| UtxoError::Supply(AmountError::ArithmeticOverflow))?;
    Amount::from_satoshis(satoshis).map_err(UtxoError::Supply)
}

/// Errors from applying or reverting a block.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UtxoError {
    /// The block does not build on the current tip.
    WrongParent {
        /// The current tip.
        expected: BlockId,
        /// The block's parent.
        actual: BlockId,
    },
    /// The coinbase height is not the next height.
    WrongHeight {
        /// The next height.
        expected: u64,
        /// The coinbase height.
        actual: u64,
    },
    /// An input spends an output that does not exist or is already spent.
    MissingCoin {
        /// Position of the transaction in the block.
        transaction: usize,
        /// Position of the input.
        input: usize,
    },
    /// An input spends a coinbase output before it matured.
    ImmatureCoinbase {
        /// Position of the transaction in the block.
        transaction: usize,
        /// Position of the input.
        input: usize,
    },
    /// A transaction failed spend validation.
    Transaction {
        /// Position of the transaction in the block.
        transaction: usize,
        /// The reason.
        error: TransactionError,
    },
    /// An output would overwrite an unspent coin.
    DuplicateOutput(OutPoint),
    /// The coinbase claims more than subsidy plus fees.
    CoinbaseTooLarge {
        /// Subsidy plus fees.
        allowed: Amount,
        /// Coinbase output total.
        claimed: Amount,
    },
    /// A monetary total overflowed or exceeded the maximum supply.
    Supply(AmountError),
    /// The tracked total disagrees with a recount of the coins.
    SupplyMismatch,
    /// Only the tip block can be reverted, with its own undo data.
    NotTip(BlockId),
    /// The undo data does not match the set.
    CorruptUndo,
}

impl fmt::Display for UtxoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongParent { expected, actual } => {
                write!(formatter, "block builds on {actual}, tip is {expected}")
            }
            Self::WrongHeight { expected, actual } => {
                write!(formatter, "block height {actual}, expected {expected}")
            }
            Self::MissingCoin { transaction, input } => write!(
                formatter,
                "transaction {transaction} input {input} spends a missing coin"
            ),
            Self::ImmatureCoinbase { transaction, input } => write!(
                formatter,
                "transaction {transaction} input {input} spends an immature coinbase"
            ),
            Self::Transaction { transaction, error } => {
                write!(formatter, "transaction {transaction} is invalid: {error}")
            }
            Self::DuplicateOutput(outpoint) => write!(
                formatter,
                "output {}:{} already exists",
                outpoint.txid, outpoint.index
            ),
            Self::CoinbaseTooLarge { allowed, claimed } => {
                write!(formatter, "coinbase claims {claimed}, allowed {allowed}")
            }
            Self::Supply(error) => write!(formatter, "supply arithmetic failed: {error}"),
            Self::SupplyMismatch => formatter.write_str("tracked supply differs from the coins"),
            Self::NotTip(block_id) => write!(formatter, "block {block_id} is not the tip"),
            Self::CorruptUndo => formatter.write_str("undo data does not match the set"),
        }
    }
}

impl std::error::Error for UtxoError {}

#[cfg(test)]
mod tests;
