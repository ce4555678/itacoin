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

use itacoin_codec::{Decode, Encode, Reader, Writer};
use itacoin_primitives::TransactionId;
use itacoin_primitives::{Amount, AmountError, BlockId, Hash256, WalletId};
use itacoin_transaction::{
    Input, OUTPOINT_BYTES, OUTPUT_BYTES, OutPoint, Output, StrippedTransaction, Transaction,
    TransactionError,
};

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
///
/// It also keeps an index from each `wallet_id` to its outpoints, derived
/// from the coins and never stored, for wallet queries over RPC.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct UtxoSet {
    coins: HashMap<OutPoint, Coin>,
    by_wallet: HashMap<WalletId, HashSet<OutPoint>>,
    total_value: Amount,
    tip: Option<Tip>,
}

impl UtxoSet {
    /// Creates the empty set that precedes the genesis block.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Rebuilds a set from stored coins and its tip.
    ///
    /// The total is recomputed from the coins and must not exceed the
    /// maximum supply.
    pub fn from_parts(
        coins: impl IntoIterator<Item = (OutPoint, Coin)>,
        tip: Option<Tip>,
    ) -> Result<Self, UtxoError> {
        let coins: HashMap<OutPoint, Coin> = coins.into_iter().collect();
        if tip.is_none() && !coins.is_empty() {
            return Err(UtxoError::CorruptUndo);
        }
        let total: u128 = coins
            .values()
            .map(|coin| u128::from(coin.output.amount.as_satoshis()))
            .sum();
        let mut by_wallet: HashMap<WalletId, HashSet<OutPoint>> = HashMap::new();
        for (outpoint, coin) in &coins {
            by_wallet
                .entry(coin.output.wallet_id)
                .or_default()
                .insert(*outpoint);
        }
        Ok(Self {
            coins,
            by_wallet,
            total_value: to_amount(total)?,
            tip,
        })
    }

    /// Iterates over the unspent outpoints paying `wallet_id`, in no
    /// particular order.
    pub fn outpoints_of(&self, wallet_id: &WalletId) -> impl Iterator<Item = &OutPoint> {
        self.by_wallet.get(wallet_id).into_iter().flatten()
    }

    fn insert_coin(&mut self, outpoint: OutPoint, coin: Coin) {
        self.by_wallet
            .entry(coin.output.wallet_id)
            .or_default()
            .insert(outpoint);
        self.coins.insert(outpoint, coin);
    }

    fn remove_coin(&mut self, outpoint: &OutPoint) {
        if let Some(coin) = self.coins.remove(outpoint)
            && let Some(set) = self.by_wallet.get_mut(&coin.output.wallet_id)
        {
            set.remove(outpoint);
            if set.is_empty() {
                self.by_wallet.remove(&coin.output.wallet_id);
            }
        }
    }

    /// Iterates over all unspent outputs, in no particular order.
    pub fn coins(&self) -> impl Iterator<Item = (&OutPoint, &Coin)> {
        self.coins.iter()
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
    /// the set is unchanged. The rules live in [`validate_block`], shared with
    /// the on-disk store.
    ///
    /// [`NormalTransaction::validate_spend`]: itacoin_transaction::NormalTransaction::validate_spend
    pub fn apply_block(
        &mut self,
        block: &Block,
        rules: &BlockRules,
    ) -> Result<BlockUndo, UtxoError> {
        let delta = validate_block(
            self,
            self.tip,
            self.total_value,
            &BlockShape::of(block),
            block.transactions(),
            rules,
        )?;
        let undo = delta.undo();
        self.commit(&delta);
        Ok(undo)
    }

    /// Reverts the tip block atomically, using the undo data
    /// [`UtxoSet::apply_block`] returned for it.
    pub fn revert_block(&mut self, block: &Block, undo: &BlockUndo) -> Result<(), UtxoError> {
        let delta = revert_delta(
            self,
            self.tip,
            self.total_value,
            &BlockShape::of(block),
            &created_outpoints(block),
            undo,
        )?;
        self.commit(&delta);
        Ok(())
    }

    /// Applies a validated change. Nothing here can fail.
    pub fn commit(&mut self, delta: &UtxoDelta) {
        for (outpoint, _) in &delta.removed {
            self.remove_coin(outpoint);
        }
        for (outpoint, coin) in &delta.added {
            self.insert_coin(*outpoint, *coin);
        }
        self.total_value = delta.total_value;
        self.tip = delta.tip;
        debug_assert_eq!(self.audit(), Ok(()));
    }
}

impl CoinSource for UtxoSet {
    fn coin(&self, outpoint: &OutPoint) -> Result<Option<Coin>, SourceError> {
        Ok(self.coins.get(outpoint).copied())
    }
}

/// Where coins are read from during validation: the in-memory [`UtxoSet`]
/// or the on-disk store.
pub trait CoinSource {
    /// Looks up an unspent output. An error means the source could not be
    /// read; it never means the coin is missing.
    fn coin(&self, outpoint: &OutPoint) -> Result<Option<Coin>, SourceError>;
}

/// A coin source could not be read. The source keeps the details.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceError;

/// The parts of a block validation needs besides its transactions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockShape {
    /// The block id.
    pub block_id: BlockId,
    /// Its parent.
    pub prev_block: BlockId,
    /// Its height.
    pub height: u64,
}

impl BlockShape {
    /// The shape of a full block.
    #[must_use]
    pub fn of(block: &Block) -> Self {
        Self {
            block_id: block.id(),
            prev_block: block.header().prev_block,
            height: block.height(),
        }
    }
}

/// A transaction as validation sees it: a full transaction, or one whose
/// witnesses were pruned after this node validated it.
pub trait BodyTransaction {
    /// The transaction id.
    fn txid(&self) -> TransactionId;
    /// Whether it is a coinbase.
    fn is_coinbase(&self) -> bool;
    /// Its inputs.
    fn inputs(&self) -> &[Input];
    /// Its outputs.
    fn outputs(&self) -> &[Output];
    /// The rules that need the spent outputs; returns the fee.
    fn check_spend(&self, chain_id: &Hash256, spent: &[Output])
    -> Result<Amount, TransactionError>;
}

impl BodyTransaction for Transaction {
    fn txid(&self) -> TransactionId {
        Self::txid(self)
    }

    fn is_coinbase(&self) -> bool {
        Self::is_coinbase(self)
    }

    fn inputs(&self) -> &[Input] {
        Self::inputs(self)
    }

    fn outputs(&self) -> &[Output] {
        Self::outputs(self)
    }

    fn check_spend(
        &self,
        chain_id: &Hash256,
        spent: &[Output],
    ) -> Result<Amount, TransactionError> {
        match self {
            Self::Normal(normal) => normal.validate_spend(chain_id, spent),
            Self::Coinbase(_) => Ok(Amount::ZERO),
        }
    }
}

impl BodyTransaction for StrippedTransaction {
    fn txid(&self) -> TransactionId {
        Self::txid(self)
    }

    fn is_coinbase(&self) -> bool {
        Self::is_coinbase(self)
    }

    fn inputs(&self) -> &[Input] {
        Self::inputs(self)
    }

    fn outputs(&self) -> &[Output] {
        Self::outputs(self)
    }

    /// Value conservation only: the signatures were verified when this node
    /// first validated the block, before its witnesses were pruned.
    fn check_spend(
        &self,
        _chain_id: &Hash256,
        spent: &[Output],
    ) -> Result<Amount, TransactionError> {
        match self {
            Self::Normal(unsigned) => unsigned.fee(spent),
            Self::Coinbase(_) => Ok(Amount::ZERO),
        }
    }
}

/// A validated change to the unspent-output set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UtxoDelta {
    /// The block applied or reverted.
    pub block_id: BlockId,
    /// Coins that leave the set, with their contents (the undo data when a
    /// block is applied).
    pub removed: Vec<(OutPoint, Coin)>,
    /// Coins that enter the set.
    pub added: Vec<(OutPoint, Coin)>,
    /// The tip afterwards.
    pub tip: Option<Tip>,
    /// The total value of all unspent outputs afterwards.
    pub total_value: Amount,
}

impl UtxoDelta {
    /// The undo data of an applied block.
    #[must_use]
    pub fn undo(&self) -> BlockUndo {
        BlockUndo {
            block_id: self.block_id,
            spent: self.removed.clone(),
        }
    }
}

fn read(source: &impl CoinSource, outpoint: &OutPoint) -> Result<Option<Coin>, UtxoError> {
    source
        .coin(outpoint)
        .map_err(|SourceError| UtxoError::Unavailable)
}

/// Validates a block against `source`, whose tip is `tip` and whose total
/// value is `total_value`, without changing anything. Every consensus rule
/// that needs the unspent outputs is here.
pub fn validate_block<T: BodyTransaction>(
    source: &impl CoinSource,
    tip: Option<Tip>,
    total_value: Amount,
    shape: &BlockShape,
    transactions: &[T],
    rules: &BlockRules,
) -> Result<UtxoDelta, UtxoError> {
    let height = shape.height;
    let (expected_parent, expected_height) = match tip {
        Some(tip) => (tip.block_id, tip.height + 1),
        None => (BlockId::new(Hash256::new([0; 32])), 0),
    };
    if shape.prev_block != expected_parent {
        return Err(UtxoError::WrongParent {
            expected: expected_parent,
            actual: shape.prev_block,
        });
    }
    if height != expected_height {
        return Err(UtxoError::WrongHeight {
            expected: expected_height,
            actual: height,
        });
    }
    let Some(first) = transactions.first().filter(|first| first.is_coinbase()) else {
        return Err(UtxoError::MissingCoinbase);
    };

    // Stage the block: outputs created earlier in the block may be spent
    // later in it, and coins from the source are only marked as spent.
    let mut created: HashMap<OutPoint, Coin> = HashMap::new();
    let mut created_order: Vec<OutPoint> = Vec::new();
    let mut spent_from_set: Vec<(OutPoint, Coin)> = Vec::new();
    let mut spent_in_set: HashSet<OutPoint> = HashSet::new();
    let mut fees = Amount::ZERO;

    for (index, transaction) in transactions.iter().enumerate() {
        if !transaction.is_coinbase() {
            let mut spent_outputs = Vec::with_capacity(transaction.inputs().len());
            for (input_index, input) in transaction.inputs().iter().enumerate() {
                let outpoint = input.previous_output;
                let coin = if let Some(coin) = created.remove(&outpoint) {
                    coin
                } else {
                    // `Block` already refuses repeated outpoints, so a coin
                    // from the source is never seen twice here.
                    let coin = read(source, &outpoint)?.ok_or(UtxoError::MissingCoin {
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
            let fee = transaction
                .check_spend(&rules.chain_id, &spent_outputs)
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
                index: u16::try_from(output_index).map_err(|_| UtxoError::CorruptUndo)?,
            };
            // An output may not overwrite an unspent coin (BIP 30). A
            // coinbase commits to its height, so this needs a collision.
            if (!spent_in_set.contains(&outpoint) && read(source, &outpoint)?.is_some())
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
            created_order.push(outpoint);
        }
    }

    let mut claimed = Amount::ZERO;
    for output in first.outputs() {
        claimed = claimed
            .checked_add(output.amount)
            .map_err(UtxoError::Supply)?;
    }
    let allowed = rules.subsidy.checked_add(fees).map_err(UtxoError::Supply)?;
    if claimed > allowed {
        return Err(UtxoError::CoinbaseTooLarge { allowed, claimed });
    }
    // Inputs equal outputs plus fees, so the supply changes by exactly
    // `claimed - fees`. Computed in u128 so a transient sum cannot overflow.
    let total = u128::from(total_value.as_satoshis()) + u128::from(claimed.as_satoshis())
        - u128::from(fees.as_satoshis());
    let total = to_amount(total)?;

    // Keep the creation order so every store writes the same sequence.
    let added: Vec<(OutPoint, Coin)> = created_order
        .into_iter()
        .filter_map(|outpoint| created.get(&outpoint).map(|coin| (outpoint, *coin)))
        .collect();
    Ok(UtxoDelta {
        block_id: shape.block_id,
        removed: spent_from_set,
        added,
        tip: Some(Tip {
            block_id: shape.block_id,
            height,
        }),
        total_value: total,
    })
}

/// Validates the reversal of the tip block, given the outpoints it created
/// and its undo data, without changing anything.
pub fn revert_delta(
    source: &impl CoinSource,
    tip: Option<Tip>,
    total_value: Amount,
    shape: &BlockShape,
    created: &[OutPoint],
    undo: &BlockUndo,
) -> Result<UtxoDelta, UtxoError> {
    let block_id = shape.block_id;
    if tip.map(|tip| tip.block_id) != Some(block_id) || undo.block_id != block_id {
        return Err(UtxoError::NotTip(block_id));
    }
    let mut total = u128::from(total_value.as_satoshis());
    let mut removed = Vec::with_capacity(created.len());
    for outpoint in created {
        let coin = read(source, outpoint)?.ok_or(UtxoError::CorruptUndo)?;
        total = total
            .checked_sub(u128::from(coin.output.amount.as_satoshis()))
            .ok_or(UtxoError::CorruptUndo)?;
        removed.push((*outpoint, coin));
    }
    for (outpoint, coin) in &undo.spent {
        if read(source, outpoint)?.is_some() {
            return Err(UtxoError::CorruptUndo);
        }
        total += u128::from(coin.output.amount.as_satoshis());
    }
    Ok(UtxoDelta {
        block_id,
        removed,
        added: undo.spent.clone(),
        tip: shape.height.checked_sub(1).map(|height| Tip {
            block_id: shape.prev_block,
            height,
        }),
        total_value: to_amount(total)?,
    })
}

/// Returns the outputs `block` adds to the set: all of its outputs except
/// those spent later in the same block, which never reach the set.
#[must_use]
pub fn created_outpoints(block: &Block) -> Vec<OutPoint> {
    created_outpoints_of(block.transactions())
}

/// [`created_outpoints`] for any block body, full or pruned.
#[must_use]
pub fn created_outpoints_of<T: BodyTransaction>(transactions: &[T]) -> Vec<OutPoint> {
    let spent_inside: HashSet<OutPoint> = transactions
        .iter()
        .flat_map(BodyTransaction::inputs)
        .map(|input| input.previous_output)
        .collect();
    let mut created = Vec::new();
    for transaction in transactions {
        let txid = transaction.txid();
        for index in 0..transaction.outputs().len() {
            let Ok(index) = u16::try_from(index) else {
                continue;
            };
            let outpoint = OutPoint { txid, index };
            if !spent_inside.contains(&outpoint) {
                created.push(outpoint);
            }
        }
    }
    created
}

/// Encoded size of a [`Coin`].
pub const COIN_BYTES: usize = OUTPUT_BYTES + 8 + 1;

impl Encode for Coin {
    fn encode(&self, writer: &mut Writer) {
        self.output.encode(writer);
        writer.u64(self.height);
        writer.u8(u8::from(self.is_coinbase));
    }

    fn encoded_len(&self) -> usize {
        COIN_BYTES
    }
}

impl Decode for Coin {
    type Error = TransactionError;

    fn decode(reader: &mut Reader<'_>) -> Result<Self, TransactionError> {
        let output = Output::decode(reader)?;
        let height = reader.u64()?;
        let is_coinbase = match reader.u8()? {
            0 => false,
            1 => true,
            flag => return Err(TransactionError::UnknownKind(flag)),
        };
        Ok(Self {
            output,
            height,
            is_coinbase,
        })
    }
}

impl Encode for BlockUndo {
    fn encode(&self, writer: &mut Writer) {
        self.block_id.encode(writer);
        writer.count_u32(self.spent.len());
        for (outpoint, coin) in &self.spent {
            outpoint.encode(writer);
            coin.encode(writer);
        }
    }

    fn encoded_len(&self) -> usize {
        32 + 4 + self.spent.len() * (OUTPOINT_BYTES + COIN_BYTES)
    }
}

impl Decode for BlockUndo {
    type Error = TransactionError;

    fn decode(reader: &mut Reader<'_>) -> Result<Self, TransactionError> {
        let block_id = BlockId::decode(reader)?;
        let count = reader.count_u32(0..=usize::MAX, OUTPOINT_BYTES + COIN_BYTES)?;
        let spent = (0..count)
            .map(|_| Ok((OutPoint::decode(reader)?, Coin::decode(reader)?)))
            .collect::<Result<Vec<_>, TransactionError>>()?;
        Ok(Self { block_id, spent })
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
    /// The block body does not start with a coinbase.
    MissingCoinbase,
    /// The coin source could not be read. This says nothing about the
    /// block: it must never mark a block invalid.
    Unavailable,
}

impl UtxoError {
    /// Whether this error proves the block invalid, as opposed to a failure
    /// to read the coins.
    #[must_use]
    pub const fn is_invalid_block(&self) -> bool {
        !matches!(self, Self::Unavailable)
    }
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
            Self::MissingCoinbase => {
                formatter.write_str("the block does not start with a coinbase")
            }
            Self::Unavailable => formatter.write_str("the coins could not be read"),
        }
    }
}

impl std::error::Error for UtxoError {}

#[cfg(test)]
mod tests;
