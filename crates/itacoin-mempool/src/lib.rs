//! The ITACOIN transaction pool, as specified in section 8 of
//! `docs/NETWORK_PROPOSAL.md`.
//!
//! The pool holds unconfirmed transactions that are valid against the active
//! chain plus their unconfirmed parents. It enforces relay policy, which is
//! not consensus: minimum fee rate, size cap with eviction by fee rate,
//! expiry, ancestor and descendant limits, replacement by fee (RBF) and a
//! small pool of orphan transactions. It has no I/O.

use core::fmt;
use std::collections::{HashMap, HashSet};

use itacoin_blockchain::{Block, CoinSource};
use itacoin_codec::Encode;
use itacoin_primitives::{Amount, Hash256, TransactionId};
use itacoin_transaction::{NormalTransaction, OutPoint, Transaction, TransactionError};

/// Relay policy. None of it is consensus.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Policy {
    /// Minimum fee in satoshis per encoded byte.
    pub min_fee_per_byte: u64,
    /// Maximum total encoded size of the pool.
    pub max_bytes: usize,
    /// Seconds a transaction may stay unconfirmed.
    pub expiry_secs: u64,
    /// Maximum unconfirmed ancestors of a transaction, itself included.
    pub max_ancestors: usize,
    /// Maximum unconfirmed descendants of a transaction, itself included.
    pub max_descendants: usize,
    /// Maximum transactions one replacement may evict.
    pub max_replaced: usize,
    /// Maximum orphan transactions kept.
    pub max_orphans: usize,
    /// Seconds an orphan is kept.
    pub orphan_expiry_secs: u64,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            min_fee_per_byte: 1,
            max_bytes: 300_000_000,
            expiry_secs: 14 * 24 * 3600,
            max_ancestors: 25,
            max_descendants: 25,
            max_replaced: 100,
            max_orphans: 100,
            orphan_expiry_secs: 20 * 60,
        }
    }
}

/// The chain state a transaction is checked against.
#[derive(Clone, Copy)]
pub struct ChainView<'a> {
    /// Unspent outputs at the active tip.
    pub coins: &'a dyn CoinSource,
    /// The network's chain id.
    pub chain_id: Hash256,
    /// Height of the next block.
    pub next_height: u64,
    /// Blocks a coinbase output must wait before it can be spent.
    pub coinbase_maturity: u64,
}

impl core::fmt::Debug for ChainView<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ChainView")
            .field("chain_id", &self.chain_id)
            .field("next_height", &self.next_height)
            .finish_non_exhaustive()
    }
}

/// A transaction in the pool.
#[derive(Clone, Debug)]
pub struct Entry {
    transaction: NormalTransaction,
    txid: TransactionId,
    witness_hash: Hash256,
    size: usize,
    fee: Amount,
    time: u64,
    parents: HashSet<TransactionId>,
    children: HashSet<TransactionId>,
}

impl Entry {
    /// Returns the transaction.
    #[must_use]
    pub const fn transaction(&self) -> &NormalTransaction {
        &self.transaction
    }

    /// Returns the transaction id.
    #[must_use]
    pub const fn txid(&self) -> TransactionId {
        self.txid
    }

    /// Returns the hash of the witnesses.
    #[must_use]
    pub const fn witness_hash(&self) -> Hash256 {
        self.witness_hash
    }

    /// Returns the encoded size in bytes.
    #[must_use]
    pub const fn size(&self) -> usize {
        self.size
    }

    /// Returns the fee.
    #[must_use]
    pub const fn fee(&self) -> Amount {
        self.fee
    }

    /// Returns when the transaction entered the pool.
    #[must_use]
    pub const fn time(&self) -> u64 {
        self.time
    }

    /// Returns the unconfirmed transactions this one spends from.
    pub fn parents(&self) -> impl Iterator<Item = &TransactionId> {
        self.parents.iter()
    }

    /// Returns the unconfirmed transactions that spend from this one.
    pub fn children(&self) -> impl Iterator<Item = &TransactionId> {
        self.children.iter()
    }

    /// Returns the fee rate as a comparable fraction `(fee, size)`.
    fn fee_rate(&self) -> FeeRate {
        FeeRate::new(self.fee.as_satoshis(), self.size)
    }
}

/// A fee rate compared exactly by cross-multiplication.
#[derive(Clone, Copy, Debug)]
struct FeeRate {
    fee: u128,
    size: u128,
}

impl FeeRate {
    fn new(fee: u64, size: usize) -> Self {
        Self {
            fee: u128::from(fee),
            size: size.max(1) as u128,
        }
    }
}

impl PartialEq for FeeRate {
    fn eq(&self, other: &Self) -> bool {
        self.fee * other.size == other.fee * self.size
    }
}

impl Eq for FeeRate {}

impl PartialOrd for FeeRate {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for FeeRate {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        (self.fee * other.size).cmp(&(other.fee * self.size))
    }
}

/// What happened to a submitted transaction.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Added {
    /// Transactions that entered the pool: the submitted one, if it did, and
    /// any orphans it made valid.
    pub accepted: Vec<TransactionId>,
    /// Transactions evicted by replacement.
    pub replaced: Vec<TransactionId>,
    /// Whether the submitted transaction is waiting as an orphan.
    pub orphaned: bool,
}

#[derive(Clone, Debug)]
struct Orphan {
    transaction: NormalTransaction,
    time: u64,
}

/// The transaction pool.
#[derive(Clone, Debug, Default)]
pub struct Mempool {
    policy: Policy,
    entries: HashMap<TransactionId, Entry>,
    spent_by: HashMap<OutPoint, TransactionId>,
    total_bytes: usize,
    orphans: HashMap<TransactionId, Orphan>,
}

impl Mempool {
    /// Creates an empty pool with `policy`.
    #[must_use]
    pub fn new(policy: Policy) -> Self {
        Self {
            policy,
            ..Self::default()
        }
    }

    /// Returns the policy.
    #[must_use]
    pub const fn policy(&self) -> &Policy {
        &self.policy
    }

    /// Returns the number of transactions in the pool.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns whether the pool is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns the total encoded size of the pool.
    #[must_use]
    pub const fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    /// Returns the number of orphans waiting for a parent.
    #[must_use]
    pub fn orphan_count(&self) -> usize {
        self.orphans.len()
    }

    /// Returns whether the pool or the orphan pool knows `txid`.
    #[must_use]
    pub fn contains(&self, txid: &TransactionId) -> bool {
        self.entries.contains_key(txid) || self.orphans.contains_key(txid)
    }

    /// Returns the pool transaction that spends `outpoint`, if any.
    #[must_use]
    pub fn spent_by(&self, outpoint: &OutPoint) -> Option<TransactionId> {
        self.spent_by.get(outpoint).copied()
    }

    /// Returns a pool entry.
    #[must_use]
    pub fn get(&self, txid: &TransactionId) -> Option<&Entry> {
        self.entries.get(txid)
    }

    /// Iterates over all entries, in no particular order.
    pub fn entries(&self) -> impl Iterator<Item = &Entry> {
        self.entries.values()
    }

    /// Validates `transaction` against `view` and the pool and adds it.
    ///
    /// A transaction whose inputs are unknown is kept as an orphan and retried
    /// when a parent arrives. Adding a transaction may also accept orphans
    /// that spend it.
    pub fn add(
        &mut self,
        transaction: Transaction,
        view: &ChainView<'_>,
        now: u64,
    ) -> Result<Added, MempoolError> {
        let Transaction::Normal(transaction) = transaction else {
            return Err(MempoolError::Coinbase);
        };
        let mut added = Added::default();
        match self.add_one(transaction, view, now, true)? {
            Insert::Accepted { txid, replaced } => {
                added.accepted.push(txid);
                added.replaced = replaced;
                self.retry_orphans(txid, view, now, &mut added);
            }
            Insert::Orphaned => added.orphaned = true,
        }
        Ok(added)
    }

    fn retry_orphans(
        &mut self,
        parent: TransactionId,
        view: &ChainView<'_>,
        now: u64,
        added: &mut Added,
    ) {
        let mut queue = vec![parent];
        while let Some(parent) = queue.pop() {
            let children: Vec<TransactionId> = self
                .orphans
                .iter()
                .filter(|(_, orphan)| {
                    orphan
                        .transaction
                        .unsigned()
                        .inputs()
                        .iter()
                        .any(|input| input.previous_output.txid == parent)
                })
                .map(|(txid, _)| *txid)
                .collect();
            for txid in children {
                let Some(orphan) = self.orphans.remove(&txid) else {
                    continue;
                };
                if let Ok(Insert::Accepted { txid, replaced }) =
                    self.add_one(orphan.transaction, view, now, true)
                {
                    added.accepted.push(txid);
                    added.replaced.extend(replaced);
                    queue.push(txid);
                }
            }
        }
    }

    fn add_one(
        &mut self,
        transaction: NormalTransaction,
        view: &ChainView<'_>,
        now: u64,
        allow_orphan: bool,
    ) -> Result<Insert, MempoolError> {
        let unsigned = transaction.unsigned();
        let txid = unsigned.txid();
        if self.entries.contains_key(&txid) || self.orphans.contains_key(&txid) {
            return Err(MempoolError::AlreadyKnown);
        }
        let size = transaction.encoded_len();

        // Resolve every input against the pool, then the chain.
        let mut spent = Vec::with_capacity(unsigned.inputs().len());
        let mut parents = HashSet::new();
        let mut conflicts = HashSet::new();
        let mut missing = false;
        for input in unsigned.inputs() {
            let outpoint = input.previous_output;
            if let Some(conflict) = self.spent_by.get(&outpoint) {
                conflicts.insert(*conflict);
            }
            if let Some(parent) = self.entries.get(&outpoint.txid) {
                match parent
                    .transaction
                    .unsigned()
                    .outputs()
                    .get(usize::from(outpoint.index))
                {
                    Some(output) => {
                        spent.push(*output);
                        parents.insert(outpoint.txid);
                    }
                    None => return Err(MempoolError::MissingInputs),
                }
            } else if let Some(coin) = view
                .coins
                .coin(&outpoint)
                .map_err(|_| MempoolError::Unavailable)?
            {
                if coin.is_coinbase
                    && view.next_height.saturating_sub(coin.height) < view.coinbase_maturity
                {
                    return Err(MempoolError::ImmatureCoinbase);
                }
                spent.push(coin.output);
            } else {
                missing = true;
            }
        }
        if missing {
            if !allow_orphan {
                return Err(MempoolError::MissingInputs);
            }
            self.add_orphan(txid, transaction, now);
            return Ok(Insert::Orphaned);
        }

        // Full validation, signatures last (and cached for the block).
        let fee = transaction
            .validate_spend(&view.chain_id, &spent)
            .map_err(MempoolError::Invalid)?;
        let required = self.min_fee(size);
        if fee.as_satoshis() < required {
            return Err(MempoolError::FeeTooLow {
                required,
                actual: fee.as_satoshis(),
            });
        }

        // Replacement by fee.
        let replaced = self.check_replacement(&conflicts, &parents, fee, size)?;

        // Ancestor and descendant limits, ignoring what will be replaced.
        let ancestors = self.ancestors(&parents);
        if ancestors.iter().any(|ancestor| replaced.contains(ancestor)) {
            return Err(MempoolError::Replacement(
                "spends a transaction it replaces",
            ));
        }
        if ancestors.len() + 1 > self.policy.max_ancestors {
            return Err(MempoolError::TooManyAncestors);
        }
        for ancestor in &ancestors {
            if self.descendants(*ancestor).len() + 1 > self.policy.max_descendants {
                return Err(MempoolError::TooManyDescendants);
            }
        }

        let replaced: Vec<TransactionId> = replaced.into_iter().collect();
        for txid in &replaced {
            self.remove_entry(*txid);
        }
        let witness_hash = Transaction::Normal(transaction.clone()).witness_hash();
        for input in transaction.unsigned().inputs() {
            self.spent_by.insert(input.previous_output, txid);
        }
        for parent in &parents {
            if let Some(entry) = self.entries.get_mut(parent) {
                entry.children.insert(txid);
            }
        }
        self.total_bytes += size;
        self.entries.insert(
            txid,
            Entry {
                transaction,
                txid,
                witness_hash,
                size,
                fee,
                time: now,
                parents,
                children: HashSet::new(),
            },
        );

        self.trim();
        if !self.entries.contains_key(&txid) {
            return Err(MempoolError::MempoolFull);
        }
        Ok(Insert::Accepted { txid, replaced })
    }

    fn min_fee(&self, size: usize) -> u64 {
        self.policy
            .min_fee_per_byte
            .saturating_mul(u64::try_from(size).unwrap_or(u64::MAX))
    }

    /// Returns what a replacement would evict, or why it is refused.
    fn check_replacement(
        &self,
        conflicts: &HashSet<TransactionId>,
        parents: &HashSet<TransactionId>,
        fee: Amount,
        size: usize,
    ) -> Result<HashSet<TransactionId>, MempoolError> {
        let mut evicted = HashSet::new();
        if conflicts.is_empty() {
            return Ok(evicted);
        }
        let new_rate = FeeRate::new(fee.as_satoshis(), size);
        for conflict in conflicts {
            if parents.contains(conflict) {
                return Err(MempoolError::Replacement(
                    "spends a transaction it replaces",
                ));
            }
            if new_rate <= self.entries[conflict].fee_rate() {
                return Err(MempoolError::Replacement("fee rate is not higher"));
            }
            evicted.extend(self.descendants(*conflict));
        }
        if evicted.len() > self.policy.max_replaced {
            return Err(MempoolError::Replacement("evicts too many transactions"));
        }
        let evicted_fees: u128 = evicted
            .iter()
            .map(|txid| u128::from(self.entries[txid].fee.as_satoshis()))
            .sum();
        // The replacement pays for everything it evicts and for its own relay.
        if u128::from(fee.as_satoshis()) < evicted_fees + u128::from(self.min_fee(size)) {
            return Err(MempoolError::Replacement("absolute fee is not high enough"));
        }
        Ok(evicted)
    }

    /// All unconfirmed ancestors of a transaction with these parents.
    fn ancestors(&self, parents: &HashSet<TransactionId>) -> HashSet<TransactionId> {
        let mut seen = HashSet::new();
        let mut stack: Vec<TransactionId> = parents.iter().copied().collect();
        while let Some(txid) = stack.pop() {
            if seen.insert(txid)
                && let Some(entry) = self.entries.get(&txid)
            {
                stack.extend(entry.parents.iter().copied());
            }
        }
        seen
    }

    /// A transaction and all of its descendants in the pool.
    fn descendants(&self, txid: TransactionId) -> HashSet<TransactionId> {
        let mut seen = HashSet::new();
        let mut stack = vec![txid];
        while let Some(txid) = stack.pop() {
            if seen.insert(txid)
                && let Some(entry) = self.entries.get(&txid)
            {
                stack.extend(entry.children.iter().copied());
            }
        }
        seen
    }

    /// Removes one entry, unlinking it from parents and children.
    fn remove_entry(&mut self, txid: TransactionId) -> Option<Entry> {
        let entry = self.entries.remove(&txid)?;
        self.total_bytes -= entry.size;
        for input in entry.transaction.unsigned().inputs() {
            if self.spent_by.get(&input.previous_output) == Some(&txid) {
                self.spent_by.remove(&input.previous_output);
            }
        }
        for parent in &entry.parents {
            if let Some(parent) = self.entries.get_mut(parent) {
                parent.children.remove(&txid);
            }
        }
        for child in &entry.children {
            if let Some(child) = self.entries.get_mut(child) {
                child.parents.remove(&txid);
            }
        }
        Some(entry)
    }

    /// Removes a transaction and everything that spends it.
    fn remove_with_descendants(&mut self, txid: TransactionId) -> Vec<TransactionId> {
        let removed: Vec<TransactionId> = self.descendants(txid).into_iter().collect();
        for txid in &removed {
            self.remove_entry(*txid);
        }
        removed
    }

    /// Evicts the lowest fee-rate transactions, with their descendants,
    /// until the pool fits the size cap.
    fn trim(&mut self) {
        while self.total_bytes > self.policy.max_bytes {
            let Some(worst) = self
                .entries
                .values()
                .min_by(|a, b| a.fee_rate().cmp(&b.fee_rate()).then(b.time.cmp(&a.time)))
                .map(|entry| entry.txid)
            else {
                return;
            };
            self.remove_with_descendants(worst);
        }
    }

    fn add_orphan(&mut self, txid: TransactionId, transaction: NormalTransaction, now: u64) {
        if self.orphans.len() >= self.policy.max_orphans {
            // Drop the oldest orphan; orphans are cheap to send, so bound them.
            if let Some(oldest) = self
                .orphans
                .iter()
                .min_by_key(|(_, orphan)| orphan.time)
                .map(|(txid, _)| *txid)
            {
                self.orphans.remove(&oldest);
            }
        }
        self.orphans.insert(
            txid,
            Orphan {
                transaction,
                time: now,
            },
        );
    }

    /// Removes expired transactions and orphans. Returns the removed txids.
    pub fn expire(&mut self, now: u64) -> Vec<TransactionId> {
        let expired: Vec<TransactionId> = self
            .entries
            .values()
            .filter(|entry| now.saturating_sub(entry.time) >= self.policy.expiry_secs)
            .map(|entry| entry.txid)
            .collect();
        let mut removed = Vec::new();
        for txid in expired {
            if self.entries.contains_key(&txid) {
                removed.extend(self.remove_with_descendants(txid));
            }
        }
        let orphan_expiry = self.policy.orphan_expiry_secs;
        self.orphans
            .retain(|_, orphan| now.saturating_sub(orphan.time) < orphan_expiry);
        removed
    }

    /// Removes the transactions a newly connected block confirmed.
    ///
    /// Conflicting transactions are removed by the [`Mempool::resync`] that
    /// must follow, once the view reflects the new tip.
    pub fn remove_confirmed(&mut self, block: &Block) {
        for transaction in block.transactions() {
            let txid = transaction.txid();
            self.remove_entry(txid);
            self.orphans.remove(&txid);
        }
    }

    /// Revalidates every entry against `view` after the tip changed.
    ///
    /// Entries whose inputs are now missing (spent by a block, or created by a
    /// disconnected block that was not re-added) or invalid are dropped.
    /// Signatures are cached, so this is cheap.
    pub fn resync(&mut self, view: &ChainView<'_>, now: u64) {
        let mut entries: Vec<Entry> = self.entries.drain().map(|(_, entry)| entry).collect();
        self.spent_by.clear();
        self.total_bytes = 0;
        // Re-add parents before children: order by unconfirmed ancestry depth.
        let depth = depths(&entries);
        entries.sort_by_key(|entry| (depth[&entry.txid], entry.time));
        for entry in entries {
            let _ = self.add_one(entry.transaction, view, entry.time.min(now), false);
        }
    }

    /// Re-adds transactions of disconnected blocks, oldest block first.
    pub fn readd_disconnected(&mut self, blocks: &[Block], view: &ChainView<'_>, now: u64) {
        for block in blocks {
            for transaction in block.transactions().iter().skip(1) {
                if let Transaction::Normal(transaction) = transaction {
                    let _ = self.add_one(transaction.clone(), view, now, false);
                }
            }
        }
    }

    /// Chooses transactions for a block template, highest fee rate first,
    /// always after their unconfirmed parents.
    #[must_use]
    pub fn select(&self, max_bytes: usize, max_signatures: usize) -> Vec<NormalTransaction> {
        let mut candidates: Vec<&Entry> = self.entries.values().collect();
        candidates.sort_by(|a, b| b.fee_rate().cmp(&a.fee_rate()).then(a.time.cmp(&b.time)));
        let mut chosen: Vec<NormalTransaction> = Vec::new();
        let mut included: HashSet<TransactionId> = HashSet::new();
        let (mut bytes, mut signatures) = (0_usize, 0_usize);
        let mut progress = true;
        while progress {
            progress = false;
            for entry in &candidates {
                if included.contains(&entry.txid)
                    || !entry.parents.iter().all(|parent| included.contains(parent))
                {
                    continue;
                }
                let witnesses = entry.transaction.witnesses().len();
                if bytes + entry.size > max_bytes || signatures + witnesses > max_signatures {
                    continue;
                }
                bytes += entry.size;
                signatures += witnesses;
                included.insert(entry.txid);
                chosen.push(entry.transaction.clone());
                progress = true;
            }
        }
        chosen
    }
}

/// Unconfirmed ancestry depth of each entry (0 for entries with no parent in
/// the set).
fn depths(entries: &[Entry]) -> HashMap<TransactionId, usize> {
    let parents: HashMap<TransactionId, &HashSet<TransactionId>> = entries
        .iter()
        .map(|entry| (entry.txid, &entry.parents))
        .collect();
    let mut depth: HashMap<TransactionId, usize> = HashMap::new();
    fn visit(
        txid: TransactionId,
        parents: &HashMap<TransactionId, &HashSet<TransactionId>>,
        depth: &mut HashMap<TransactionId, usize>,
    ) -> usize {
        if let Some(known) = depth.get(&txid) {
            return *known;
        }
        let value = parents.get(&txid).map_or(0, |set| {
            set.iter()
                .filter(|parent| parents.contains_key(parent))
                .map(|parent| visit(*parent, parents, depth) + 1)
                .max()
                .unwrap_or(0)
        });
        depth.insert(txid, value);
        value
    }
    for entry in entries {
        visit(entry.txid, &parents, &mut depth);
    }
    depth
}

enum Insert {
    Accepted {
        txid: TransactionId,
        replaced: Vec<TransactionId>,
    },
    Orphaned,
}

/// Why a transaction was not accepted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MempoolError {
    /// Coinbase transactions only exist in blocks.
    Coinbase,
    /// The transaction is already in the pool or the orphan pool.
    AlreadyKnown,
    /// An input does not exist (and orphans are not allowed here).
    MissingInputs,
    /// An input spends a coinbase output that has not matured.
    ImmatureCoinbase,
    /// The transaction is invalid.
    Invalid(TransactionError),
    /// The fee is below the minimum relay fee.
    FeeTooLow {
        /// Required fee in satoshis.
        required: u64,
        /// Offered fee in satoshis.
        actual: u64,
    },
    /// A conflicting transaction is in the pool and replacement is refused.
    Replacement(&'static str),
    /// Too many unconfirmed ancestors.
    TooManyAncestors,
    /// An ancestor would have too many unconfirmed descendants.
    TooManyDescendants,
    /// The pool is full and the fee rate is too low to stay.
    MempoolFull,
    /// The chain state could not be read.
    Unavailable,
}

impl fmt::Display for MempoolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Coinbase => formatter.write_str("coinbase transactions are not relayed"),
            Self::AlreadyKnown => formatter.write_str("transaction already known"),
            Self::MissingInputs => formatter.write_str("missing inputs"),
            Self::ImmatureCoinbase => formatter.write_str("spends an immature coinbase"),
            Self::Invalid(error) => write!(formatter, "invalid transaction: {error}"),
            Self::FeeTooLow { required, actual } => {
                write!(formatter, "fee {actual} below minimum {required}")
            }
            Self::Replacement(reason) => write!(formatter, "replacement refused: {reason}"),
            Self::TooManyAncestors => formatter.write_str("too many unconfirmed ancestors"),
            Self::TooManyDescendants => formatter.write_str("too many unconfirmed descendants"),
            Self::MempoolFull => formatter.write_str("mempool full"),
            Self::Unavailable => formatter.write_str("the chain state could not be read"),
        }
    }
}

impl std::error::Error for MempoolError {}

#[cfg(test)]
mod tests;
