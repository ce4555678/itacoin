//! Chain selection: header validation, the most-work chain and
//! reorganization, as specified in `docs/CONSENSUS_PROPOSAL.md`.
//!
//! Every block that passes the header rules is stored with its index entry
//! before anything else happens. [`Chain`] then activates the valid chain with
//! the most accumulated work, reverting to the fork point and applying the
//! new branch. A block that fails full validation is marked invalid together
//! with its descendants, and activation picks the best valid chain again.
//!
//! Each revert and apply is atomic on disk, but a reorganization spans many
//! of them. After a crash the store holds some valid prefix; [`Chain::open`]
//! runs the same activation again and finishes the reorganization.

use core::{cmp::Reverse, fmt};
use std::{
    collections::{HashMap, VecDeque},
    path::Path,
};

use itacoin_blockchain::{Block, BlockHeader, HEADER_BYTES, Tip, UtxoError, UtxoSet};
use itacoin_codec::{Decode, Encode, Reader, Writer};
use itacoin_consensus::{
    AsertAnchor, ConsensusError, ConsensusParams, HeaderContext, MEDIAN_TIME_SPAN, U256,
    block_work, check_header, median_time_past, next_target,
};
use itacoin_primitives::{BlockId, Hash256};

use crate::{ChainStore, StorageError};

const ENTRY_BYTES: usize = HEADER_BYTES + 8 + 32 + 8 + 1;

/// What the chain knows about a stored block.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IndexEntry {
    /// The block header.
    pub header: BlockHeader,
    /// Height of the block.
    pub height: u64,
    /// Total work of the chain ending at this block.
    pub chain_work: U256,
    /// Arrival order, which breaks ties between chains of equal work.
    pub sequence: u64,
    /// Whether the block or one of its ancestors failed validation.
    pub invalid: bool,
}

impl IndexEntry {
    fn to_bytes(self) -> Vec<u8> {
        let mut writer = Writer::with_capacity(ENTRY_BYTES);
        self.header.encode(&mut writer);
        writer.u64(self.height);
        writer.bytes(&self.chain_work.to_be_bytes());
        writer.u64(self.sequence);
        writer.u8(u8::from(self.invalid));
        writer.into_bytes()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, ChainError> {
        let corrupt = |_| ChainError::Corrupt("index entry");
        let mut reader = Reader::new(bytes);
        let header =
            BlockHeader::decode(&mut reader).map_err(|_| ChainError::Corrupt("index header"))?;
        let entry = Self {
            header,
            height: reader.u64().map_err(corrupt)?,
            chain_work: U256::from_be_bytes(reader.array().map_err(corrupt)?),
            sequence: reader.u64().map_err(corrupt)?,
            invalid: match reader.u8().map_err(corrupt)? {
                0 => false,
                1 => true,
                _ => return Err(ChainError::Corrupt("index flag")),
            },
        };
        reader.finish().map_err(corrupt)?;
        Ok(entry)
    }
}

/// The result of submitting a block that passed the header rules.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubmitOutcome {
    /// The block was already known.
    Duplicate,
    /// The block is the new tip.
    NewTip,
    /// The block was stored on a chain with no more work than the active one.
    SideChain,
}

/// The active chain of one network, on durable storage.
pub struct Chain {
    store: ChainStore,
    params: ConsensusParams,
    chain_id: Hash256,
    anchor: AsertAnchor,
    index: HashMap<BlockId, IndexEntry>,
    next_sequence: u64,
}

impl Chain {
    /// Opens the chain at `path` for `params`, creating it from the network's
    /// genesis block if it is new, and finishes any interrupted
    /// reorganization.
    pub fn open(path: &Path, params: ConsensusParams) -> Result<Self, ChainError> {
        let genesis = params.genesis();
        let chain_id = genesis.id().into_hash();
        let store = ChainStore::open(path, chain_id)?;
        let mut index = HashMap::new();
        for (id, bytes) in store.index_entries()? {
            index.insert(id, IndexEntry::from_bytes(&bytes)?);
        }
        let next_sequence = index
            .values()
            .map(|entry| entry.sequence + 1)
            .max()
            .unwrap_or(0);
        let mut chain = Self {
            store,
            params,
            chain_id,
            anchor: params.asert_anchor(),
            index,
            next_sequence,
        };
        if chain.index.is_empty() {
            let entry = IndexEntry {
                header: *genesis.header(),
                height: 0,
                chain_work: block_work(params.pow_limit),
                sequence: 0,
                invalid: false,
            };
            chain.insert(&genesis, entry)?;
        }
        chain.activate_best_chain()?;
        Ok(chain)
    }

    /// Returns the network parameters.
    #[must_use]
    pub const fn params(&self) -> &ConsensusParams {
        &self.params
    }

    /// Returns the chain id (the genesis block id).
    #[must_use]
    pub const fn chain_id(&self) -> Hash256 {
        self.chain_id
    }

    /// Returns the active tip.
    #[must_use]
    pub const fn tip(&self) -> Option<Tip> {
        self.store.tip()
    }

    /// Returns the unspent-output set at the active tip.
    #[must_use]
    pub const fn utxo(&self) -> &UtxoSet {
        self.store.utxo()
    }

    /// Returns the underlying store, for block and height queries.
    #[must_use]
    pub const fn store(&self) -> &ChainStore {
        &self.store
    }

    /// Returns the index entry of a known block.
    #[must_use]
    pub fn entry(&self, block_id: &BlockId) -> Option<&IndexEntry> {
        self.index.get(block_id)
    }

    /// Iterates over every known block's index entry, in no particular order.
    pub fn index(&self) -> impl Iterator<Item = (&BlockId, &IndexEntry)> {
        self.index.iter()
    }

    /// Returns the last common ancestor of two known blocks.
    #[must_use]
    pub fn common_ancestor(&self, a: BlockId, b: BlockId) -> Option<BlockId> {
        if !self.index.contains_key(&a) || !self.index.contains_key(&b) {
            return None;
        }
        self.fork_point(Some(a), b)
    }

    /// Returns the blocks after `ancestor` up to and including `tip`, oldest
    /// first. `ancestor` must be an ancestor of `tip`.
    #[must_use]
    pub fn branch(&self, ancestor: BlockId, tip: BlockId) -> Vec<BlockId> {
        if !self.index.contains_key(&tip) {
            return Vec::new();
        }
        self.path(Some(ancestor), tip)
    }

    /// Returns the target the block after `parent` must have.
    pub fn next_target(&self, parent: &BlockId) -> Result<U256, ChainError> {
        let parent = self
            .index
            .get(parent)
            .ok_or(ChainError::UnknownParent(*parent))?;
        Ok(self.target_after(parent))
    }

    /// Validates the header rules of `block`, stores it, and activates the
    /// chain with the most work.
    ///
    /// `now` is the local clock in seconds since the Unix epoch. A block that
    /// fails the header rules is not stored. A block that passes them is
    /// stored even if it ends up on a side chain; it is fully validated only
    /// when its chain becomes the one with the most work.
    pub fn submit_block(&mut self, block: &Block, now: u64) -> Result<SubmitOutcome, ChainError> {
        let block_id = block.id();
        if self.index.contains_key(&block_id) {
            return Ok(SubmitOutcome::Duplicate);
        }
        let parent_id = block.header().prev_block;
        let parent = *self
            .index
            .get(&parent_id)
            .ok_or(ChainError::UnknownParent(parent_id))?;
        if parent.invalid {
            return Err(ChainError::InvalidParent(parent_id));
        }
        let height = parent.height + 1;
        if block.height() != height {
            return Err(ChainError::WrongHeight {
                expected: height,
                actual: block.height(),
            });
        }
        let context = HeaderContext {
            expected_target: self.target_after(&parent),
            median_time_past: self.median_time_past(parent_id),
            now,
        };
        check_header(block.header(), &context, &self.chain_id, &self.params)?;
        let chain_work = parent
            .chain_work
            .checked_add(block_work(context.expected_target))
            .ok_or(ChainError::Corrupt("chain work overflow"))?;

        let entry = IndexEntry {
            header: *block.header(),
            height,
            chain_work,
            sequence: self.next_sequence,
            invalid: false,
        };
        self.insert(block, entry)?;

        let failures = self.activate_best_chain()?;
        if let Some(error) = failures.get(&block_id) {
            return Err(ChainError::InvalidBlock {
                block_id,
                error: error.clone(),
            });
        }
        if self.index[&block_id].invalid {
            return Err(ChainError::InvalidAncestor(block_id));
        }
        Ok(if self.tip().map(|tip| tip.block_id) == Some(block_id) {
            SubmitOutcome::NewTip
        } else {
            SubmitOutcome::SideChain
        })
    }

    fn insert(&mut self, block: &Block, entry: IndexEntry) -> Result<(), ChainError> {
        self.store.store_block(block, &entry.to_bytes())?;
        self.index.insert(block.id(), entry);
        self.next_sequence = self.next_sequence.max(entry.sequence + 1);
        Ok(())
    }

    fn target_after(&self, parent: &IndexEntry) -> U256 {
        let time = i64::try_from(parent.header.timestamp).unwrap_or(i64::MAX);
        next_target(&self.anchor, parent.height, time, &self.params)
    }

    fn median_time_past(&self, mut block_id: BlockId) -> u64 {
        let mut timestamps = Vec::with_capacity(MEDIAN_TIME_SPAN);
        while let Some(entry) = self.index.get(&block_id) {
            timestamps.push(entry.header.timestamp);
            if timestamps.len() == MEDIAN_TIME_SPAN || entry.height == 0 {
                break;
            }
            block_id = entry.header.prev_block;
        }
        median_time_past(&timestamps)
    }

    /// The valid block with the most work; the earliest arrival wins ties.
    fn best_candidate(&self) -> BlockId {
        self.index
            .iter()
            .filter(|(_, entry)| !entry.invalid)
            .max_by_key(|(_, entry)| (entry.chain_work, Reverse(entry.sequence)))
            .map(|(id, _)| *id)
            .expect("the genesis block is always valid")
    }

    fn parent(&self, block_id: &BlockId) -> BlockId {
        self.index[block_id].header.prev_block
    }

    fn fork_point(&self, tip: Option<BlockId>, best: BlockId) -> Option<BlockId> {
        let mut a = tip?;
        let mut b = best;
        while self.index[&a].height > self.index[&b].height {
            a = self.parent(&a);
        }
        while self.index[&b].height > self.index[&a].height {
            b = self.parent(&b);
        }
        while a != b {
            a = self.parent(&a);
            b = self.parent(&b);
        }
        Some(a)
    }

    /// Block ids after `fork` up to and including `best`, oldest first.
    fn path(&self, fork: Option<BlockId>, best: BlockId) -> Vec<BlockId> {
        let mut path = Vec::new();
        let mut current = best;
        loop {
            if Some(current) == fork {
                break;
            }
            path.push(current);
            if self.index[&current].height == 0 {
                break;
            }
            current = self.parent(&current);
        }
        path.reverse();
        path
    }

    fn rules(&self, height: u64) -> itacoin_blockchain::BlockRules {
        self.params.block_rules(self.chain_id, height)
    }

    /// Switches to the valid chain with the most work. Returns the blocks
    /// found invalid on the way, with the reason.
    fn activate_best_chain(&mut self) -> Result<HashMap<BlockId, UtxoError>, ChainError> {
        let mut failures = HashMap::new();
        loop {
            let best = self.best_candidate();
            let tip = self.tip().map(|tip| tip.block_id);
            if tip == Some(best) {
                return Ok(failures);
            }
            let fork = self.fork_point(tip, best);
            let path = self.path(fork, best);
            // Defense in depth: a candidate above an invalid block is itself
            // invalid, even if its flag was never set. Without this check the
            // loop would retry the same branch forever.
            if path.iter().any(|id| self.index[id].invalid) {
                self.mark_invalid(best)?;
                continue;
            }

            while self.tip().map(|tip| tip.block_id) != fork {
                self.store.revert_tip()?;
            }
            for block_id in &path {
                let block = self
                    .store
                    .block(block_id)?
                    .ok_or(ChainError::Corrupt("indexed block missing"))?;
                let rules = self.rules(block.height());
                match self.store.apply_block(&block, &rules) {
                    Ok(()) => {}
                    Err(StorageError::Utxo(error)) => {
                        // The tip stays at the last valid block of this
                        // branch; the next iteration picks the best valid
                        // chain again and reorganizes to it.
                        self.mark_invalid(*block_id)?;
                        failures.insert(*block_id, error);
                        break;
                    }
                    Err(error) => return Err(error.into()),
                }
            }
        }
    }

    /// Marks a block and all of its known descendants invalid, durably.
    fn mark_invalid(&mut self, block_id: BlockId) -> Result<(), ChainError> {
        let mut children: HashMap<BlockId, Vec<BlockId>> = HashMap::new();
        for (id, entry) in &self.index {
            children
                .entry(entry.header.prev_block)
                .or_default()
                .push(*id);
        }
        let mut queue = VecDeque::from([block_id]);
        let mut updates = Vec::new();
        while let Some(id) = queue.pop_front() {
            let entry = self.index.get_mut(&id).expect("indexed");
            if !entry.invalid {
                entry.invalid = true;
                updates.push((id, entry.to_bytes()));
            }
            queue.extend(children.get(&id).into_iter().flatten().copied());
        }
        self.store.store_index_entries(&updates)?;
        Ok(())
    }
}

impl fmt::Debug for Chain {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Chain")
            .field("network", &self.params.network)
            .field("tip", &self.tip())
            .field("known_blocks", &self.index.len())
            .finish_non_exhaustive()
    }
}

/// Errors from submitting blocks or opening the chain.
#[derive(Debug)]
pub enum ChainError {
    /// The store failed.
    Storage(StorageError),
    /// The header breaks a consensus rule; the block was not stored.
    Consensus(ConsensusError),
    /// The parent is unknown; the block may be retried once it arrives.
    UnknownParent(BlockId),
    /// The parent is known to be invalid.
    InvalidParent(BlockId),
    /// The coinbase height is not one more than the parent's.
    WrongHeight {
        /// Parent height plus one.
        expected: u64,
        /// The coinbase height.
        actual: u64,
    },
    /// The block failed full validation and was marked invalid.
    InvalidBlock {
        /// The invalid block.
        block_id: BlockId,
        /// Why it failed.
        error: UtxoError,
    },
    /// The block was marked invalid because an ancestor failed validation.
    InvalidAncestor(BlockId),
    /// Stored data is inconsistent.
    Corrupt(&'static str),
}

impl From<StorageError> for ChainError {
    fn from(error: StorageError) -> Self {
        Self::Storage(error)
    }
}

impl From<ConsensusError> for ChainError {
    fn from(error: ConsensusError) -> Self {
        Self::Consensus(error)
    }
}

impl fmt::Display for ChainError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Storage(error) => write!(formatter, "{error}"),
            Self::Consensus(error) => write!(formatter, "invalid header: {error}"),
            Self::UnknownParent(id) => write!(formatter, "unknown parent block {id}"),
            Self::InvalidParent(id) => write!(formatter, "parent block {id} is invalid"),
            Self::WrongHeight { expected, actual } => {
                write!(formatter, "coinbase height {actual}, expected {expected}")
            }
            Self::InvalidBlock { block_id, error } => {
                write!(formatter, "block {block_id} is invalid: {error}")
            }
            Self::InvalidAncestor(id) => {
                write!(formatter, "block {id} descends from an invalid block")
            }
            Self::Corrupt(what) => write!(formatter, "corrupt chain index: {what}"),
        }
    }
}

impl std::error::Error for ChainError {}

#[cfg(test)]
mod tests;
