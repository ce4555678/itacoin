//! Header tree and header-first synchronization (section 4 of
//! `docs/NETWORK_PROPOSAL.md`).
//!
//! The tree holds validated headers, including those whose blocks have not
//! arrived yet. A batch of headers is checked cheapest rule first, and the
//! Argon2id proofs of work of a batch are verified in parallel.
//!
//! # Low-work header spam
//!
//! A branch is stored only if its work reaches [`HeaderTree::min_chain_work`]
//! and it either forks at most [`MAX_SHALLOW_FORK`] blocks below the best
//! header or ends with more work than it. Otherwise the peer's headers are
//! *presynced*: verified but not stored, keeping only a 4-byte salted
//! commitment per header. Once the presynced branch has enough work, the
//! headers are downloaded again from the fork, checked against the
//! commitments (so the peer cannot swap in a different branch), and stored.

use std::collections::{HashMap, VecDeque};

use itacoin_blockchain::BlockHeader;
use itacoin_consensus::{
    AsertAnchor, ConsensusError, ConsensusParams, HeaderContext, MEDIAN_TIME_SPAN, U256,
    block_work, check_header_context, check_pow, median_time_past, next_target,
};
use itacoin_primitives::{BlockId, Hash256};
use rand_core::{OsRng, RngCore};

/// A side branch that forks deeper than this below the best header is stored
/// only once it has more work than the best header.
pub const MAX_SHALLOW_FORK: u64 = 288;
/// Most headers one peer may presync before it is disconnected.
pub const MAX_PRESYNC_HEADERS: usize = 10_000_000;

/// A validated header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HeaderNode {
    /// The header.
    pub header: BlockHeader,
    /// Its height.
    pub height: u64,
    /// Total work of the chain ending here.
    pub work: U256,
    /// Whether the block (or an ancestor) is known to be invalid.
    pub invalid: bool,
    /// Whether the full block is stored.
    pub have_block: bool,
}

/// Per-peer header synchronization state.
#[derive(Debug)]
pub struct PeerHeaderSync {
    salt: [u8; 32],
    presync: Option<Presync>,
    redownload: Option<Redownload>,
    /// The best header this peer is known to have.
    pub best_known: Option<BlockId>,
}

impl Default for PeerHeaderSync {
    fn default() -> Self {
        let mut salt = [0_u8; 32];
        OsRng.fill_bytes(&mut salt);
        Self {
            salt,
            presync: None,
            redownload: None,
            best_known: None,
        }
    }
}

impl PeerHeaderSync {
    /// Whether the peer is in presync or redownload.
    #[must_use]
    pub const fn is_presyncing(&self) -> bool {
        self.presync.is_some()
    }
}

#[derive(Debug)]
struct Presync {
    fork: BlockId,
    /// Context of the last verified header of the branch.
    tip: Parent,
    commitments: Vec<[u8; 4]>,
}

#[derive(Debug)]
struct Redownload {
    commitments: Vec<[u8; 4]>,
    position: usize,
}

/// What processing a `headers` message produced.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HeaderOutcome {
    /// Headers were stored. `full` means the message was full and more may
    /// follow from `last`.
    Stored {
        /// Newly stored header ids, in order.
        new: Vec<BlockId>,
        /// The last header of the message.
        last: BlockId,
        /// Whether the message had the maximum number of headers.
        full: bool,
    },
    /// The branch does not have enough work yet; headers were verified but
    /// not stored. Ask for more after `last`.
    Presyncing {
        /// The last header of the message.
        last: BlockId,
        /// Whether the message had the maximum number of headers.
        full: bool,
    },
    /// The presynced branch has enough work: download it again from `fork`.
    Redownload {
        /// Where the branch leaves the stored tree.
        fork: BlockId,
    },
    /// The first header's parent is unknown.
    Unconnected,
}

/// Why a batch of headers was rejected. The peer is misbehaving, except
/// for [`ConsensusError::TimestampInFuture`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HeaderError {
    /// A header breaks a consensus rule.
    Consensus(ConsensusError),
    /// The headers of a message are not a chain.
    NotContinuous,
    /// A header descends from an invalid block.
    InvalidAncestor,
    /// The redownloaded branch differs from the presynced one.
    CommitmentMismatch,
    /// The presynced branch is longer than [`MAX_PRESYNC_HEADERS`].
    TooLong,
    /// Accumulated work exceeds 256 bits.
    WorkOverflow,
}

/// Id, height and chain work of each validated header, plus the context
/// after the last one.
type Validated = (Vec<(BlockId, u64, U256)>, Parent);

/// The context of the parent of the next header to validate.
#[derive(Debug)]
struct Parent {
    id: BlockId,
    timestamp: u64,
    height: u64,
    work: U256,
    /// Timestamps of up to [`MEDIAN_TIME_SPAN`] blocks ending at the parent.
    timestamps: VecDeque<u64>,
}

/// The tree of validated headers.
#[derive(Debug)]
pub struct HeaderTree {
    params: ConsensusParams,
    chain_id: Hash256,
    anchor: AsertAnchor,
    min_chain_work: U256,
    nodes: HashMap<BlockId, HeaderNode>,
    best: BlockId,
}

impl HeaderTree {
    /// Builds the tree from stored blocks: `(id, header, height, work,
    /// invalid)` for every block in the chain index.
    #[must_use]
    pub fn new(
        params: ConsensusParams,
        chain_id: Hash256,
        min_chain_work: U256,
        stored: impl IntoIterator<Item = (BlockId, BlockHeader, u64, U256, bool)>,
    ) -> Self {
        let nodes: HashMap<BlockId, HeaderNode> = stored
            .into_iter()
            .map(|(id, header, height, work, invalid)| {
                (
                    id,
                    HeaderNode {
                        header,
                        height,
                        work,
                        invalid,
                        have_block: true,
                    },
                )
            })
            .collect();
        let mut tree = Self {
            params,
            chain_id,
            anchor: params.asert_anchor(),
            min_chain_work,
            best: BlockId::new(chain_id),
            nodes,
        };
        tree.recompute_best();
        tree
    }

    /// The best valid header.
    #[must_use]
    pub fn best(&self) -> (BlockId, &HeaderNode) {
        (self.best, &self.nodes[&self.best])
    }

    /// The minimum work a branch needs to be stored.
    #[must_use]
    pub const fn min_chain_work(&self) -> U256 {
        self.min_chain_work
    }

    /// Looks up a header.
    #[must_use]
    pub fn get(&self, id: &BlockId) -> Option<&HeaderNode> {
        self.nodes.get(id)
    }

    /// Number of headers.
    #[must_use]
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Whether the tree is empty (never: it always holds genesis).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Records that a block is stored, adding its header if it was unknown
    /// (blocks can arrive without a preceding `headers` message).
    pub fn block_stored(&mut self, id: BlockId, header: BlockHeader, height: u64, work: U256) {
        let node = self.nodes.entry(id).or_insert(HeaderNode {
            header,
            height,
            work,
            invalid: false,
            have_block: false,
        });
        node.have_block = true;
        if !node.invalid && work > self.nodes[&self.best].work {
            self.best = id;
        }
    }

    /// Marks a header and all known descendants invalid.
    pub fn mark_invalid(&mut self, id: BlockId) {
        let mut children: HashMap<BlockId, Vec<BlockId>> = HashMap::new();
        for (child, node) in &self.nodes {
            children
                .entry(node.header.prev_block)
                .or_default()
                .push(*child);
        }
        let mut stack = vec![id];
        while let Some(id) = stack.pop() {
            if let Some(node) = self.nodes.get_mut(&id)
                && !node.invalid
            {
                node.invalid = true;
                stack.extend(children.get(&id).into_iter().flatten().copied());
            }
        }
        self.recompute_best();
    }

    fn recompute_best(&mut self) {
        if let Some((id, _)) = self
            .nodes
            .iter()
            .filter(|(_, node)| !node.invalid)
            .max_by_key(|(id, node)| (node.work, core::cmp::Reverse(**id)))
        {
            self.best = *id;
        }
    }

    /// Returns a locator for `from`: the last 10 ancestors one by one, then
    /// exponentially sparser, always ending at genesis.
    #[must_use]
    pub fn locator(&self, from: BlockId) -> Vec<BlockId> {
        let mut locator = Vec::new();
        let mut current = from;
        let mut step = 1_u64;
        while let Some(node) = self.nodes.get(&current) {
            locator.push(current);
            if node.height == 0 || locator.len() == crate::message::MAX_LOCATOR - 1 {
                break;
            }
            if locator.len() >= 10 {
                step *= 2;
            }
            let target = node.height.saturating_sub(step);
            match self.ancestor_at(current, target) {
                Some(ancestor) => current = ancestor,
                None => break,
            }
        }
        let genesis = BlockId::new(self.chain_id);
        if locator.last() != Some(&genesis) {
            locator.push(genesis);
        }
        locator
    }

    /// The ancestor of `from` at `height`.
    #[must_use]
    pub fn ancestor_at(&self, from: BlockId, height: u64) -> Option<BlockId> {
        let mut current = from;
        loop {
            let node = self.nodes.get(&current)?;
            if node.height == height {
                return Some(current);
            }
            if node.height < height {
                return None;
            }
            current = node.header.prev_block;
        }
    }

    /// Headers on the path to `to` whose blocks are missing, oldest first, at
    /// most `limit`.
    #[must_use]
    pub fn missing_blocks(&self, to: BlockId, limit: usize) -> Vec<BlockId> {
        let mut missing = Vec::new();
        let mut current = to;
        while let Some(node) = self.nodes.get(&current) {
            if node.have_block {
                break;
            }
            missing.push(current);
            current = node.header.prev_block;
        }
        missing.reverse();
        missing.truncate(limit);
        missing
    }

    fn parent_from_tree(&self, id: BlockId) -> Option<Parent> {
        let node = self.nodes.get(&id)?;
        let mut timestamps = VecDeque::with_capacity(MEDIAN_TIME_SPAN);
        let mut current = Some(id);
        while let Some(cursor) = current {
            let Some(ancestor) = self.nodes.get(&cursor) else {
                break;
            };
            timestamps.push_front(ancestor.header.timestamp);
            if timestamps.len() == MEDIAN_TIME_SPAN || ancestor.height == 0 {
                break;
            }
            current = Some(ancestor.header.prev_block);
        }
        Some(Parent {
            id,
            timestamp: node.header.timestamp,
            height: node.height,
            work: node.work,
            timestamps,
        })
    }

    /// Validates a continuous batch after `parent`. Returns the ids, heights
    /// and chain work of each header, and the final parent context.
    fn validate(
        &self,
        mut parent: Parent,
        headers: &[BlockHeader],
        now: u64,
    ) -> Result<Validated, HeaderError> {
        let mut out = Vec::with_capacity(headers.len());
        for header in headers {
            if header.prev_block != parent.id {
                return Err(HeaderError::NotContinuous);
            }
            let time = i64::try_from(parent.timestamp).unwrap_or(i64::MAX);
            let expected_target = next_target(&self.anchor, parent.height, time, &self.params);
            let mtp = median_time_past(parent.timestamps.make_contiguous());
            let context = HeaderContext {
                expected_target,
                median_time_past: mtp,
                now,
            };
            check_header_context(header, &context, &self.params).map_err(HeaderError::Consensus)?;
            let id = header.id();
            let height = parent.height + 1;
            let work = parent
                .work
                .checked_add(block_work(expected_target))
                .ok_or(HeaderError::WorkOverflow)?;
            out.push((id, height, work));
            parent.timestamps.push_back(header.timestamp);
            if parent.timestamps.len() > MEDIAN_TIME_SPAN {
                parent.timestamps.pop_front();
            }
            parent.id = id;
            parent.timestamp = header.timestamp;
            parent.height = height;
            parent.work = work;
        }
        self.check_pow_parallel(headers)?;
        Ok((out, parent))
    }

    /// Verifies the proofs of work of a batch across the available cores.
    fn check_pow_parallel(&self, headers: &[BlockHeader]) -> Result<(), HeaderError> {
        let threads = std::thread::available_parallelism()
            .map_or(1, std::num::NonZeroUsize::get)
            .min(headers.len().max(1));
        let chunk = headers.len().div_ceil(threads).max(1);
        let chain_id = self.chain_id;
        let all_valid = std::thread::scope(|scope| {
            let handles: Vec<_> = headers
                .chunks(chunk)
                .map(|part| {
                    scope.spawn(move || part.iter().all(|header| check_pow(header, &chain_id)))
                })
                .collect();
            handles
                .into_iter()
                .all(|handle| handle.join().unwrap_or(false))
        });
        if all_valid {
            Ok(())
        } else {
            Err(HeaderError::Consensus(ConsensusError::InsufficientWork))
        }
    }

    fn store(
        &mut self,
        headers: &[BlockHeader],
        validated: &[(BlockId, u64, U256)],
    ) -> Vec<BlockId> {
        let mut new = Vec::new();
        for (header, (id, height, work)) in headers.iter().zip(validated) {
            if self.nodes.contains_key(id) {
                continue;
            }
            self.nodes.insert(
                *id,
                HeaderNode {
                    header: *header,
                    height: *height,
                    work: *work,
                    invalid: false,
                    have_block: false,
                },
            );
            if *work > self.nodes[&self.best].work {
                self.best = *id;
            }
            new.push(*id);
        }
        new
    }

    /// Processes a `headers` message from a peer.
    pub fn process(
        &mut self,
        sync: &mut PeerHeaderSync,
        headers: &[BlockHeader],
        now: u64,
    ) -> Result<HeaderOutcome, HeaderError> {
        let full = headers.len() == crate::message::MAX_HEADERS;
        let Some(first) = headers.first() else {
            return Ok(HeaderOutcome::Stored {
                new: Vec::new(),
                last: self.best,
                full: false,
            });
        };
        let last = headers.last().expect("non-empty").id();

        // Continue a presync.
        if let Some(presync) = sync.presync.as_ref()
            && presync.tip.id == first.prev_block
        {
            return self.continue_presync(sync, headers, now, last, full);
        }

        // Skip headers already known.
        let known = headers
            .iter()
            .take_while(|header| self.nodes.contains_key(&header.id()))
            .count();
        let fresh = &headers[known..];
        let Some(first_fresh) = fresh.first() else {
            sync.best_known = Some(last);
            return Ok(HeaderOutcome::Stored {
                new: Vec::new(),
                last,
                full,
            });
        };
        let Some(fork) = self.nodes.get(&first_fresh.prev_block).copied() else {
            return Ok(HeaderOutcome::Unconnected);
        };
        if fork.invalid {
            return Err(HeaderError::InvalidAncestor);
        }
        let parent = self
            .parent_from_tree(first_fresh.prev_block)
            .expect("fork is in the tree");
        let (validated, final_parent) = self.validate(parent, fresh, now)?;

        // Redownload of a presynced branch: must match the commitments.
        if let Some(redownload) = sync.redownload.as_mut() {
            for (id, _, _) in &validated {
                let expected = redownload.commitments.get(redownload.position).copied();
                if expected != Some(sync_commit(&sync.salt, id)) {
                    sync.redownload = None;
                    return Err(HeaderError::CommitmentMismatch);
                }
                redownload.position += 1;
            }
            if redownload.position == redownload.commitments.len() {
                sync.redownload = None;
            }
            let new = self.store(fresh, &validated);
            sync.best_known = Some(last);
            return Ok(HeaderOutcome::Stored { new, last, full });
        }

        let best_work = self.nodes[&self.best].work;
        let depth = self.nodes[&self.best].height.saturating_sub(fork.height);
        let enough = final_parent.work >= self.min_chain_work
            && (depth <= MAX_SHALLOW_FORK || final_parent.work > best_work);
        if enough {
            let new = self.store(fresh, &validated);
            sync.best_known = Some(last);
            return Ok(HeaderOutcome::Stored { new, last, full });
        }

        // Start a presync: keep only commitments and the tip context.
        let commitments = validated
            .iter()
            .map(|(id, _, _)| sync_commit(&sync.salt, id))
            .collect();
        sync.presync = Some(Presync {
            fork: first_fresh.prev_block,
            tip: final_parent,
            commitments,
        });
        Ok(HeaderOutcome::Presyncing { last, full })
    }

    fn continue_presync(
        &mut self,
        sync: &mut PeerHeaderSync,
        headers: &[BlockHeader],
        now: u64,
        last: BlockId,
        full: bool,
    ) -> Result<HeaderOutcome, HeaderError> {
        let mut presync = sync.presync.take().expect("checked");
        let parent = Parent {
            id: presync.tip.id,
            timestamp: presync.tip.timestamp,
            height: presync.tip.height,
            work: presync.tip.work,
            timestamps: presync.tip.timestamps.clone(),
        };
        let (validated, final_parent) = self.validate(parent, headers, now)?;
        presync.commitments.extend(
            validated
                .iter()
                .map(|(id, _, _)| sync_commit(&sync.salt, id)),
        );
        if presync.commitments.len() > MAX_PRESYNC_HEADERS {
            return Err(HeaderError::TooLong);
        }
        presync.tip = final_parent;

        let best_work = self.nodes[&self.best].work;
        if presync.tip.work >= self.min_chain_work && presync.tip.work > best_work {
            sync.redownload = Some(Redownload {
                commitments: presync.commitments,
                position: 0,
            });
            return Ok(HeaderOutcome::Redownload { fork: presync.fork });
        }
        sync.presync = Some(presync);
        Ok(HeaderOutcome::Presyncing { last, full })
    }
}

fn sync_commit(salt: &[u8; 32], id: &BlockId) -> [u8; 4] {
    let digest = blake3::keyed_hash(salt, id.as_bytes());
    digest.as_bytes()[..4].try_into().expect("4 bytes")
}

#[cfg(test)]
mod tests;
