//! Durable, crash-safe ITACOIN chain state (`docs/STORAGE_PROPOSAL.md`).
//!
//! The chain is stored in a single [redb] file, and the disk is the source of
//! truth at every block: each applied or reverted block is one ACID write
//! transaction holding the coin changes, the wallet index, the block's undo
//! data, the height index, the tip and the supply. A crash at any point
//! leaves the file at a whole block, never in between.
//!
//! Coins are read from disk through a bounded, two-generation read cache
//! ([`StoreOptions::coin_cache_bytes`]); nothing holds the whole set in
//! memory. During initial sync, commits can be batched
//! ([`ChainStore::set_bulk`]): non-durable commits in between are still
//! whole blocks, so a crash only rolls back to the last durable one.
//!
//! [redb]: https://docs.rs/redb

use core::{cell::RefCell, fmt};
use std::{
    collections::{HashMap, HashSet},
    path::Path,
    time::{Duration, Instant},
};

use itacoin_blockchain::{
    Block, BlockRules, BlockShape, BlockUndo, BodyTransaction, Coin, CoinSource, PrunedBlock,
    SourceError, Tip, UtxoDelta, UtxoError, UtxoSet, created_outpoints_of, revert_delta,
    validate_block,
};
use itacoin_codec::{Decode, Encode, Reader, decode_exact};
use itacoin_primitives::{Amount, BlockId, Hash256, WalletId};
use itacoin_transaction::{OutPoint, TransactionError};
use redb::{
    Database, Durability, ReadOnlyTable, ReadableDatabase, ReadableTable, ReadableTableMetadata,
    TableDefinition, WriteTransaction,
};

/// Version of the on-disk layout. Version 1 files are upgraded on open.
pub const SCHEMA_VERSION: u32 = 2;
/// Default size of the coin cache.
pub const DEFAULT_COIN_CACHE_BYTES: usize = 300 * 1024 * 1024;
/// Smallest coin cache accepted.
pub const MIN_COIN_CACHE_BYTES: usize = 16 * 1024 * 1024;
/// Default number of recent blocks whose witnesses are kept when pruning.
pub const DEFAULT_PRUNE_DEPTH: u64 = 2_880;
/// Fewest recent blocks a pruning node keeps whole: the blocks the network
/// serves without limit.
pub const MIN_PRUNE_DEPTH: u64 = 288;
/// Most blocks pruned after one new block, so pruning never stalls
/// validation.
pub const PRUNE_BATCH: u64 = 100;
/// During initial sync, a durable commit every this many commits…
pub const BULK_DURABLE_EVERY: usize = 1_000;
/// …or this often, whichever comes first.
pub const BULK_DURABLE_INTERVAL: Duration = Duration::from_secs(30);
/// Approximate memory per cached coin, for the cache budget.
const CACHE_ENTRY_BYTES: usize = 200;

/// Unspent outputs: encoded `OutPoint` → encoded `Coin`.
const COINS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("coins");
/// Full blocks: block id → encoded block.
const BLOCKS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("blocks");
/// Blocks of the active chain whose witnesses were pruned: block id →
/// encoded [`PrunedBlock`].
const PRUNED: TableDefinition<&[u8], &[u8]> = TableDefinition::new("pruned");
/// Undo data of the blocks on the current chain: block id → encoded undo.
const UNDO: TableDefinition<&[u8], &[u8]> = TableDefinition::new("undo");
/// The current chain: height → block id.
const HEIGHTS: TableDefinition<u64, &[u8]> = TableDefinition::new("heights");
/// Header index, including side chains: block id → index entry, encoded by
/// [`chain`].
const HEADERS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("headers");
/// Coins by owner: wallet id ‖ encoded `OutPoint` → nothing.
const WALLET_COINS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("wallet_coins");
/// Store metadata.
const META: TableDefinition<&str, &[u8]> = TableDefinition::new("meta");

const META_SCHEMA: &str = "schema";
const META_CHAIN_ID: &str = "chain_id";
const META_TIP: &str = "tip";
const META_SUPPLY: &str = "supply";
const META_COINS: &str = "coins";
const META_WALLET_INDEX: &str = "wallet_index";
const META_PRUNE_DEPTH: &str = "prune_depth";
const META_PRUNED_TO: &str = "pruned_to";

/// How a store is opened.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StoreOptions {
    /// Memory for the coin read cache.
    pub coin_cache_bytes: usize,
    /// Keep the index of coins by wallet id.
    pub wallet_index: bool,
    /// Prune the witnesses of blocks deeper than this; `None` keeps
    /// everything (archive mode). Once set, it cannot be turned off.
    pub prune_depth: Option<u64>,
}

impl Default for StoreOptions {
    fn default() -> Self {
        Self {
            coin_cache_bytes: DEFAULT_COIN_CACHE_BYTES,
            wallet_index: true,
            prune_depth: None,
        }
    }
}

/// Totals of the unspent-output set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UtxoStats {
    /// Number of unspent outputs.
    pub coins: u64,
    /// Their total value.
    pub total_value: Amount,
}

/// A stored block: whole, or with its witnesses pruned.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StoredBlock {
    /// The whole block.
    Full(Block),
    /// A block of the active chain whose witnesses were pruned after this
    /// node validated it.
    Pruned(PrunedBlock),
}

impl StoredBlock {
    /// The block id.
    #[must_use]
    pub fn id(&self) -> BlockId {
        match self {
            Self::Full(block) => block.id(),
            Self::Pruned(block) => block.id(),
        }
    }

    /// The height.
    #[must_use]
    pub fn height(&self) -> u64 {
        match self {
            Self::Full(block) => block.height(),
            Self::Pruned(block) => block.height(),
        }
    }

    /// The full block, if it was not pruned.
    #[must_use]
    pub fn into_full(self) -> Option<Block> {
        match self {
            Self::Full(block) => Some(block),
            Self::Pruned(_) => None,
        }
    }
}

/// The coin read cache: two generations, an approximate LRU in O(1).
///
/// Reads and new coins go to the hot generation. When it holds half the
/// budget, the cold generation is dropped and the hot one becomes cold.
#[derive(Debug, Default)]
struct CoinCache {
    hot: HashMap<OutPoint, Coin>,
    cold: HashMap<OutPoint, Coin>,
    half: usize,
    hits: u64,
    misses: u64,
}

impl CoinCache {
    fn new(bytes: usize) -> Self {
        Self {
            half: (bytes.max(MIN_COIN_CACHE_BYTES) / CACHE_ENTRY_BYTES / 2).max(1),
            ..Self::default()
        }
    }

    fn get(&mut self, outpoint: &OutPoint) -> Option<Coin> {
        if let Some(coin) = self.hot.get(outpoint) {
            self.hits += 1;
            return Some(*coin);
        }
        if let Some(coin) = self.cold.remove(outpoint) {
            self.hits += 1;
            self.insert(*outpoint, coin);
            return Some(coin);
        }
        self.misses += 1;
        None
    }

    fn insert(&mut self, outpoint: OutPoint, coin: Coin) {
        self.cold.remove(&outpoint);
        self.hot.insert(outpoint, coin);
        if self.hot.len() >= self.half {
            self.cold = std::mem::take(&mut self.hot);
        }
    }

    fn remove(&mut self, outpoint: &OutPoint) {
        self.hot.remove(outpoint);
        self.cold.remove(outpoint);
    }

    fn clear(&mut self) {
        self.hot.clear();
        self.cold.clear();
    }

    fn len(&self) -> usize {
        self.hot.len() + self.cold.len()
    }
}

/// Coins read through the cache, then from one read transaction.
struct DiskCoins<'a> {
    cache: &'a RefCell<CoinCache>,
    table: ReadOnlyTable<&'static [u8], &'static [u8]>,
    error: RefCell<Option<StorageError>>,
}

impl DiskCoins<'_> {
    fn read(&self, outpoint: &OutPoint) -> Result<Option<Coin>, StorageError> {
        if let Some(coin) = self.cache.borrow_mut().get(outpoint) {
            return Ok(Some(coin));
        }
        let Some(bytes) = self
            .table
            .get(outpoint.to_bytes().as_slice())
            .map_err(database)?
        else {
            return Ok(None);
        };
        let coin = decode_exact::<Coin>(bytes.value(), usize::MAX)
            .map_err(|_: TransactionError| StorageError::Corrupt("coin"))?;
        self.cache.borrow_mut().insert(*outpoint, coin);
        Ok(Some(coin))
    }
}

impl CoinSource for DiskCoins<'_> {
    fn coin(&self, outpoint: &OutPoint) -> Result<Option<Coin>, SourceError> {
        self.read(outpoint).map_err(|error| {
            *self.error.borrow_mut() = Some(error);
            SourceError
        })
    }
}

/// A [`CoinSource`] over a store, for the mempool.
pub struct StoreCoins<'a>(&'a ChainStore);

impl CoinSource for StoreCoins<'_> {
    fn coin(&self, outpoint: &OutPoint) -> Result<Option<Coin>, SourceError> {
        self.0.coin(outpoint).map_err(|_| SourceError)
    }
}

/// Durable chain state for one network.
pub struct ChainStore {
    db: Database,
    chain_id: Hash256,
    options: StoreOptions,
    tip: Option<Tip>,
    total_value: Amount,
    coin_count: u64,
    cache: RefCell<CoinCache>,
    bulk: bool,
    unflushed: usize,
    last_durable: Instant,
    durable_every: usize,
    pruned_to: Option<u64>,
    /// Number of commits to let through before failing one (tests only).
    #[cfg(test)]
    fail_commit_in: Option<usize>,
}

impl ChainStore {
    /// Opens the store at `path` with the default options, creating it for
    /// `chain_id` if it is new.
    pub fn open(path: &Path, chain_id: Hash256) -> Result<Self, StorageError> {
        Self::open_with(path, chain_id, StoreOptions::default())
    }

    /// Opens the store at `path`, creating it for `chain_id` if it is new and
    /// upgrading a version 1 file.
    ///
    /// Fails if the file belongs to another chain or a newer schema, if it
    /// was pruned and `options` does not prune, or if its contents are
    /// inconsistent. Only one process can hold the store open.
    pub fn open_with(
        path: &Path,
        chain_id: Hash256,
        options: StoreOptions,
    ) -> Result<Self, StorageError> {
        if let Some(depth) = options.prune_depth
            && depth < MIN_PRUNE_DEPTH
        {
            return Err(StorageError::PruneDepth(depth));
        }
        if !path.exists() {
            create_atomically(path)?;
        }
        let db = Database::open(path).map_err(database)?;
        let write = db.begin_write().map_err(database)?;
        let pruned_to;
        {
            for table in [COINS, BLOCKS, PRUNED, UNDO, HEADERS, WALLET_COINS] {
                write.open_table(table).map_err(database)?;
            }
            write.open_table(HEIGHTS).map_err(database)?;
            let mut meta = write.open_table(META).map_err(database)?;
            let schema = meta
                .get(META_SCHEMA)
                .map_err(database)?
                .map(|value| value.value().to_vec());
            match schema {
                None => {
                    meta.insert(META_SCHEMA, SCHEMA_VERSION.to_be_bytes().as_slice())
                        .map_err(database)?;
                    meta.insert(META_CHAIN_ID, chain_id.as_bytes().as_slice())
                        .map_err(database)?;
                    meta.insert(META_SUPPLY, 0_u64.to_be_bytes().as_slice())
                        .map_err(database)?;
                    meta.insert(META_COINS, 0_u64.to_be_bytes().as_slice())
                        .map_err(database)?;
                }
                Some(bytes) => {
                    let version = <[u8; 4]>::try_from(bytes.as_slice())
                        .map(u32::from_be_bytes)
                        .map_err(|_| StorageError::Corrupt("schema version"))?;
                    let stored = meta
                        .get(META_CHAIN_ID)
                        .map_err(database)?
                        .ok_or(StorageError::Corrupt("missing chain id"))?
                        .value()
                        .to_vec();
                    let stored = Hash256::new(
                        <[u8; 32]>::try_from(stored.as_slice())
                            .map_err(|_| StorageError::Corrupt("chain id"))?,
                    );
                    if stored != chain_id {
                        return Err(StorageError::WrongChain {
                            expected: chain_id,
                            stored,
                        });
                    }
                    match version {
                        SCHEMA_VERSION => {}
                        1 => {
                            drop(meta);
                            upgrade_from_v1(&write)?;
                            meta = write.open_table(META).map_err(database)?;
                        }
                        other => return Err(StorageError::UnsupportedSchema(other)),
                    }
                }
            }

            // Pruning is one-way: refuse to run an archive node on a pruned
            // file, and record the depth the first time it is enabled.
            let stored_depth = read_u64(&meta, META_PRUNE_DEPTH)?;
            match (stored_depth, options.prune_depth) {
                (Some(_), None) => return Err(StorageError::PrunedStore),
                (_, Some(depth)) => {
                    meta.insert(META_PRUNE_DEPTH, depth.to_be_bytes().as_slice())
                        .map_err(database)?;
                }
                (None, None) => {}
            }
            pruned_to = read_u64(&meta, META_PRUNED_TO)?;

            let indexed = read_u64(&meta, META_WALLET_INDEX)? == Some(1);
            drop(meta);
            if options.wallet_index && !indexed {
                build_wallet_index(&write)?;
                set_u64(&write, META_WALLET_INDEX, 1)?;
            } else if !options.wallet_index && indexed {
                write.delete_table(WALLET_COINS).map_err(database)?;
                write.open_table(WALLET_COINS).map_err(database)?;
                set_u64(&write, META_WALLET_INDEX, 0)?;
            }
        }
        write.commit().map_err(database)?;

        let (tip, total_value, coin_count) = load_meta(&db)?;
        Ok(Self {
            db,
            chain_id,
            options,
            tip,
            total_value,
            coin_count,
            cache: RefCell::new(CoinCache::new(options.coin_cache_bytes)),
            bulk: false,
            unflushed: 0,
            last_durable: Instant::now(),
            durable_every: BULK_DURABLE_EVERY,
            pruned_to,
            #[cfg(test)]
            fail_commit_in: None,
        })
    }

    /// Returns the chain id this store was created for.
    #[must_use]
    pub const fn chain_id(&self) -> Hash256 {
        self.chain_id
    }

    /// Returns the options the store was opened with.
    #[must_use]
    pub const fn options(&self) -> &StoreOptions {
        &self.options
    }

    /// Returns the tip, or `None` before genesis.
    #[must_use]
    pub const fn tip(&self) -> Option<Tip> {
        self.tip
    }

    /// Totals of the unspent-output set, kept in the metadata.
    #[must_use]
    pub const fn utxo_stats(&self) -> UtxoStats {
        UtxoStats {
            coins: self.coin_count,
            total_value: self.total_value,
        }
    }

    /// Hits and misses of the coin cache, and the coins it holds.
    #[must_use]
    pub fn cache_stats(&self) -> (u64, u64, usize) {
        let cache = self.cache.borrow();
        (cache.hits, cache.misses, cache.len())
    }

    /// The highest active-chain height whose witnesses were pruned.
    #[must_use]
    pub const fn pruned_height(&self) -> Option<u64> {
        self.pruned_to
    }

    /// Looks up an unspent output.
    pub fn coin(&self, outpoint: &OutPoint) -> Result<Option<Coin>, StorageError> {
        let read = self.db.begin_read().map_err(database)?;
        let lookup = DiskCoins {
            cache: &self.cache,
            table: read.open_table(COINS).map_err(database)?,
            error: RefCell::new(None),
        };
        lookup.read(outpoint)
    }

    /// A [`CoinSource`] over this store.
    #[must_use]
    pub const fn coins(&self) -> StoreCoins<'_> {
        StoreCoins(self)
    }

    /// Unspent outputs paying `wallet_id`, in outpoint order, after `after`,
    /// at most `limit`. Needs the wallet index.
    pub fn coins_of(
        &self,
        wallet_id: &WalletId,
        after: Option<OutPoint>,
        limit: usize,
    ) -> Result<Vec<(OutPoint, Coin)>, StorageError> {
        if !self.options.wallet_index {
            return Err(StorageError::NoWalletIndex);
        }
        let read = self.db.begin_read().map_err(database)?;
        let index = read.open_table(WALLET_COINS).map_err(database)?;
        let lookup = DiskCoins {
            cache: &self.cache,
            table: read.open_table(COINS).map_err(database)?,
            error: RefCell::new(None),
        };
        let mut start = wallet_id.as_bytes().to_vec();
        if let Some(after) = after {
            start.extend_from_slice(&after.to_bytes());
        }
        let mut found = Vec::new();
        for entry in index.range(start.as_slice()..).map_err(database)? {
            if found.len() == limit {
                break;
            }
            let (key, _) = entry.map_err(database)?;
            let key = key.value();
            if key.len() < 32 || &key[..32] != wallet_id.as_bytes() {
                break;
            }
            let outpoint = decode_exact::<OutPoint>(&key[32..], usize::MAX)
                .map_err(|_| StorageError::Corrupt("wallet index key"))?;
            if Some(outpoint) == after {
                continue;
            }
            let coin = lookup
                .read(&outpoint)?
                .ok_or(StorageError::Corrupt("wallet index points to a spent coin"))?;
            found.push((outpoint, coin));
        }
        Ok(found)
    }

    /// Switches batched commits for initial sync on or off. Turning it off
    /// makes everything written so far durable.
    pub fn set_bulk(&mut self, bulk: bool) -> Result<(), StorageError> {
        if self.bulk && !bulk {
            self.flush()?;
        }
        self.bulk = bulk;
        Ok(())
    }

    /// Makes every commit so far durable.
    pub fn flush(&mut self) -> Result<(), StorageError> {
        if self.unflushed == 0 {
            return Ok(());
        }
        let write = self.db.begin_write().map_err(database)?;
        write.commit().map_err(database)?;
        self.unflushed = 0;
        self.last_durable = Instant::now();
        Ok(())
    }

    /// Validates `block` against the tip and applies it.
    ///
    /// On a validation error nothing is written. A failure to read the coins
    /// is a storage error, never a validation error.
    pub fn apply_block(&mut self, block: &Block, rules: &BlockRules) -> Result<(), StorageError> {
        self.apply_body(
            &BlockShape::of(block),
            block.transactions(),
            rules,
            Some(block),
        )
    }

    /// Applies a stored block, full or pruned. A pruned block is one this
    /// node already validated on its active chain, so its signatures are not
    /// checked again; everything else is.
    pub fn apply_stored(
        &mut self,
        block: &StoredBlock,
        rules: &BlockRules,
    ) -> Result<(), StorageError> {
        match block {
            StoredBlock::Full(block) => self.apply_block(block, rules),
            StoredBlock::Pruned(block) => {
                self.apply_body(&block.shape(), block.transactions(), rules, None)
            }
        }
    }

    fn apply_body<T: BodyTransaction>(
        &mut self,
        shape: &BlockShape,
        transactions: &[T],
        rules: &BlockRules,
        full: Option<&Block>,
    ) -> Result<(), StorageError> {
        if rules.chain_id != self.chain_id {
            return Err(StorageError::WrongChain {
                expected: self.chain_id,
                stored: rules.chain_id,
            });
        }
        let delta = {
            let read = self.db.begin_read().map_err(database)?;
            let lookup = DiskCoins {
                cache: &self.cache,
                table: read.open_table(COINS).map_err(database)?,
                error: RefCell::new(None),
            };
            match validate_block(
                &lookup,
                self.tip,
                self.total_value,
                shape,
                transactions,
                rules,
            ) {
                Ok(delta) => delta,
                Err(UtxoError::Unavailable) => {
                    return Err(lookup
                        .error
                        .into_inner()
                        .unwrap_or(StorageError::Corrupt("coin read failed")));
                }
                Err(error) => return Err(StorageError::Utxo(error)),
            }
        };
        let write = self.begin_write()?;
        {
            let key = shape.block_id.as_bytes().as_slice();
            if let Some(block) = full {
                write
                    .open_table(BLOCKS)
                    .map_err(database)?
                    .insert(key, block.to_bytes().as_slice())
                    .map_err(database)?;
            }
            write
                .open_table(UNDO)
                .map_err(database)?
                .insert(key, delta.undo().to_bytes().as_slice())
                .map_err(database)?;
            write
                .open_table(HEIGHTS)
                .map_err(database)?
                .insert(shape.height, key)
                .map_err(database)?;
        }
        self.write_delta(&write, &delta)?;
        self.commit(write)?;
        self.finish_delta(&delta);
        Ok(())
    }

    /// Reverts the tip block and returns it.
    pub fn revert_tip(&mut self) -> Result<StoredBlock, StorageError> {
        let tip = self.tip.ok_or(StorageError::NoTip)?;
        let block = self
            .stored_block(&tip.block_id)?
            .ok_or(StorageError::Corrupt("tip block missing"))?;
        let undo = self.undo(&tip.block_id)?;
        let (shape, created) = match &block {
            StoredBlock::Full(block) => (
                BlockShape::of(block),
                created_outpoints_of(block.transactions()),
            ),
            StoredBlock::Pruned(block) => (block.shape(), block.created_outpoints()),
        };
        let delta = {
            let read = self.db.begin_read().map_err(database)?;
            let lookup = DiskCoins {
                cache: &self.cache,
                table: read.open_table(COINS).map_err(database)?,
                error: RefCell::new(None),
            };
            match revert_delta(&lookup, self.tip, self.total_value, &shape, &created, &undo) {
                Ok(delta) => delta,
                Err(UtxoError::Unavailable) => {
                    return Err(lookup
                        .error
                        .into_inner()
                        .unwrap_or(StorageError::Corrupt("coin read failed")));
                }
                Err(error) => return Err(StorageError::Utxo(error)),
            }
        };
        let write = self.begin_write()?;
        {
            // The block itself is kept, so a reorganization can return to it.
            write
                .open_table(UNDO)
                .map_err(database)?
                .remove(tip.block_id.as_bytes().as_slice())
                .map_err(database)?;
            write
                .open_table(HEIGHTS)
                .map_err(database)?
                .remove(tip.height)
                .map_err(database)?;
        }
        // A reverted height may be filled by a new, full block: let pruning
        // look at it again.
        let pruned_to = self
            .pruned_to
            .map(|pruned| pruned.min(tip.height.saturating_sub(1)));
        if let Some(pruned) = pruned_to {
            set_u64(&write, META_PRUNED_TO, pruned)?;
        }
        self.write_delta(&write, &delta)?;
        self.commit(write)?;
        self.finish_delta(&delta);
        self.pruned_to = pruned_to;
        Ok(block)
    }

    fn write_delta(&self, write: &WriteTransaction, delta: &UtxoDelta) -> Result<(), StorageError> {
        let mut coins = write.open_table(COINS).map_err(database)?;
        let mut index = write.open_table(WALLET_COINS).map_err(database)?;
        for (outpoint, coin) in &delta.removed {
            coins
                .remove(outpoint.to_bytes().as_slice())
                .map_err(database)?;
            if self.options.wallet_index {
                index
                    .remove(wallet_key(&coin.output.wallet_id, outpoint).as_slice())
                    .map_err(database)?;
            }
        }
        for (outpoint, coin) in &delta.added {
            coins
                .insert(outpoint.to_bytes().as_slice(), coin.to_bytes().as_slice())
                .map_err(database)?;
            if self.options.wallet_index {
                index
                    .insert(
                        wallet_key(&coin.output.wallet_id, outpoint).as_slice(),
                        [].as_slice(),
                    )
                    .map_err(database)?;
            }
        }
        drop(coins);
        drop(index);
        set_tip(write, delta.tip)?;
        set_u64(write, META_SUPPLY, delta.total_value.as_satoshis())?;
        let count = self.count_after(delta)?;
        set_u64(write, META_COINS, count)
    }

    fn count_after(&self, delta: &UtxoDelta) -> Result<u64, StorageError> {
        let removed =
            u64::try_from(delta.removed.len()).map_err(|_| StorageError::Corrupt("count"))?;
        let added = u64::try_from(delta.added.len()).map_err(|_| StorageError::Corrupt("count"))?;
        self.coin_count
            .checked_sub(removed)
            .and_then(|count| count.checked_add(added))
            .ok_or(StorageError::Corrupt("coin count"))
    }

    fn finish_delta(&mut self, delta: &UtxoDelta) {
        let mut cache = self.cache.borrow_mut();
        for (outpoint, _) in &delta.removed {
            cache.remove(outpoint);
        }
        for (outpoint, coin) in &delta.added {
            cache.insert(*outpoint, *coin);
        }
        drop(cache);
        self.coin_count = self.count_after(delta).unwrap_or(self.coin_count);
        self.tip = delta.tip;
        self.total_value = delta.total_value;
    }

    /// Loads a full stored block by id; `None` if unknown or pruned.
    pub fn block(&self, block_id: &BlockId) -> Result<Option<Block>, StorageError> {
        Ok(self
            .stored_block(block_id)?
            .and_then(StoredBlock::into_full))
    }

    /// Loads a stored block by id, full or pruned.
    pub fn stored_block(&self, block_id: &BlockId) -> Result<Option<StoredBlock>, StorageError> {
        let read = self.db.begin_read().map_err(database)?;
        let key = block_id.as_bytes().as_slice();
        if let Some(bytes) = read
            .open_table(BLOCKS)
            .map_err(database)?
            .get(key)
            .map_err(database)?
        {
            return Block::from_bytes(bytes.value())
                .map(|block| Some(StoredBlock::Full(block)))
                .map_err(|_| StorageError::Corrupt("stored block"));
        }
        let Some(bytes) = read
            .open_table(PRUNED)
            .map_err(database)?
            .get(key)
            .map_err(database)?
        else {
            return Ok(None);
        };
        decode_exact::<PrunedBlock>(bytes.value(), usize::MAX)
            .map(|block| Some(StoredBlock::Pruned(block)))
            .map_err(|_| StorageError::Corrupt("pruned block"))
    }

    /// Returns the id of the block at `height` on the current chain.
    pub fn block_id_at(&self, height: u64) -> Result<Option<BlockId>, StorageError> {
        let read = self.db.begin_read().map_err(database)?;
        let heights = read.open_table(HEIGHTS).map_err(database)?;
        heights
            .get(height)
            .map_err(database)?
            .map(|value| block_id(value.value()))
            .transpose()
    }

    /// Recounts every coin, checks the count and supply in the metadata and,
    /// with the wallet index, that both tables hold the same coins.
    /// Linear in the size of the set (`--check-utxo`).
    pub fn check_utxo(&self) -> Result<UtxoStats, StorageError> {
        let read = self.db.begin_read().map_err(database)?;
        let coins = read.open_table(COINS).map_err(database)?;
        let mut count = 0_u64;
        let mut total = 0_u128;
        let mut owners: HashSet<Vec<u8>> = HashSet::new();
        for entry in coins.iter().map_err(database)? {
            let (key, value) = entry.map_err(database)?;
            let outpoint = decode_exact::<OutPoint>(key.value(), usize::MAX)
                .map_err(|_| StorageError::Corrupt("coin key"))?;
            let coin = decode_exact::<Coin>(value.value(), usize::MAX)
                .map_err(|_: TransactionError| StorageError::Corrupt("coin"))?;
            count += 1;
            total += u128::from(coin.output.amount.as_satoshis());
            if self.options.wallet_index {
                owners.insert(wallet_key(&coin.output.wallet_id, &outpoint));
            }
        }
        if count != self.coin_count || total != u128::from(self.total_value.as_satoshis()) {
            return Err(StorageError::Utxo(UtxoError::SupplyMismatch));
        }
        if self.options.wallet_index {
            let index = read.open_table(WALLET_COINS).map_err(database)?;
            if index.len().map_err(database)? != count {
                return Err(StorageError::Corrupt("wallet index size"));
            }
            for entry in index.iter().map_err(database)? {
                let (key, _) = entry.map_err(database)?;
                if !owners.contains(key.value()) {
                    return Err(StorageError::Corrupt("wallet index entry without a coin"));
                }
            }
        }
        Ok(self.utxo_stats())
    }

    /// Checks the last `count` blocks of the active chain: each is stored,
    /// matches its header's roots, and its undo data spends exactly the
    /// coins its inputs name (`--check-blocks`).
    pub fn check_blocks(&self, count: u64) -> Result<u64, StorageError> {
        let Some(tip) = self.tip else {
            return Ok(0);
        };
        let mut checked = 0;
        let lowest = tip.height.saturating_sub(count.saturating_sub(1));
        for height in (lowest..=tip.height).rev() {
            let id = self
                .block_id_at(height)?
                .ok_or(StorageError::Corrupt("height index gap"))?;
            // Decoding verifies both roots against the header.
            let block = self
                .stored_block(&id)?
                .ok_or(StorageError::Corrupt("active block missing"))?;
            if block.id() != id || block.height() != height {
                return Err(StorageError::Corrupt(
                    "stored block does not match its height",
                ));
            }
            let from_set = match &block {
                StoredBlock::Full(block) => spent_from_set(block.transactions()),
                StoredBlock::Pruned(block) => spent_from_set(block.transactions()),
            };
            let undo = self.undo(&id)?;
            let undone: HashSet<OutPoint> =
                undo.spent().iter().map(|(outpoint, _)| *outpoint).collect();
            if undone != from_set || undo.spent().len() != from_set.len() {
                // The same set, and no outpoint undone twice.
                return Err(StorageError::Corrupt("undo data does not match the block"));
            }
            checked += 1;
        }
        Ok(checked)
    }

    /// Loads the whole unspent-output set into memory. Linear in its size;
    /// for tests and audits.
    pub fn snapshot(&self) -> Result<UtxoSet, StorageError> {
        let read = self.db.begin_read().map_err(database)?;
        let table = read.open_table(COINS).map_err(database)?;
        let mut coins = Vec::new();
        for entry in table.iter().map_err(database)? {
            let (key, value) = entry.map_err(database)?;
            let outpoint = decode_exact::<OutPoint>(key.value(), usize::MAX)
                .map_err(|_| StorageError::Corrupt("coin key"))?;
            let coin = decode_exact::<Coin>(value.value(), usize::MAX)
                .map_err(|_: TransactionError| StorageError::Corrupt("coin"))?;
            coins.push((outpoint, coin));
        }
        let set = UtxoSet::from_parts(coins, self.tip)?;
        if set.total_value() != self.total_value {
            return Err(StorageError::Utxo(UtxoError::SupplyMismatch));
        }
        Ok(set)
    }

    /// Checks the cheap invariants and, linearly, the coins against the
    /// metadata. Kept for callers of the earlier API.
    pub fn verify(&self) -> Result<(), StorageError> {
        self.check_utxo().map(|_| ())
    }

    /// Stores a block and its header-index entry, without applying it.
    pub fn store_block(&mut self, block: &Block, index_entry: &[u8]) -> Result<(), StorageError> {
        let key = block.id();
        let write = self.begin_write()?;
        write
            .open_table(BLOCKS)
            .map_err(database)?
            .insert(key.as_bytes().as_slice(), block.to_bytes().as_slice())
            .map_err(database)?;
        write
            .open_table(HEADERS)
            .map_err(database)?
            .insert(key.as_bytes().as_slice(), index_entry)
            .map_err(database)?;
        self.commit(write)
    }

    /// Stores a block body for an already indexed block, full or pruned.
    pub fn store_body(&mut self, block: &StoredBlock) -> Result<(), StorageError> {
        let key = block.id();
        let write = self.begin_write()?;
        let (table, bytes) = match block {
            StoredBlock::Full(block) => (BLOCKS, block.to_bytes()),
            StoredBlock::Pruned(block) => (PRUNED, block.to_bytes()),
        };
        write
            .open_table(table)
            .map_err(database)?
            .insert(key.as_bytes().as_slice(), bytes.as_slice())
            .map_err(database)?;
        self.commit(write)
    }

    /// Replaces header-index entries in one transaction.
    pub fn store_index_entries(
        &mut self,
        entries: &[(BlockId, Vec<u8>)],
    ) -> Result<(), StorageError> {
        let write = self.begin_write()?;
        {
            let mut headers = write.open_table(HEADERS).map_err(database)?;
            for (id, entry) in entries {
                headers
                    .insert(id.as_bytes().as_slice(), entry.as_slice())
                    .map_err(database)?;
            }
        }
        self.commit(write)
    }

    /// Returns every header-index entry.
    pub fn index_entries(&self) -> Result<Vec<(BlockId, Vec<u8>)>, StorageError> {
        let read = self.db.begin_read().map_err(database)?;
        let headers = read.open_table(HEADERS).map_err(database)?;
        let mut entries = Vec::new();
        for entry in headers.iter().map_err(database)? {
            let (key, value) = entry.map_err(database)?;
            entries.push((block_id(key.value())?, value.value().to_vec()));
        }
        Ok(entries)
    }

    /// Prunes the witnesses of up to [`PRUNE_BATCH`] active blocks deeper
    /// than the prune depth, in one transaction. Returns the blocks pruned.
    /// Does nothing in archive mode.
    ///
    /// Side-chain blocks are never pruned: they were not validated yet, and
    /// validating them later needs their witnesses.
    pub fn prune(&mut self) -> Result<u64, StorageError> {
        let (Some(depth), Some(tip)) = (self.options.prune_depth, self.tip) else {
            return Ok(0);
        };
        let Some(target) = tip.height.checked_sub(depth) else {
            return Ok(0);
        };
        let first = self.pruned_to.map_or(0, |pruned| pruned + 1);
        if first > target {
            return Ok(0);
        }
        let last = target.min(first.saturating_add(PRUNE_BATCH - 1));
        let write = self.begin_write()?;
        let mut pruned = 0;
        {
            let heights = write.open_table(HEIGHTS).map_err(database)?;
            let mut blocks = write.open_table(BLOCKS).map_err(database)?;
            let mut stripped = write.open_table(PRUNED).map_err(database)?;
            for height in first..=last {
                let Some(id) = heights.get(height).map_err(database)? else {
                    return Err(StorageError::Corrupt("height index gap"));
                };
                let id = block_id(id.value())?;
                let key = id.as_bytes().as_slice();
                let full = blocks
                    .get(key)
                    .map_err(database)?
                    .map(|bytes| bytes.value().to_vec());
                if let Some(bytes) = full {
                    let block = Block::from_bytes(&bytes)
                        .map_err(|_| StorageError::Corrupt("stored block"))?;
                    stripped
                        .insert(key, PrunedBlock::from_block(&block).to_bytes().as_slice())
                        .map_err(database)?;
                    blocks.remove(key).map_err(database)?;
                    pruned += 1;
                }
            }
        }
        set_u64(&write, META_PRUNED_TO, last)?;
        self.commit(write)?;
        self.pruned_to = Some(last);
        Ok(pruned)
    }

    fn undo(&self, block_id: &BlockId) -> Result<BlockUndo, StorageError> {
        let read = self.db.begin_read().map_err(database)?;
        let undo = read.open_table(UNDO).map_err(database)?;
        let bytes = undo
            .get(block_id.as_bytes().as_slice())
            .map_err(database)?
            .ok_or(StorageError::Corrupt("undo data missing"))?;
        decode_exact::<BlockUndo>(bytes.value(), usize::MAX)
            .map_err(|_| StorageError::Corrupt("undo data"))
    }

    /// Begins a write, durable unless batching for initial sync and a
    /// durable commit is not due yet.
    fn begin_write(&mut self) -> Result<WriteTransaction, StorageError> {
        let mut write = self.db.begin_write().map_err(database)?;
        let due = self.unflushed + 1 >= self.durable_every
            || self.last_durable.elapsed() >= BULK_DURABLE_INTERVAL;
        if self.bulk && !due {
            write
                .set_durability(Durability::None)
                .map_err(|_| StorageError::Corrupt("could not batch commits"))?;
            self.unflushed += 1;
        } else {
            self.unflushed = 0;
            self.last_durable = Instant::now();
        }
        Ok(write)
    }

    fn commit(&mut self, write: WriteTransaction) -> Result<(), StorageError> {
        #[cfg(test)]
        match self.fail_commit_in {
            Some(0) => {
                self.fail_commit_in = None;
                // Dropping an uncommitted transaction aborts it.
                drop(write);
                return Err(StorageError::Corrupt("injected commit failure"));
            }
            Some(remaining) => self.fail_commit_in = Some(remaining - 1),
            None => {}
        }
        write.commit().map_err(database)
    }

    /// Drops every cached coin (tests and recovery).
    pub fn clear_cache(&self) {
        self.cache.borrow_mut().clear();
    }

    /// Makes a durable commit every `commits` in bulk mode (tests).
    #[cfg(test)]
    pub(crate) fn set_durable_every(&mut self, commits: usize) {
        self.durable_every = commits.max(1);
    }

    /// Shrinks the cache to a few entries, to exercise eviction in tests.
    #[cfg(test)]
    pub(crate) fn set_cache_half(&self, half: usize) {
        let mut cache = self.cache.borrow_mut();
        cache.clear();
        cache.half = half.max(1);
    }
}

impl Drop for ChainStore {
    fn drop(&mut self) {
        let _ = self.flush();
    }
}

impl fmt::Debug for ChainStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ChainStore")
            .field("chain_id", &self.chain_id)
            .field("tip", &self.tip)
            .field("coins", &self.coin_count)
            .finish_non_exhaustive()
    }
}

/// The coins a block body spends from the set: its inputs, minus outputs it
/// creates and spends itself.
fn spent_from_set<T: BodyTransaction>(transactions: &[T]) -> HashSet<OutPoint> {
    let mut created = HashSet::new();
    for transaction in transactions {
        let txid = transaction.txid();
        for index in 0..transaction.outputs().len() {
            if let Ok(index) = u16::try_from(index) {
                created.insert(OutPoint { txid, index });
            }
        }
    }
    transactions
        .iter()
        .flat_map(BodyTransaction::inputs)
        .map(|input| input.previous_output)
        .filter(|outpoint| !created.contains(outpoint))
        .collect()
}

fn wallet_key(wallet_id: &WalletId, outpoint: &OutPoint) -> Vec<u8> {
    let mut key = Vec::with_capacity(32 + 34);
    key.extend_from_slice(wallet_id.as_bytes());
    key.extend_from_slice(&outpoint.to_bytes());
    key
}

fn read_u64(
    meta: &impl ReadableTable<&'static str, &'static [u8]>,
    key: &str,
) -> Result<Option<u64>, StorageError> {
    meta.get(key)
        .map_err(database)?
        .map(|value| {
            <[u8; 8]>::try_from(value.value())
                .map(u64::from_be_bytes)
                .map_err(|_| StorageError::Corrupt("metadata value"))
        })
        .transpose()
}

fn set_u64(write: &WriteTransaction, key: &str, value: u64) -> Result<(), StorageError> {
    write
        .open_table(META)
        .map_err(database)?
        .insert(key, value.to_be_bytes().as_slice())
        .map_err(database)?;
    Ok(())
}

/// Builds the wallet index from the coins table.
fn build_wallet_index(write: &WriteTransaction) -> Result<(), StorageError> {
    let coins = write.open_table(COINS).map_err(database)?;
    let mut index = write.open_table(WALLET_COINS).map_err(database)?;
    for entry in coins.iter().map_err(database)? {
        let (key, value) = entry.map_err(database)?;
        let outpoint = decode_exact::<OutPoint>(key.value(), usize::MAX)
            .map_err(|_| StorageError::Corrupt("coin key"))?;
        let coin = decode_exact::<Coin>(value.value(), usize::MAX)
            .map_err(|_: TransactionError| StorageError::Corrupt("coin"))?;
        index
            .insert(
                wallet_key(&coin.output.wallet_id, &outpoint).as_slice(),
                [].as_slice(),
            )
            .map_err(database)?;
    }
    Ok(())
}

/// Upgrades a version 1 file: the supply and the coin count move into the
/// metadata. The wallet index, if wanted, is built by the caller.
fn upgrade_from_v1(write: &WriteTransaction) -> Result<(), StorageError> {
    let coins = write.open_table(COINS).map_err(database)?;
    let mut count = 0_u64;
    let mut total = 0_u128;
    for entry in coins.iter().map_err(database)? {
        let (_, value) = entry.map_err(database)?;
        let coin = decode_exact::<Coin>(value.value(), usize::MAX)
            .map_err(|_: TransactionError| StorageError::Corrupt("coin"))?;
        count += 1;
        total += u128::from(coin.output.amount.as_satoshis());
    }
    drop(coins);
    let total = u64::try_from(total).map_err(|_| StorageError::Utxo(UtxoError::SupplyMismatch))?;
    Amount::from_satoshis(total).map_err(|_| StorageError::Utxo(UtxoError::SupplyMismatch))?;
    set_u64(write, META_SUPPLY, total)?;
    set_u64(write, META_COINS, count)?;
    write
        .open_table(META)
        .map_err(database)?
        .insert(META_SCHEMA, SCHEMA_VERSION.to_be_bytes().as_slice())
        .map_err(database)?;
    Ok(())
}

/// Creates an empty database at `path` so that a crash never leaves a
/// half-initialized file there: it is built and committed under a temporary
/// name in the same directory, then renamed into place. A stale temporary file
/// from an earlier crash was never published and is discarded.
fn create_atomically(path: &Path) -> Result<(), StorageError> {
    let invalid_path = || StorageError::Corrupt("store path has no file name");
    let mut temporary_name = std::ffi::OsString::from(".");
    temporary_name.push(path.file_name().ok_or_else(invalid_path)?);
    temporary_name.push(".creating");
    let temporary = path.with_file_name(temporary_name);
    let io = |error: std::io::Error| StorageError::Database(redb::Error::Io(error));

    match std::fs::remove_file(&temporary) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => return Err(io(error)),
        _ => {}
    }
    {
        let db = Database::create(&temporary).map_err(database)?;
        // An empty durable commit leaves a complete, synced redb file.
        db.begin_write()
            .map_err(database)?
            .commit()
            .map_err(database)?;
    }
    std::fs::rename(&temporary, path).map_err(io)?;
    #[cfg(unix)]
    {
        let parent = match path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent,
            _ => Path::new("."),
        };
        std::fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(io)?;
    }
    Ok(())
}

fn set_tip(write: &WriteTransaction, tip: Option<Tip>) -> Result<(), StorageError> {
    let mut meta = write.open_table(META).map_err(database)?;
    match tip {
        Some(tip) => {
            let mut bytes = [0_u8; 40];
            bytes[..32].copy_from_slice(tip.block_id.as_bytes());
            bytes[32..].copy_from_slice(&tip.height.to_be_bytes());
            meta.insert(META_TIP, bytes.as_slice()).map_err(database)?;
        }
        None => {
            meta.remove(META_TIP).map_err(database)?;
        }
    }
    Ok(())
}

/// Reads the tip, supply and count, and checks the tip against the height
/// index. Constant time: the coins themselves are not read.
fn load_meta(db: &Database) -> Result<(Option<Tip>, Amount, u64), StorageError> {
    let read = db.begin_read().map_err(database)?;
    let meta = read.open_table(META).map_err(database)?;
    let tip = match meta.get(META_TIP).map_err(database)? {
        None => None,
        Some(bytes) => {
            let bytes = bytes.value();
            if bytes.len() != 40 {
                return Err(StorageError::Corrupt("tip"));
            }
            let mut reader = Reader::new(bytes);
            let tip = Tip {
                block_id: BlockId::decode(&mut reader).map_err(|_| StorageError::Corrupt("tip"))?,
                height: reader.u64().map_err(|_| StorageError::Corrupt("tip"))?,
            };
            Some(tip)
        }
    };

    let heights = read.open_table(HEIGHTS).map_err(database)?;
    let indexed_tip = heights.last().map_err(database)?;
    match (tip, indexed_tip) {
        (None, None) => {}
        (Some(tip), Some((height, id))) => {
            if height.value() != tip.height || block_id(id.value())? != tip.block_id {
                return Err(StorageError::Corrupt("tip does not match the height index"));
            }
        }
        _ => return Err(StorageError::Corrupt("tip does not match the height index")),
    }
    let supply = read_u64(&meta, META_SUPPLY)?.ok_or(StorageError::Corrupt("missing supply"))?;
    let supply =
        Amount::from_satoshis(supply).map_err(|_| StorageError::Utxo(UtxoError::SupplyMismatch))?;
    let coins = read_u64(&meta, META_COINS)?.ok_or(StorageError::Corrupt("missing coin count"))?;
    if tip.is_none() && (coins != 0 || supply != Amount::ZERO) {
        return Err(StorageError::Corrupt("coins without a tip"));
    }
    Ok((tip, supply, coins))
}

fn block_id(bytes: &[u8]) -> Result<BlockId, StorageError> {
    <[u8; 32]>::try_from(bytes)
        .map(|bytes| BlockId::new(Hash256::new(bytes)))
        .map_err(|_| StorageError::Corrupt("block id"))
}

fn database(error: impl Into<redb::Error>) -> StorageError {
    StorageError::Database(error.into())
}

/// Errors from the chain store.
#[derive(Debug)]
pub enum StorageError {
    /// The database engine failed (I/O, locking, or a damaged file).
    Database(redb::Error),
    /// The block failed validation against the current tip.
    Utxo(UtxoError),
    /// The file or the rules belong to another chain.
    WrongChain {
        /// The chain id this store expects.
        expected: Hash256,
        /// The chain id found.
        stored: Hash256,
    },
    /// The file uses an unknown schema version.
    UnsupportedSchema(u32),
    /// There is no block to revert.
    NoTip,
    /// Stored data is inconsistent.
    Corrupt(&'static str),
    /// The file was pruned; it can only be opened with pruning on.
    PrunedStore,
    /// The prune depth is below [`MIN_PRUNE_DEPTH`].
    PruneDepth(u64),
    /// The wallet index is turned off.
    NoWalletIndex,
}

impl From<UtxoError> for StorageError {
    fn from(error: UtxoError) -> Self {
        Self::Utxo(error)
    }
}

impl fmt::Display for StorageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database(error) => write!(formatter, "database error: {error}"),
            Self::Utxo(error) => write!(formatter, "block rejected: {error}"),
            Self::WrongChain { expected, stored } => {
                write!(formatter, "chain id {stored} does not match {expected}")
            }
            Self::UnsupportedSchema(version) => {
                write!(formatter, "unsupported storage schema version {version}")
            }
            Self::NoTip => formatter.write_str("there is no block to revert"),
            Self::Corrupt(what) => write!(formatter, "corrupt chain store: {what}"),
            Self::PrunedStore => formatter.write_str(
                "this chain store was pruned; start with --prune-witnesses or sync again",
            ),
            Self::PruneDepth(depth) => write!(
                formatter,
                "prune depth {depth} is below the minimum of {MIN_PRUNE_DEPTH} blocks"
            ),
            Self::NoWalletIndex => formatter.write_str("the wallet index is turned off"),
        }
    }
}

impl std::error::Error for StorageError {}

pub mod chain;

pub use chain::{Chain, ChainError, IndexEntry, SubmitOutcome, reindex};

#[cfg(test)]
mod tests;
