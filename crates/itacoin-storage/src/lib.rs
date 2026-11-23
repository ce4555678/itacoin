//! Durable, crash-safe ITACOIN chain state.
//!
//! The chain is stored in a single [redb] file. Each applied or reverted block
//! is one ACID write transaction: the coin changes, the block, its undo data,
//! the height index and the tip are committed together and synced before the
//! call returns, or not at all. A crash at any point leaves the file at the
//! previous or the next block, never in between, and redb repairs its own
//! structures on the next open.
//!
//! The disk is the source of truth. An in-memory [`UtxoSet`] mirrors it for
//! validation; whenever a write fails, the mirror is reloaded from disk.
//!
//! [redb]: https://docs.rs/redb

use core::fmt;
use std::path::Path;

use itacoin_blockchain::{
    Block, BlockRules, BlockUndo, Coin, Tip, UtxoError, UtxoSet, created_outpoints,
};
use itacoin_codec::{Decode, Encode, Reader, decode_exact};
use itacoin_primitives::{BlockId, Hash256};
use itacoin_transaction::{OutPoint, TransactionError};
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition, WriteTransaction};

/// Version of the on-disk layout. Opening a file with another version fails.
pub const SCHEMA_VERSION: u32 = 1;

/// Unspent outputs: encoded `OutPoint` → encoded `Coin`.
const COINS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("coins");
/// Every block ever applied: block id → encoded block.
const BLOCKS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("blocks");
/// Undo data of the blocks on the current chain: block id → encoded undo.
const UNDO: TableDefinition<&[u8], &[u8]> = TableDefinition::new("undo");
/// The current chain: height → block id.
const HEIGHTS: TableDefinition<u64, &[u8]> = TableDefinition::new("heights");
/// Store metadata: schema version, chain id and tip.
const META: TableDefinition<&str, &[u8]> = TableDefinition::new("meta");

const META_SCHEMA: &str = "schema";
const META_CHAIN_ID: &str = "chain_id";
const META_TIP: &str = "tip";

/// Durable chain state for one network.
pub struct ChainStore {
    db: Database,
    chain_id: Hash256,
    utxo: UtxoSet,
    #[cfg(test)]
    fail_next_commit: bool,
}

impl ChainStore {
    /// Opens the store at `path`, creating it for `chain_id` if it is new.
    ///
    /// Fails if the file belongs to another chain or schema version, or if its
    /// contents are inconsistent. Only one process can hold the store open.
    pub fn open(path: &Path, chain_id: Hash256) -> Result<Self, StorageError> {
        let db = Database::create(path).map_err(database)?;
        let write = db.begin_write().map_err(database)?;
        {
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
                }
                Some(bytes) => {
                    let version = <[u8; 4]>::try_from(bytes.as_slice())
                        .map(u32::from_be_bytes)
                        .map_err(|_| StorageError::Corrupt("schema version"))?;
                    if version != SCHEMA_VERSION {
                        return Err(StorageError::UnsupportedSchema(version));
                    }
                    let stored = meta
                        .get(META_CHAIN_ID)
                        .map_err(database)?
                        .ok_or(StorageError::Corrupt("missing chain id"))?;
                    let stored = Hash256::new(
                        <[u8; 32]>::try_from(stored.value())
                            .map_err(|_| StorageError::Corrupt("chain id"))?,
                    );
                    if stored != chain_id {
                        return Err(StorageError::WrongChain {
                            expected: chain_id,
                            stored,
                        });
                    }
                }
            }
            // Create the remaining tables so readers never miss one.
            write.open_table(COINS).map_err(database)?;
            write.open_table(BLOCKS).map_err(database)?;
            write.open_table(UNDO).map_err(database)?;
            write.open_table(HEIGHTS).map_err(database)?;
        }
        write.commit().map_err(database)?;

        let utxo = load(&db)?;
        Ok(Self {
            db,
            chain_id,
            utxo,
            #[cfg(test)]
            fail_next_commit: false,
        })
    }

    /// Returns the chain id this store was created for.
    #[must_use]
    pub const fn chain_id(&self) -> Hash256 {
        self.chain_id
    }

    /// Returns the unspent-output set at the tip.
    #[must_use]
    pub const fn utxo(&self) -> &UtxoSet {
        &self.utxo
    }

    /// Returns the tip, or `None` before genesis.
    #[must_use]
    pub const fn tip(&self) -> Option<Tip> {
        self.utxo.tip()
    }

    /// Validates `block` against the tip and durably applies it.
    ///
    /// On a validation error nothing is written. On a write error the disk is
    /// unchanged and the in-memory set is reloaded from it.
    pub fn apply_block(&mut self, block: &Block, rules: &BlockRules) -> Result<(), StorageError> {
        if rules.chain_id != self.chain_id {
            return Err(StorageError::WrongChain {
                expected: self.chain_id,
                stored: rules.chain_id,
            });
        }
        let undo = self.utxo.apply_block(block, rules)?;
        let result = self.persist_apply(block, &undo);
        self.recover_on_error(result)
    }

    /// Durably reverts the tip block and returns it.
    pub fn revert_tip(&mut self) -> Result<Block, StorageError> {
        let tip = self.tip().ok_or(StorageError::NoTip)?;
        let block = self
            .block(&tip.block_id)?
            .ok_or(StorageError::Corrupt("tip block missing"))?;
        let undo = self.undo(&tip.block_id)?;
        let created = created_outpoints(&block);
        self.utxo.revert_block(&block, &undo)?;
        let result = self.persist_revert(&block, &undo, &created);
        self.recover_on_error(result).map(|()| block)
    }

    /// Loads a stored block by id.
    pub fn block(&self, block_id: &BlockId) -> Result<Option<Block>, StorageError> {
        let read = self.db.begin_read().map_err(database)?;
        let blocks = read.open_table(BLOCKS).map_err(database)?;
        let Some(bytes) = blocks
            .get(block_id.as_bytes().as_slice())
            .map_err(database)?
        else {
            return Ok(None);
        };
        Block::from_bytes(bytes.value())
            .map(Some)
            .map_err(|_| StorageError::Corrupt("stored block"))
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

    /// Reloads the set from disk and checks that it matches the mirror and
    /// that the tracked supply matches a recount of the coins.
    pub fn verify(&self) -> Result<(), StorageError> {
        let stored = load(&self.db)?;
        stored.audit()?;
        if stored == self.utxo {
            Ok(())
        } else {
            Err(StorageError::Corrupt("memory and disk disagree"))
        }
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

    fn persist_apply(&mut self, block: &Block, undo: &BlockUndo) -> Result<(), StorageError> {
        let block_id = undo.block_id();
        let write = self.db.begin_write().map_err(database)?;
        {
            let mut coins = write.open_table(COINS).map_err(database)?;
            for (outpoint, _) in undo.spent() {
                coins
                    .remove(outpoint.to_bytes().as_slice())
                    .map_err(database)?;
            }
            for outpoint in created_outpoints(block) {
                let coin = self
                    .utxo
                    .get(&outpoint)
                    .ok_or(StorageError::Corrupt("created coin missing in memory"))?;
                coins
                    .insert(outpoint.to_bytes().as_slice(), coin.to_bytes().as_slice())
                    .map_err(database)?;
            }
            let key = block_id.as_bytes().as_slice();
            write
                .open_table(BLOCKS)
                .map_err(database)?
                .insert(key, block.to_bytes().as_slice())
                .map_err(database)?;
            write
                .open_table(UNDO)
                .map_err(database)?
                .insert(key, undo.to_bytes().as_slice())
                .map_err(database)?;
            write
                .open_table(HEIGHTS)
                .map_err(database)?
                .insert(block.height(), key)
                .map_err(database)?;
            set_tip(&write, self.utxo.tip())?;
        }
        self.commit(write)
    }

    fn persist_revert(
        &mut self,
        block: &Block,
        undo: &BlockUndo,
        created: &[OutPoint],
    ) -> Result<(), StorageError> {
        let write = self.db.begin_write().map_err(database)?;
        {
            let mut coins = write.open_table(COINS).map_err(database)?;
            for outpoint in created {
                coins
                    .remove(outpoint.to_bytes().as_slice())
                    .map_err(database)?;
            }
            for (outpoint, coin) in undo.spent() {
                coins
                    .insert(outpoint.to_bytes().as_slice(), coin.to_bytes().as_slice())
                    .map_err(database)?;
            }
            // The block itself is kept, so a reorganization can return to it.
            write
                .open_table(UNDO)
                .map_err(database)?
                .remove(undo.block_id().as_bytes().as_slice())
                .map_err(database)?;
            write
                .open_table(HEIGHTS)
                .map_err(database)?
                .remove(block.height())
                .map_err(database)?;
            set_tip(&write, self.utxo.tip())?;
        }
        self.commit(write)
    }

    fn commit(&mut self, write: WriteTransaction) -> Result<(), StorageError> {
        #[cfg(test)]
        if std::mem::take(&mut self.fail_next_commit) {
            // Dropping an uncommitted transaction aborts it.
            drop(write);
            return Err(StorageError::Corrupt("injected commit failure"));
        }
        write.commit().map_err(database)
    }

    fn recover_on_error(&mut self, result: Result<(), StorageError>) -> Result<(), StorageError> {
        if result.is_err() {
            // The write was not committed; resynchronize the mirror with disk.
            self.utxo = load(&self.db)?;
        }
        result
    }
}

impl fmt::Debug for ChainStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ChainStore")
            .field("chain_id", &self.chain_id)
            .field("tip", &self.tip())
            .field("coins", &self.utxo.len())
            .finish_non_exhaustive()
    }
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

/// Reads the coins and tip, and checks the tip against the height index.
fn load(db: &Database) -> Result<UtxoSet, StorageError> {
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
    Ok(UtxoSet::from_parts(coins, tip)?)
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
        }
    }
}

impl std::error::Error for StorageError {}

#[cfg(test)]
mod tests;
