//! ITACOIN mining, as specified in section 3 of `docs/NODE_PROPOSAL.md`.
//!
//! - [`template`]: the next block on the active tip, filled from the mempool.
//! - [`Miner`]: a pool of OS threads searching Argon2id nonces.
//!
//! The crate does no I/O and holds no keys: work comes in through
//! [`Miner::set_work`] and solved blocks leave through a channel.

use std::{
    sync::{
        Arc, Condvar, Mutex, MutexGuard, PoisonError,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    thread::JoinHandle,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use itacoin_blockchain::{Block, BlockHeader};
use itacoin_consensus::check_pow;
use itacoin_primitives::Hash256;
use itacoin_transaction::Transaction;
use tokio::sync::mpsc::UnboundedSender;

pub mod template;

pub use template::{Template, TemplateError, build_block, build_template};

/// Tries between checks for new work.
pub const CHECK_INTERVAL: u64 = 64;
/// How often a worker moves its header timestamp forward.
pub const TIMESTAMP_REFRESH: Duration = Duration::from_secs(10);
/// Window over which the local hash rate is measured.
const RATE_WINDOW: Duration = Duration::from_secs(5);

/// The `k`-th nonce worker `index` of `count` tries: workers split the nonce
/// space by remainder, so they never repeat each other's work.
#[must_use]
pub const fn nonce_for(index: u64, count: u64, k: u64) -> u64 {
    index.wrapping_add(count.wrapping_mul(k))
}

struct Work {
    generation: u64,
    header: BlockHeader,
    transactions: Vec<Transaction>,
    chain_id: Hash256,
}

struct Rate {
    since: Instant,
    hashes_at_start: u64,
    last: f64,
}

struct Inner {
    work: Mutex<Option<Arc<Work>>>,
    changed: Condvar,
    generation: AtomicU64,
    solved: AtomicU64,
    epoch: AtomicU64,
    workers: Mutex<Vec<JoinHandle<()>>>,
    count: AtomicUsize,
    hashes: AtomicU64,
    rate: Mutex<Rate>,
    found: UnboundedSender<Block>,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// A pool of mining threads. Cloning gives another handle to the same pool.
#[derive(Clone)]
pub struct Miner {
    inner: Arc<Inner>,
}

impl core::fmt::Debug for Miner {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("Miner")
            .field("threads", &self.threads())
            .field("hashes", &self.hashes())
            .finish()
    }
}

impl Miner {
    /// Creates an idle pool that sends each solved block to `found`.
    #[must_use]
    pub fn new(found: UnboundedSender<Block>) -> Self {
        Self {
            inner: Arc::new(Inner {
                work: Mutex::new(None),
                changed: Condvar::new(),
                // Generation 0 means "no work"; real work starts at 1.
                generation: AtomicU64::new(0),
                solved: AtomicU64::new(0),
                epoch: AtomicU64::new(0),
                workers: Mutex::new(Vec::new()),
                count: AtomicUsize::new(0),
                hashes: AtomicU64::new(0),
                rate: Mutex::new(Rate {
                    since: Instant::now(),
                    hashes_at_start: 0,
                    last: 0.0,
                }),
                found,
            }),
        }
    }

    /// Replaces the worker threads with `count` new ones; zero stops mining.
    ///
    /// Blocks until the old workers exit, at most [`CHECK_INTERVAL`] hashes.
    pub fn set_threads(&self, count: usize) {
        let mut workers = lock(&self.inner.workers);
        let epoch = self.inner.epoch.fetch_add(1, Ordering::SeqCst) + 1;
        {
            let _guard = lock(&self.inner.work);
            self.inner.changed.notify_all();
        }
        for worker in workers.drain(..) {
            let _ = worker.join();
        }
        self.inner.count.store(count, Ordering::SeqCst);
        for index in 0..count {
            let inner = Arc::clone(&self.inner);
            let spawned = std::thread::Builder::new()
                .name(format!("itacoin-miner-{index}"))
                .spawn(move || work_loop(&inner, index as u64, count as u64, epoch));
            match spawned {
                Ok(handle) => workers.push(handle),
                Err(_) => {
                    self.inner.count.store(workers.len(), Ordering::SeqCst);
                    break;
                }
            }
        }
    }

    /// The number of worker threads.
    #[must_use]
    pub fn threads(&self) -> usize {
        self.inner.count.load(Ordering::SeqCst)
    }

    /// Gives the workers a new block to solve for `chain_id`. Workers drop
    /// their current work within [`CHECK_INTERVAL`] hashes.
    pub fn set_work(&self, block: &Block, chain_id: Hash256) {
        let mut work = lock(&self.inner.work);
        let generation = self.inner.generation.fetch_add(1, Ordering::SeqCst) + 1;
        *work = Some(Arc::new(Work {
            generation,
            header: *block.header(),
            transactions: block.transactions().to_vec(),
            chain_id,
        }));
        self.inner.changed.notify_all();
    }

    /// Withdraws the current work; workers idle until [`Miner::set_work`].
    pub fn clear_work(&self) {
        let mut work = lock(&self.inner.work);
        self.inner.generation.fetch_add(1, Ordering::SeqCst);
        *work = None;
        self.inner.changed.notify_all();
    }

    /// Whether the workers have work that is not solved yet.
    #[must_use]
    pub fn has_work(&self) -> bool {
        lock(&self.inner.work)
            .as_ref()
            .is_some_and(|work| work.generation != self.inner.solved.load(Ordering::SeqCst))
    }

    /// Total hashes computed since the pool was created.
    #[must_use]
    pub fn hashes(&self) -> u64 {
        self.inner.hashes.load(Ordering::Relaxed)
    }

    /// Hashes per second over the last few seconds.
    #[must_use]
    pub fn hashrate(&self) -> f64 {
        let mut rate = lock(&self.inner.rate);
        let elapsed = rate.since.elapsed();
        let hashes = self.hashes();
        let current = (hashes - rate.hashes_at_start) as f64 / elapsed.as_secs_f64().max(1e-3);
        if elapsed >= RATE_WINDOW {
            rate.last = current;
            rate.since = Instant::now();
            rate.hashes_at_start = hashes;
        }
        if rate.last == 0.0 { current } else { rate.last }
    }

    /// Stops every worker.
    pub fn shutdown(&self) {
        self.clear_work();
        self.set_threads(0);
    }
}

fn work_loop(inner: &Inner, index: u64, count: u64, epoch: u64) {
    let mut current: Option<Arc<Work>> = None;
    let mut header = BlockHeader {
        prev_block: itacoin_primitives::BlockId::new(Hash256::new([0; 32])),
        tx_root: Hash256::new([0; 32]),
        witness_root: Hash256::new([0; 32]),
        timestamp: 0,
        target: Hash256::new([0; 32]),
        nonce: 0,
    };
    let mut k = 0_u64;
    let mut refreshed = Instant::now();
    loop {
        if inner.epoch.load(Ordering::SeqCst) != epoch {
            return;
        }
        let generation = inner.generation.load(Ordering::SeqCst);
        let stale = current
            .as_ref()
            .is_none_or(|work| work.generation != generation)
            || inner.solved.load(Ordering::SeqCst) == generation;
        if stale {
            let mut guard = lock(&inner.work);
            loop {
                if inner.epoch.load(Ordering::SeqCst) != epoch {
                    return;
                }
                let solved = inner.solved.load(Ordering::SeqCst);
                if let Some(work) = guard.as_ref().filter(|work| work.generation != solved) {
                    current = Some(Arc::clone(work));
                    break;
                }
                guard = inner
                    .changed
                    .wait_timeout(guard, Duration::from_millis(500))
                    .unwrap_or_else(PoisonError::into_inner)
                    .0;
            }
            drop(guard);
            let Some(work) = current.as_ref() else {
                continue;
            };
            header = work.header;
            k = 0;
            refreshed = Instant::now();
        }
        let Some(work) = current.as_ref() else {
            continue;
        };

        if refreshed.elapsed() >= TIMESTAMP_REFRESH {
            header.timestamp = header.timestamp.max(unix_now());
            refreshed = Instant::now();
        }
        for _ in 0..CHECK_INTERVAL {
            header.nonce = nonce_for(index, count, k);
            k = k.wrapping_add(1);
            inner.hashes.fetch_add(1, Ordering::Relaxed);
            if check_pow(&header, &work.chain_id) {
                // Only the first worker to solve a generation sends it.
                let first =
                    inner.solved.fetch_max(work.generation, Ordering::SeqCst) < work.generation;
                if first && let Ok(block) = Block::new(header, work.transactions.clone()) {
                    let _ = inner.found.send(block);
                }
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests;
