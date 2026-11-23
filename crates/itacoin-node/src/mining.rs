//! The control loop that feeds the embedded miner (sections 3.2 and 3.3 of
//! `docs/NODE_PROPOSAL.md`).

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use itacoin_blockchain::{Block, Tip};
use itacoin_miner::{Miner, build_block};
use itacoin_network::node::{BlockVerdict, NodeHandle};
use itacoin_primitives::{Hash256, WalletId};
use tokio::sync::{mpsc::UnboundedReceiver, watch};

/// How often the loop looks at the chain.
const POLL: Duration = Duration::from_millis(500);
/// Minimum time between templates when only the mempool changed.
pub const MEMPOOL_REFRESH: Duration = Duration::from_secs(30);

/// What the miner is waiting for, logged when it changes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum State {
    Off,
    Syncing,
    NoPeers,
    Mining,
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// Runs until `stop` turns true.
pub async fn run(
    handle: NodeHandle,
    miner: Miner,
    payout: WalletId,
    chain_id: Hash256,
    without_peers: bool,
    mut found: UnboundedReceiver<Block>,
    mut stop: watch::Receiver<bool>,
) {
    let mut state = State::Off;
    let mut last_tip: Option<Tip> = None;
    let mut last_mempool = (0_usize, 0_usize);
    let mut last_template = Instant::now();
    loop {
        tokio::select! {
            block = found.recv() => {
                let Some(block) = block else { return };
                let id = block.id();
                let height = block.height();
                match handle.call(move |core| core.submit_local_block(block)).await {
                    Some(BlockVerdict::Accepted(outcome)) => {
                        tracing::info!("mined block {id} at height {height} ({outcome:?})");
                    }
                    Some(other) => tracing::warn!("mined block {id} not accepted: {other:?}"),
                    None => return,
                }
                last_tip = None;
            }
            () = tokio::time::sleep(POLL) => {}
            _ = stop.changed() => return,
        }
        if *stop.borrow() {
            return;
        }

        let next = if miner.threads() == 0 {
            State::Off
        } else {
            let Some((tip, ibd, peers, mempool)) = handle
                .call(|core| {
                    (
                        core.chain().tip(),
                        core.is_initial_block_download(),
                        core.ready_peers(),
                        (core.mempool().len(), core.mempool().total_bytes()),
                    )
                })
                .await
            else {
                return;
            };
            let next = if ibd {
                State::Syncing
            } else if peers == 0 && !without_peers {
                State::NoPeers
            } else {
                State::Mining
            };
            let stale_mempool =
                mempool != last_mempool && last_template.elapsed() >= MEMPOOL_REFRESH;
            if next == State::Mining
                && (tip != last_tip || stale_mempool || !miner.has_work() || state != State::Mining)
            {
                let template = handle
                    .call(move |core| build_block(core.chain(), core.mempool(), payout, unix_now()))
                    .await;
                match template {
                    Some(Ok(block)) => {
                        miner.set_work(&block, chain_id);
                        last_tip = tip;
                        last_mempool = mempool;
                        last_template = Instant::now();
                    }
                    Some(Err(error)) => {
                        tracing::warn!("could not build a block template: {error}");
                        miner.clear_work();
                    }
                    None => return,
                }
            }
            next
        };
        if next != State::Mining && miner.has_work() {
            miner.clear_work();
            last_tip = None;
        }
        if next != state {
            match next {
                State::Off => tracing::info!("miner off"),
                State::Syncing => tracing::info!("miner paused: initial block download"),
                State::NoPeers => tracing::info!("miner paused: no peers"),
                State::Mining => tracing::info!("mining with {} threads", miner.threads()),
            }
            state = next;
        }
    }
}
