//! The networked node (sections 4 to 9 of `docs/NETWORK_PROPOSAL.md`).
//!
//! One core thread owns all state (chain, mempool, header tree, address
//! manager, peers) and processes events one at a time, so there are no locks
//! around consensus state. Async tasks do the I/O: each peer has a task that
//! runs the encrypted handshake and moves decoded messages to the core, and a
//! writer task that sends what the core queues.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use itacoin_blockchain::{Block, Tip};
use itacoin_consensus::{ConsensusError, ConsensusParams, U256};
use itacoin_mempool::{Added, ChainView, Mempool, MempoolError, Policy};
use itacoin_primitives::{BlockId, Hash256, Network};
use itacoin_storage::{Chain, ChainError, StoreOptions, SubmitOutcome};
use itacoin_transaction::Transaction;
use rand_core::{OsRng, RngCore};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{mpsc, oneshot},
};
use tracing::debug;

use crate::{
    NetError,
    addrman::{AddrMan, group},
    compact::{self, Partial, Reconstruction},
    headers::{HeaderError, HeaderOutcome, HeaderTree, PeerHeaderSync},
    limits::{Discouraged, TokenBucket},
    message::{
        AddrEntry, InvItem, InvKind, MAX_ADDR, MAX_HEADERS, MAX_INV, Message, NetAddress,
        PROTOCOL_VERSION, SERVICE_NETWORK, SERVICE_WITNESS_PRUNED, Version,
    },
    transport,
};

/// The default port of each network.
#[must_use]
pub const fn default_port(network: Network) -> u16 {
    match network {
        Network::Mainnet => 7210,
        Network::Testnet => 17210,
        Network::Regtest => 17310,
    }
}

/// Node configuration.
#[derive(Clone, Debug)]
pub struct NodeConfig {
    /// Consensus parameters of the network.
    pub params: ConsensusParams,
    /// Directory for the chain store and peer files.
    pub data_dir: PathBuf,
    /// Address to accept connections on, if any.
    pub listen: Option<SocketAddr>,
    /// Connect only to these peers (disables automatic outbound selection).
    pub connect: Vec<SocketAddr>,
    /// Peers to stay connected to, in addition to automatic ones.
    pub add_nodes: Vec<SocketAddr>,
    /// DNS seed host names. Empty until the project defines its domains.
    pub dns_seeds: Vec<String>,
    /// Fallback seed addresses.
    pub fixed_seeds: Vec<SocketAddr>,
    /// Maximum inbound connections.
    pub max_inbound: usize,
    /// Outbound full-relay connections.
    pub outbound_full_relay: usize,
    /// Outbound block-relay-only connections.
    pub outbound_block_relay: usize,
    /// Time allowed for the transport and version handshakes.
    pub handshake_timeout: Duration,
    /// Interval between pings.
    pub ping_interval: Duration,
    /// Disconnect a peer that has not answered a ping for this long.
    pub ping_timeout: Duration,
    /// Mempool policy.
    pub mempool_policy: Policy,
    /// Minimum work a header branch needs to be stored.
    pub min_chain_work: U256,
    /// User agent sent in `version`.
    pub user_agent: String,
    /// Chain store options: coin cache, wallet index and pruning.
    pub store: StoreOptions,
}

impl NodeConfig {
    /// Defaults from the proposal for `params`, storing data in `data_dir`.
    #[must_use]
    pub fn new(params: ConsensusParams, data_dir: PathBuf) -> Self {
        Self {
            params,
            data_dir,
            listen: None,
            connect: Vec::new(),
            add_nodes: Vec::new(),
            dns_seeds: Vec::new(),
            fixed_seeds: Vec::new(),
            max_inbound: 117,
            outbound_full_relay: 8,
            outbound_block_relay: 2,
            handshake_timeout: Duration::from_secs(60),
            ping_interval: Duration::from_secs(120),
            ping_timeout: Duration::from_secs(20 * 60),
            mempool_policy: Policy::default(),
            min_chain_work: U256::ZERO,
            user_agent: "/itacoin:0.1.0/".into(),
            store: StoreOptions::default(),
        }
    }
}

/// Peer identifier, unique for the life of the node.
pub type PeerId = u64;

/// Why a connection exists.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnKind {
    /// They connected to us.
    Inbound,
    /// Outbound, relaying blocks, transactions and addresses.
    FullRelay,
    /// Outbound, relaying only blocks.
    BlockRelay,
    /// Short-lived outbound connection that tests an address.
    Feeler,
    /// Outbound to a configured peer; exempt from automatic limits.
    Manual,
}

const MAX_SEND_QUEUE: usize = 5_000_000;
const MAX_BLOCKS_IN_FLIGHT: usize = 16;
const DOWNLOAD_WINDOW: usize = 1_024;
const BLOCK_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_ORPHAN_BLOCKS: usize = 100;
const MAX_ORPHAN_BLOCKS_PER_PEER: usize = 10;
const ORPHAN_BLOCK_EXPIRY: Duration = Duration::from_secs(3_600);
const MAX_UNCONNECTING_HEADERS: u32 = 10;
const HIGH_BANDWIDTH_PEERS: usize = 3;
const FEELER_INTERVAL: Duration = Duration::from_secs(120);
const ADDR_SAVE_INTERVAL: Duration = Duration::from_secs(15 * 60);
const MEMPOOL_EXPIRE_INTERVAL: Duration = Duration::from_secs(60);
const TICK: Duration = Duration::from_millis(200);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_KNOWN_INVENTORY: usize = 50_000;
const MAX_RECENT_REJECTS: usize = 50_000;
/// Blocks below its announced tip a pruning peer is asked for.
const PRUNED_PEER_SERVES: u64 = 288;

enum Event {
    Inbound(TcpStream, SocketAddr),
    Connected {
        peer: PeerId,
        writer: mpsc::UnboundedSender<Message>,
        queued: Arc<AtomicUsize>,
    },
    Message {
        peer: PeerId,
        message: Box<Message>,
    },
    Closed {
        peer: PeerId,
        error: Option<NetError>,
    },
    Tick,
    Call(Box<dyn FnOnce(&mut Core) + Send>),
    Shutdown(oneshot::Sender<()>),
}

/// A bounded set that forgets its oldest entries.
#[derive(Debug, Default)]
struct RecentSet {
    set: HashSet<Hash256>,
    order: VecDeque<Hash256>,
    capacity: usize,
}

impl RecentSet {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            ..Self::default()
        }
    }

    fn insert(&mut self, key: Hash256) {
        if self.set.insert(key) {
            self.order.push_back(key);
            if self.order.len() > self.capacity
                && let Some(oldest) = self.order.pop_front()
            {
                self.set.remove(&oldest);
            }
        }
    }

    fn contains(&self, key: &Hash256) -> bool {
        self.set.contains(key)
    }
}

struct Peer {
    addr: SocketAddr,
    kind: ConnKind,
    writer: Option<mpsc::UnboundedSender<Message>>,
    queued: Arc<AtomicUsize>,
    kill: Option<oneshot::Sender<()>>,
    connected_at: Instant,
    version: Option<Version>,
    verack: bool,
    ready: bool,
    ping: Option<(u64, Instant)>,
    last_ping: Instant,
    min_ping: Option<Duration>,
    addr_bucket: TokenBucket,
    inv_bucket: TokenBucket,
    tx_queue: Vec<InvItem>,
    next_tx_flush: Instant,
    fee_filter: u64,
    wants_high_bandwidth: bool,
    asked_high_bandwidth: bool,
    sync: PeerHeaderSync,
    unconnecting: u32,
    in_flight: HashMap<BlockId, Instant>,
    pending_compact: Option<(BlockId, Partial)>,
    last_block: Option<Instant>,
    last_tx: Option<Instant>,
    known: RecentSet,
}

impl Peer {
    fn new(addr: SocketAddr, kind: ConnKind, kill: oneshot::Sender<()>, now: Instant) -> Self {
        Self {
            addr,
            kind,
            writer: None,
            queued: Arc::new(AtomicUsize::new(0)),
            kill: Some(kill),
            connected_at: now,
            version: None,
            verack: false,
            ready: false,
            ping: None,
            last_ping: now,
            min_ping: None,
            addr_bucket: TokenBucket::new(0.1, MAX_ADDR as f64, now),
            inv_bucket: TokenBucket::new(7.0, MAX_INV as f64, now),
            tx_queue: Vec::new(),
            next_tx_flush: now,
            fee_filter: 0,
            wants_high_bandwidth: false,
            asked_high_bandwidth: false,
            sync: PeerHeaderSync::default(),
            unconnecting: 0,
            in_flight: HashMap::new(),
            pending_compact: None,
            last_block: None,
            last_tx: None,
            known: RecentSet::new(MAX_KNOWN_INVENTORY),
        }
    }

    const fn inbound(&self) -> bool {
        matches!(self.kind, ConnKind::Inbound)
    }

    /// Whether transactions and addresses are relayed on this connection.
    fn relays(&self) -> bool {
        !matches!(self.kind, ConnKind::BlockRelay | ConnKind::Feeler)
            && self.version.as_ref().is_some_and(|version| version.relay)
    }
}

/// Counters for observing relay behavior.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Stats {
    /// Compact blocks rebuilt entirely from the mempool.
    pub compact_complete: u64,
    /// Compact blocks that needed a `getblocktxn` round trip.
    pub compact_partial: u64,
    /// Compact blocks that fell back to the full block.
    pub compact_fallback: u64,
}

/// What happened to a submitted block.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BlockVerdict {
    /// It passed validation: new tip, side chain or already known.
    Accepted(SubmitOutcome),
    /// Its parent is unknown.
    Orphan,
    /// Its timestamp is too far in the future; it may be retried later.
    Deferred,
    /// It is invalid.
    Rejected(String),
}

/// A connected peer, for diagnostics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerInfo {
    /// Its address.
    pub addr: SocketAddr,
    /// Why the connection exists.
    pub kind: ConnKind,
    /// Whether the handshake completed.
    pub ready: bool,
    /// Its protocol version, once known.
    pub protocol: Option<u32>,
    /// Its user agent, once known.
    pub user_agent: Option<String>,
    /// The tip height it announced in `version`.
    pub start_height: Option<u64>,
    /// Whether it relays transactions and addresses to us.
    pub relay: bool,
    /// Lowest ping round trip seen.
    pub min_ping: Option<Duration>,
    /// How long it has been connected.
    pub connected_for: Duration,
    /// Blocks it has in flight to us.
    pub blocks_in_flight: usize,
}

/// The node's state, owned by the core thread.
pub struct Core {
    config: NodeConfig,
    chain: Chain,
    mempool: Mempool,
    tree: HeaderTree,
    addrman: AddrMan,
    discouraged: Discouraged,
    peers: HashMap<PeerId, Peer>,
    next_id: PeerId,
    nonce: u64,
    runtime: tokio::runtime::Handle,
    events: mpsc::UnboundedSender<Event>,
    orphan_blocks: HashMap<BlockId, (Block, Instant, PeerId)>,
    recent_rejects: RecentSet,
    pending_outbound: HashSet<SocketAddr>,
    anchors: Vec<SocketAddr>,
    last_feeler: Instant,
    last_addr_save: Instant,
    last_mempool_expire: Instant,
    last_manual_attempt: HashMap<SocketAddr, Instant>,
    stats: Stats,
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

impl Core {
    /// The chain.
    #[must_use]
    pub const fn chain(&self) -> &Chain {
        &self.chain
    }

    /// The mempool.
    #[must_use]
    pub const fn mempool(&self) -> &Mempool {
        &self.mempool
    }

    /// The header tree.
    #[must_use]
    pub const fn headers(&self) -> &HeaderTree {
        &self.tree
    }

    /// The address manager.
    #[must_use]
    pub const fn addrman(&self) -> &AddrMan {
        &self.addrman
    }

    /// Number of peers that completed the handshake.
    #[must_use]
    pub fn ready_peers(&self) -> usize {
        self.peers.values().filter(|peer| peer.ready).count()
    }

    /// Addresses of the connected peers and their connection kinds.
    #[must_use]
    pub fn peer_addresses(&self) -> Vec<(SocketAddr, ConnKind)> {
        self.peers
            .values()
            .map(|peer| (peer.addr, peer.kind))
            .collect()
    }

    /// Relay counters.
    #[must_use]
    pub const fn stats(&self) -> Stats {
        self.stats
    }

    /// Whether `ip` is discouraged.
    #[must_use]
    pub fn is_discouraged(&self, ip: &IpAddr) -> bool {
        self.discouraged.contains(ip, Instant::now())
    }

    /// The configuration the node runs with.
    #[must_use]
    pub const fn config(&self) -> &NodeConfig {
        &self.config
    }

    /// Details of every connection.
    #[must_use]
    pub fn peer_info(&self) -> Vec<PeerInfo> {
        let now = Instant::now();
        let mut peers: Vec<(PeerId, PeerInfo)> = self
            .peers
            .iter()
            .map(|(id, peer)| {
                (
                    *id,
                    PeerInfo {
                        addr: peer.addr,
                        kind: peer.kind,
                        ready: peer.ready,
                        protocol: peer.version.as_ref().map(|version| version.protocol),
                        user_agent: peer
                            .version
                            .as_ref()
                            .map(|version| version.user_agent.clone()),
                        start_height: peer.version.as_ref().map(|version| version.height),
                        relay: peer.relays(),
                        min_ping: peer.min_ping,
                        connected_for: now.duration_since(peer.connected_at),
                        blocks_in_flight: peer.in_flight.len(),
                    },
                )
            })
            .collect();
        peers.sort_by_key(|(id, _)| *id);
        peers.into_iter().map(|(_, info)| info).collect()
    }

    /// Whether the node is still catching up: the header tree knows a chain
    /// with more work than the active tip, or a peer announced a higher tip.
    #[must_use]
    pub fn is_initial_block_download(&self) -> bool {
        let Some(tip) = self.chain.tip() else {
            return true;
        };
        let tip_work = self
            .chain
            .entry(&tip.block_id)
            .map_or(U256::ZERO, |entry| entry.chain_work);
        let best = self.tree.best().1;
        if !best.invalid && best.work > tip_work {
            return true;
        }
        self.peers.values().any(|peer| {
            peer.ready
                && peer
                    .version
                    .as_ref()
                    .is_some_and(|version| version.height > tip.height)
        })
    }

    /// Keeps a connection to `addr`, reconnecting when it drops.
    pub fn add_node(&mut self, addr: SocketAddr) {
        if !self.config.add_nodes.contains(&addr) {
            self.config.add_nodes.push(addr);
        }
        self.connect_outbound(addr, ConnKind::Manual);
    }

    /// Stops keeping a connection to `addr`. Returns whether it was listed.
    pub fn remove_node(&mut self, addr: SocketAddr) -> bool {
        let before = self.config.add_nodes.len();
        self.config.add_nodes.retain(|listed| *listed != addr);
        before != self.config.add_nodes.len()
    }

    /// Connects once to `addr`, without reconnecting.
    pub fn connect_once(&mut self, addr: SocketAddr) {
        self.connect_outbound(addr, ConnKind::Manual);
    }

    /// Disconnects every peer at `addr`. Returns how many were connected.
    pub fn disconnect_addr(&mut self, addr: SocketAddr) -> usize {
        let ids: Vec<PeerId> = self
            .peers
            .iter()
            .filter(|(_, peer)| peer.addr == addr)
            .map(|(id, _)| *id)
            .collect();
        for id in &ids {
            self.disconnect(*id);
        }
        ids.len()
    }

    /// Discouraged IPs and the time each stays discouraged.
    #[must_use]
    pub fn discouraged(&self) -> Vec<(IpAddr, Duration)> {
        self.discouraged.list(Instant::now())
    }

    /// Forgets every discouraged IP.
    pub fn clear_discouraged(&mut self) {
        self.discouraged = Discouraged::default();
    }

    /// Submits a locally produced block and reports what happened to it.
    pub fn submit_local_block(&mut self, block: Block) -> BlockVerdict {
        self.handle_block(block, None)
    }

    /// Submits a locally produced transaction to the mempool and relays it.
    pub fn submit_local_transaction(
        &mut self,
        transaction: Transaction,
    ) -> Result<Added, MempoolError> {
        self.on_transaction(None, transaction)
    }

    fn magic(&self) -> [u8; 4] {
        self.chain.chain_id().as_bytes()[..4]
            .try_into()
            .expect("4 bytes")
    }

    // ---------------------------------------------------------------- peers

    fn send(&mut self, peer: PeerId, message: Message) {
        let Some(state) = self.peers.get(&peer) else {
            return;
        };
        let Some(writer) = &state.writer else {
            return;
        };
        let size = message.encode_payload().len() + 64;
        state.queued.fetch_add(size, Ordering::Relaxed);
        if writer.send(message).is_err() {
            state.queued.fetch_sub(size, Ordering::Relaxed);
        }
    }

    fn disconnect(&mut self, peer: PeerId) {
        if let Some(mut state) = self.peers.remove(&peer) {
            if let Some(kill) = state.kill.take() {
                let _ = kill.send(());
            }
            debug!("disconnected {} ({:?})", state.addr, state.kind);
        }
    }

    fn misbehave(&mut self, peer: PeerId, reason: &str) {
        if let Some(state) = self.peers.get(&peer) {
            debug!("peer {} misbehaved: {reason}", state.addr);
            let ip = state.addr.ip();
            self.discouraged.add(ip, Instant::now());
        }
        self.disconnect(peer);
    }

    fn spawn_peer(&mut self, stream: TcpStream, addr: SocketAddr, kind: ConnKind) {
        let id = self.next_id;
        self.next_id += 1;
        let (kill_tx, kill_rx) = oneshot::channel();
        self.peers
            .insert(id, Peer::new(addr, kind, kill_tx, Instant::now()));
        let events = self.events.clone();
        let magic = self.magic();
        let timeout = self.config.handshake_timeout;
        let initiator = !matches!(kind, ConnKind::Inbound);
        self.runtime.spawn(run_peer(
            stream, id, initiator, magic, timeout, events, kill_rx,
        ));
    }

    fn connect_outbound(&mut self, addr: SocketAddr, kind: ConnKind) {
        if !self.pending_outbound.insert(addr) {
            return;
        }
        self.addrman.attempt(&addr, unix_now());
        let events = self.events.clone();
        self.runtime.spawn(async move {
            let stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await;
            let call: Box<dyn FnOnce(&mut Core) + Send> = match stream {
                Ok(Ok(stream)) => Box::new(move |core: &mut Core| {
                    core.pending_outbound.remove(&addr);
                    core.spawn_peer(stream, addr, kind);
                }),
                _ => Box::new(move |core: &mut Core| {
                    core.pending_outbound.remove(&addr);
                }),
            };
            let _ = events.send(Event::Call(call));
        });
    }

    fn on_inbound(&mut self, stream: TcpStream, addr: SocketAddr) {
        let now = Instant::now();
        let inbound = self.peers.values().filter(|peer| peer.inbound()).count();
        let discouraged = self.discouraged.contains(&addr.ip(), now);
        if discouraged && inbound * 2 >= self.config.max_inbound {
            return;
        }
        if inbound >= self.config.max_inbound && !self.evict_inbound() {
            return;
        }
        self.spawn_peer(stream, addr, ConnKind::Inbound);
    }

    /// Evicts one inbound peer, protecting diverse, fast and useful ones.
    fn evict_inbound(&mut self) -> bool {
        let now = Instant::now();
        let mut candidates: Vec<(PeerId, &Peer)> = self
            .peers
            .iter()
            .filter(|(_, peer)| peer.inbound())
            .map(|(id, peer)| (*id, peer))
            .collect();
        if let Some((id, _)) = candidates
            .iter()
            .find(|(_, peer)| self.discouraged.contains(&peer.addr.ip(), now))
        {
            let id = *id;
            self.disconnect(id);
            return true;
        }
        let salt = self.nonce.to_be_bytes();
        let keyed_group = |peer: &Peer| {
            let mut hasher = blake3::Hasher::new_keyed(&blake3::hash(&salt).into());
            hasher.update(&group(peer.addr.ip()));
            *hasher.finalize().as_bytes()
        };
        // Protect 4 by distinct keyed network group.
        candidates.sort_by_key(|(_, peer)| keyed_group(peer));
        let mut protected_groups = HashSet::new();
        candidates.retain(|(_, peer)| {
            if protected_groups.len() < 4 && protected_groups.insert(group(peer.addr.ip())) {
                return false;
            }
            true
        });
        // Protect the 8 fastest, then the 4 latest transaction and block givers.
        candidates.sort_by_key(|(_, peer)| peer.min_ping.unwrap_or(Duration::MAX));
        candidates.drain(..candidates.len().min(8));
        candidates.sort_by_key(|(_, peer)| core::cmp::Reverse(peer.last_tx));
        candidates.drain(..candidates.len().min(4));
        candidates.sort_by_key(|(_, peer)| core::cmp::Reverse(peer.last_block));
        candidates.drain(..candidates.len().min(4));
        if candidates.is_empty() {
            return false;
        }
        // Evict the youngest peer of the most represented group.
        let mut by_group: HashMap<Vec<u8>, Vec<(PeerId, Instant)>> = HashMap::new();
        for (id, peer) in &candidates {
            by_group
                .entry(group(peer.addr.ip()))
                .or_default()
                .push((*id, peer.connected_at));
        }
        let victim = by_group
            .values()
            .max_by_key(|members| (members.len(), members.iter().map(|m| m.1).max()))
            .and_then(|members| members.iter().max_by_key(|member| member.1))
            .map(|member| member.0);
        match victim {
            Some(id) => {
                self.disconnect(id);
                true
            }
            None => false,
        }
    }

    fn on_connected(
        &mut self,
        peer: PeerId,
        writer: mpsc::UnboundedSender<Message>,
        queued: Arc<AtomicUsize>,
    ) {
        let Some(state) = self.peers.get_mut(&peer) else {
            return;
        };
        state.writer = Some(writer);
        state.queued = queued;
        if !state.inbound() {
            self.send_version(peer);
        }
    }

    fn send_version(&mut self, peer: PeerId) {
        let relay = self
            .peers
            .get(&peer)
            .is_some_and(|state| !matches!(state.kind, ConnKind::BlockRelay | ConnKind::Feeler));
        let version = Version {
            protocol: PROTOCOL_VERSION,
            // A pruning node serves only recent blocks (section 5.4 of the
            // storage proposal).
            services: if self.config.store.prune_depth.is_some() {
                SERVICE_WITNESS_PRUNED
            } else {
                SERVICE_NETWORK
            },
            height: self.chain.tip().map_or(0, |tip| tip.height),
            timestamp: unix_now(),
            nonce: self.nonce,
            relay,
            user_agent: self.config.user_agent.clone(),
        };
        self.send(peer, Message::Version(version));
    }

    fn on_ready(&mut self, peer: PeerId) {
        let Some(state) = self.peers.get_mut(&peer) else {
            return;
        };
        state.ready = true;
        let kind = state.kind;
        let addr = state.addr;
        let relays = state.relays();
        debug!("peer {addr} ready ({kind:?})");
        if !matches!(kind, ConnKind::Inbound) {
            self.addrman.good(&addr, unix_now());
        }
        if kind == ConnKind::Feeler {
            self.disconnect(peer);
            return;
        }
        if relays {
            let fee = self.mempool.policy().min_fee_per_byte;
            self.send(peer, Message::FeeFilter(fee));
        }
        let high_bandwidth = matches!(kind, ConnKind::FullRelay | ConnKind::Manual)
            && self
                .peers
                .values()
                .filter(|other| other.ready && other.wants_high_bandwidth_from_us())
                .count()
                < HIGH_BANDWIDTH_PEERS;
        self.send(
            peer,
            Message::SendCmpct {
                high_bandwidth,
                version: 1,
            },
        );
        if let Some(state) = self.peers.get_mut(&peer) {
            state.asked_high_bandwidth = high_bandwidth;
        }
        let locator = self.tree.locator(self.tree.best().0);
        self.send(
            peer,
            Message::GetHeaders {
                locator,
                stop: BlockId::new(Hash256::new([0; 32])),
            },
        );
        if relays {
            let now = unix_now();
            let sample: Vec<AddrEntry> = self
                .addrman
                .sample(MAX_ADDR, now)
                .into_iter()
                .map(|info| AddrEntry {
                    time: info.last_seen,
                    services: info.services,
                    address: NetAddress::Ip(info.addr),
                })
                .collect();
            if !sample.is_empty() {
                self.send(peer, Message::Addr(sample));
            }
        }
    }

    // ------------------------------------------------------------- messages

    fn on_message(&mut self, peer: PeerId, message: Message) {
        let Some(state) = self.peers.get(&peer) else {
            return;
        };
        if !state.ready {
            self.on_handshake_message(peer, message);
            return;
        }
        match message {
            Message::Version(_) | Message::Verack => self.misbehave(peer, "repeated handshake"),
            Message::Ping(nonce) => self.send(peer, Message::Pong(nonce)),
            Message::Pong(nonce) => self.on_pong(peer, nonce),
            Message::Addr(entries) => self.on_addr(peer, entries),
            Message::GetHeaders { locator, stop } => self.on_getheaders(peer, &locator, stop),
            Message::Headers(headers) => self.on_headers(peer, &headers),
            Message::Inv(items) => self.on_inv(peer, &items),
            Message::GetData(items) => self.on_getdata(peer, &items),
            Message::NotFound(items) => {
                if let Some(state) = self.peers.get_mut(&peer) {
                    for item in items {
                        state.in_flight.remove(&BlockId::new(item.id));
                    }
                }
            }
            Message::Tx(transaction) => {
                let _ = self.on_transaction(Some(peer), transaction);
            }
            Message::Block(block) => {
                self.handle_block(block, Some(peer));
            }
            Message::SendCmpct {
                high_bandwidth,
                version,
            } => {
                if version == 1
                    && let Some(state) = self.peers.get_mut(&peer)
                {
                    state.wants_high_bandwidth = high_bandwidth;
                }
            }
            Message::CmpctBlock(compact) => self.on_compact_block(peer, compact),
            Message::GetBlockTxn { block_id, indexes } => {
                self.on_getblocktxn(peer, block_id, &indexes);
            }
            Message::BlockTxn {
                block_id,
                transactions,
            } => self.on_blocktxn(peer, block_id, transactions),
            Message::FeeFilter(rate) => {
                if let Some(state) = self.peers.get_mut(&peer) {
                    state.fee_filter = rate;
                }
            }
        }
    }

    fn on_handshake_message(&mut self, peer: PeerId, message: Message) {
        let Some(state) = self.peers.get_mut(&peer) else {
            return;
        };
        match message {
            Message::Version(version) => {
                if state.version.is_some() {
                    self.misbehave(peer, "repeated version");
                    return;
                }
                if version.nonce == self.nonce {
                    debug!("connected to self at {}", state.addr);
                    self.disconnect(peer);
                    return;
                }
                if version.protocol < PROTOCOL_VERSION {
                    self.disconnect(peer);
                    return;
                }
                let inbound = state.inbound();
                state.version = Some(version);
                if inbound {
                    self.send_version(peer);
                }
                self.send(peer, Message::Verack);
                self.check_ready(peer);
            }
            Message::Verack => {
                if state.verack || state.version.is_none() {
                    self.misbehave(peer, "unexpected verack");
                    return;
                }
                state.verack = true;
                self.check_ready(peer);
            }
            _ => self.misbehave(peer, "message before handshake"),
        }
    }

    fn check_ready(&mut self, peer: PeerId) {
        if self
            .peers
            .get(&peer)
            .is_some_and(|state| state.version.is_some() && state.verack && !state.ready)
        {
            self.on_ready(peer);
        }
    }

    fn on_pong(&mut self, peer: PeerId, nonce: u64) {
        if let Some(state) = self.peers.get_mut(&peer)
            && let Some((expected, sent)) = state.ping
            && expected == nonce
        {
            let latency = sent.elapsed();
            state.min_ping = Some(state.min_ping.map_or(latency, |min| min.min(latency)));
            state.ping = None;
        }
    }

    fn on_addr(&mut self, peer: PeerId, entries: Vec<AddrEntry>) {
        let now = unix_now();
        let instant = Instant::now();
        let Some(state) = self.peers.get_mut(&peer) else {
            return;
        };
        if !state.relays() {
            return;
        }
        // Excess addresses are ignored, not punished.
        let granted = state.addr_bucket.take(entries.len(), instant);
        let source = state.addr.ip();
        let mut fresh = Vec::new();
        for entry in entries.iter().take(granted) {
            if let NetAddress::Ip(addr) = entry.address {
                if addr.port() == 0 {
                    continue;
                }
                self.addrman
                    .add(addr, entry.services, entry.time, source, now);
                if entries.len() <= 10 && now.saturating_sub(entry.time) < 600 {
                    fresh.push(*entry);
                }
            }
        }
        if !fresh.is_empty() {
            let mut targets: Vec<PeerId> = self
                .peers
                .iter()
                .filter(|(id, other)| **id != peer && other.ready && other.relays())
                .map(|(id, _)| *id)
                .collect();
            targets.sort_by_key(|_| OsRng.next_u32());
            for target in targets.into_iter().take(2) {
                self.send(target, Message::Addr(fresh.clone()));
            }
        }
    }

    fn on_getheaders(&mut self, peer: PeerId, locator: &[BlockId], stop: BlockId) {
        let store = self.chain.store();
        let mut start = 0;
        for id in locator {
            if let Some(entry) = self.chain.entry(id)
                && store.block_id_at(entry.height).ok().flatten() == Some(*id)
            {
                start = entry.height + 1;
                break;
            }
        }
        let tip_height = self.chain.tip().map_or(0, |tip| tip.height);
        let mut headers = Vec::new();
        let mut height = start;
        while height <= tip_height && headers.len() < MAX_HEADERS {
            let Some(id) = store.block_id_at(height).ok().flatten() else {
                break;
            };
            let Some(entry) = self.chain.entry(&id) else {
                break;
            };
            headers.push(entry.header);
            if id == stop {
                break;
            }
            height += 1;
        }
        self.send(peer, Message::Headers(headers));
    }

    fn on_headers(&mut self, peer: PeerId, headers: &[itacoin_blockchain::BlockHeader]) {
        let now = unix_now();
        let Some(state) = self.peers.get_mut(&peer) else {
            return;
        };
        let outcome = self.tree.process(&mut state.sync, headers, now);
        // An empty answer to our locator means the peer has nothing beyond
        // our chain: it holds our best chain up to the height it announced.
        // Without this, a peer that joins after the headers are known is
        // never asked for blocks.
        if headers.is_empty()
            && let Some(version) = state.version.as_ref()
        {
            let (best, node) = self.tree.best();
            let height = version.height.min(node.height);
            if let Some(known) = self.tree.ancestor_at(best, height) {
                state.sync.best_known = Some(known);
            }
        }
        match outcome {
            Ok(HeaderOutcome::Stored { last, full, .. }) => {
                state.unconnecting = 0;
                if full {
                    let locator = self.tree.locator(last);
                    self.send(
                        peer,
                        Message::GetHeaders {
                            locator,
                            stop: BlockId::new(Hash256::new([0; 32])),
                        },
                    );
                }
                self.request_blocks();
            }
            Ok(HeaderOutcome::Presyncing { last, full }) => {
                if full {
                    self.send(
                        peer,
                        Message::GetHeaders {
                            locator: vec![last],
                            stop: BlockId::new(Hash256::new([0; 32])),
                        },
                    );
                }
            }
            Ok(HeaderOutcome::Redownload { fork }) => {
                let locator = self.tree.locator(fork);
                self.send(
                    peer,
                    Message::GetHeaders {
                        locator,
                        stop: BlockId::new(Hash256::new([0; 32])),
                    },
                );
            }
            Ok(HeaderOutcome::Unconnected) => {
                state.unconnecting += 1;
                if state.unconnecting > MAX_UNCONNECTING_HEADERS {
                    self.misbehave(peer, "too many unconnecting headers");
                    return;
                }
                let locator = self.tree.locator(self.tree.best().0);
                self.send(
                    peer,
                    Message::GetHeaders {
                        locator,
                        stop: BlockId::new(Hash256::new([0; 32])),
                    },
                );
            }
            Err(HeaderError::Consensus(ConsensusError::TimestampInFuture)) => {}
            Err(_) => self.misbehave(peer, "invalid headers"),
        }
    }

    fn on_inv(&mut self, peer: PeerId, items: &[InvItem]) {
        let instant = Instant::now();
        let mut wanted = Vec::new();
        let mut unknown_block = false;
        let Some(state) = self.peers.get_mut(&peer) else {
            return;
        };
        let relays = state.relays();
        let granted = state.inv_bucket.take(items.len(), instant);
        for item in items.iter().take(granted) {
            match item.kind {
                InvKind::Block => {
                    if self.tree.get(&BlockId::new(item.id)).is_none() {
                        unknown_block = true;
                    }
                }
                InvKind::Tx => {
                    state.known.insert(item.id);
                    let txid = itacoin_primitives::TransactionId::new(item.id);
                    if relays
                        && !self.mempool.contains(&txid)
                        && !self.recent_rejects.contains(&item.id)
                    {
                        wanted.push(*item);
                    }
                }
                InvKind::CmpctBlock => {}
            }
        }
        if !wanted.is_empty() {
            self.send(peer, Message::GetData(wanted));
        }
        if unknown_block {
            let locator = self.tree.locator(self.tree.best().0);
            self.send(
                peer,
                Message::GetHeaders {
                    locator,
                    stop: BlockId::new(Hash256::new([0; 32])),
                },
            );
        }
    }

    fn on_getdata(&mut self, peer: PeerId, items: &[InvItem]) {
        let mut not_found = Vec::new();
        for item in items {
            match item.kind {
                InvKind::Tx => {
                    let txid = itacoin_primitives::TransactionId::new(item.id);
                    match self.mempool.get(&txid) {
                        Some(entry) if entry.witness_hash() == item.witness_hash => {
                            let transaction = Transaction::Normal(entry.transaction().clone());
                            self.send(peer, Message::Tx(transaction));
                        }
                        _ => not_found.push(*item),
                    }
                }
                InvKind::Block | InvKind::CmpctBlock => {
                    match self.chain.store().block(&BlockId::new(item.id)) {
                        Ok(Some(block)) if item.kind == InvKind::CmpctBlock => {
                            let nonce = OsRng.next_u64();
                            self.send(peer, Message::CmpctBlock(compact::build(&block, nonce)));
                        }
                        Ok(Some(block)) => self.send(peer, Message::Block(block)),
                        _ => not_found.push(*item),
                    }
                }
            }
        }
        if !not_found.is_empty() {
            self.send(peer, Message::NotFound(not_found));
        }
    }

    fn on_compact_block(&mut self, peer: PeerId, compact: crate::message::CmpctBlock) {
        let id = compact.header.id();
        if self.tree.get(&id).is_some_and(|node| node.have_block) {
            return;
        }
        let now = unix_now();
        let Some(state) = self.peers.get_mut(&peer) else {
            return;
        };
        match self.tree.process(&mut state.sync, &[compact.header], now) {
            Ok(HeaderOutcome::Stored { .. }) => {}
            Ok(HeaderOutcome::Unconnected) => {
                let locator = self.tree.locator(self.tree.best().0);
                self.send(
                    peer,
                    Message::GetHeaders {
                        locator,
                        stop: BlockId::new(Hash256::new([0; 32])),
                    },
                );
                return;
            }
            Ok(_) | Err(HeaderError::Consensus(ConsensusError::TimestampInFuture)) => return,
            Err(_) => {
                self.misbehave(peer, "invalid compact block header");
                return;
            }
        }
        let candidates = self.mempool.entries().map(|entry| {
            (
                entry.txid().into_hash(),
                entry.witness_hash(),
                entry.transaction(),
            )
        });
        match compact::reconstruct(&compact, candidates) {
            Reconstruction::Complete(partial) => match partial.finish() {
                Some(block) => {
                    self.stats.compact_complete += 1;
                    self.handle_block(block, Some(peer));
                }
                None => {
                    self.stats.compact_fallback += 1;
                    self.request_full_block(peer, id);
                }
            },
            Reconstruction::Missing(partial, missing) => {
                self.stats.compact_partial += 1;
                if let Some(state) = self.peers.get_mut(&peer) {
                    state.pending_compact = Some((id, partial));
                }
                self.send(
                    peer,
                    Message::GetBlockTxn {
                        block_id: id,
                        indexes: missing,
                    },
                );
            }
            Reconstruction::Collision => {
                self.stats.compact_fallback += 1;
                self.request_full_block(peer, id);
            }
        }
    }

    fn request_full_block(&mut self, peer: PeerId, id: BlockId) {
        if let Some(state) = self.peers.get_mut(&peer) {
            state.in_flight.insert(id, Instant::now());
        }
        self.send(
            peer,
            Message::GetData(vec![InvItem::block(InvKind::Block, id)]),
        );
    }

    fn on_getblocktxn(&mut self, peer: PeerId, block_id: BlockId, indexes: &[u32]) {
        let Ok(Some(block)) = self.chain.store().block(&block_id) else {
            return;
        };
        let mut transactions = Vec::with_capacity(indexes.len());
        for index in indexes {
            match block.transactions().get(*index as usize) {
                Some(transaction) => transactions.push(transaction.clone()),
                None => {
                    self.misbehave(peer, "getblocktxn index out of range");
                    return;
                }
            }
        }
        self.send(
            peer,
            Message::BlockTxn {
                block_id,
                transactions,
            },
        );
    }

    fn on_blocktxn(&mut self, peer: PeerId, block_id: BlockId, transactions: Vec<Transaction>) {
        let Some(state) = self.peers.get_mut(&peer) else {
            return;
        };
        let Some((pending, mut partial)) = state.pending_compact.take() else {
            return;
        };
        if pending != block_id {
            state.pending_compact = Some((pending, partial));
            return;
        }
        if partial.fill(transactions)
            && let Some(block) = partial.finish()
        {
            self.handle_block(block, Some(peer));
            return;
        }
        self.request_full_block(peer, block_id);
    }

    // ---------------------------------------------------------------- relay

    fn on_transaction(
        &mut self,
        source: Option<PeerId>,
        transaction: Transaction,
    ) -> Result<Added, MempoolError> {
        if let Some(peer) = source {
            let Some(state) = self.peers.get_mut(&peer) else {
                return Err(MempoolError::AlreadyKnown);
            };
            if !state.relays() {
                return Err(MempoolError::AlreadyKnown);
            }
            state.last_tx = Some(Instant::now());
            state.known.insert(transaction.txid().into_hash());
        }
        let txid = transaction.txid().into_hash();
        if self.recent_rejects.contains(&txid) {
            return Err(MempoolError::AlreadyKnown);
        }
        let now = unix_now();
        let view = ChainView {
            coins: &self.chain.coins(),
            chain_id: self.chain.chain_id(),
            next_height: self.chain.tip().map_or(0, |tip| tip.height + 1),
            coinbase_maturity: self.config.params.coinbase_maturity,
        };
        match self.mempool.add(transaction, &view, now) {
            Ok(added) => {
                for txid in &added.accepted {
                    self.announce_transaction(*txid, source);
                }
                Ok(added)
            }
            Err(MempoolError::Invalid(error)) => {
                // Consensus-invalid: the sender either is broken or attacking.
                if let Some(peer) = source {
                    self.misbehave(peer, "invalid transaction");
                }
                self.recent_rejects.insert(txid);
                Err(MempoolError::Invalid(error))
            }
            Err(MempoolError::AlreadyKnown) => Err(MempoolError::AlreadyKnown),
            Err(error) => {
                self.recent_rejects.insert(txid);
                Err(error)
            }
        }
    }

    fn announce_transaction(
        &mut self,
        txid: itacoin_primitives::TransactionId,
        source: Option<PeerId>,
    ) {
        let Some(entry) = self.mempool.get(&txid) else {
            return;
        };
        let item = InvItem::tx(txid.into_hash(), entry.witness_hash());
        let rate_numerator = entry.fee().as_satoshis();
        let size = entry.size() as u64;
        for (id, peer) in &mut self.peers {
            if Some(*id) == source || !peer.ready || !peer.relays() {
                continue;
            }
            if rate_numerator < peer.fee_filter.saturating_mul(size) {
                continue;
            }
            if peer.known.contains(&item.id) {
                continue;
            }
            peer.known.insert(item.id);
            peer.tx_queue.push(item);
        }
    }

    fn flush_transaction_announcements(&mut self, now: Instant) {
        let ready: Vec<PeerId> = self
            .peers
            .iter()
            .filter(|(_, peer)| {
                peer.ready && !peer.tx_queue.is_empty() && now >= peer.next_tx_flush
            })
            .map(|(id, _)| *id)
            .collect();
        for id in ready {
            let Some(peer) = self.peers.get_mut(&id) else {
                continue;
            };
            let mean = if peer.inbound() { 5.0 } else { 2.0 };
            peer.next_tx_flush = now + poisson_delay(mean);
            let batch: Vec<InvItem> = peer
                .tx_queue
                .drain(..peer.tx_queue.len().min(MAX_INV))
                .collect();
            self.send(id, Message::Inv(batch));
        }
    }

    // --------------------------------------------------------------- blocks

    /// Submits `block` and any orphans it connects. Returns what happened to
    /// `block` itself.
    fn handle_block(&mut self, block: Block, source: Option<PeerId>) -> BlockVerdict {
        let mut verdict = None;
        let mut queue = VecDeque::from([(block, source)]);
        while let Some((block, source)) = queue.pop_front() {
            let id = block.id();
            for peer in self.peers.values_mut() {
                peer.in_flight.remove(&id);
            }
            if let Some(peer) = source.and_then(|peer| self.peers.get_mut(&peer)) {
                peer.last_block = Some(Instant::now());
            }
            let tip_before = self.chain.tip();
            // Batch commits while catching up (section 4 of the storage
            // proposal); every block is durable once in sync.
            let bulk = self.is_initial_block_download();
            if let Err(error) = self.chain.set_bulk(bulk) {
                tracing::error!("could not change the commit mode: {error}");
            }
            let result = self.chain.submit_block(&block, unix_now());
            if verdict.is_none() {
                verdict = Some(match &result {
                    Ok(outcome) => BlockVerdict::Accepted(*outcome),
                    Err(ChainError::UnknownParent(_)) => BlockVerdict::Orphan,
                    Err(ChainError::Consensus(ConsensusError::TimestampInFuture)) => {
                        BlockVerdict::Deferred
                    }
                    Err(error) => BlockVerdict::Rejected(error.to_string()),
                });
            }
            match result {
                Ok(outcome) => {
                    if let Some(entry) = self.chain.entry(&id) {
                        self.tree
                            .block_stored(id, entry.header, entry.height, entry.chain_work);
                    }
                    if outcome != SubmitOutcome::Duplicate && self.chain.tip() != tip_before {
                        self.on_tip_changed(tip_before, source);
                    }
                    let children: Vec<BlockId> = self
                        .orphan_blocks
                        .iter()
                        .filter(|(_, (orphan, _, _))| orphan.header().prev_block == id)
                        .map(|(child, _)| *child)
                        .collect();
                    for child in children {
                        if let Some((orphan, _, from)) = self.orphan_blocks.remove(&child) {
                            queue.push_back((orphan, Some(from)));
                        }
                    }
                }
                Err(ChainError::UnknownParent(_)) => {
                    if let Some(peer) = source {
                        self.add_orphan_block(block, peer);
                        let locator = self.tree.locator(self.tree.best().0);
                        self.send(
                            peer,
                            Message::GetHeaders {
                                locator,
                                stop: BlockId::new(Hash256::new([0; 32])),
                            },
                        );
                    }
                }
                Err(ChainError::Consensus(ConsensusError::TimestampInFuture)) => {}
                Err(ChainError::Storage(error)) => {
                    tracing::error!("storage failure: {error}");
                }
                Err(
                    ChainError::InvalidBlock { block_id, .. }
                    | ChainError::InvalidAncestor(block_id),
                ) => {
                    self.sync_invalid(block_id);
                    if let Some(peer) = source {
                        self.misbehave(peer, "invalid block");
                    }
                }
                Err(_) => {
                    if self.tree.get(&id).is_some() {
                        self.tree.mark_invalid(id);
                    }
                    if let Some(peer) = source {
                        self.misbehave(peer, "invalid block");
                    }
                }
            }
        }
        self.request_blocks();
        verdict.unwrap_or(BlockVerdict::Deferred)
    }

    /// Copies the chain's invalid marks into the header tree for `from` and
    /// its ancestors.
    fn sync_invalid(&mut self, from: BlockId) {
        let mut current = from;
        for _ in 0..DOWNLOAD_WINDOW {
            let invalid = self
                .chain
                .entry(&current)
                .is_some_and(|entry| entry.invalid);
            let parent = self.tree.get(&current).map(|node| node.header.prev_block);
            if invalid && !self.tree.get(&current).is_some_and(|node| node.invalid) {
                self.tree.mark_invalid(current);
            }
            match parent {
                Some(parent) => current = parent,
                None => break,
            }
        }
    }

    fn add_orphan_block(&mut self, block: Block, peer: PeerId) {
        let from_peer = self
            .orphan_blocks
            .values()
            .filter(|(_, _, from)| *from == peer)
            .count();
        if from_peer >= MAX_ORPHAN_BLOCKS_PER_PEER {
            return;
        }
        if self.orphan_blocks.len() >= MAX_ORPHAN_BLOCKS
            && let Some(oldest) = self
                .orphan_blocks
                .iter()
                .min_by_key(|(_, (_, time, _))| *time)
                .map(|(id, _)| *id)
        {
            self.orphan_blocks.remove(&oldest);
        }
        self.orphan_blocks
            .insert(block.id(), (block, Instant::now(), peer));
    }

    fn on_tip_changed(&mut self, old: Option<Tip>, source: Option<PeerId>) {
        let Some(new) = self.chain.tip() else {
            return;
        };
        let fork = old.and_then(|old| self.chain.common_ancestor(old.block_id, new.block_id));
        let load = |chain: &Chain, ids: Vec<BlockId>| -> Vec<Block> {
            ids.iter()
                .filter_map(|id| chain.store().block(id).ok().flatten())
                .collect()
        };
        let (disconnected, connected) = match (old, fork) {
            (Some(old), Some(fork)) => (
                load(&self.chain, self.chain.branch(fork, old.block_id)),
                load(&self.chain, self.chain.branch(fork, new.block_id)),
            ),
            _ => (Vec::new(), load(&self.chain, vec![new.block_id])),
        };

        let now = unix_now();
        for block in &connected {
            self.mempool.remove_confirmed(block);
        }
        let view = ChainView {
            coins: &self.chain.coins(),
            chain_id: self.chain.chain_id(),
            next_height: new.height + 1,
            coinbase_maturity: self.config.params.coinbase_maturity,
        };
        self.mempool.readd_disconnected(&disconnected, &view, now);
        self.mempool.resync(&view, now);

        // Announce: compact blocks to peers that asked for high bandwidth,
        // headers to the others.
        let announce: Vec<&Block> = connected.iter().rev().take(8).rev().collect();
        let headers: Vec<_> = announce.iter().map(|block| *block.header()).collect();
        let tip_block = connected.last().cloned();
        let targets: Vec<(PeerId, bool)> = self
            .peers
            .iter()
            .filter(|(id, peer)| Some(**id) != source && peer.ready)
            .map(|(id, peer)| (*id, peer.wants_high_bandwidth))
            .collect();
        for (peer, high_bandwidth) in targets {
            match (&tip_block, high_bandwidth && connected.len() == 1) {
                (Some(block), true) => {
                    let nonce = OsRng.next_u64();
                    self.send(peer, Message::CmpctBlock(compact::build(block, nonce)));
                }
                _ => self.send(peer, Message::Headers(headers.clone())),
            }
        }
    }

    /// Requests missing blocks of the best header chain from peers that have
    /// them, at most [`MAX_BLOCKS_IN_FLIGHT`] per peer.
    fn request_blocks(&mut self) {
        let best = self.tree.best().0;
        let missing = self.tree.missing_blocks(best, DOWNLOAD_WINDOW);
        if missing.is_empty() {
            return;
        }
        let in_flight: HashSet<BlockId> = self
            .peers
            .values()
            .flat_map(|peer| peer.in_flight.keys().copied())
            .collect();
        let mut requests: HashMap<PeerId, Vec<InvItem>> = HashMap::new();
        for id in missing {
            if in_flight.contains(&id) || self.orphan_blocks.contains_key(&id) {
                continue;
            }
            let Some(height) = self.tree.get(&id).map(|node| node.height) else {
                continue;
            };
            let candidate = self.peers.iter().find(|(peer_id, peer)| {
                peer.ready
                    && !matches!(peer.kind, ConnKind::Feeler)
                    && peer.serves_height(height)
                    && peer.in_flight.len() + requests.get(*peer_id).map_or(0, Vec::len)
                        < MAX_BLOCKS_IN_FLIGHT
                    && peer
                        .sync
                        .best_known
                        .is_some_and(|known| self.tree.ancestor_at(known, height) == Some(id))
            });
            if let Some((peer_id, _)) = candidate {
                requests
                    .entry(*peer_id)
                    .or_default()
                    .push(InvItem::block(InvKind::Block, id));
            }
        }
        let now = Instant::now();
        for (peer, items) in requests {
            if let Some(state) = self.peers.get_mut(&peer) {
                for item in &items {
                    state.in_flight.insert(BlockId::new(item.id), now);
                }
            }
            self.send(peer, Message::GetData(items));
        }
    }

    // ----------------------------------------------------------------- tick

    fn on_tick(&mut self) {
        let now = Instant::now();
        let handshake_timeout = self.config.handshake_timeout;
        let ping_interval = self.config.ping_interval;
        let ping_timeout = self.config.ping_timeout;
        let mut stale = Vec::new();
        let mut pings = Vec::new();
        let mut stalled_blocks = false;
        for (id, peer) in &mut self.peers {
            if !peer.ready {
                if now.duration_since(peer.connected_at) > handshake_timeout {
                    stale.push(*id);
                }
                continue;
            }
            if let Some((_, sent)) = peer.ping {
                if now.duration_since(sent) > ping_timeout {
                    stale.push(*id);
                    continue;
                }
            } else if now.duration_since(peer.last_ping) >= ping_interval {
                let nonce = OsRng.next_u64();
                peer.ping = Some((nonce, now));
                peer.last_ping = now;
                pings.push((*id, nonce));
            }
            let before = peer.in_flight.len();
            peer.in_flight
                .retain(|_, requested| now.duration_since(*requested) < BLOCK_TIMEOUT);
            stalled_blocks |= peer.in_flight.len() != before;
        }
        for id in stale {
            self.disconnect(id);
        }
        for (id, nonce) in pings {
            self.send(id, Message::Ping(nonce));
        }
        if stalled_blocks {
            self.request_blocks();
        }
        self.flush_transaction_announcements(now);

        if now.duration_since(self.last_mempool_expire) >= MEMPOOL_EXPIRE_INTERVAL {
            self.last_mempool_expire = now;
            self.mempool.expire(unix_now());
            self.orphan_blocks
                .retain(|_, (_, time, _)| now.duration_since(*time) < ORPHAN_BLOCK_EXPIRY);
            self.discouraged.expire(now);
        }
        if now.duration_since(self.last_addr_save) >= ADDR_SAVE_INTERVAL {
            self.last_addr_save = now;
            self.save_peers();
        }
        self.maintain_outbound(now);
    }

    fn maintain_outbound(&mut self, now: Instant) {
        let manual: Vec<SocketAddr> = self
            .config
            .connect
            .iter()
            .chain(&self.config.add_nodes)
            .copied()
            .collect();
        for addr in manual {
            let connected = self.peers.values().any(|peer| peer.addr == addr);
            let recent = self
                .last_manual_attempt
                .get(&addr)
                .is_some_and(|last| now.duration_since(*last) < Duration::from_secs(10));
            if !connected && !recent && !self.pending_outbound.contains(&addr) {
                self.last_manual_attempt.insert(addr, now);
                self.connect_outbound(addr, ConnKind::Manual);
            }
        }
        if !self.config.connect.is_empty() {
            return;
        }

        let count = |kind: ConnKind| self.peers.values().filter(|peer| peer.kind == kind).count();
        let kind = if count(ConnKind::BlockRelay) < self.config.outbound_block_relay {
            Some(ConnKind::BlockRelay)
        } else if count(ConnKind::FullRelay) < self.config.outbound_full_relay {
            Some(ConnKind::FullRelay)
        } else {
            None
        };
        let feeler_due = now.duration_since(self.last_feeler) >= FEELER_INTERVAL;
        let kind = match kind {
            Some(kind) => kind,
            None if feeler_due => {
                self.last_feeler = now;
                ConnKind::Feeler
            }
            None => return,
        };
        if kind == ConnKind::BlockRelay
            && let Some(anchor) = self.anchors.pop()
        {
            self.connect_outbound(anchor, kind);
            return;
        }
        let used_groups: HashSet<Vec<u8>> = self
            .peers
            .values()
            .filter(|peer| matches!(peer.kind, ConnKind::FullRelay | ConnKind::BlockRelay))
            .map(|peer| group(peer.addr.ip()))
            .collect();
        let connected: HashSet<SocketAddr> = self.peers.values().map(|peer| peer.addr).collect();
        let instant = Instant::now();
        let candidate = self.addrman.select(unix_now(), |addr| {
            connected.contains(addr)
                || self.pending_outbound.contains(addr)
                || self.discouraged.contains(&addr.ip(), instant)
                || (kind != ConnKind::Feeler && used_groups.contains(&group(addr.ip())))
        });
        if let Some(addr) = candidate {
            self.connect_outbound(addr, kind);
        }
    }

    // ---------------------------------------------------------- persistence

    fn peers_path(&self) -> PathBuf {
        self.config.data_dir.join("peers.dat")
    }

    fn anchors_path(&self) -> PathBuf {
        self.config.data_dir.join("anchors.dat")
    }

    fn save_peers(&self) {
        let _ = write_atomically(&self.peers_path(), &self.addrman.to_bytes());
    }

    fn save_anchors(&self) {
        let anchors: Vec<String> = self
            .peers
            .values()
            .filter(|peer| peer.kind == ConnKind::BlockRelay && peer.ready)
            .map(|peer| peer.addr.to_string())
            .collect();
        let _ = write_atomically(&self.anchors_path(), anchors.join("\n").as_bytes());
    }

    fn shutdown(&mut self) {
        if let Err(error) = self.chain.flush() {
            tracing::error!("could not flush the chain store: {error}");
        }
        self.save_peers();
        self.save_anchors();
        let ids: Vec<PeerId> = self.peers.keys().copied().collect();
        for id in ids {
            self.disconnect(id);
        }
    }
}

impl Peer {
    /// Whether the peer can serve the block at `height`: a full node serves
    /// every block, a pruning one only the recent ones.
    fn serves_height(&self, height: u64) -> bool {
        self.version.as_ref().is_some_and(|version| {
            version.services & SERVICE_NETWORK != 0
                || (version.services & SERVICE_WITNESS_PRUNED != 0
                    && height.saturating_add(PRUNED_PEER_SERVES) > version.height)
        })
    }

    fn wants_high_bandwidth_from_us(&self) -> bool {
        self.asked_high_bandwidth
    }
}

fn poisson_delay(mean_secs: f64) -> Duration {
    let uniform = (f64::from(OsRng.next_u32()) + 1.0) / (f64::from(u32::MAX) + 2.0);
    Duration::from_secs_f64(-uniform.ln() * mean_secs)
}

fn write_atomically(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    let temporary = path.with_extension("tmp");
    std::fs::write(&temporary, bytes)?;
    std::fs::File::open(&temporary)?.sync_all()?;
    std::fs::rename(&temporary, path)
}

/// One peer connection: transport handshake, then reader and writer loops.
async fn run_peer(
    stream: TcpStream,
    peer: PeerId,
    initiator: bool,
    magic: [u8; 4],
    handshake_timeout: Duration,
    events: mpsc::UnboundedSender<Event>,
    mut kill: oneshot::Receiver<()>,
) {
    let _ = stream.set_nodelay(true);
    let session = tokio::select! {
        result = tokio::time::timeout(handshake_timeout, transport::handshake(stream, initiator, magic)) => result,
        _ = &mut kill => return,
    };
    let (mut reader, mut writer) = match session {
        Ok(Ok(session)) => session,
        Ok(Err(error)) => {
            let _ = events.send(Event::Closed {
                peer,
                error: Some(error),
            });
            return;
        }
        Err(_) => {
            let _ = events.send(Event::Closed {
                peer,
                error: Some(NetError::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "handshake timeout",
                ))),
            });
            return;
        }
    };

    let (writer_tx, mut writer_rx) = mpsc::unbounded_channel::<Message>();
    let queued = Arc::new(AtomicUsize::new(0));
    let _ = events.send(Event::Connected {
        peer,
        writer: writer_tx,
        queued: Arc::clone(&queued),
    });

    let write_queued = Arc::clone(&queued);
    let mut write_task = tokio::spawn(async move {
        while let Some(message) = writer_rx.recv().await {
            let size = message.encode_payload().len() + 64;
            let result = writer.send(&message).await;
            write_queued.fetch_sub(
                size.min(write_queued.load(Ordering::Relaxed)),
                Ordering::Relaxed,
            );
            if result.is_err() {
                break;
            }
        }
    });

    let error = loop {
        // Back-pressure: stop reading while our replies pile up.
        while queued.load(Ordering::Relaxed) > MAX_SEND_QUEUE {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_millis(50)) => {}
                _ = &mut kill => break,
            }
        }
        tokio::select! {
            result = reader.receive() => match result {
                Ok(message) => {
                    if events.send(Event::Message { peer, message: Box::new(message) }).is_err() {
                        break None;
                    }
                }
                Err(error) => break Some(error),
            },
            _ = &mut kill => break None,
            _ = &mut write_task => break None,
        }
    };
    write_task.abort();
    let _ = events.send(Event::Closed { peer, error });
}

/// A running node.
#[derive(Clone, Debug)]
pub struct NodeHandle {
    events: mpsc::UnboundedSender<Event>,
    local_addr: Option<SocketAddr>,
}

impl NodeHandle {
    /// The address the node listens on, if any.
    #[must_use]
    pub const fn local_addr(&self) -> Option<SocketAddr> {
        self.local_addr
    }

    /// Runs `function` on the core thread and returns its result.
    pub async fn call<R: Send + 'static>(
        &self,
        function: impl FnOnce(&mut Core) -> R + Send + 'static,
    ) -> Option<R> {
        let (reply, receive) = oneshot::channel();
        let call: Box<dyn FnOnce(&mut Core) + Send> = Box::new(move |core: &mut Core| {
            let _ = reply.send(function(core));
        });
        self.events.send(Event::Call(call)).ok()?;
        receive.await.ok()
    }

    /// The active tip.
    pub async fn tip(&self) -> Option<Tip> {
        self.call(|core| core.chain.tip()).await.flatten()
    }

    /// Submits a locally produced block.
    pub async fn submit_block(&self, block: Block) {
        self.call(move |core| core.handle_block(block, None)).await;
    }

    /// Submits a locally produced transaction.
    pub async fn submit_transaction(
        &self,
        transaction: Transaction,
    ) -> Result<Added, MempoolError> {
        self.call(move |core| core.on_transaction(None, transaction))
            .await
            .unwrap_or(Err(MempoolError::AlreadyKnown))
    }

    /// Connects to `addr` as a manual peer.
    pub async fn connect(&self, addr: SocketAddr) {
        self.call(move |core| core.connect_outbound(addr, ConnKind::Manual))
            .await;
    }

    /// Disconnects every peer.
    pub async fn disconnect_all(&self) {
        self.call(|core| {
            let ids: Vec<PeerId> = core.peers.keys().copied().collect();
            for id in ids {
                core.disconnect(id);
            }
        })
        .await;
    }

    /// Stops the node, saving peer files.
    pub async fn shutdown(&self) {
        let (done, wait) = oneshot::channel();
        if self.events.send(Event::Shutdown(done)).is_ok() {
            let _ = wait.await;
        }
    }
}

/// Starts a node on the current tokio runtime.
pub async fn start(config: NodeConfig) -> Result<NodeHandle, StartError> {
    std::fs::create_dir_all(&config.data_dir).map_err(StartError::Io)?;
    let chain = Chain::open_with(
        &config.data_dir.join("chain.redb"),
        config.params,
        config.store,
    )
    .map_err(StartError::Chain)?;
    let tree = HeaderTree::new(
        config.params,
        chain.chain_id(),
        config.min_chain_work,
        chain.index().map(|(id, entry)| {
            (
                *id,
                entry.header,
                entry.height,
                entry.chain_work,
                entry.invalid,
            )
        }),
    );
    let now = unix_now();
    let addrman = std::fs::read(config.data_dir.join("peers.dat"))
        .ok()
        .and_then(|bytes| AddrMan::from_bytes(&bytes, now))
        .unwrap_or_default();
    let anchors_path = config.data_dir.join("anchors.dat");
    let anchors: Vec<SocketAddr> = std::fs::read_to_string(&anchors_path)
        .unwrap_or_default()
        .lines()
        .filter_map(|line| line.parse().ok())
        .collect();
    let _ = std::fs::remove_file(&anchors_path);

    let listener = match config.listen {
        Some(addr) => Some(TcpListener::bind(addr).await.map_err(StartError::Io)?),
        None => None,
    };
    let local_addr = listener
        .as_ref()
        .and_then(|listener| listener.local_addr().ok());

    let (events_tx, mut events_rx) = mpsc::unbounded_channel::<Event>();
    let runtime = tokio::runtime::Handle::current();
    let mempool = Mempool::new(config.mempool_policy);
    let seeds: Vec<SocketAddr> = config.fixed_seeds.clone();
    let dns_seeds = config.dns_seeds.clone();
    let port = default_port(config.params.network);
    let instant = Instant::now();
    let mut core = Core {
        config,
        chain,
        mempool,
        tree,
        addrman,
        discouraged: Discouraged::default(),
        peers: HashMap::new(),
        next_id: 0,
        nonce: OsRng.next_u64(),
        runtime: runtime.clone(),
        events: events_tx.clone(),
        orphan_blocks: HashMap::new(),
        recent_rejects: RecentSet::new(MAX_RECENT_REJECTS),
        pending_outbound: HashSet::new(),
        anchors,
        last_feeler: instant,
        last_addr_save: instant,
        last_mempool_expire: instant,
        last_manual_attempt: HashMap::new(),
        stats: Stats::default(),
    };
    let seed_source: IpAddr = "0.0.0.0".parse().expect("valid address");
    for seed in seeds {
        core.addrman
            .add(seed, SERVICE_NETWORK, now, seed_source, now);
    }

    if let Some(listener) = listener {
        let events = events_tx.clone();
        runtime.spawn(async move {
            while let Ok((stream, addr)) = listener.accept().await {
                if events.send(Event::Inbound(stream, addr)).is_err() {
                    break;
                }
            }
        });
    }
    {
        let events = events_tx.clone();
        runtime.spawn(async move {
            let mut interval = tokio::time::interval(TICK);
            loop {
                interval.tick().await;
                if events.send(Event::Tick).is_err() {
                    break;
                }
            }
        });
    }
    if !dns_seeds.is_empty() {
        let events = events_tx.clone();
        runtime.spawn(async move {
            for seed in dns_seeds {
                if let Ok(addresses) = tokio::net::lookup_host((seed.as_str(), port)).await {
                    let found: Vec<SocketAddr> = addresses.collect();
                    let call: Box<dyn FnOnce(&mut Core) + Send> =
                        Box::new(move |core: &mut Core| {
                            let now = unix_now();
                            for addr in found {
                                core.addrman
                                    .add(addr, SERVICE_NETWORK, now, seed_source, now);
                            }
                        });
                    let _ = events.send(Event::Call(call));
                }
            }
        });
    }

    std::thread::Builder::new()
        .name("itacoin-core".into())
        .spawn(move || {
            while let Some(event) = events_rx.blocking_recv() {
                match event {
                    Event::Inbound(stream, addr) => core.on_inbound(stream, addr),
                    Event::Connected {
                        peer,
                        writer,
                        queued,
                    } => core.on_connected(peer, writer, queued),
                    Event::Message { peer, message } => core.on_message(peer, *message),
                    Event::Closed { peer, error } => {
                        if let Some(NetError::Protocol(reason)) = error {
                            core.misbehave(peer, reason);
                        } else {
                            core.disconnect(peer);
                        }
                    }
                    Event::Tick => core.on_tick(),
                    Event::Call(function) => function(&mut core),
                    Event::Shutdown(done) => {
                        core.shutdown();
                        let _ = done.send(());
                        break;
                    }
                }
            }
        })
        .map_err(StartError::Io)?;

    Ok(NodeHandle {
        events: events_tx,
        local_addr,
    })
}

/// Why a node failed to start.
#[derive(Debug)]
pub enum StartError {
    /// File or socket error.
    Io(std::io::Error),
    /// The chain store failed to open.
    Chain(ChainError),
}

impl core::fmt::Display for StartError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "I/O error: {error}"),
            Self::Chain(error) => write!(formatter, "chain error: {error}"),
        }
    }
}

impl std::error::Error for StartError {}

#[cfg(test)]
mod tests;
