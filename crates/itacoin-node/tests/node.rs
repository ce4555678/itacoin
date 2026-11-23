//! Tests of the real binary (section 8 of `docs/NODE_PROPOSAL.md`): nodes
//! started as processes and driven over the RPC.

use std::{
    net::{SocketAddr, TcpListener},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread::sleep,
    time::{Duration, Instant},
};

use itacoin_codec::Encode;
use itacoin_consensus::ConsensusParams;
use itacoin_crypto::{KeyPair, SigningDomain};
use itacoin_primitives::{Address, Amount, Hash256, Network, TransactionId, WalletId};
use itacoin_rpc::{
    Client, Cookie,
    text::{decode_hash, encode_base64url},
};
use itacoin_transaction::{Input, OutPoint, Output, Transaction, UnsignedTransaction, Witness};
use serde_json::{Value, json};

const BINARY: &str = env!("CARGO_BIN_EXE_itacoin-node");
const WAIT: Duration = Duration::from_secs(60);

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct Node {
    child: Option<Child>,
    base: PathBuf,
    network: &'static str,
    p2p: SocketAddr,
    rpc: SocketAddr,
    extra: Vec<String>,
}

impl Node {
    fn start(base: &Path, network: &'static str, extra: &[&str]) -> Self {
        let mut node = Self {
            child: None,
            base: base.to_path_buf(),
            network,
            p2p: SocketAddr::from(([127, 0, 0, 1], free_port())),
            rpc: SocketAddr::from(([127, 0, 0, 1], free_port())),
            extra: extra.iter().map(|arg| (*arg).to_owned()).collect(),
        };
        node.spawn();
        node
    }

    fn command(&self) -> Command {
        let mut command = Command::new(BINARY);
        command
            .args(["--network", self.network])
            .arg("--datadir")
            .arg(&self.base)
            .args(["--listen", &self.p2p.to_string()])
            .args(["--rpc-port", &self.rpc.port().to_string()])
            .args(["--log-level", "warn"])
            .args(&self.extra)
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        command
    }

    fn spawn(&mut self) {
        self.child = Some(self.command().spawn().unwrap());
        let deadline = Instant::now() + WAIT;
        while Instant::now() < deadline {
            if let Some(status) = self.child.as_mut().unwrap().try_wait().unwrap() {
                panic!("node exited early with {status}");
            }
            if let Ok(client) = self.try_client()
                && client.call("uptime", vec![]).is_ok()
            {
                return;
            }
            sleep(Duration::from_millis(100));
        }
        panic!("node never answered the RPC");
    }

    fn dir(&self) -> PathBuf {
        self.base.join(self.network)
    }

    fn try_client(&self) -> std::io::Result<Client> {
        let (user, password) = Cookie::read(&self.dir().join(".cookie"))?;
        Ok(Client::new(self.rpc, &user, &password))
    }

    fn call(&self, method: &str, params: Vec<Value>) -> Value {
        self.try_client()
            .unwrap()
            .call(method, params)
            .unwrap_or_else(|error| panic!("{method} failed: {error}"))
    }

    fn height(&self) -> u64 {
        self.call("getblockchaininfo", vec![])["height"]
            .as_u64()
            .unwrap()
    }

    fn pid(&self) -> u32 {
        self.child.as_ref().unwrap().id()
    }

    /// Sends SIGTERM and waits for the exit; returns how long it took.
    fn terminate(&mut self) -> Duration {
        let started = Instant::now();
        let status = Command::new("kill")
            .args(["-TERM", &self.pid().to_string()])
            .status()
            .unwrap();
        assert!(status.success());
        let status = self.child.take().unwrap().wait().unwrap();
        assert!(status.success(), "node exited with {status}");
        started.elapsed()
    }

    fn kill(&mut self) {
        let mut child = self.child.take().unwrap();
        child.kill().unwrap();
        child.wait().unwrap();
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn eventually(mut check: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + WAIT;
    while Instant::now() < deadline {
        if check() {
            return true;
        }
        sleep(Duration::from_millis(200));
    }
    false
}

fn regtest_address(wallet_id: WalletId) -> String {
    Address::new(Network::Regtest, wallet_id).to_string()
}

#[test]
fn three_nodes_relay_blocks_and_transactions() {
    let dirs: Vec<_> = (0..3).map(|_| tempfile::tempdir().unwrap()).collect();
    let a = Node::start(dirs[0].path(), "regtest", &[]);
    let b_connect = a.p2p.to_string();
    let b = Node::start(dirs[1].path(), "regtest", &["--connect", &b_connect]);
    let c_connect = b.p2p.to_string();
    let c = Node::start(dirs[2].path(), "regtest", &["--connect", &c_connect]);
    assert!(eventually(|| a.call("getconnectioncount", vec![])
        == json!(1)
        && c.call("getconnectioncount", vec![]) == json!(1)));

    let key = KeyPair::generate().unwrap();
    let mine = regtest_address(key.public_key.wallet_id());
    a.call("generatetoaddress", vec![json!(3), json!(mine)]);
    assert!(eventually(|| [&a, &b, &c]
        .iter()
        .all(|node| node.height() == 3)));

    // A transaction sent to the last node is confirmed by the first.
    let coins = c.call("listunspent", vec![json!([mine])]);
    let coin = &coins["unspent"][0];
    let value = coin["amount_sat"].as_str().unwrap().parse::<u64>().unwrap();
    let outpoint = OutPoint {
        txid: TransactionId::new(decode_hash(coin["txid"].as_str().unwrap()).unwrap()),
        index: u16::try_from(coin["index"].as_u64().unwrap()).unwrap(),
    };
    let output = Output {
        amount: Amount::from_satoshis(value).unwrap(),
        wallet_id: key.public_key.wallet_id(),
    };
    let to = WalletId::new(Hash256::new([4; 32]));
    let unsigned = UnsignedTransaction::new(
        vec![Input {
            previous_output: outpoint,
            witness_index: 0,
        }],
        vec![Output {
            amount: Amount::from_satoshis(value - 30_000).unwrap(),
            wallet_id: to,
        }],
    )
    .unwrap();
    let message = unsigned
        .sighash(&ConsensusParams::regtest().chain_id(), &[output])
        .unwrap();
    let signature = key
        .private_key
        .sign(SigningDomain::Transaction, message.as_bytes())
        .unwrap();
    let transaction = Transaction::Normal(
        unsigned
            .with_witnesses(vec![Witness {
                public_key: key.public_key.clone(),
                signature,
            }])
            .unwrap(),
    );
    let txid = c.call(
        "sendrawtransaction",
        vec![json!(encode_base64url(&transaction.to_bytes()))],
    );
    assert!(eventually(
        || a.call("getmempoolinfo", vec![])["size"] == json!(1)
    ));
    a.call("generatetoaddress", vec![json!(1), json!(mine)]);
    assert!(eventually(|| [&a, &b, &c]
        .iter()
        .all(|node| node.height() == 4)));
    for node in [&a, &b, &c] {
        let out = node.call("gettxout", vec![txid.clone(), json!(0)]);
        assert_eq!(out["address"], json!(regtest_address(to)));
        assert_eq!(node.call("getmempoolinfo", vec![])["size"], json!(0));
    }
}

#[test]
fn a_second_instance_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let node = Node::start(dir.path(), "regtest", &[]);
    let output = node.command().output().unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("another itacoin-node"), "{stderr}");
    // The running node is unaffected.
    assert_eq!(node.height(), 0);
}

#[test]
fn files_are_private_and_removed_on_exit() {
    let dir = tempfile::tempdir().unwrap();
    let mut node = Node::start(dir.path(), "regtest", &[]);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = |path: PathBuf| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(node.dir()), 0o700);
        assert_eq!(mode(node.dir().join(".cookie")), 0o600);
        assert_eq!(mode(node.dir().join("chain.redb")), 0o600);
    }
    node.terminate();
    assert!(!node.dir().join(".cookie").exists());
    assert!(!node.dir().join(".lock").exists());
}

#[test]
fn mainnet_needs_the_feature_and_the_network_is_required() {
    let dir = tempfile::tempdir().unwrap();
    let output = Command::new(BINARY)
        .arg("--datadir")
        .arg(dir.path())
        .output()
        .unwrap();
    assert!(!output.status.success());
    #[cfg(not(feature = "mainnet"))]
    {
        let output = Command::new(BINARY)
            .args(["--network", "mainnet", "--datadir"])
            .arg(dir.path())
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("no mainnet"));
    }
    let output = Command::new(BINARY)
        .args(["--network", "regtest", "--mine", "--datadir"])
        .arg(dir.path())
        .output()
        .unwrap();
    assert!(!output.status.success());
}

#[test]
fn sigterm_with_the_miner_running_exits_quickly_and_keeps_the_tip() {
    let dir = tempfile::tempdir().unwrap();
    let payout = Address::new(Network::Testnet, WalletId::new(Hash256::new([2; 32]))).to_string();
    let mut node = Node::start(
        dir.path(),
        "testnet",
        &[
            "--mine",
            "--mine-address",
            &payout,
            "--mine-threads",
            "2",
            "--mine-without-peers",
            "--connect",
            "127.0.0.1:1",
        ],
    );
    assert!(eventually(|| {
        let info = node.call("getmininginfo", vec![]);
        info["threads"] == json!(2) && info["has_work"] == json!(true)
    }));
    let tip = node.call("getbestblockhash", vec![]);
    sleep(Duration::from_millis(500));
    let took = node.terminate();
    assert!(took < Duration::from_secs(10), "shutdown took {took:?}");

    // Restart with a payout address but without --mine: the miner is
    // available and off.
    node.extra = vec![
        "--mine-address".into(),
        payout.clone(),
        "--connect".into(),
        "127.0.0.1:1".into(),
    ];
    node.spawn();
    // The tip survived (or grew by a block the miner found meanwhile).
    let reopened = node.call("getbestblockhash", vec![]);
    if reopened != tip {
        assert_eq!(
            node.call("getblockheader", vec![reopened])["prev_block"],
            tip
        );
    }
    // The miner can be switched over RPC.
    assert_eq!(node.call("getmininginfo", vec![])["threads"], json!(0));
    assert_eq!(
        node.call("setmining", vec![json!(true), json!(1)])["threads"],
        json!(1)
    );
    assert_eq!(
        node.call("setmining", vec![json!(false)])["threads"],
        json!(0)
    );
}

#[test]
fn a_killed_node_reopens_with_a_sound_state() {
    let dir = tempfile::tempdir().unwrap();
    let mut node = Node::start(dir.path(), "regtest", &[]);
    let mine = regtest_address(WalletId::new(Hash256::new([6; 32])));
    node.call("generatetoaddress", vec![json!(5), json!(mine)]);
    // Kill it in the middle of a burst of block submissions.
    let client = node.try_client().unwrap();
    let burst = std::thread::spawn(move || {
        for _ in 0..20 {
            if client
                .call("generatetoaddress", vec![json!(5), json!(mine)])
                .is_err()
            {
                break;
            }
        }
    });
    sleep(Duration::from_millis(300));
    node.kill();
    let _ = burst.join();
    // The stale lock and cookie do not stop the restart, and the start-up
    // verification passes.
    node.spawn();
    let height = node.height();
    assert!(height >= 5, "height {height}");
    let info = node.call("getblockchaininfo", vec![]);
    assert_eq!(info["height"], json!(height));
}

/// A real proof-of-work block on testnet, accepted by a second node. Slow:
/// about two CPU-minutes per block at the minimum difficulty.
#[test]
#[ignore = "mines a real Argon2id block; run with --ignored"]
fn the_embedded_miner_finds_blocks_other_nodes_accept() {
    let dirs: Vec<_> = (0..2).map(|_| tempfile::tempdir().unwrap()).collect();
    let payout = Address::new(Network::Testnet, WalletId::new(Hash256::new([3; 32]))).to_string();
    let threads = std::thread::available_parallelism()
        .map_or(2, |cores| cores.get())
        .to_string();
    let a = Node::start(
        dirs[0].path(),
        "testnet",
        &[
            "--mine",
            "--mine-address",
            &payout,
            "--mine-threads",
            &threads,
            "--mine-without-peers",
            "--connect",
            "127.0.0.1:1",
        ],
    );
    let connect = a.p2p.to_string();
    let b = Node::start(dirs[1].path(), "testnet", &["--connect", &connect]);
    let deadline = Instant::now() + Duration::from_secs(30 * 60);
    while Instant::now() < deadline && b.height() == 0 {
        sleep(Duration::from_secs(1));
    }
    assert!(b.height() >= 1);
    assert_eq!(
        b.call("getblockhash", vec![json!(1)]),
        a.call("getblockhash", vec![json!(1)])
    );
}
