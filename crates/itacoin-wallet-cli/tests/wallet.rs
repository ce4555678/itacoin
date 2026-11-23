//! End to end: a regtest node and RPC server in this process, and the real
//! `itacoin-wallet` binary driven through its standard input (section 11 of
//! `docs/WALLET_PROPOSAL.md`).

use std::{
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    time::Instant,
};

use itacoin_consensus::ConsensusParams;
use itacoin_network::node::{NodeConfig, NodeHandle, start};
use itacoin_rpc::{Client, Context, Cookie, Credentials, RpcConfig, RpcServer, serve};
use serde_json::{Value, json};
use tokio::sync::watch;

const BINARY: &str = env!("CARGO_BIN_EXE_itacoin-wallet");
const PASSWORD: &str = "correct horse battery";

struct Harness {
    runtime: tokio::runtime::Runtime,
    base: tempfile::TempDir,
    node: NodeHandle,
    server: Option<RpcServer>,
    client: Client,
    rpc: String,
}

impl Harness {
    fn new() -> Self {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let base = tempfile::tempdir().unwrap();
        let data = base.path().join("regtest");
        std::fs::create_dir_all(&data).unwrap();
        let params = ConsensusParams::regtest();
        let (node, server) = runtime.block_on(async {
            let node = start(NodeConfig::new(params, data.clone())).await.unwrap();
            let cookie = Cookie::create(&data.join(".cookie")).unwrap();
            let context = Context {
                handle: node.clone(),
                params,
                miner: None,
                started: Instant::now(),
                stop: watch::channel(false).0,
                data_dir: data.clone(),
                rpc_addrs: Vec::new(),
            };
            let server = serve(
                RpcConfig {
                    binds: vec!["127.0.0.1:0".parse().unwrap()],
                    allow: Vec::new(),
                    credentials: Credentials {
                        cookie: Some(cookie),
                        fixed: Vec::new(),
                    },
                },
                context,
            )
            .await
            .unwrap();
            (node, server)
        });
        let addr = server.local_addrs()[0];
        let (user, password) = Cookie::read(&data.join(".cookie")).unwrap();
        Self {
            runtime,
            base,
            node,
            client: Client::new(addr, &user, &password),
            server: Some(server),
            rpc: addr.to_string(),
        }
    }

    fn command(&self, wallet: &str, args: &[&str]) -> Command {
        let mut command = Command::new(BINARY);
        command
            .args(["--network", "regtest", "--datadir"])
            .arg(self.base.path())
            .args(["--wallet", wallet, "--rpc-connect", &self.rpc])
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    }

    /// Runs a command, feeding `input` line by line.
    fn run(&self, wallet: &str, args: &[&str], input: &[&str]) -> Output {
        let mut child = self.command(wallet, args).spawn().unwrap();
        let mut stdin = child.stdin.take().unwrap();
        for line in input {
            writeln!(stdin, "{line}").unwrap();
        }
        drop(stdin);
        child.wait_with_output().unwrap()
    }

    fn ok(&self, wallet: &str, args: &[&str], input: &[&str]) -> String {
        let output = self.run(wallet, args, input);
        assert!(
            output.status.success(),
            "{args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap()
    }

    fn fails(&self, wallet: &str, args: &[&str], input: &[&str]) -> String {
        let output = self.run(wallet, args, input);
        assert!(!output.status.success(), "{args:?} should fail");
        String::from_utf8(output.stderr).unwrap()
    }

    /// Creates a wallet, typing the backup confirmation it asks for, and
    /// returns the backup.
    fn create(&self, wallet: &str) -> String {
        let mut child = self.command(wallet, &["create"]).spawn().unwrap();
        let mut stdin = child.stdin.take().unwrap();
        writeln!(stdin, "{PASSWORD}").unwrap();
        writeln!(stdin, "{PASSWORD}").unwrap();
        let mut stdout = BufReader::new(child.stdout.take().unwrap());
        let mut backup = String::new();
        let mut line = String::new();
        while stdout.read_line(&mut line).unwrap() > 0 {
            if line.starts_with("itcseed1") {
                backup = line.trim().to_owned();
                break;
            }
            line.clear();
        }
        assert_eq!(backup.len(), 67, "no backup printed");
        writeln!(stdin, "{}", &backup[backup.len() - 8..]).unwrap();
        drop(stdin);
        let mut rest = String::new();
        std::io::Read::read_to_string(&mut stdout, &mut rest).unwrap();
        let status = child.wait().unwrap();
        assert!(status.success(), "create failed");
        assert!(rest.contains("Wallet created"));
        backup
    }

    fn rpc(&self, method: &str, params: Vec<Value>) -> Value {
        self.client.call(method, params).unwrap()
    }

    fn mempool(&self) -> Vec<String> {
        self.rpc("getrawmempool", vec![])["txids"]
            .as_array()
            .unwrap()
            .iter()
            .map(|txid| txid.as_str().unwrap().to_owned())
            .collect()
    }

    fn wallet_dir(&self, wallet: &str) -> PathBuf {
        self.base.path().join("wallets").join(wallet)
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        if let Some(server) = self.server.take() {
            self.runtime.block_on(async {
                server.shutdown().await;
                self.node.shutdown().await;
            });
        }
    }
}

fn spendable(balance: &str) -> String {
    balance
        .lines()
        .find(|line| line.starts_with("spendable:"))
        .unwrap()
        .to_owned()
}

fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[test]
fn create_receive_send_bump_and_restore() {
    let h = Harness::new();
    let backup = h.create("alice");
    assert_eq!(mode(&h.wallet_dir("alice")), 0o700);
    assert_eq!(mode(&h.wallet_dir("alice").join("wallet.itcw")), 0o600);
    assert_eq!(
        mode(&h.wallet_dir("alice").join("state-regtest.json")),
        0o600
    );

    // Receiving needs no password while the stock lasts.
    let alice = h
        .ok("alice", &["receive", "--label", "mining"], &[])
        .trim()
        .to_owned();
    assert!(alice.starts_with("ritc1"));
    let second = h.ok("alice", &["receive"], &[]).trim().to_owned();
    assert_ne!(alice, second);
    h.create("bob");
    let bob = h.ok("bob", &["receive"], &[]).trim().to_owned();

    h.rpc("generatetoaddress", vec![json!(3), json!(alice)]);
    let balance = h.ok("alice", &["balance"], &[]);
    let reward = h.rpc("listunspent", vec![json!([alice])])["unspent"][0]["amount_sat"]
        .as_str()
        .unwrap()
        .parse::<u128>()
        .unwrap();
    assert!(spendable(&balance).contains(&itc(3 * reward)), "{balance}");
    assert!(h.ok("alice", &["addresses"], &[]).contains("mining"));

    // A dry run signs but sends nothing; a high fee needs an explicit flag.
    let dry = h.ok(
        "alice",
        &["send", &bob, "1.5", "--fee-rate", "2", "--dry-run"],
        &[PASSWORD],
    );
    assert!(dry.trim().len() > 7_000);
    assert!(h.mempool().is_empty());
    let refused = h.fails(
        "alice",
        &["send", &bob, "0.0001", "--fee-rate", "2000", "--yes"],
        &[],
    );
    assert!(refused.contains("--allow-high-fee"), "{refused}");
    let wrong = h.fails(
        "alice",
        &["send", &bob, "1", "--fee-rate", "2", "--yes"],
        &["wrong password!!"],
    );
    assert!(wrong.contains("wrong password"), "{wrong}");

    let first = h.ok(
        "alice",
        &["send", &bob, "1.5", "--fee-rate", "2", "--yes"],
        &[PASSWORD],
    );
    let first = first.trim().to_owned();
    assert_eq!(h.mempool(), vec![first.clone()]);
    assert!(h.ok("alice", &["history"], &[]).contains("mempool"));
    // The coins being spent are not offered again.
    assert!(h.ok("alice", &["balance"], &[]).contains("being spent"));

    let bumped = h.ok(
        "alice",
        &["bumpfee", &first, "--fee-rate", "10", "--yes"],
        &[PASSWORD],
    );
    let bumped = bumped.trim().to_owned();
    assert_ne!(bumped, first);
    assert_eq!(h.mempool(), vec![bumped.clone()]);
    let entry = h.rpc("getmempoolentry", vec![json!(bumped)]);
    assert!(entry["fee_per_byte"].as_f64().unwrap() >= 10.0);

    h.rpc("generatetoaddress", vec![json!(1), json!(second)]);
    let history = h.ok("alice", &["history"], &[]);
    assert!(
        history.contains(&format!("replaced by {bumped}")),
        "{history}"
    );
    assert!(
        history
            .lines()
            .any(|line| line.starts_with(&bumped) && line.ends_with("confirmed"))
    );
    assert!(spendable(&h.ok("bob", &["balance"], &[])).contains("1.50000000"));

    // Restoring the backup into an empty wallet finds the same balance,
    // change included.
    let before = spendable(&h.ok("alice", &["balance"], &[]));
    let restored = h.ok("alice2", &["restore"], &[&backup, PASSWORD, PASSWORD]);
    assert!(restored.contains(&before), "{restored}\n{before}");
    assert!(restored.contains("1 change"), "{restored}");
    assert_eq!(h.ok("alice2", &["backup"], &[PASSWORD]).trim(), backup);
}

#[test]
fn passwords_rollback_and_consolidation() {
    let h = Harness::new();
    h.create("carol");
    // Three keys with coins.
    let mut addresses = Vec::new();
    for _ in 0..3 {
        let address = h.ok("carol", &["receive"], &[]).trim().to_owned();
        h.rpc("generatetoaddress", vec![json!(1), json!(address)]);
        addresses.push(address);
    }
    let coins = h.ok("carol", &["coins"], &[]);
    assert_eq!(
        coins
            .lines()
            .filter(|line| line.starts_with("ritc1"))
            .count(),
        3
    );

    let txid = h.ok(
        "carol",
        &["consolidate", "--fee-rate", "1", "--yes"],
        &[PASSWORD],
    );
    assert_eq!(h.mempool(), vec![txid.trim().to_owned()]);
    h.rpc("generatetoaddress", vec![json!(1), json!(addresses[0])]);
    let coins = h.ok("carol", &["coins"], &[]);
    // The three keys became one change key, plus the new block reward.
    assert_eq!(
        coins
            .lines()
            .filter(|line| line.starts_with("ritc1"))
            .count(),
        2,
        "{coins}"
    );

    // Changing the password, then restoring the old file, is caught.
    let file = h.wallet_dir("carol").join("wallet.itcw");
    let old = h.base.path().join("old.itcw");
    std::fs::copy(&file, &old).unwrap();
    h.ok(
        "carol",
        &["passwd"],
        &[PASSWORD, "another long password", "another long password"],
    );
    h.fails("carol", &["backup"], &[PASSWORD]);
    assert!(
        !h.ok("carol", &["backup"], &["another long password"])
            .is_empty()
    );
    std::fs::copy(&old, &file).unwrap();
    let rolled = h.fails("carol", &["backup"], &[PASSWORD]);
    assert!(rolled.contains("older"), "{rolled}");

    // Creating over an existing wallet and bad backups are refused.
    assert!(
        h.fails("carol", &["create"], &[])
            .contains("already exists")
    );
    let damaged = h.fails(
        "dave",
        &["restore"],
        &["itcseed1qqqqqqqq", PASSWORD, PASSWORD],
    );
    assert!(damaged.contains("backup"), "{damaged}");
    let info = h.ok("carol", &["info"], &[]);
    assert!(info.contains("master secret (ITCW v3)"));
}

fn itc(satoshis: u128) -> String {
    format!("{}.{:08}", satoshis / 100_000_000, satoshis % 100_000_000)
}
