//! Command line and configuration file (section 6.1 of
//! `docs/NODE_PROPOSAL.md`). The command line wins over the file, and the
//! file wins over the defaults of the network proposal.

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
};

use clap::Parser;
use itacoin_consensus::ConsensusParams;
use itacoin_network::node::default_port;
use itacoin_primitives::{Address, Network, WalletId};
use itacoin_rpc::{IpNet, RpcAuth, default_rpc_port, parse_network};
use serde::Deserialize;

/// Name of the optional configuration file inside the data directory.
pub const CONFIG_FILE: &str = "itacoin.toml";

/// The ITACOIN full node.
#[derive(Debug, Parser)]
#[command(name = "itacoin-node", version, about)]
pub struct Cli {
    /// Network: mainnet, testnet or regtest. Required, so a command without
    /// it never talks to the main network by mistake.
    #[arg(long)]
    pub network: String,
    /// Base data directory; the network's directory goes under it.
    /// Defaults to ~/.itacoin.
    #[arg(long)]
    pub datadir: Option<PathBuf>,
    /// Address to accept P2P connections on (default 0.0.0.0 and the
    /// network's port).
    #[arg(long)]
    pub listen: Option<SocketAddr>,
    /// Do not accept P2P connections.
    #[arg(long)]
    pub no_listen: bool,
    /// Connect only to these peers.
    #[arg(long)]
    pub connect: Vec<SocketAddr>,
    /// Stay connected to these peers, besides automatic ones.
    #[arg(long = "addnode")]
    pub add_node: Vec<SocketAddr>,
    /// Maximum inbound P2P connections.
    #[arg(long)]
    pub max_inbound: Option<usize>,
    /// Address for the RPC (IP or IP:port). Non-loopback needs
    /// --rpc-allow-ip.
    #[arg(long)]
    pub rpc_bind: Vec<String>,
    /// RPC port (default 7211 / 17211 / 17311).
    #[arg(long)]
    pub rpc_port: Option<u16>,
    /// Network (CIDR) allowed to reach the RPC besides loopback.
    #[arg(long)]
    pub rpc_allow_ip: Vec<String>,
    /// Fixed RPC credential `user:salt:hash`, from `itacoin-cli rpcauth`.
    #[arg(long)]
    pub rpc_auth: Vec<String>,
    /// Start the embedded miner.
    #[arg(long)]
    pub mine: bool,
    /// Address that receives mined rewards.
    #[arg(long)]
    pub mine_address: Option<String>,
    /// Mining threads (default: cores minus one).
    #[arg(long)]
    pub mine_threads: Option<usize>,
    /// Mine even with no peers, to start a new network.
    #[arg(long)]
    pub mine_without_peers: bool,
    /// Log filter, such as `info` or `info,itacoin_network=debug`.
    #[arg(long)]
    pub log_level: Option<String>,
}

/// The configuration file: the same options, minus `network` and
/// `datadir`, which locate the file itself.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct FileConfig {
    listen: Option<SocketAddr>,
    no_listen: Option<bool>,
    #[serde(default)]
    connect: Vec<SocketAddr>,
    #[serde(default)]
    addnode: Vec<SocketAddr>,
    max_inbound: Option<usize>,
    #[serde(default)]
    rpc_bind: Vec<String>,
    rpc_port: Option<u16>,
    #[serde(default)]
    rpc_allow_ip: Vec<String>,
    #[serde(default)]
    rpc_auth: Vec<String>,
    mine: Option<bool>,
    mine_address: Option<String>,
    mine_threads: Option<usize>,
    mine_without_peers: Option<bool>,
    log_level: Option<String>,
}

impl FileConfig {
    /// Reads `path`, or the defaults if it does not exist.
    pub fn load(path: &Path) -> Result<Self, String> {
        match std::fs::read_to_string(path) {
            Ok(text) => toml::from_str(&text)
                .map_err(|error| format!("invalid {}: {error}", path.display())),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(error) => Err(format!("could not read {}: {error}", path.display())),
        }
    }
}

/// The embedded miner's settings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MiningSettings {
    /// Who receives the rewards.
    pub payout: WalletId,
    /// Start mining at once.
    pub start: bool,
    /// Worker threads when mining.
    pub threads: usize,
    /// Mine with no peers.
    pub without_peers: bool,
}

/// Everything the node needs, resolved.
#[derive(Debug)]
pub struct Settings {
    /// Consensus parameters.
    pub params: ConsensusParams,
    /// The network's data directory.
    pub data_dir: PathBuf,
    /// P2P listen address.
    pub listen: Option<SocketAddr>,
    /// Exclusive peers.
    pub connect: Vec<SocketAddr>,
    /// Extra peers.
    pub add_nodes: Vec<SocketAddr>,
    /// Inbound limit.
    pub max_inbound: Option<usize>,
    /// RPC addresses.
    pub rpc_binds: Vec<SocketAddr>,
    /// Networks allowed on the RPC.
    pub rpc_allow: Vec<IpNet>,
    /// Fixed RPC credentials.
    pub rpc_auth: Vec<RpcAuth>,
    /// The miner, if a payout address was given.
    pub mining: Option<MiningSettings>,
    /// Log filter.
    pub log_level: String,
}

/// Resolves the network and its data directory from the command line.
pub fn network_and_dir(cli: &Cli) -> Result<(Network, PathBuf), String> {
    let network = parse_network(&cli.network).ok_or_else(|| {
        format!(
            "unknown network {:?}; use mainnet, testnet or regtest",
            cli.network
        )
    })?;
    let dir = itacoin_rpc::data_dir(cli.datadir.clone(), network)
        .ok_or("no home directory; use --datadir")?;
    Ok((network, dir))
}

/// The consensus parameters of `network`, refusing the main network in
/// builds without the `mainnet` feature.
pub fn params_for(network: Network) -> Result<ConsensusParams, String> {
    match network {
        Network::Testnet => Ok(ConsensusParams::testnet()),
        Network::Regtest => Ok(ConsensusParams::regtest()),
        #[cfg(feature = "mainnet")]
        Network::Mainnet => Ok(ConsensusParams::mainnet()),
        #[cfg(not(feature = "mainnet"))]
        Network::Mainnet => Err(
            "this build has no mainnet: the transport handshake and ML-DSA \
             still await independent review. Build with --features mainnet to override."
                .into(),
        ),
    }
}

fn default_threads() -> usize {
    std::thread::available_parallelism()
        .map_or(1, |cores| cores.get().saturating_sub(1))
        .max(1)
}

fn rpc_bind(text: &str, port: u16) -> Result<SocketAddr, String> {
    if let Ok(addr) = text.parse::<SocketAddr>() {
        return Ok(addr);
    }
    let ip: IpAddr = text
        .trim_start_matches('[')
        .trim_end_matches(']')
        .parse()
        .map_err(|_| format!("invalid --rpc-bind {text:?}"))?;
    Ok(SocketAddr::new(ip, port))
}

/// Combines the command line, the file and the defaults.
pub fn resolve(
    cli: Cli,
    file: FileConfig,
    network: Network,
    data_dir: PathBuf,
) -> Result<Settings, String> {
    let params = params_for(network)?;
    let pick = |cli: Vec<String>, file: Vec<String>| if cli.is_empty() { file } else { cli };

    let listen = if cli.no_listen || file.no_listen.unwrap_or(false) {
        None
    } else {
        Some(cli.listen.or(file.listen).unwrap_or_else(|| {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), default_port(network))
        }))
    };
    let connect = if cli.connect.is_empty() {
        file.connect
    } else {
        cli.connect
    };
    let add_nodes = if cli.add_node.is_empty() {
        file.addnode
    } else {
        cli.add_node
    };

    let rpc_port = cli
        .rpc_port
        .or(file.rpc_port)
        .unwrap_or(default_rpc_port(network));
    let binds = pick(cli.rpc_bind, file.rpc_bind);
    let rpc_binds = if binds.is_empty() {
        vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), rpc_port)]
    } else {
        binds
            .iter()
            .map(|bind| rpc_bind(bind, rpc_port))
            .collect::<Result<_, _>>()?
    };
    let rpc_allow = pick(cli.rpc_allow_ip, file.rpc_allow_ip)
        .iter()
        .map(|net| IpNet::parse(net).map_err(|error| format!("--rpc-allow-ip {net}: {error}")))
        .collect::<Result<_, _>>()?;
    let rpc_auth = pick(cli.rpc_auth, file.rpc_auth)
        .iter()
        .map(|auth| RpcAuth::parse(auth).map_err(|error| format!("--rpc-auth: {error}")))
        .collect::<Result<_, _>>()?;

    let start = cli.mine || file.mine.unwrap_or(false);
    let mine_address = cli.mine_address.or(file.mine_address);
    let mining = match mine_address {
        None if start => return Err("--mine needs --mine-address".into()),
        None => None,
        Some(_) if network == Network::Regtest => {
            return Err(
                "the embedded miner is unavailable on regtest; use the generatetoaddress RPC"
                    .into(),
            );
        }
        Some(text) => {
            let payout = Address::parse_for_network(&text, network)
                .map_err(|error| format!("--mine-address: {error}"))?
                .wallet_id();
            let threads = cli
                .mine_threads
                .or(file.mine_threads)
                .unwrap_or_else(default_threads);
            if threads == 0 || threads > 1_024 {
                return Err("--mine-threads must be 1 to 1024".into());
            }
            Some(MiningSettings {
                payout,
                start,
                threads,
                without_peers: cli.mine_without_peers || file.mine_without_peers.unwrap_or(false),
            })
        }
    };

    Ok(Settings {
        params,
        data_dir,
        listen,
        connect,
        add_nodes,
        max_inbound: cli.max_inbound.or(file.max_inbound),
        rpc_binds,
        rpc_allow,
        rpc_auth,
        mining,
        log_level: cli
            .log_level
            .or(file.log_level)
            .unwrap_or_else(|| "info".into()),
    })
}

#[cfg(test)]
mod tests {
    use itacoin_primitives::Hash256;

    use super::*;

    fn cli(args: &[&str]) -> Cli {
        Cli::try_parse_from(std::iter::once("itacoin-node").chain(args.iter().copied())).unwrap()
    }

    fn settings(args: &[&str], file: &str) -> Result<Settings, String> {
        let cli = cli(args);
        let (network, dir) = network_and_dir(&cli)?;
        let file: FileConfig = toml::from_str(file).map_err(|error| error.to_string())?;
        resolve(cli, file, network, dir)
    }

    fn testnet_address() -> String {
        Address::new(Network::Testnet, WalletId::new(Hash256::new([5; 32]))).to_string()
    }

    #[test]
    fn the_network_is_required() {
        assert!(Cli::try_parse_from(["itacoin-node"]).is_err());
        assert!(settings(&["--network", "moon"], "").is_err());
        #[cfg(not(feature = "mainnet"))]
        assert!(settings(&["--network", "mainnet", "--datadir", "/x"], "").is_err());
    }

    #[test]
    fn defaults_follow_the_proposals() {
        let settings = settings(&["--network", "testnet", "--datadir", "/data"], "").unwrap();
        assert_eq!(settings.data_dir, PathBuf::from("/data/testnet"));
        assert_eq!(settings.listen, Some("0.0.0.0:17210".parse().unwrap()));
        assert_eq!(settings.rpc_binds, vec!["127.0.0.1:17211".parse().unwrap()]);
        assert!(settings.mining.is_none());
        assert_eq!(settings.log_level, "info");
    }

    #[test]
    fn the_command_line_wins_over_the_file() {
        let file = r#"
            rpc-port = 20000
            log-level = "debug"
            mine-address = "itc1nope"
            addnode = ["10.0.0.1:17210"]
        "#;
        let address = testnet_address();
        let settings = settings(
            &[
                "--network",
                "testnet",
                "--datadir",
                "/d",
                "--log-level",
                "warn",
                "--mine-address",
                &address,
                "--rpc-bind",
                "127.0.0.1",
            ],
            file,
        )
        .unwrap();
        assert_eq!(settings.log_level, "warn");
        assert_eq!(settings.rpc_binds, vec!["127.0.0.1:20000".parse().unwrap()]);
        assert_eq!(settings.add_nodes, vec!["10.0.0.1:17210".parse().unwrap()]);
        let mining = settings.mining.unwrap();
        assert!(!mining.start);
        assert_eq!(mining.payout, WalletId::new(Hash256::new([5; 32])));
    }

    #[test]
    fn invalid_combinations_are_refused() {
        let address = testnet_address();
        assert!(settings(&["--network", "testnet", "--datadir", "/d", "--mine"], "").is_err());
        // An address of another network.
        let regtest =
            Address::new(Network::Regtest, WalletId::new(Hash256::new([5; 32]))).to_string();
        assert!(
            settings(
                &[
                    "--network",
                    "testnet",
                    "--datadir",
                    "/d",
                    "--mine-address",
                    &regtest
                ],
                ""
            )
            .is_err()
        );
        // No miner on regtest.
        assert!(
            settings(
                &[
                    "--network",
                    "regtest",
                    "--datadir",
                    "/d",
                    "--mine-address",
                    &regtest
                ],
                ""
            )
            .is_err()
        );
        assert!(
            settings(
                &[
                    "--network",
                    "testnet",
                    "--datadir",
                    "/d",
                    "--mine-address",
                    &address,
                    "--mine-threads",
                    "0"
                ],
                ""
            )
            .is_err()
        );
        assert!(settings(&["--network", "testnet", "--datadir", "/d"], "unknown = 1").is_err());
        assert!(
            settings(
                &[
                    "--network",
                    "testnet",
                    "--datadir",
                    "/d",
                    "--rpc-allow-ip",
                    "x"
                ],
                ""
            )
            .is_err()
        );
        assert!(
            settings(
                &[
                    "--network",
                    "testnet",
                    "--datadir",
                    "/d",
                    "--rpc-auth",
                    "a:b"
                ],
                ""
            )
            .is_err()
        );
    }
}
