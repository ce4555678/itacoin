//! Command-line client for the ITACOIN node RPC.
//!
//! ```text
//! itacoin-cli --network testnet getblockchaininfo
//! itacoin-cli --network regtest generatetoaddress 10 ritc1...
//! itacoin-cli rpcauth alice        # reads the password from stdin
//! ```
//!
//! Credentials come from the cookie in the data directory, or from
//! `--rpc-user` with the password in `ITACOIN_RPC_PASSWORD` (never on the
//! command line, where other users can read it).

use std::{
    io::BufRead,
    net::{SocketAddr, ToSocketAddrs},
    path::PathBuf,
    process::ExitCode,
};

use itacoin_rpc::{Client, Cookie, RpcAuth, data_dir, default_rpc_port, parse_network};
use serde_json::Value;
use zeroize::Zeroizing;

const USAGE: &str = "usage:
  itacoin-cli --network <mainnet|testnet|regtest> [--datadir DIR]
              [--rpc-connect HOST:PORT] [--rpc-user USER] <method> [params...]
  itacoin-cli rpcauth <user>

Each parameter is parsed as JSON when it is valid JSON, otherwise passed as
a string. With --rpc-user the password is read from ITACOIN_RPC_PASSWORD.";

fn main() -> ExitCode {
    match run(std::env::args().skip(1).collect()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: Vec<String>) -> Result<(), String> {
    if args.first().map(String::as_str) == Some("rpcauth") {
        return rpcauth(&args[1..]);
    }
    let mut network = None;
    let mut base = None;
    let mut connect = None;
    let mut user = None;
    let mut rest = Vec::new();
    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        let mut value = |name: &str| iter.next().ok_or(format!("{name} needs a value"));
        match arg.as_str() {
            "--network" => network = Some(value("--network")?),
            "--datadir" => base = Some(PathBuf::from(value("--datadir")?)),
            "--rpc-connect" => connect = Some(value("--rpc-connect")?),
            "--rpc-user" => user = Some(value("--rpc-user")?),
            "-h" | "--help" => return Err(USAGE.into()),
            _ if arg.starts_with("--") && rest.is_empty() => {
                return Err(format!("unknown option {arg}\n\n{USAGE}"));
            }
            _ => {
                rest.push(arg);
                rest.extend(iter.by_ref());
            }
        }
    }
    let network = network.ok_or(format!("--network is required\n\n{USAGE}"))?;
    let network = parse_network(&network).ok_or("unknown network")?;
    let Some((method, params)) = rest.split_first() else {
        return Err(USAGE.into());
    };
    let addr: SocketAddr = match connect {
        Some(text) => text
            .to_socket_addrs()
            .ok()
            .and_then(|mut addrs| addrs.next())
            .ok_or("invalid --rpc-connect")?,
        None => SocketAddr::from(([127, 0, 0, 1], default_rpc_port(network))),
    };
    let client = match user {
        Some(user) => {
            let password = Zeroizing::new(
                std::env::var("ITACOIN_RPC_PASSWORD")
                    .map_err(|_| "set ITACOIN_RPC_PASSWORD for --rpc-user")?,
            );
            Client::new(addr, &user, &password)
        }
        None => {
            let directory = data_dir(base, network).ok_or("no home directory; use --datadir")?;
            let (user, password) = Cookie::read(&directory.join(".cookie")).map_err(|error| {
                format!("could not read the cookie (is the node running?): {error}")
            })?;
            Client::new(addr, &user, &password)
        }
    };
    let params: Vec<Value> = params
        .iter()
        .map(|param| serde_json::from_str(param).unwrap_or_else(|_| Value::String(param.clone())))
        .collect();
    let result = client
        .call(method, params)
        .map_err(|error| error.to_string())?;
    match result {
        Value::String(text) => println!("{text}"),
        Value::Null => {}
        other => println!(
            "{}",
            serde_json::to_string_pretty(&other).map_err(|error| error.to_string())?
        ),
    }
    Ok(())
}

fn rpcauth(args: &[String]) -> Result<(), String> {
    let [user] = args else {
        return Err("usage: itacoin-cli rpcauth <user>   (password on stdin)".into());
    };
    let mut password = Zeroizing::new(String::new());
    std::io::stdin()
        .lock()
        .read_line(&mut password)
        .map_err(|error| error.to_string())?;
    let password = Zeroizing::new(password.trim_end_matches(['\r', '\n']).to_owned());
    if password.len() < 12 {
        return Err("use a password of at least 12 bytes".into());
    }
    let line = RpcAuth::generate(user, &password).map_err(str::to_owned)?;
    println!("--rpc-auth {line}");
    Ok(())
}
