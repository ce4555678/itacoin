//! ITACOIN JSON-RPC, as specified in sections 4 and 5 of
//! `docs/NODE_PROPOSAL.md`.
//!
//! - [`server`]: HTTP/1.1, authentication, exposure checks and limits.
//! - [`methods`]: the methods, all going through the node's `NodeHandle`.
//! - [`request`]: JSON-RPC 2.0 parsing and error codes.
//! - [`text`]: the strict text forms of hashes, blobs and amounts.
//! - [`client`]: the blocking client used by `itacoin-cli`.

pub mod auth;
pub mod client;
pub mod methods;
pub mod request;
pub mod server;
pub mod text;

pub use auth::{COOKIE_USER, Cookie, Credentials, IpNet, RpcAuth};
pub use client::{Client, ClientError};
pub use methods::{Context, MinerControl};
pub use server::{RpcConfig, RpcServer, ServeError, serve};

/// Parses a request body; exposed for fuzzing.
pub fn parse_request(bytes: &[u8]) -> Result<request::Body, request::RpcError> {
    request::parse_body(bytes)
}

use std::path::PathBuf;

use itacoin_primitives::Network;

/// The default RPC port of each network (section 6.1 of the proposal).
#[must_use]
pub const fn default_rpc_port(network: Network) -> u16 {
    match network {
        Network::Mainnet => 7211,
        Network::Testnet => 17211,
        Network::Regtest => 17311,
    }
}

/// The lowercase name of a network.
#[must_use]
pub const fn network_name(network: Network) -> &'static str {
    match network {
        Network::Mainnet => "mainnet",
        Network::Testnet => "testnet",
        Network::Regtest => "regtest",
    }
}

/// Parses a network name.
#[must_use]
pub fn parse_network(name: &str) -> Option<Network> {
    match name {
        "mainnet" => Some(Network::Mainnet),
        "testnet" => Some(Network::Testnet),
        "regtest" => Some(Network::Regtest),
        _ => None,
    }
}

/// The data directory of `network` under `base`, or under `~/.itacoin`.
#[must_use]
pub fn data_dir(base: Option<PathBuf>, network: Network) -> Option<PathBuf> {
    let base =
        base.or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".itacoin")))?;
    Some(base.join(network_name(network)))
}
