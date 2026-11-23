//! ITACOIN peer-to-peer networking, as specified in
//! `docs/NETWORK_PROPOSAL.md`.
//!
//! - [`transport`]: hybrid X25519 + ML-KEM-768 encrypted sessions.
//! - [`message`]: messages with per-command size limits.

use core::fmt;

pub mod addrman;
pub mod compact;
pub mod headers;
pub mod limits;
pub mod message;
pub mod node;
pub mod transport;

/// Network errors.
#[derive(Debug)]
pub enum NetError {
    /// The connection failed.
    Io(std::io::Error),
    /// The peer broke the protocol; it is disconnected.
    Protocol(&'static str),
}

impl fmt::Display for NetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "network I/O failed: {error}"),
            Self::Protocol(reason) => write!(formatter, "protocol violation: {reason}"),
        }
    }
}

impl std::error::Error for NetError {}
