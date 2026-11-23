//! Peer-to-peer messages and their canonical encoding (section 5 of
//! `docs/NETWORK_PROPOSAL.md`).
//!
//! Every command has a maximum payload size, checked against the declared
//! length before the payload buffer is allocated (protocol requirement 1.8).
//! Payloads use the strict canonical codec: trailing bytes, unknown values and
//! out-of-range counts are errors.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use itacoin_blockchain::{
    Block, BlockHeader, HEADER_BYTES, MAX_BLOCK_BYTES, MAX_BLOCK_TRANSACTIONS,
};
use itacoin_codec::{CodecError, Decode, Encode, Reader, Writer};
use itacoin_primitives::{BlockId, Hash256};
use itacoin_transaction::{MAX_TX_BYTES, Transaction};

use crate::NetError;

/// The protocol version this release speaks.
pub const PROTOCOL_VERSION: u32 = 1;
/// Service bit: serves the full chain.
pub const SERVICE_NETWORK: u64 = 1 << 0;
/// Service bit: serves headers and recent blocks, with old witnesses pruned.
pub const SERVICE_WITNESS_PRUNED: u64 = 1 << 1;
/// Maximum user-agent length in bytes.
pub const MAX_USER_AGENT: usize = 64;
/// Maximum addresses per `addr` message.
pub const MAX_ADDR: usize = 1_000;
/// Maximum locator entries per `getheaders`.
pub const MAX_LOCATOR: usize = 64;
/// Maximum headers per `headers` message.
pub const MAX_HEADERS: usize = 1_000;
/// Maximum inventory items per `inv`, `getdata` or `notfound`.
pub const MAX_INV: usize = 1_000;
/// Length of a compact-block short transaction id.
pub const SHORT_ID_BYTES: usize = 6;

const INV_BYTES: usize = 1 + 32 + 32;
const ADDR_MAX_BYTES: usize = 8 + 8 + 1 + 32 + 2;

/// Message type, sent before the payload.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum Command {
    /// Handshake: protocol version and node information.
    Version = 0,
    /// Handshake acknowledgement.
    Verack = 1,
    /// Keep-alive request.
    Ping = 2,
    /// Keep-alive reply.
    Pong = 3,
    /// Peer addresses.
    Addr = 4,
    /// Request for headers after a locator.
    GetHeaders = 5,
    /// Block headers.
    Headers = 6,
    /// Inventory announcement.
    Inv = 7,
    /// Inventory request.
    GetData = 8,
    /// Requested inventory that is not available.
    NotFound = 9,
    /// A transaction.
    Tx = 10,
    /// A block.
    Block = 11,
    /// Compact-block negotiation.
    SendCmpct = 12,
    /// A compact block.
    CmpctBlock = 13,
    /// Request for missing compact-block transactions.
    GetBlockTxn = 14,
    /// Missing compact-block transactions.
    BlockTxn = 15,
    /// Minimum fee rate the peer wants announced.
    FeeFilter = 16,
}

impl Command {
    /// Parses a command byte.
    pub fn from_u8(value: u8) -> Result<Self, NetError> {
        Ok(match value {
            0 => Self::Version,
            1 => Self::Verack,
            2 => Self::Ping,
            3 => Self::Pong,
            4 => Self::Addr,
            5 => Self::GetHeaders,
            6 => Self::Headers,
            7 => Self::Inv,
            8 => Self::GetData,
            9 => Self::NotFound,
            10 => Self::Tx,
            11 => Self::Block,
            12 => Self::SendCmpct,
            13 => Self::CmpctBlock,
            14 => Self::GetBlockTxn,
            15 => Self::BlockTxn,
            16 => Self::FeeFilter,
            _ => return Err(NetError::Protocol("unknown command")),
        })
    }

    /// Largest payload this command may carry.
    #[must_use]
    pub const fn max_payload(self) -> usize {
        match self {
            Self::Version => 4 + 8 + 8 + 8 + 8 + 1 + 1 + MAX_USER_AGENT,
            Self::Verack => 0,
            Self::Ping | Self::Pong | Self::FeeFilter => 8,
            Self::Addr => 2 + MAX_ADDR * ADDR_MAX_BYTES,
            Self::GetHeaders => 2 + MAX_LOCATOR * 32 + 32,
            Self::Headers => 2 + MAX_HEADERS * HEADER_BYTES,
            Self::Inv | Self::GetData | Self::NotFound => 2 + MAX_INV * INV_BYTES,
            Self::Tx => MAX_TX_BYTES,
            Self::Block => MAX_BLOCK_BYTES,
            Self::SendCmpct => 1 + 8,
            Self::CmpctBlock | Self::BlockTxn => MAX_BLOCK_BYTES + 1_024,
            Self::GetBlockTxn => 32 + 4 + 4 * MAX_BLOCK_TRANSACTIONS,
        }
    }
}

/// The `version` handshake message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Version {
    /// Protocol version of the sender.
    pub protocol: u32,
    /// Service bits.
    pub services: u64,
    /// Height of the sender's active tip.
    pub height: u64,
    /// Sender's clock, seconds since the Unix epoch.
    pub timestamp: u64,
    /// Random value that detects connections to oneself.
    pub nonce: u64,
    /// Whether the sender wants transactions and addresses relayed to it.
    /// Block-relay-only connections set this to false.
    pub relay: bool,
    /// Printable ASCII software name, at most [`MAX_USER_AGENT`] bytes.
    pub user_agent: String,
}

/// A network address as carried in `addr`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum NetAddress {
    /// IPv4 address and port.
    Ip(SocketAddr),
    /// Tor v3 onion service public key and port. Kept for compatibility;
    /// this release has no Tor support and does not connect to it.
    TorV3([u8; 32], u16),
}

/// One entry of an `addr` message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AddrEntry {
    /// When the address was last seen, seconds since the Unix epoch.
    pub time: u64,
    /// Service bits of the advertised node.
    pub services: u64,
    /// The address.
    pub address: NetAddress,
}

/// Kind of an inventory item.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum InvKind {
    /// A transaction, identified by `txid ‖ witness_hash`.
    Tx,
    /// A full block.
    Block,
    /// A compact block (only in `getdata`).
    CmpctBlock,
}

/// An inventory item.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct InvItem {
    /// The kind.
    pub kind: InvKind,
    /// Transaction id or block id.
    pub id: Hash256,
    /// For transactions, the witness hash; all zero for blocks.
    pub witness_hash: Hash256,
}

impl InvItem {
    /// A transaction item.
    #[must_use]
    pub const fn tx(txid: Hash256, witness_hash: Hash256) -> Self {
        Self {
            kind: InvKind::Tx,
            id: txid,
            witness_hash,
        }
    }

    /// A block item of `kind` (`Block` or `CmpctBlock`).
    #[must_use]
    pub const fn block(kind: InvKind, block_id: BlockId) -> Self {
        Self {
            kind,
            id: block_id.into_hash(),
            witness_hash: Hash256::new([0; 32]),
        }
    }
}

/// A compact block: header, short ids and prefilled transactions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CmpctBlock {
    /// The block header.
    pub header: BlockHeader,
    /// Random value mixed into the short-id key.
    pub nonce: u64,
    /// Short ids of the transactions that are not prefilled, in block order.
    pub short_ids: Vec<[u8; SHORT_ID_BYTES]>,
    /// Transactions sent in full with their block positions, increasing.
    pub prefilled: Vec<(u32, Transaction)>,
}

/// A peer-to-peer message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Message {
    /// See [`Version`].
    Version(Version),
    /// Handshake acknowledgement.
    Verack,
    /// Keep-alive request with a nonce.
    Ping(u64),
    /// Keep-alive reply echoing the nonce.
    Pong(u64),
    /// Peer addresses.
    Addr(Vec<AddrEntry>),
    /// Request for headers after the first known locator entry.
    GetHeaders {
        /// Block ids, densest near the sender's tip.
        locator: Vec<BlockId>,
        /// Last header wanted, or all zero for as many as allowed.
        stop: BlockId,
    },
    /// Block headers, each the child of the previous.
    Headers(Vec<BlockHeader>),
    /// Inventory announcement.
    Inv(Vec<InvItem>),
    /// Inventory request.
    GetData(Vec<InvItem>),
    /// Requested inventory that is not available.
    NotFound(Vec<InvItem>),
    /// A transaction.
    Tx(Transaction),
    /// A block.
    Block(Block),
    /// Compact-block negotiation: whether the sender wants compact blocks
    /// pushed before validation (high-bandwidth mode).
    SendCmpct {
        /// High-bandwidth mode.
        high_bandwidth: bool,
        /// Compact-block version; 1.
        version: u64,
    },
    /// A compact block.
    CmpctBlock(CmpctBlock),
    /// Request for transactions of a compact block, by position.
    GetBlockTxn {
        /// The block.
        block_id: BlockId,
        /// Positions, strictly increasing.
        indexes: Vec<u32>,
    },
    /// Transactions answering a `GetBlockTxn`, in the requested order.
    BlockTxn {
        /// The block.
        block_id: BlockId,
        /// The transactions.
        transactions: Vec<Transaction>,
    },
    /// Minimum fee rate, in satoshis per byte, the sender wants announced.
    FeeFilter(u64),
}

impl Message {
    /// Returns this message's command.
    #[must_use]
    pub const fn command(&self) -> Command {
        match self {
            Self::Version(_) => Command::Version,
            Self::Verack => Command::Verack,
            Self::Ping(_) => Command::Ping,
            Self::Pong(_) => Command::Pong,
            Self::Addr(_) => Command::Addr,
            Self::GetHeaders { .. } => Command::GetHeaders,
            Self::Headers(_) => Command::Headers,
            Self::Inv(_) => Command::Inv,
            Self::GetData(_) => Command::GetData,
            Self::NotFound(_) => Command::NotFound,
            Self::Tx(_) => Command::Tx,
            Self::Block(_) => Command::Block,
            Self::SendCmpct { .. } => Command::SendCmpct,
            Self::CmpctBlock(_) => Command::CmpctBlock,
            Self::GetBlockTxn { .. } => Command::GetBlockTxn,
            Self::BlockTxn { .. } => Command::BlockTxn,
            Self::FeeFilter(_) => Command::FeeFilter,
        }
    }

    /// Encodes the payload.
    #[must_use]
    pub fn encode_payload(&self) -> Vec<u8> {
        let mut writer = Writer::default();
        match self {
            Self::Version(version) => {
                writer.u32(version.protocol);
                writer.u64(version.services);
                writer.u64(version.height);
                writer.u64(version.timestamp);
                writer.u64(version.nonce);
                writer.u8(u8::from(version.relay));
                let agent = version.user_agent.as_bytes();
                writer.u8(u8::try_from(agent.len()).expect("validated user agent"));
                writer.bytes(agent);
            }
            Self::Verack => {}
            Self::Ping(nonce) | Self::Pong(nonce) | Self::FeeFilter(nonce) => writer.u64(*nonce),
            Self::Addr(entries) => {
                writer.count_u16(entries.len());
                for entry in entries {
                    writer.u64(entry.time);
                    writer.u64(entry.services);
                    encode_address(&entry.address, &mut writer);
                }
            }
            Self::GetHeaders { locator, stop } => {
                writer.count_u16(locator.len());
                for id in locator {
                    id.encode(&mut writer);
                }
                stop.encode(&mut writer);
            }
            Self::Headers(headers) => {
                writer.count_u16(headers.len());
                for header in headers {
                    header.encode(&mut writer);
                }
            }
            Self::Inv(items) | Self::GetData(items) | Self::NotFound(items) => {
                writer.count_u16(items.len());
                for item in items {
                    writer.u8(match item.kind {
                        InvKind::Tx => 1,
                        InvKind::Block => 2,
                        InvKind::CmpctBlock => 3,
                    });
                    item.id.encode(&mut writer);
                    item.witness_hash.encode(&mut writer);
                }
            }
            Self::Tx(transaction) => transaction.encode(&mut writer),
            Self::Block(block) => block.encode(&mut writer),
            Self::SendCmpct {
                high_bandwidth,
                version,
            } => {
                writer.u8(u8::from(*high_bandwidth));
                writer.u64(*version);
            }
            Self::CmpctBlock(block) => {
                block.header.encode(&mut writer);
                writer.u64(block.nonce);
                writer.count_u32(block.short_ids.len());
                for id in &block.short_ids {
                    writer.bytes(id);
                }
                writer.count_u32(block.prefilled.len());
                for (index, transaction) in &block.prefilled {
                    writer.u32(*index);
                    transaction.encode(&mut writer);
                }
            }
            Self::GetBlockTxn { block_id, indexes } => {
                block_id.encode(&mut writer);
                writer.count_u32(indexes.len());
                for index in indexes {
                    writer.u32(*index);
                }
            }
            Self::BlockTxn {
                block_id,
                transactions,
            } => {
                block_id.encode(&mut writer);
                writer.count_u32(transactions.len());
                for transaction in transactions {
                    transaction.encode(&mut writer);
                }
            }
        }
        writer.into_bytes()
    }

    /// Strictly decodes a payload of `command`.
    pub fn decode(command: Command, payload: &[u8]) -> Result<Self, NetError> {
        if payload.len() > command.max_payload() {
            return Err(NetError::Protocol("payload exceeds the command limit"));
        }
        let mut reader = Reader::new(payload);
        let message = Self::decode_body(command, &mut reader)?;
        reader.finish().map_err(codec)?;
        Ok(message)
    }

    fn decode_body(command: Command, reader: &mut Reader<'_>) -> Result<Self, NetError> {
        Ok(match command {
            Command::Version => {
                let protocol = reader.u32().map_err(codec)?;
                let services = reader.u64().map_err(codec)?;
                let height = reader.u64().map_err(codec)?;
                let timestamp = reader.u64().map_err(codec)?;
                let nonce = reader.u64().map_err(codec)?;
                let relay = decode_bool(reader)?;
                let length = usize::from(reader.u8().map_err(codec)?);
                if length > MAX_USER_AGENT {
                    return Err(NetError::Protocol("user agent too long"));
                }
                let agent = reader.take(length).map_err(codec)?;
                if !agent.iter().all(|byte| (0x20..0x7f).contains(byte)) {
                    return Err(NetError::Protocol("user agent is not printable ASCII"));
                }
                Self::Version(Version {
                    protocol,
                    services,
                    height,
                    timestamp,
                    nonce,
                    relay,
                    user_agent: String::from_utf8(agent.to_vec()).expect("checked ASCII"),
                })
            }
            Command::Verack => Self::Verack,
            Command::Ping => Self::Ping(reader.u64().map_err(codec)?),
            Command::Pong => Self::Pong(reader.u64().map_err(codec)?),
            Command::FeeFilter => Self::FeeFilter(reader.u64().map_err(codec)?),
            Command::Addr => {
                let count = reader
                    .count_u16(0..=MAX_ADDR, 8 + 8 + 1 + 4 + 2)
                    .map_err(codec)?;
                let mut entries = Vec::with_capacity(count);
                for _ in 0..count {
                    entries.push(AddrEntry {
                        time: reader.u64().map_err(codec)?,
                        services: reader.u64().map_err(codec)?,
                        address: decode_address(reader)?,
                    });
                }
                Self::Addr(entries)
            }
            Command::GetHeaders => {
                let count = reader.count_u16(0..=MAX_LOCATOR, 32).map_err(codec)?;
                let locator = (0..count)
                    .map(|_| BlockId::decode(reader))
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(codec)?;
                Self::GetHeaders {
                    locator,
                    stop: BlockId::decode(reader).map_err(codec)?,
                }
            }
            Command::Headers => {
                let count = reader
                    .count_u16(0..=MAX_HEADERS, HEADER_BYTES)
                    .map_err(codec)?;
                let headers = (0..count)
                    .map(|_| BlockHeader::decode(reader))
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|_| NetError::Protocol("invalid header"))?;
                Self::Headers(headers)
            }
            Command::Inv | Command::GetData | Command::NotFound => {
                let count = reader.count_u16(0..=MAX_INV, INV_BYTES).map_err(codec)?;
                let mut items = Vec::with_capacity(count);
                for _ in 0..count {
                    let kind = match reader.u8().map_err(codec)? {
                        1 => InvKind::Tx,
                        2 => InvKind::Block,
                        3 => InvKind::CmpctBlock,
                        _ => return Err(NetError::Protocol("unknown inventory kind")),
                    };
                    let id = Hash256::decode(reader).map_err(codec)?;
                    let witness_hash = Hash256::decode(reader).map_err(codec)?;
                    if kind != InvKind::Tx && witness_hash != Hash256::new([0; 32]) {
                        return Err(NetError::Protocol("block inventory with a witness hash"));
                    }
                    if command == Command::Inv && kind == InvKind::CmpctBlock {
                        return Err(NetError::Protocol(
                            "compact blocks are not announced by inv",
                        ));
                    }
                    items.push(InvItem {
                        kind,
                        id,
                        witness_hash,
                    });
                }
                match command {
                    Command::Inv => Self::Inv(items),
                    Command::GetData => Self::GetData(items),
                    _ => Self::NotFound(items),
                }
            }
            Command::Tx => Self::Tx(
                Transaction::decode(reader)
                    .map_err(|_| NetError::Protocol("invalid transaction"))?,
            ),
            Command::Block => {
                Self::Block(Block::decode(reader).map_err(|_| NetError::Protocol("invalid block"))?)
            }
            Command::SendCmpct => Self::SendCmpct {
                high_bandwidth: decode_bool(reader)?,
                version: reader.u64().map_err(codec)?,
            },
            Command::CmpctBlock => {
                let header = BlockHeader::decode(reader)
                    .map_err(|_| NetError::Protocol("invalid header"))?;
                let nonce = reader.u64().map_err(codec)?;
                let count = reader
                    .count_u32(0..=MAX_BLOCK_TRANSACTIONS, SHORT_ID_BYTES)
                    .map_err(codec)?;
                let short_ids = (0..count)
                    .map(|_| reader.array::<SHORT_ID_BYTES>())
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(codec)?;
                let count = reader
                    .count_u32(1..=MAX_BLOCK_TRANSACTIONS, 4)
                    .map_err(codec)?;
                let mut prefilled = Vec::with_capacity(count);
                let mut previous: Option<u32> = None;
                for _ in 0..count {
                    let index = reader.u32().map_err(codec)?;
                    if previous.is_some_and(|previous| index <= previous) {
                        return Err(NetError::Protocol("prefilled indexes must increase"));
                    }
                    previous = Some(index);
                    let transaction = Transaction::decode(reader)
                        .map_err(|_| NetError::Protocol("invalid transaction"))?;
                    prefilled.push((index, transaction));
                }
                let total = short_ids.len() + prefilled.len();
                if total > MAX_BLOCK_TRANSACTIONS
                    || prefilled
                        .last()
                        .is_some_and(|(index, _)| *index as usize >= total)
                {
                    return Err(NetError::Protocol("prefilled index out of range"));
                }
                Self::CmpctBlock(CmpctBlock {
                    header,
                    nonce,
                    short_ids,
                    prefilled,
                })
            }
            Command::GetBlockTxn => {
                let block_id = BlockId::decode(reader).map_err(codec)?;
                let count = reader
                    .count_u32(1..=MAX_BLOCK_TRANSACTIONS, 4)
                    .map_err(codec)?;
                let mut indexes = Vec::with_capacity(count);
                for _ in 0..count {
                    let index = reader.u32().map_err(codec)?;
                    if indexes.last().is_some_and(|previous| index <= *previous) {
                        return Err(NetError::Protocol("requested indexes must increase"));
                    }
                    indexes.push(index);
                }
                Self::GetBlockTxn { block_id, indexes }
            }
            Command::BlockTxn => {
                let block_id = BlockId::decode(reader).map_err(codec)?;
                let count = reader
                    .count_u32(
                        1..=MAX_BLOCK_TRANSACTIONS,
                        itacoin_transaction::MIN_TX_BYTES,
                    )
                    .map_err(codec)?;
                let transactions = (0..count)
                    .map(|_| Transaction::decode(reader))
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|_| NetError::Protocol("invalid transaction"))?;
                Self::BlockTxn {
                    block_id,
                    transactions,
                }
            }
        })
    }
}

fn codec(_: CodecError) -> NetError {
    NetError::Protocol("malformed payload")
}

fn decode_bool(reader: &mut Reader<'_>) -> Result<bool, NetError> {
    match reader.u8().map_err(codec)? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(NetError::Protocol("invalid boolean")),
    }
}

fn encode_address(address: &NetAddress, writer: &mut Writer) {
    match address {
        NetAddress::Ip(SocketAddr::V4(socket)) => {
            writer.u8(1);
            writer.bytes(&socket.ip().octets());
            writer.u16(socket.port());
        }
        NetAddress::Ip(SocketAddr::V6(socket)) => {
            writer.u8(2);
            writer.bytes(&socket.ip().octets());
            writer.u16(socket.port());
        }
        NetAddress::TorV3(key, port) => {
            writer.u8(3);
            writer.bytes(key);
            writer.u16(*port);
        }
    }
}

fn decode_address(reader: &mut Reader<'_>) -> Result<NetAddress, NetError> {
    Ok(match reader.u8().map_err(codec)? {
        1 => {
            let ip = Ipv4Addr::from(reader.array::<4>().map_err(codec)?);
            NetAddress::Ip(SocketAddr::new(
                IpAddr::V4(ip),
                reader.u16().map_err(codec)?,
            ))
        }
        2 => {
            let ip = Ipv6Addr::from(reader.array::<16>().map_err(codec)?);
            NetAddress::Ip(SocketAddr::new(
                IpAddr::V6(ip),
                reader.u16().map_err(codec)?,
            ))
        }
        3 => NetAddress::TorV3(
            reader.array::<32>().map_err(codec)?,
            reader.u16().map_err(codec)?,
        ),
        _ => return Err(NetError::Protocol("unknown address network")),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(message: Message) {
        let payload = message.encode_payload();
        assert!(
            payload.len() <= message.command().max_payload(),
            "{message:?}"
        );
        assert_eq!(
            Message::decode(message.command(), &payload).unwrap(),
            message
        );
        let mut trailing = payload.clone();
        trailing.push(0);
        assert!(Message::decode(message.command(), &trailing).is_err());
    }

    #[test]
    fn messages_round_trip_and_refuse_trailing_bytes() {
        round_trip(Message::Version(Version {
            protocol: PROTOCOL_VERSION,
            services: SERVICE_NETWORK,
            height: 7,
            timestamp: 1_800_000_000,
            nonce: 42,
            relay: true,
            user_agent: "/itacoin:0.1.0/".into(),
        }));
        round_trip(Message::Verack);
        round_trip(Message::Ping(1));
        round_trip(Message::Pong(2));
        round_trip(Message::FeeFilter(3));
        round_trip(Message::Addr(vec![
            AddrEntry {
                time: 1,
                services: SERVICE_NETWORK,
                address: NetAddress::Ip("1.2.3.4:7210".parse().unwrap()),
            },
            AddrEntry {
                time: 2,
                services: 0,
                address: NetAddress::Ip("[2001:db8::1]:7210".parse().unwrap()),
            },
            AddrEntry {
                time: 3,
                services: 0,
                address: NetAddress::TorV3([9; 32], 7210),
            },
        ]));
        round_trip(Message::GetHeaders {
            locator: vec![BlockId::new(Hash256::new([1; 32]))],
            stop: BlockId::new(Hash256::new([0; 32])),
        });
        round_trip(Message::Inv(vec![
            InvItem::tx(Hash256::new([1; 32]), Hash256::new([2; 32])),
            InvItem::block(InvKind::Block, BlockId::new(Hash256::new([3; 32]))),
        ]));
        round_trip(Message::SendCmpct {
            high_bandwidth: true,
            version: 1,
        });
        round_trip(Message::GetBlockTxn {
            block_id: BlockId::new(Hash256::new([4; 32])),
            indexes: vec![1, 5, 9],
        });
    }

    #[test]
    fn limits_and_strictness() {
        assert!(Command::from_u8(17).is_err());
        assert!(Message::decode(Command::Verack, &[0]).is_err());
        // A count above the limit is refused without allocating.
        let mut addr = vec![0x03, 0xe9];
        addr.extend_from_slice(&[0; 64]);
        assert!(Message::decode(Command::Addr, &addr).is_err());
        // Booleans are strictly 0 or 1.
        assert!(Message::decode(Command::SendCmpct, &[2, 0, 0, 0, 0, 0, 0, 0, 1]).is_err());
        // Non-printable user agent.
        let mut version = Message::Version(Version {
            protocol: 1,
            services: 0,
            height: 0,
            timestamp: 0,
            nonce: 0,
            relay: false,
            user_agent: "x".into(),
        })
        .encode_payload();
        *version.last_mut().unwrap() = 0x07;
        assert!(Message::decode(Command::Version, &version).is_err());
        // Increasing indexes only.
        let request = Message::GetBlockTxn {
            block_id: BlockId::new(Hash256::new([4; 32])),
            indexes: vec![5, 5],
        }
        .encode_payload();
        assert!(Message::decode(Command::GetBlockTxn, &request).is_err());
        // Block inventory may not carry a witness hash.
        let mut inv = Message::Inv(vec![InvItem::block(
            InvKind::Block,
            BlockId::new(Hash256::new([3; 32])),
        )])
        .encode_payload();
        *inv.last_mut().unwrap() = 1;
        assert!(Message::decode(Command::Inv, &inv).is_err());
    }
}
