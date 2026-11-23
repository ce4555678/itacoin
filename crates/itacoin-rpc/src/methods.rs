//! RPC methods (section 5 of `docs/NODE_PROPOSAL.md`).
//!
//! Every call into the node runs on its single core thread, so each closure
//! passed to [`NodeHandle::call`] is bounded: lists are paginated, and
//! encoding to JSON and base64url happens here, on a copy.

use std::{
    collections::HashSet,
    net::SocketAddr,
    path::PathBuf,
    str::FromStr,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use itacoin_blockchain::{Block, BlockHeader, Coin, MAX_BLOCK_BYTES};
use itacoin_codec::Encode;
use itacoin_consensus::{ConsensusParams, U256, block_work};
use itacoin_mempool::MempoolError;
use itacoin_miner::{Miner, build_template, template::median_time_past_of};
use itacoin_network::{
    message::PROTOCOL_VERSION,
    node::{BlockVerdict, ConnKind, Core, NodeHandle},
};
use itacoin_primitives::{
    Address, AddressError, BlockId, Hash256, Network, TransactionId, WalletId,
};
use itacoin_storage::{Chain, SubmitOutcome};
use itacoin_transaction::{MAX_TX_BYTES, OutPoint, Transaction};
use serde_json::{Value, json};
use tokio::sync::watch;

use crate::{
    network_name,
    request::{RpcError, code},
    text::{decode_base64url, decode_hash, encode_base64url, format_sat, format_sat_u128},
};

/// Most entries in one page of a list.
pub const MAX_PAGE: usize = 1_000;
/// Most addresses in one wallet query.
pub const MAX_ADDRESSES: usize = 100;
/// Most blocks `generatetoaddress` makes in one call.
pub const MAX_GENERATE: u64 = 100;

/// The embedded miner as the RPC sees it.
#[derive(Clone, Debug)]
pub struct MinerControl {
    /// The worker pool.
    pub miner: Miner,
    /// Threads used when `setmining true` gives no count.
    pub default_threads: usize,
}

/// What the methods need.
#[derive(Clone, Debug)]
pub struct Context {
    /// The node.
    pub handle: NodeHandle,
    /// The network's parameters.
    pub params: ConsensusParams,
    /// The embedded miner, if the node was started with a payout address.
    pub miner: Option<MinerControl>,
    /// When the node started.
    pub started: Instant,
    /// Set to true by `stop`.
    pub stop: watch::Sender<bool>,
    /// Data directory, for the size on disk.
    pub data_dir: PathBuf,
    /// Addresses the RPC listens on.
    pub rpc_addrs: Vec<SocketAddr>,
}

/// The method names, for `help`.
pub const METHODS: &[&str] = &[
    "addnode",
    "cleardiscouraged",
    "decoderawtransaction",
    "disconnectnode",
    "generatetoaddress",
    "getbalance",
    "getbestblockhash",
    "getblock",
    "getblockchaininfo",
    "getblockhash",
    "getblockheader",
    "getblocktemplate",
    "getchaintips",
    "getconnectioncount",
    "getmempoolentry",
    "getmempoolinfo",
    "getmininginfo",
    "getnetworkinfo",
    "getpeerinfo",
    "getrawmempool",
    "gettxout",
    "help",
    "listdiscouraged",
    "listunspent",
    "sendrawtransaction",
    "setmining",
    "stop",
    "submitblock",
    "uptime",
    "validateaddress",
];

type RpcResult = Result<Value, RpcError>;

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// Runs a method.
pub async fn dispatch(context: &Context, method: &str, params: &[Value]) -> RpcResult {
    match method {
        "help" => Ok(json!(METHODS)),
        "uptime" => Ok(json!(context.started.elapsed().as_secs())),
        "stop" => {
            let _ = context.stop.send(true);
            Ok(json!("ITACOIN node stopping"))
        }
        "getblockchaininfo" => get_blockchain_info(context).await,
        "getbestblockhash" => {
            let tip = core(context, |core| core.chain().tip()).await?;
            Ok(json!(tip.map(|tip| tip.block_id.to_string())))
        }
        "getblockhash" => get_block_hash(context, params).await,
        "getblockheader" => get_block_header(context, params).await,
        "getblock" => get_block(context, params).await,
        "getchaintips" => get_chain_tips(context).await,
        "gettxout" => get_tx_out(context, params).await,
        "sendrawtransaction" => send_raw_transaction(context, params).await,
        "getmempoolinfo" => get_mempool_info(context).await,
        "getrawmempool" => get_raw_mempool(context, params).await,
        "getmempoolentry" => get_mempool_entry(context, params).await,
        "decoderawtransaction" => {
            let transaction = transaction_param(params, 0)?;
            Ok(transaction_json(&transaction, context.params.network))
        }
        "getblocktemplate" => get_block_template(context, params).await,
        "submitblock" => submit_block(context, params).await,
        "getmininginfo" => get_mining_info(context).await,
        "setmining" => set_mining(context, params).await,
        "generatetoaddress" => generate_to_address(context, params).await,
        "validateaddress" => validate_address(context, params),
        "listunspent" => list_unspent(context, params).await,
        "getbalance" => get_balance(context, params).await,
        "getnetworkinfo" => get_network_info(context).await,
        "getpeerinfo" => get_peer_info(context).await,
        "getconnectioncount" => Ok(json!(core(context, |core| core.ready_peers()).await?)),
        "addnode" => add_node(context, params).await,
        "disconnectnode" => {
            let addr = socket_param(params, 0)?;
            let count = core(context, move |core| core.disconnect_addr(addr)).await?;
            if count == 0 {
                return Err(RpcError::new(code::NOT_FOUND, "peer not connected"));
            }
            Ok(Value::Null)
        }
        "listdiscouraged" => {
            let list = core(context, |core| core.discouraged()).await?;
            Ok(json!(
                list.into_iter()
                    .map(
                        |(ip, left)| json!({"ip": ip.to_string(), "remaining_secs": left.as_secs()})
                    )
                    .collect::<Vec<_>>()
            ))
        }
        "cleardiscouraged" => {
            core(context, Core::clear_discouraged).await?;
            Ok(Value::Null)
        }
        _ => Err(RpcError::new(code::METHOD_NOT_FOUND, "method not found")),
    }
}

async fn core<R: Send + 'static>(
    context: &Context,
    function: impl FnOnce(&mut Core) -> R + Send + 'static,
) -> Result<R, RpcError> {
    context
        .handle
        .call(function)
        .await
        .ok_or_else(|| RpcError::new(code::INTERNAL_ERROR, "the node is shutting down"))
}

// ------------------------------------------------------------ parameters

fn param(params: &[Value], index: usize) -> Option<&Value> {
    params.get(index).filter(|value| !value.is_null())
}

fn string_param<'a>(params: &'a [Value], index: usize, name: &str) -> Result<&'a str, RpcError> {
    match param(params, index) {
        Some(Value::String(text)) => Ok(text),
        _ => Err(RpcError::params(format!("{name} must be a string"))),
    }
}

fn u64_param(params: &[Value], index: usize, name: &str) -> Result<Option<u64>, RpcError> {
    match param(params, index) {
        None => Ok(None),
        Some(value) => value
            .as_u64()
            .map(Some)
            .ok_or_else(|| RpcError::params(format!("{name} must be a non-negative integer"))),
    }
}

fn bool_param(params: &[Value], index: usize, name: &str) -> Result<Option<bool>, RpcError> {
    match param(params, index) {
        None => Ok(None),
        Some(Value::Bool(value)) => Ok(Some(*value)),
        Some(_) => Err(RpcError::params(format!("{name} must be true or false"))),
    }
}

fn bad_format(what: &str) -> RpcError {
    RpcError::new(code::BAD_FORMAT, format!("malformed {what}"))
}

fn hash_param(params: &[Value], index: usize, name: &str) -> Result<Hash256, RpcError> {
    decode_hash(string_param(params, index, name)?).map_err(|_| bad_format(name))
}

fn address_from(text: &str, network: Network) -> Result<Address, RpcError> {
    Address::parse_for_network(text, network).map_err(|error| match error {
        AddressError::WrongNetwork { .. } => {
            RpcError::new(code::WRONG_NETWORK, "address of another network")
        }
        _ => bad_format("address"),
    })
}

fn address_param(params: &[Value], index: usize, network: Network) -> Result<Address, RpcError> {
    address_from(string_param(params, index, "address")?, network)
}

fn addresses_param(
    params: &[Value],
    index: usize,
    network: Network,
) -> Result<Vec<WalletId>, RpcError> {
    let Some(Value::Array(items)) = param(params, index) else {
        return Err(RpcError::params("addresses must be an array of strings"));
    };
    if items.is_empty() || items.len() > MAX_ADDRESSES {
        return Err(RpcError::params(format!(
            "between 1 and {MAX_ADDRESSES} addresses"
        )));
    }
    let mut seen = HashSet::new();
    let mut wallets = Vec::with_capacity(items.len());
    for item in items {
        let Value::String(text) = item else {
            return Err(RpcError::params("addresses must be an array of strings"));
        };
        let wallet = address_from(text, network)?.wallet_id();
        if seen.insert(wallet) {
            wallets.push(wallet);
        }
    }
    Ok(wallets)
}

fn socket_param(params: &[Value], index: usize) -> Result<SocketAddr, RpcError> {
    SocketAddr::from_str(string_param(params, index, "address")?)
        .map_err(|_| RpcError::params("address must be ip:port"))
}

fn limit_param(params: &[Value], index: usize) -> Result<usize, RpcError> {
    let limit = u64_param(params, index, "limit")?.unwrap_or(MAX_PAGE as u64);
    if limit == 0 || limit > MAX_PAGE as u64 {
        return Err(RpcError::params(format!("limit must be 1 to {MAX_PAGE}")));
    }
    Ok(usize::try_from(limit).unwrap_or(MAX_PAGE))
}

fn transaction_param(params: &[Value], index: usize) -> Result<Transaction, RpcError> {
    let bytes = decode_base64url(string_param(params, index, "transaction")?, MAX_TX_BYTES)
        .map_err(|_| bad_format("transaction"))?;
    Transaction::from_bytes(&bytes).map_err(|error| {
        RpcError::new(
            code::INVALID_TRANSACTION,
            format!("invalid transaction: {error}"),
        )
    })
}

fn block_param(params: &[Value], index: usize) -> Result<Block, RpcError> {
    let bytes = decode_base64url(string_param(params, index, "block")?, MAX_BLOCK_BYTES)
        .map_err(|_| bad_format("block"))?;
    Block::from_bytes(&bytes)
        .map_err(|error| RpcError::new(code::BLOCK_REJECTED, format!("invalid block: {error}")))
}

// --------------------------------------------------------------- encoding

fn u256_hex(value: U256) -> String {
    crate::text::encode_hex(&value.to_be_bytes())
}

fn u256_to_f64(value: U256) -> f64 {
    value
        .to_be_bytes()
        .iter()
        .fold(0.0, |total, byte| total * 256.0 + f64::from(*byte))
}

fn header_json(header: &BlockHeader) -> Value {
    json!({
        "prev_block": header.prev_block.to_string(),
        "tx_root": header.tx_root.to_string(),
        "witness_root": header.witness_root.to_string(),
        "timestamp": header.timestamp,
        "target": header.target.to_string(),
        "nonce": header.nonce,
    })
}

fn transaction_json(transaction: &Transaction, network: Network) -> Value {
    let txid = transaction.txid();
    let outputs: Vec<Value> = transaction
        .outputs()
        .iter()
        .enumerate()
        .map(|(index, output)| {
            json!({
                "index": index,
                "amount_sat": format_sat(output.amount),
                "wallet_id": output.wallet_id.to_string(),
                "address": Address::new(network, output.wallet_id).to_string(),
            })
        })
        .collect();
    let inputs: Vec<Value> = transaction
        .inputs()
        .iter()
        .map(|input| {
            json!({
                "txid": input.previous_output.txid.to_string(),
                "index": input.previous_output.index,
                "witness_index": input.witness_index,
            })
        })
        .collect();
    let mut object = json!({
        "txid": txid.to_string(),
        "witness_hash": transaction.witness_hash().to_string(),
        "size": transaction.encoded_len(),
        "coinbase": transaction.is_coinbase(),
        "inputs": inputs,
        "outputs": outputs,
    });
    match transaction {
        Transaction::Coinbase(coinbase) => {
            object["height"] = json!(coinbase.height());
        }
        Transaction::Normal(normal) => {
            object["witnesses"] = json!(
                normal
                    .witnesses()
                    .iter()
                    .map(|witness| json!({
                        "public_key": encode_base64url(witness.public_key.as_bytes()),
                        "signature": encode_base64url(witness.signature.as_bytes()),
                    }))
                    .collect::<Vec<_>>()
            );
        }
    }
    object
}

/// Where a block sits relative to the active chain.
struct Placement {
    height: u64,
    chain_work: U256,
    in_active_chain: bool,
    confirmations: u64,
    next: Option<BlockId>,
}

fn placement(chain: &Chain, id: &BlockId) -> Option<Placement> {
    let entry = chain.entry(id)?;
    let tip = chain.tip()?;
    let in_active_chain = chain.store().block_id_at(entry.height).ok().flatten() == Some(*id);
    let next = if in_active_chain {
        chain.store().block_id_at(entry.height + 1).ok().flatten()
    } else {
        None
    };
    Some(Placement {
        height: entry.height,
        chain_work: entry.chain_work,
        in_active_chain,
        confirmations: if in_active_chain {
            tip.height - entry.height + 1
        } else {
            0
        },
        next,
    })
}

fn placement_json(placement: &Placement, object: &mut Value) {
    object["height"] = json!(placement.height);
    object["chainwork"] = json!(u256_hex(placement.chain_work));
    object["in_active_chain"] = json!(placement.in_active_chain);
    object["confirmations"] = json!(placement.confirmations);
    object["next_block"] = json!(placement.next.map(|id| id.to_string()));
}

fn coin_json(outpoint: &OutPoint, coin: &Coin, tip_height: u64, params: &ConsensusParams) -> Value {
    let confirmations = tip_height.saturating_sub(coin.height) + 1;
    let mature = !coin.is_coinbase || confirmations >= params.coinbase_maturity;
    json!({
        "txid": outpoint.txid.to_string(),
        "index": outpoint.index,
        "amount_sat": format_sat(coin.output.amount),
        "wallet_id": coin.output.wallet_id.to_string(),
        "address": Address::new(params.network, coin.output.wallet_id).to_string(),
        "height": coin.height,
        "confirmations": confirmations,
        "coinbase": coin.is_coinbase,
        "mature": mature,
    })
}

/// Parses a `txid:index` cursor.
fn outpoint_cursor(text: &str) -> Result<OutPoint, RpcError> {
    let (txid, index) = text
        .split_once(':')
        .ok_or_else(|| RpcError::params("cursor must be txid:index"))?;
    Ok(OutPoint {
        txid: TransactionId::new(decode_hash(txid).map_err(|_| bad_format("cursor"))?),
        index: index
            .parse()
            .map_err(|_| RpcError::params("cursor must be txid:index"))?,
    })
}

// ------------------------------------------------------------------ chain

async fn get_blockchain_info(context: &Context) -> RpcResult {
    let snapshot = core(context, |core| {
        let chain = core.chain();
        let tip = chain.tip()?;
        let entry = chain.entry(&tip.block_id)?;
        Some((
            tip,
            entry.chain_work,
            chain.next_target(&tip.block_id).ok(),
            median_time_past_of(chain, tip.block_id),
            core.headers().best().1.height,
            core.is_initial_block_download(),
            chain.utxo().len(),
            chain.utxo().total_value(),
            core.config().data_dir.join("chain.redb"),
        ))
    })
    .await?
    .ok_or_else(|| RpcError::new(code::INTERNAL_ERROR, "the chain has no tip"))?;
    let (tip, work, target, mtp, headers, ibd, coins, supply, path) = snapshot;
    let size = std::fs::metadata(path).map_or(0, |metadata| metadata.len());
    Ok(json!({
        "network": network_name(context.params.network),
        "height": tip.height,
        "best_block": tip.block_id.to_string(),
        "chainwork": u256_hex(work),
        "next_target": target.map(u256_hex),
        "median_time": mtp,
        "headers": headers,
        "initial_block_download": ibd,
        "utxo_count": coins,
        "supply_sat": format_sat(supply),
        "size_on_disk": size,
    }))
}

async fn get_block_hash(context: &Context, params: &[Value]) -> RpcResult {
    let height =
        u64_param(params, 0, "height")?.ok_or_else(|| RpcError::params("height is required"))?;
    let id = core(context, move |core| {
        core.chain().store().block_id_at(height).ok().flatten()
    })
    .await?
    .ok_or_else(|| RpcError::new(code::NOT_FOUND, "height above the active tip"))?;
    Ok(json!(id.to_string()))
}

async fn get_block_header(context: &Context, params: &[Value]) -> RpcResult {
    let id = BlockId::new(hash_param(params, 0, "block id")?);
    let verbose = bool_param(params, 1, "verbose")?.unwrap_or(true);
    let (header, placement) = core(context, move |core| {
        let chain = core.chain();
        Some((chain.entry(&id)?.header, placement(chain, &id)?))
    })
    .await?
    .ok_or_else(|| RpcError::new(code::NOT_FOUND, "block not found"))?;
    if !verbose {
        return Ok(json!(encode_base64url(&header.to_bytes())));
    }
    let mut object = header_json(&header);
    object["id"] = json!(id.to_string());
    placement_json(&placement, &mut object);
    Ok(object)
}

async fn get_block(context: &Context, params: &[Value]) -> RpcResult {
    let id = BlockId::new(hash_param(params, 0, "block id")?);
    let verbosity = u64_param(params, 1, "verbosity")?.unwrap_or(1);
    if verbosity > 2 {
        return Err(RpcError::params("verbosity must be 0, 1 or 2"));
    }
    let (block, placement) = core(context, move |core| {
        let chain = core.chain();
        Some((
            chain.store().block(&id).ok().flatten()?,
            placement(chain, &id)?,
        ))
    })
    .await?
    .ok_or_else(|| RpcError::new(code::NOT_FOUND, "block not found"))?;
    if verbosity == 0 {
        return Ok(json!(encode_base64url(&block.to_bytes())));
    }
    let mut object = header_json(block.header());
    object["id"] = json!(id.to_string());
    object["size"] = json!(block.encoded_len());
    placement_json(&placement, &mut object);
    let network = context.params.network;
    object["transactions"] = if verbosity == 1 {
        json!(
            block
                .transactions()
                .iter()
                .map(|transaction| transaction.txid().to_string())
                .collect::<Vec<_>>()
        )
    } else {
        json!(
            block
                .transactions()
                .iter()
                .map(|transaction| transaction_json(transaction, network))
                .collect::<Vec<_>>()
        )
    };
    Ok(object)
}

async fn get_chain_tips(context: &Context) -> RpcResult {
    let tips = core(context, |core| {
        let chain = core.chain();
        let active = chain.tip()?;
        let parents: HashSet<BlockId> = chain
            .index()
            .map(|(_, entry)| entry.header.prev_block)
            .collect();
        let mut tips: Vec<Value> = chain
            .index()
            .filter(|(id, _)| !parents.contains(id))
            .map(|(id, entry)| {
                let fork = chain
                    .common_ancestor(*id, active.block_id)
                    .and_then(|fork| chain.entry(&fork))
                    .map_or(0, |fork| fork.height);
                let status = if *id == active.block_id {
                    "active"
                } else if entry.invalid {
                    "invalid"
                } else {
                    "valid-fork"
                };
                json!({
                    "id": id.to_string(),
                    "height": entry.height,
                    "branch_length": entry.height - fork,
                    "status": status,
                })
            })
            .collect();
        let (best_id, best) = core.headers().best();
        if !best.have_block && chain.entry(&best_id).is_none() {
            tips.push(json!({
                "id": best_id.to_string(),
                "height": best.height,
                "branch_length": best.height.saturating_sub(active.height),
                "status": "headers-only",
            }));
        }
        Some(tips)
    })
    .await?
    .unwrap_or_default();
    Ok(json!(tips))
}

async fn get_tx_out(context: &Context, params: &[Value]) -> RpcResult {
    let txid = TransactionId::new(hash_param(params, 0, "txid")?);
    let index = u64_param(params, 1, "index")?
        .and_then(|index| u16::try_from(index).ok())
        .ok_or_else(|| RpcError::params("index must be 0 to 65535"))?;
    let outpoint = OutPoint { txid, index };
    let found = core(context, move |core| {
        let chain = core.chain();
        Some((*chain.utxo().get(&outpoint)?, chain.tip()?.height))
    })
    .await?;
    Ok(found.map_or(Value::Null, |(coin, tip)| {
        coin_json(&outpoint, &coin, tip, &context.params)
    }))
}

// ---------------------------------------------------------- transactions

fn mempool_error(error: &MempoolError) -> RpcError {
    let code = match error {
        MempoolError::Invalid(_) | MempoolError::Coinbase => code::INVALID_TRANSACTION,
        _ => code::MEMPOOL_REJECTED,
    };
    RpcError::new(code, error.to_string())
}

async fn send_raw_transaction(context: &Context, params: &[Value]) -> RpcResult {
    let transaction = transaction_param(params, 0)?;
    let txid = transaction.txid();
    let added = core(context, move |core| {
        core.submit_local_transaction(transaction)
    })
    .await?
    .map_err(|error| mempool_error(&error))?;
    if added.orphaned {
        return Err(RpcError::new(code::MEMPOOL_REJECTED, "missing inputs")
            .with_data(json!({"orphan": true, "txid": txid.to_string()})));
    }
    Ok(json!(txid.to_string()))
}

async fn get_mempool_info(context: &Context) -> RpcResult {
    let (size, bytes, policy, orphans) = core(context, |core| {
        let mempool = core.mempool();
        (
            mempool.len(),
            mempool.total_bytes(),
            *mempool.policy(),
            mempool.orphan_count(),
        )
    })
    .await?;
    Ok(json!({
        "size": size,
        "bytes": bytes,
        "max_bytes": policy.max_bytes,
        "min_fee_per_byte": policy.min_fee_per_byte,
        "orphans": orphans,
    }))
}

async fn get_raw_mempool(context: &Context, params: &[Value]) -> RpcResult {
    let after = match param(params, 0) {
        None => None,
        Some(_) => Some(TransactionId::new(hash_param(params, 0, "after")?)),
    };
    let limit = limit_param(params, 1)?;
    let (page, more) = core(context, move |core| {
        let mut txids: Vec<TransactionId> = core
            .mempool()
            .entries()
            .map(itacoin_mempool::Entry::txid)
            .filter(|txid| after.is_none_or(|after| *txid > after))
            .collect();
        txids.sort_unstable();
        let more = txids.len() > limit;
        txids.truncate(limit);
        (txids, more)
    })
    .await?;
    let next = if more {
        page.last().map(ToString::to_string)
    } else {
        None
    };
    Ok(json!({
        "txids": page.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "next": next,
    }))
}

async fn get_mempool_entry(context: &Context, params: &[Value]) -> RpcResult {
    let txid = TransactionId::new(hash_param(params, 0, "txid")?);
    let entry = core(context, move |core| {
        core.mempool().get(&txid).map(|entry| {
            let mut parents: Vec<String> = entry.parents().map(ToString::to_string).collect();
            let mut children: Vec<String> = entry.children().map(ToString::to_string).collect();
            parents.sort();
            children.sort();
            json!({
                "txid": entry.txid().to_string(),
                "witness_hash": entry.witness_hash().to_string(),
                "size": entry.size(),
                "fee_sat": format_sat(entry.fee()),
                "fee_per_byte": entry.fee().as_satoshis() as f64 / entry.size().max(1) as f64,
                "time": entry.time(),
                "parents": parents,
                "children": children,
            })
        })
    })
    .await?;
    entry.ok_or_else(|| RpcError::new(code::NOT_FOUND, "transaction not in the mempool"))
}

// ----------------------------------------------------------------- mining

async fn get_block_template(context: &Context, params: &[Value]) -> RpcResult {
    let payout = address_param(params, 0, context.params.network)?.wallet_id();
    let regtest = context.params.network == Network::Regtest;
    let template = core(context, move |core| {
        if !regtest && core.is_initial_block_download() {
            return Err(RpcError::new(
                code::IN_IBD,
                "initial block download in progress",
            ));
        }
        build_template(core.chain(), core.mempool(), payout, unix_now())
            .map_err(|error| RpcError::new(code::INTERNAL_ERROR, error.to_string()))
    })
    .await??;
    let header = template.block.header();
    Ok(json!({
        "block": encode_base64url(&template.block.to_bytes()),
        "template_id": template.block.id().to_string(),
        "height": template.height,
        "prev_block": header.prev_block.to_string(),
        "target": header.target.to_string(),
        "timestamp": header.timestamp,
        "min_timestamp": template.min_timestamp,
        "max_timestamp": unix_now() + context.params.max_future_drift,
        "fees_sat": format_sat(template.fees),
        "coinbase_sat": format_sat(template.block.transactions()[0].outputs()[0].amount),
        "transactions": template.block.transactions().len(),
    }))
}

fn verdict_json(verdict: BlockVerdict) -> RpcResult {
    match verdict {
        BlockVerdict::Accepted(SubmitOutcome::NewTip) => Ok(json!("accepted")),
        BlockVerdict::Accepted(SubmitOutcome::Duplicate) => Ok(json!("duplicate")),
        BlockVerdict::Accepted(SubmitOutcome::SideChain) => Ok(json!("stale")),
        BlockVerdict::Orphan => Ok(json!("orphan")),
        BlockVerdict::Deferred => Ok(json!("deferred")),
        BlockVerdict::Rejected(reason) => {
            Err(RpcError::new(code::BLOCK_REJECTED, "block rejected").with_data(json!(reason)))
        }
    }
}

async fn submit_block(context: &Context, params: &[Value]) -> RpcResult {
    let block = block_param(params, 0)?;
    verdict_json(core(context, move |core| core.submit_local_block(block)).await?)
}

async fn get_mining_info(context: &Context) -> RpcResult {
    let (height, target, work) = core(context, |core| {
        let chain = core.chain();
        let tip = chain.tip()?;
        let entry = chain.entry(&tip.block_id)?;
        Some((
            tip.height,
            chain.next_target(&tip.block_id).ok()?,
            block_work(U256::from_hash(&entry.header.target)),
        ))
    })
    .await?
    .ok_or_else(|| RpcError::new(code::INTERNAL_ERROR, "the chain has no tip"))?;
    let network_rate = u256_to_f64(work) / context.params.target_spacing as f64;
    let (threads, local_rate, working) =
        context.miner.as_ref().map_or((0, 0.0, false), |control| {
            (
                control.miner.threads(),
                control.miner.hashrate(),
                control.miner.has_work(),
            )
        });
    Ok(json!({
        "height": height,
        "next_target": u256_hex(target),
        "network_hashrate": network_rate,
        "local_hashrate": local_rate,
        "threads": threads,
        "mining": threads > 0,
        "has_work": working,
        "miner_available": context.miner.is_some(),
    }))
}

async fn set_mining(context: &Context, params: &[Value]) -> RpcResult {
    let enabled =
        bool_param(params, 0, "enabled")?.ok_or_else(|| RpcError::params("enabled is required"))?;
    let control = context.miner.clone().ok_or_else(|| {
        RpcError::new(
            code::UNAVAILABLE,
            "the miner needs --mine-address (and is unavailable on regtest)",
        )
    })?;
    let threads = if enabled {
        let threads = u64_param(params, 1, "threads")?.map_or(control.default_threads, |threads| {
            usize::try_from(threads).unwrap_or(usize::MAX)
        });
        if threads == 0 || threads > 1_024 {
            return Err(RpcError::params("threads must be 1 to 1024"));
        }
        threads
    } else {
        0
    };
    let miner = control.miner.clone();
    tokio::task::spawn_blocking(move || miner.set_threads(threads))
        .await
        .map_err(|_| RpcError::new(code::INTERNAL_ERROR, "could not change the miner"))?;
    Ok(json!({"threads": control.miner.threads()}))
}

async fn generate_to_address(context: &Context, params: &[Value]) -> RpcResult {
    if context.params.network != Network::Regtest {
        return Err(RpcError::new(
            code::UNAVAILABLE,
            "generatetoaddress is regtest only",
        ));
    }
    let count =
        u64_param(params, 0, "count")?.ok_or_else(|| RpcError::params("count is required"))?;
    if count == 0 || count > MAX_GENERATE {
        return Err(RpcError::params(format!(
            "count must be 1 to {MAX_GENERATE}"
        )));
    }
    let payout = address_param(params, 1, context.params.network)?.wallet_id();
    let mut ids = Vec::new();
    for _ in 0..count {
        let id = core(context, move |core| {
            let block = build_template(core.chain(), core.mempool(), payout, unix_now())
                .map_err(|error| RpcError::new(code::INTERNAL_ERROR, error.to_string()))?
                .block;
            // The regtest target accepts every hash.
            let block = itacoin_miner::template::mine(&block, &core.chain().chain_id(), 1)
                .ok_or_else(|| RpcError::new(code::INTERNAL_ERROR, "no proof of work found"))?;
            let id = block.id();
            match core.submit_local_block(block) {
                BlockVerdict::Accepted(SubmitOutcome::NewTip) => Ok(id),
                other => Err(
                    RpcError::new(code::BLOCK_REJECTED, "generated block not accepted")
                        .with_data(json!(format!("{other:?}"))),
                ),
            }
        })
        .await??;
        ids.push(json!(id.to_string()));
    }
    Ok(Value::Array(ids))
}

// --------------------------------------------------------------- wallets

fn validate_address(context: &Context, params: &[Value]) -> RpcResult {
    let text = string_param(params, 0, "address")?;
    Ok(match Address::from_str(text) {
        Ok(address) => json!({
            "valid": true,
            "address": address.to_string(),
            "network": network_name(address.network()),
            "is_this_network": address.network() == context.params.network,
            "wallet_id": address.wallet_id().to_string(),
        }),
        Err(error) => json!({"valid": false, "error": error.to_string()}),
    })
}

async fn list_unspent(context: &Context, params: &[Value]) -> RpcResult {
    let wallets = addresses_param(params, 0, context.params.network)?;
    let after = match param(params, 1) {
        None => None,
        Some(_) => Some(outpoint_cursor(string_param(params, 1, "cursor")?)?),
    };
    let limit = limit_param(params, 2)?;
    let (coins, tip, more) = core(context, move |core| {
        let utxo = core.chain().utxo();
        let mut coins: Vec<(OutPoint, Coin)> = wallets
            .iter()
            .flat_map(|wallet| utxo.outpoints_of(wallet))
            .filter(|outpoint| after.is_none_or(|after| **outpoint > after))
            .filter_map(|outpoint| utxo.get(outpoint).map(|coin| (*outpoint, *coin)))
            .collect();
        coins.sort_unstable_by_key(|(outpoint, _)| *outpoint);
        let more = coins.len() > limit;
        coins.truncate(limit);
        (coins, core.chain().tip().map_or(0, |tip| tip.height), more)
    })
    .await?;
    let next = if more {
        coins
            .last()
            .map(|(outpoint, _)| format!("{}:{}", outpoint.txid, outpoint.index))
    } else {
        None
    };
    Ok(json!({
        "unspent": coins
            .iter()
            .map(|(outpoint, coin)| coin_json(outpoint, coin, tip, &context.params))
            .collect::<Vec<_>>(),
        "next": next,
    }))
}

async fn get_balance(context: &Context, params: &[Value]) -> RpcResult {
    let wallets = addresses_param(params, 0, context.params.network)?;
    let maturity = context.params.coinbase_maturity;
    let (mature, immature, count) = core(context, move |core| {
        let chain = core.chain();
        let tip = chain.tip().map_or(0, |tip| tip.height);
        let (mut mature, mut immature, mut count) = (0_u128, 0_u128, 0_usize);
        for wallet in &wallets {
            for outpoint in chain.utxo().outpoints_of(wallet) {
                let Some(coin) = chain.utxo().get(outpoint) else {
                    continue;
                };
                count += 1;
                let value = u128::from(coin.output.amount.as_satoshis());
                if coin.is_coinbase && tip.saturating_sub(coin.height) + 1 < maturity {
                    immature += value;
                } else {
                    mature += value;
                }
            }
        }
        (mature, immature, count)
    })
    .await?;
    Ok(json!({
        "mature_sat": format_sat_u128(mature),
        "immature_sat": format_sat_u128(immature),
        "total_sat": format_sat_u128(mature + immature),
        "outputs": count,
    }))
}

// ---------------------------------------------------------------- network

fn kind_name(kind: ConnKind) -> &'static str {
    match kind {
        ConnKind::Inbound => "inbound",
        ConnKind::FullRelay => "outbound-full-relay",
        ConnKind::BlockRelay => "outbound-block-relay",
        ConnKind::Feeler => "feeler",
        ConnKind::Manual => "manual",
    }
}

async fn get_network_info(context: &Context) -> RpcResult {
    let (user_agent, listen, peers, min_fee) = core(context, |core| {
        (
            core.config().user_agent.clone(),
            core.config().listen,
            core.peer_info(),
            core.mempool().policy().min_fee_per_byte,
        )
    })
    .await?;
    let ready: Vec<_> = peers.iter().filter(|peer| peer.ready).collect();
    let inbound = ready
        .iter()
        .filter(|peer| peer.kind == ConnKind::Inbound)
        .count();
    Ok(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "user_agent": user_agent,
        "protocol": PROTOCOL_VERSION,
        "network": network_name(context.params.network),
        "p2p_listen": listen.map(|addr| addr.to_string()),
        "rpc_listen": context.rpc_addrs.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "connections": ready.len(),
        "inbound": inbound,
        "outbound": ready.len() - inbound,
        "min_relay_fee_per_byte": min_fee,
    }))
}

async fn get_peer_info(context: &Context) -> RpcResult {
    let peers = core(context, |core| core.peer_info()).await?;
    Ok(json!(
        peers
            .iter()
            .map(|peer| json!({
                "addr": peer.addr.to_string(),
                "kind": kind_name(peer.kind),
                "ready": peer.ready,
                "protocol": peer.protocol,
                "user_agent": peer.user_agent,
                "start_height": peer.start_height,
                "relay": peer.relay,
                "min_ping_ms": peer.min_ping.map(|ping| ping.as_secs_f64() * 1_000.0),
                "connected_secs": peer.connected_for.as_secs(),
                "blocks_in_flight": peer.blocks_in_flight,
            }))
            .collect::<Vec<_>>()
    ))
}

async fn add_node(context: &Context, params: &[Value]) -> RpcResult {
    let addr = socket_param(params, 0)?;
    match string_param(params, 1, "command")? {
        "add" => core(context, move |core| core.add_node(addr)).await?,
        "remove" => {
            if !core(context, move |core| core.remove_node(addr)).await? {
                return Err(RpcError::new(code::NOT_FOUND, "node was not added"));
            }
        }
        "onetry" => core(context, move |core| core.connect_once(addr)).await?,
        _ => return Err(RpcError::params("command must be add, remove or onetry")),
    }
    Ok(Value::Null)
}
