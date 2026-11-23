//! End-to-end tests: a regtest node, the RPC server and the blocking client.

use std::{net::SocketAddr, time::Instant};

use itacoin_blockchain::Block;
use itacoin_codec::Encode;
use itacoin_consensus::ConsensusParams;
use itacoin_crypto::{KeyPair, SigningDomain};
use itacoin_network::node::{NodeConfig, NodeHandle, start};
use itacoin_primitives::{Address, Amount, Hash256, Network, TransactionId, WalletId};
use itacoin_rpc::{
    Client, ClientError, Context, Cookie, Credentials, IpNet, RpcConfig, RpcServer, ServeError,
    request::code,
    serve,
    text::{decode_base64url, encode_base64url},
};
use itacoin_transaction::{Input, OutPoint, Output, Transaction, UnsignedTransaction, Witness};
use serde_json::{Value, json};
use tokio::sync::watch;

struct Harness {
    _directory: tempfile::TempDir,
    node: NodeHandle,
    server: RpcServer,
    client: Client,
    stop: watch::Receiver<bool>,
}

async fn harness() -> Harness {
    let directory = tempfile::tempdir().unwrap();
    let params = ConsensusParams::regtest();
    let mut config = NodeConfig::new(params, directory.path().to_path_buf());
    config.listen = None;
    let node = start(config).await.unwrap();
    let cookie_path = directory.path().join(".cookie");
    let cookie = Cookie::create(&cookie_path).unwrap();
    let (stop_tx, stop) = watch::channel(false);
    let context = Context {
        handle: node.clone(),
        params,
        miner: None,
        started: Instant::now(),
        stop: stop_tx,
        data_dir: directory.path().to_path_buf(),
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
    let (user, password) = Cookie::read(&cookie_path).unwrap();
    let client = Client::new(server.local_addrs()[0], &user, &password);
    Harness {
        _directory: directory,
        node,
        server,
        client,
        stop,
    }
}

async fn call(client: &Client, method: &str, params: Vec<Value>) -> Result<Value, ClientError> {
    let client = client.clone();
    let method = method.to_owned();
    tokio::task::spawn_blocking(move || client.call(&method, params))
        .await
        .unwrap()
}

async fn ok(client: &Client, method: &str, params: Vec<Value>) -> Value {
    call(client, method, params)
        .await
        .unwrap_or_else(|error| panic!("{method} failed: {error}"))
}

async fn error_code(client: &Client, method: &str, params: Vec<Value>) -> i64 {
    match call(client, method, params).await {
        Err(ClientError::Rpc { code, .. }) => code,
        other => panic!("{method}: expected an RPC error, got {other:?}"),
    }
}

async fn raw(
    client: &Client,
    body: Vec<u8>,
    headers: Vec<(&'static str, &'static str)>,
    authenticate: bool,
) -> itacoin_rpc::client::RawResponse {
    let client = client.clone();
    tokio::task::spawn_blocking(move || client.post(&body, &headers, authenticate).unwrap())
        .await
        .unwrap()
}

fn address(wallet_id: WalletId) -> String {
    Address::new(Network::Regtest, wallet_id).to_string()
}

const JSON: (&str, &str) = ("Content-Type", "application/json");

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_http_layer_refuses_what_it_must() {
    let h = harness().await;
    let body = br#"{"jsonrpc":"2.0","id":1,"method":"uptime"}"#.to_vec();

    assert_eq!(
        raw(&h.client, body.clone(), vec![JSON], true).await.status,
        200
    );
    // No credentials, or wrong ones.
    let response = raw(&h.client, body.clone(), vec![JSON], false).await;
    assert_eq!(response.status, 401);
    assert!(
        response
            .headers
            .iter()
            .any(|(name, _)| name == "www-authenticate")
    );
    let wrong = Client::new(h.server.local_addrs()[0], "__cookie__", &"0".repeat(64));
    let response = raw(&wrong, body.clone(), vec![JSON], true).await;
    assert_eq!(response.status, 401);
    // A browser form post, or a request without the JSON type.
    let response = raw(
        &h.client,
        body.clone(),
        vec![("Content-Type", "text/plain")],
        true,
    )
    .await;
    assert_eq!(response.status, 415);
    // No CORS header is ever sent.
    let response = raw(&h.client, body.clone(), vec![JSON], true).await;
    assert!(
        !response
            .headers
            .iter()
            .any(|(name, _)| name.starts_with("access-control"))
    );

    // A rebinding attack arrives with the attacker's host name.
    let client = h.client.clone();
    let body_len = body.len();
    let status = tokio::task::spawn_blocking(move || {
        let head = format!(
            "POST / HTTP/1.1\r\nHost: evil.example:80\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {body_len}\r\n\r\n"
        );
        client.exchange(head.as_bytes(), &body).unwrap().status
    })
    .await
    .unwrap();
    assert_eq!(status, 403);

    // A declared body over 2 MB is refused before it is read.
    let client = h.client.clone();
    let addr = h.server.local_addrs()[0];
    let status = tokio::task::spawn_blocking(move || {
        let head = format!(
            "POST / HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: 2000001\r\n\r\n"
        );
        client.exchange(head.as_bytes(), b"").unwrap().status
    })
    .await
    .unwrap();
    assert_eq!(status, 413);

    // A batch of 101 and deep nesting are refused; a batch of 2 is answered.
    let batch = format!("[{}]", vec![r#"{"id":1,"method":"uptime"}"#; 101].join(","));
    let response = raw(&h.client, batch.into_bytes(), vec![JSON], true).await;
    let value: Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(value["error"]["code"], json!(code::INVALID_REQUEST));
    let deep = format!(
        r#"{{"id":1,"method":"uptime","params":{}{}}}"#,
        "[".repeat(40),
        "]".repeat(40)
    );
    let response = raw(&h.client, deep.into_bytes(), vec![JSON], true).await;
    let value: Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(value["error"]["code"], json!(code::INVALID_REQUEST));
    let batch = br#"[{"id":1,"method":"uptime"},{"id":2,"method":"nope"}]"#.to_vec();
    let response = raw(&h.client, batch, vec![JSON], true).await;
    let value: Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(value.as_array().unwrap().len(), 2);
    assert_eq!(value[1]["error"]["code"], json!(code::METHOD_NOT_FOUND));

    h.server.shutdown().await;
    h.node.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn exposure_needs_an_allow_list() {
    let directory = tempfile::tempdir().unwrap();
    let params = ConsensusParams::regtest();
    let node = start(NodeConfig::new(params, directory.path().to_path_buf()))
        .await
        .unwrap();
    let context = || Context {
        handle: node.clone(),
        params,
        miner: None,
        started: Instant::now(),
        stop: watch::channel(false).0,
        data_dir: directory.path().to_path_buf(),
        rpc_addrs: Vec::new(),
    };
    let cookie = || Credentials {
        cookie: Some(Cookie::create(&directory.path().join(".cookie")).unwrap()),
        fixed: Vec::new(),
    };
    let exposed: SocketAddr = "0.0.0.0:0".parse().unwrap();
    let refused = serve(
        RpcConfig {
            binds: vec![exposed],
            allow: Vec::new(),
            credentials: cookie(),
        },
        context(),
    )
    .await;
    assert!(matches!(
        refused,
        Err(ServeError::ExposedWithoutAllowList(_))
    ));
    let no_credentials = serve(
        RpcConfig {
            binds: vec!["127.0.0.1:0".parse().unwrap()],
            allow: Vec::new(),
            credentials: Credentials::default(),
        },
        context(),
    )
    .await;
    assert!(matches!(no_credentials, Err(ServeError::NoCredentials)));
    let allowed = serve(
        RpcConfig {
            binds: vec![exposed],
            allow: vec![IpNet::parse("10.0.0.0/8").unwrap()],
            credentials: cookie(),
        },
        context(),
    )
    .await
    .unwrap();
    allowed.shutdown().await;
    node.shutdown().await;
}

fn spend(key: &KeyPair, coin: (OutPoint, Output), to: WalletId, fee: u64) -> Transaction {
    let chain_id = ConsensusParams::regtest().chain_id();
    let (outpoint, output) = coin;
    let unsigned = UnsignedTransaction::new(
        vec![Input {
            previous_output: outpoint,
            witness_index: 0,
        }],
        vec![Output {
            amount: Amount::from_satoshis(output.amount.as_satoshis() - fee).unwrap(),
            wallet_id: to,
        }],
    )
    .unwrap();
    let message = unsigned.sighash(&chain_id, &[output]).unwrap();
    let signature = key
        .private_key
        .sign(SigningDomain::Transaction, message.as_bytes())
        .unwrap();
    Transaction::Normal(
        unsigned
            .with_witnesses(vec![Witness {
                public_key: key.public_key.clone(),
                signature,
            }])
            .unwrap(),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn chain_mining_and_wallet_methods() {
    let h = harness().await;
    let c = &h.client;
    let key = KeyPair::generate().unwrap();
    let mine = address(key.public_key.wallet_id());
    let other = WalletId::new(Hash256::new([9; 32]));

    // generatetoaddress builds and submits blocks.
    let ids = ok(c, "generatetoaddress", vec![json!(3), json!(mine)]).await;
    assert_eq!(ids.as_array().unwrap().len(), 3);
    let info = ok(c, "getblockchaininfo", vec![]).await;
    assert_eq!(info["height"], json!(3));
    assert_eq!(info["network"], json!("regtest"));
    assert_eq!(info["initial_block_download"], json!(false));
    assert_eq!(ok(c, "getbestblockhash", vec![]).await, ids[2]);
    assert_eq!(ok(c, "getblockhash", vec![json!(2)]).await, ids[1]);
    assert_eq!(
        error_code(c, "getblockhash", vec![json!(99)]).await,
        code::NOT_FOUND
    );

    let block = ok(c, "getblock", vec![ids[1].clone(), json!(1)]).await;
    assert_eq!(block["height"], json!(2));
    assert_eq!(block["confirmations"], json!(2));
    assert_eq!(block["next_block"], ids[2]);
    assert_eq!(block["transactions"].as_array().unwrap().len(), 1);
    let full = ok(c, "getblock", vec![ids[1].clone(), json!(2)]).await;
    assert_eq!(full["transactions"][0]["coinbase"], json!(true));
    assert_eq!(
        full["transactions"][0]["outputs"][0]["address"],
        json!(mine)
    );
    let encoded = ok(c, "getblock", vec![ids[1].clone(), json!(0)]).await;
    let decoded =
        Block::from_bytes(&decode_base64url(encoded.as_str().unwrap(), 1_000_000).unwrap())
            .unwrap();
    assert_eq!(decoded.id().to_string(), ids[1].as_str().unwrap());
    let header = ok(c, "getblockheader", vec![ids[0].clone()]).await;
    assert_eq!(header["height"], json!(1));
    assert_eq!(
        error_code(c, "getblock", vec![json!("00".repeat(32))]).await,
        code::NOT_FOUND
    );
    assert_eq!(
        error_code(c, "getblock", vec![json!(format!("0x{}", "00".repeat(31)))]).await,
        code::BAD_FORMAT
    );
    let tips = ok(c, "getchaintips", vec![]).await;
    assert_eq!(tips[0]["status"], json!("active"));

    // The three coinbases belong to the key; regtest matures after 1 block.
    let unspent = ok(c, "listunspent", vec![json!([mine])]).await;
    let coins = unspent["unspent"].as_array().unwrap();
    assert_eq!(coins.len(), 3);
    assert!(coins.iter().all(|coin| coin["mature"] == json!(true)));
    let balance = ok(c, "getbalance", vec![json!([mine])]).await;
    assert_eq!(balance["outputs"], json!(3));
    // Amounts are strings of satoshis.
    let per_block = coins[0]["amount_sat"]
        .as_str()
        .unwrap()
        .parse::<u64>()
        .unwrap();
    assert_eq!(balance["total_sat"], json!((3 * per_block).to_string()));
    // Pagination.
    let page = ok(c, "listunspent", vec![json!([mine]), Value::Null, json!(2)]).await;
    assert_eq!(page["unspent"].as_array().unwrap().len(), 2);
    let cursor = page["next"].clone();
    let rest = ok(c, "listunspent", vec![json!([mine]), cursor, json!(2)]).await;
    assert_eq!(rest["unspent"].as_array().unwrap().len(), 1);
    assert_eq!(rest["next"], Value::Null);

    // Spend one coinbase through the mempool.
    let coin = &coins[0];
    let outpoint = OutPoint {
        txid: TransactionId::new(
            itacoin_rpc::text::decode_hash(coin["txid"].as_str().unwrap()).unwrap(),
        ),
        index: u16::try_from(coin["index"].as_u64().unwrap()).unwrap(),
    };
    let output = Output {
        amount: Amount::from_satoshis(per_block).unwrap(),
        wallet_id: key.public_key.wallet_id(),
    };
    let transaction = spend(&key, (outpoint, output), other, 50_000);
    let encoded = encode_base64url(&transaction.to_bytes());
    let decoded = ok(c, "decoderawtransaction", vec![json!(encoded)]).await;
    assert_eq!(decoded["txid"], json!(transaction.txid().to_string()));
    let txid = ok(c, "sendrawtransaction", vec![json!(encoded)]).await;
    assert_eq!(txid, json!(transaction.txid().to_string()));
    assert_eq!(
        error_code(c, "sendrawtransaction", vec![json!(encoded)]).await,
        code::MEMPOOL_REJECTED
    );
    let pool = ok(c, "getrawmempool", vec![]).await;
    assert_eq!(pool["txids"], json!([txid]));
    let entry = ok(c, "getmempoolentry", vec![txid.clone()]).await;
    assert_eq!(entry["fee_sat"], json!("50000"));
    assert_eq!(ok(c, "getmempoolinfo", vec![]).await["size"], json!(1));

    // A template includes it and pays the fee; submitting it confirms it.
    let template = ok(c, "getblocktemplate", vec![json!(mine)]).await;
    assert_eq!(template["height"], json!(4));
    assert_eq!(template["fees_sat"], json!("50000"));
    assert_eq!(template["transactions"], json!(2));
    let block = template["block"].clone();
    assert_eq!(
        ok(c, "submitblock", vec![block.clone()]).await,
        json!("accepted")
    );
    assert_eq!(ok(c, "submitblock", vec![block]).await, json!("duplicate"));
    assert_eq!(ok(c, "getmempoolinfo", vec![]).await["size"], json!(0));
    let out = ok(c, "gettxout", vec![txid.clone(), json!(0)]).await;
    assert_eq!(out["address"], json!(address(other)));
    assert_eq!(out["amount_sat"], json!((per_block - 50_000).to_string()));
    assert_eq!(
        ok(
            c,
            "gettxout",
            vec![coin["txid"].clone(), coin["index"].clone()]
        )
        .await,
        Value::Null
    );
    let balance = ok(c, "getbalance", vec![json!([address(other)])]).await;
    assert_eq!(
        balance["total_sat"],
        json!((per_block - 50_000).to_string())
    );

    // A block that breaks consensus is reported, not accepted.
    let template = ok(c, "getblocktemplate", vec![json!(mine)]).await;
    let mut tampered = Block::from_bytes(
        &decode_base64url(template["block"].as_str().unwrap(), 1_000_000).unwrap(),
    )
    .unwrap()
    .header()
    .to_owned();
    tampered.prev_block = itacoin_primitives::BlockId::new(Hash256::new([3; 32]));
    let template_block = Block::from_bytes(
        &decode_base64url(template["block"].as_str().unwrap(), 1_000_000).unwrap(),
    )
    .unwrap();
    let orphan = Block::new(tampered, template_block.transactions().to_vec()).unwrap();
    assert_eq!(
        ok(
            c,
            "submitblock",
            vec![json!(encode_base64url(&orphan.to_bytes()))]
        )
        .await,
        json!("orphan")
    );
    assert_eq!(
        error_code(c, "submitblock", vec![json!("AA")]).await,
        code::BLOCK_REJECTED
    );

    h.server.shutdown().await;
    h.node.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn parameters_and_control() {
    let mut h = harness().await;
    let c = &h.client;
    let testnet = Address::new(Network::Testnet, WalletId::new(Hash256::new([1; 32]))).to_string();
    assert_eq!(
        error_code(c, "generatetoaddress", vec![json!(1), json!(testnet)]).await,
        code::WRONG_NETWORK
    );
    assert_eq!(
        error_code(c, "generatetoaddress", vec![json!(1), json!("ritc1nope")]).await,
        code::BAD_FORMAT
    );
    let mine = address(WalletId::new(Hash256::new([1; 32])));
    assert_eq!(
        error_code(c, "generatetoaddress", vec![json!(101), json!(mine)]).await,
        code::INVALID_PARAMS
    );
    assert_eq!(
        error_code(c, "setmining", vec![json!(true)]).await,
        code::UNAVAILABLE
    );
    assert_eq!(error_code(c, "nope", vec![]).await, code::METHOD_NOT_FOUND);
    assert_eq!(
        error_code(c, "listunspent", vec![json!([])]).await,
        code::INVALID_PARAMS
    );

    let valid = ok(c, "validateaddress", vec![json!(testnet)]).await;
    assert_eq!(valid["valid"], json!(true));
    assert_eq!(valid["is_this_network"], json!(false));
    assert_eq!(
        ok(c, "validateaddress", vec![json!("x")]).await["valid"],
        json!(false)
    );

    let network = ok(c, "getnetworkinfo", vec![]).await;
    assert_eq!(network["connections"], json!(0));
    assert_eq!(network["network"], json!("regtest"));
    assert_eq!(ok(c, "getpeerinfo", vec![]).await, json!([]));
    assert_eq!(ok(c, "getconnectioncount", vec![]).await, json!(0));
    assert_eq!(ok(c, "listdiscouraged", vec![]).await, json!([]));
    assert_eq!(
        error_code(c, "disconnectnode", vec![json!("127.0.0.1:1")]).await,
        code::NOT_FOUND
    );
    assert_eq!(
        error_code(c, "addnode", vec![json!("127.0.0.1:1"), json!("remove")]).await,
        code::NOT_FOUND
    );
    let mining = ok(c, "getmininginfo", vec![]).await;
    assert_eq!(mining["miner_available"], json!(false));
    assert!(ok(c, "help", vec![]).await.as_array().unwrap().len() > 20);

    assert!(!*h.stop.borrow());
    ok(c, "stop", vec![]).await;
    h.stop.changed().await.unwrap();
    assert!(*h.stop.borrow());
    h.server.shutdown().await;
    h.node.shutdown().await;
}
