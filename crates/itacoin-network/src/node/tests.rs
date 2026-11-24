use std::{future::Future, time::Duration};

use itacoin_crypto::{KeyPair, SigningDomain};
use itacoin_primitives::{Amount, WalletId};
use itacoin_transaction::{
    CoinbaseTransaction, Input, OutPoint, Output, UnsignedTransaction, Witness,
};
use tokio::{
    io::{AsyncReadExt, ReadHalf, WriteHalf},
    net::TcpStream,
};

use super::*;
use crate::{
    message::Command,
    transport::{FrameReader, FrameWriter},
};

const WAIT: Duration = Duration::from_secs(30);

async fn eventually<F, Fut>(mut check: F) -> bool
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    let deadline = Instant::now() + WAIT;
    while Instant::now() < deadline {
        if check().await {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

async fn node(directory: &tempfile::TempDir) -> NodeHandle {
    let mut config = NodeConfig::new(ConsensusParams::regtest(), directory.path().to_path_buf());
    config.listen = Some("127.0.0.1:0".parse().unwrap());
    config.handshake_timeout = Duration::from_secs(2);
    start(config).await.unwrap()
}

async fn mine(node: &NodeHandle, payout: WalletId) -> Block {
    let block = node
        .call(move |core| {
            itacoin_miner::build_block(&core.chain, &core.mempool, payout, unix_now()).unwrap()
        })
        .await
        .unwrap();
    node.submit_block(block.clone()).await;
    block
}

async fn connected(a: &NodeHandle, b: &NodeHandle) {
    b.connect(a.local_addr().unwrap()).await;
    assert!(
        eventually(|| async {
            a.call(|core| core.ready_peers()).await == Some(1)
                && b.call(|core| core.ready_peers()).await == Some(1)
        })
        .await,
        "peers never completed the handshake"
    );
}

async fn same_tip(nodes: Vec<NodeHandle>) -> bool {
    let first = nodes[0].tip().await;
    for node in &nodes[1..] {
        if node.tip().await != first {
            return false;
        }
    }
    true
}

fn spend_coinbase(key: &KeyPair, block: &Block, chain_id: Hash256, to: WalletId) -> Transaction {
    let coinbase = &block.transactions()[0];
    let output = coinbase.outputs()[0];
    let unsigned = UnsignedTransaction::new(
        vec![Input {
            previous_output: OutPoint {
                txid: coinbase.txid(),
                index: 0,
            },
            witness_index: 0,
        }],
        vec![Output {
            amount: Amount::from_satoshis(output.amount.as_satoshis() - 20_000).unwrap(),
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
async fn two_nodes_sync_blocks() {
    let (dir_a, dir_b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (a, b) = (node(&dir_a).await, node(&dir_b).await);
    let payout = WalletId::new(Hash256::new([1; 32]));
    // Blocks mined before the connection arrive through header sync.
    for _ in 0..3 {
        mine(&a, payout).await;
    }
    connected(&a, &b).await;
    assert!(eventually(|| same_tip(vec![a.clone(), b.clone()])).await);
    assert_eq!(b.tip().await.unwrap().height, 3);
    // A new block is announced and relayed.
    mine(&a, payout).await;
    assert!(eventually(|| same_tip(vec![a.clone(), b.clone()])).await);
    assert_eq!(b.tip().await.unwrap().height, 4);
    a.shutdown().await;
    b.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn transactions_and_compact_blocks_cross_a_line_of_nodes() {
    let dirs: Vec<_> = (0..3).map(|_| tempfile::tempdir().unwrap()).collect();
    let a = node(&dirs[0]).await;
    let b = node(&dirs[1]).await;
    let c = node(&dirs[2]).await;
    b.connect(a.local_addr().unwrap()).await;
    c.connect(b.local_addr().unwrap()).await;
    assert!(eventually(|| async { b.call(|core| core.ready_peers()).await == Some(2) }).await);

    let key = KeyPair::generate().unwrap();
    let owner = key.public_key.wallet_id();
    let first = mine(&a, owner).await;
    mine(&a, owner).await;
    assert!(eventually(|| same_tip(vec![a.clone(), b.clone(), c.clone()])).await);

    // A transaction submitted at C reaches A through B.
    let chain_id = ConsensusParams::regtest().chain_id();
    let transaction = spend_coinbase(&key, &first, chain_id, WalletId::new(Hash256::new([7; 32])));
    let txid = transaction.txid();
    c.submit_transaction(transaction).await.unwrap();
    assert!(
        eventually(|| async {
            a.call(move |core| core.mempool.contains(&txid)).await == Some(true)
        })
        .await,
        "transaction did not reach A"
    );

    // A mines it; B and C reconstruct the block and clear their mempools.
    let block = mine(&a, owner).await;
    assert_eq!(block.transactions().len(), 2);
    assert!(eventually(|| same_tip(vec![a.clone(), b.clone(), c.clone()])).await);
    assert!(
        eventually(|| async {
            c.call(|core| core.mempool.len()).await == Some(0)
                && b.call(|core| core.mempool.len()).await == Some(0)
        })
        .await
    );
    // The block reached B and C as a compact block rebuilt from their own
    // mempools, without asking for any transaction.
    for node in [&b, &c] {
        let stats = node.call(|core| core.stats()).await.unwrap();
        assert!(stats.compact_complete >= 1, "{stats:?}");
        assert_eq!(stats.compact_fallback, 0, "{stats:?}");
    }
    for node in [&a, &b, &c] {
        node.shutdown().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn partitioned_nodes_converge_on_the_heavier_chain() {
    let (dir_a, dir_b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (a, b) = (node(&dir_a).await, node(&dir_b).await);
    connected(&a, &b).await;
    mine(&a, WalletId::new(Hash256::new([1; 32]))).await;
    assert!(eventually(|| same_tip(vec![a.clone(), b.clone()])).await);

    a.disconnect_all().await;
    b.disconnect_all().await;
    assert!(eventually(|| async { a.call(|core| core.ready_peers()).await == Some(0) }).await);
    for _ in 0..2 {
        mine(&a, WalletId::new(Hash256::new([2; 32]))).await;
    }
    for _ in 0..3 {
        mine(&b, WalletId::new(Hash256::new([3; 32]))).await;
    }
    let heavier = b.tip().await;
    assert_ne!(a.tip().await, heavier);

    b.connect(a.local_addr().unwrap()).await;
    assert!(eventually(|| async { a.tip().await == heavier }).await);
    assert_eq!(a.tip().await.unwrap().height, 4);
    let totals = (
        a.call(|core| core.chain.utxo_stats().total_value).await,
        b.call(|core| core.chain.utxo_stats().total_value).await,
    );
    assert_eq!(totals.0, totals.1);
    a.shutdown().await;
    b.shutdown().await;
}

// ------------------------------------------------------------ adversarial

type RawReader = FrameReader<ReadHalf<TcpStream>>;
type RawWriter = FrameWriter<WriteHalf<TcpStream>>;

fn magic() -> [u8; 4] {
    ConsensusParams::regtest().chain_id().as_bytes()[..4]
        .try_into()
        .unwrap()
}

async fn raw_session(addr: SocketAddr) -> (RawReader, RawWriter) {
    let stream = TcpStream::connect(addr).await.unwrap();
    transport::handshake(stream, true, magic()).await.unwrap()
}

async fn raw_version_handshake(reader: &mut RawReader, writer: &mut RawWriter) {
    writer
        .send(&Message::Version(Version {
            protocol: PROTOCOL_VERSION,
            services: SERVICE_NETWORK,
            height: 0,
            timestamp: unix_now(),
            nonce: OsRng.next_u64(),
            relay: true,
            user_agent: "/raw-test/".into(),
        }))
        .await
        .unwrap();
    let (mut version, mut verack) = (false, false);
    while !(version && verack) {
        match tokio::time::timeout(WAIT, reader.receive())
            .await
            .unwrap()
            .unwrap()
        {
            Message::Version(_) => version = true,
            Message::Verack => verack = true,
            _ => {}
        }
    }
    writer.send(&Message::Verack).await.unwrap();
}

/// Reads until the node closes the connection.
async fn closed(reader: &mut RawReader) -> bool {
    tokio::time::timeout(WAIT, async {
        loop {
            if reader.receive().await.is_err() {
                return true;
            }
        }
    })
    .await
    .unwrap_or(false)
}

async fn discouraged(node: &NodeHandle) -> bool {
    let localhost: IpAddr = "127.0.0.1".parse().unwrap();
    eventually(|| async {
        node.call(move |core| core.is_discouraged(&localhost)).await == Some(true)
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_oversized_message_disconnects_and_discourages() {
    let dir = tempfile::tempdir().unwrap();
    let a = node(&dir).await;
    let (mut reader, mut writer) = raw_session(a.local_addr().unwrap()).await;
    raw_version_handshake(&mut reader, &mut writer).await;
    writer.send_raw(Command::Ping as u8, &[0; 9]).await.unwrap();
    assert!(closed(&mut reader).await);
    assert!(discouraged(&a).await);
    a.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_message_before_version_disconnects() {
    let dir = tempfile::tempdir().unwrap();
    let a = node(&dir).await;
    let (mut reader, mut writer) = raw_session(a.local_addr().unwrap()).await;
    writer.send(&Message::Ping(1)).await.unwrap();
    assert!(closed(&mut reader).await);
    assert!(discouraged(&a).await);
    a.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_silent_connection_is_dropped_after_the_handshake_timeout() {
    let dir = tempfile::tempdir().unwrap();
    let a = node(&dir).await;
    let mut stream = TcpStream::connect(a.local_addr().unwrap()).await.unwrap();
    let mut buffer = [0_u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(10), stream.read(&mut buffer)).await;
    // The node closes the socket (read returns 0 bytes or an error) instead
    // of waiting forever.
    assert!(matches!(read, Ok(Ok(0)) | Ok(Err(_))), "{read:?}");
    // Slowness alone is not punished.
    let localhost: IpAddr = "127.0.0.1".parse().unwrap();
    assert_eq!(
        a.call(move |core| core.is_discouraged(&localhost)).await,
        Some(false)
    );
    a.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn address_floods_are_rate_limited() {
    let dir = tempfile::tempdir().unwrap();
    let a = node(&dir).await;
    let (mut reader, mut writer) = raw_session(a.local_addr().unwrap()).await;
    raw_version_handshake(&mut reader, &mut writer).await;
    let now = unix_now();
    for round in 0..5_u8 {
        let entries = (0..MAX_ADDR as u32)
            .map(|index| {
                let [_, b, c, d] = index.to_be_bytes();
                AddrEntry {
                    time: now,
                    services: SERVICE_NETWORK,
                    address: NetAddress::Ip(SocketAddr::new(
                        IpAddr::from([11 + round, b, c, d]),
                        7210,
                    )),
                }
            })
            .collect();
        writer.send(&Message::Addr(entries)).await.unwrap();
    }
    // Let the node process everything, then count.
    writer.send(&Message::Ping(9)).await.unwrap();
    loop {
        if let Message::Pong(9) = tokio::time::timeout(WAIT, reader.receive())
            .await
            .unwrap()
            .unwrap()
        {
            break;
        }
    }
    let known = a.call(|core| core.addrman.len()).await.unwrap();
    assert!(known <= MAX_ADDR + 5, "{known}");
    assert!(known > 0);
    a.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_invalid_block_disconnects_and_discourages() {
    let dir = tempfile::tempdir().unwrap();
    let a = node(&dir).await;
    let (mut reader, mut writer) = raw_session(a.local_addr().unwrap()).await;
    raw_version_handshake(&mut reader, &mut writer).await;

    // A block whose coinbase claims one satoshi more than the subsidy.
    let honest = a
        .call(|core| {
            itacoin_miner::build_block(
                &core.chain,
                &core.mempool,
                WalletId::new(Hash256::new([1; 32])),
                unix_now(),
            )
            .unwrap()
        })
        .await
        .unwrap();
    let coinbase = honest.transactions()[0].clone();
    let greedy = Transaction::Coinbase(
        CoinbaseTransaction::new(
            1,
            vec![Output {
                amount: Amount::from_satoshis(coinbase.outputs()[0].amount.as_satoshis() + 1)
                    .unwrap(),
                wallet_id: coinbase.outputs()[0].wallet_id,
            }],
        )
        .unwrap(),
    );
    let transactions = vec![greedy];
    let (tx_root, witness_root) = Block::roots(&transactions).unwrap();
    let block = Block::new(
        itacoin_blockchain::BlockHeader {
            tx_root,
            witness_root,
            ..*honest.header()
        },
        transactions,
    )
    .unwrap();
    writer.send(&Message::Block(block)).await.unwrap();
    assert!(closed(&mut reader).await);
    assert!(discouraged(&a).await);
    assert_eq!(a.tip().await.unwrap().height, 0);
    a.shutdown().await;
}
