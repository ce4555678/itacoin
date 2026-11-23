use itacoin_crypto::{KeyPair, SigningDomain};
use itacoin_primitives::{Amount, COIN, TransactionId, WalletId};
use itacoin_transaction::{
    CoinbaseTransaction, Input, OutPoint, Output, UnsignedTransaction, Witness,
};

use super::*;

fn wallet(byte: u8) -> WalletId {
    WalletId::new(Hash256::new([byte; 32]))
}

fn coinbase(height: u64) -> Transaction {
    Transaction::Coinbase(
        CoinbaseTransaction::new(
            height,
            vec![Output {
                amount: Amount::from_satoshis(50 * COIN).unwrap(),
                wallet_id: wallet(0x11),
            }],
        )
        .unwrap(),
    )
}

fn spend(key: &KeyPair, source: u8) -> Transaction {
    let unsigned = UnsignedTransaction::new(
        vec![Input {
            previous_output: OutPoint {
                txid: TransactionId::new(Hash256::new([source; 32])),
                index: 0,
            },
            witness_index: 0,
        }],
        vec![Output {
            amount: Amount::from_satoshis(1).unwrap(),
            wallet_id: wallet(2),
        }],
    )
    .unwrap();
    // Block rules do not verify signatures; any valid encoding will do.
    let signature = key
        .private_key
        .sign(SigningDomain::Transaction, b"placeholder")
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

fn header_for(transactions: &[Transaction]) -> BlockHeader {
    let (tx_root, witness_root) = Block::roots(transactions).unwrap();
    BlockHeader {
        prev_block: BlockId::new(Hash256::new([0; 32])),
        tx_root,
        witness_root,
        timestamp: 1_800_000_000,
        target: Hash256::new([0xff; 32]),
        nonce: 9,
    }
}

fn block(transactions: Vec<Transaction>) -> Result<Block, BlockError> {
    Block::new(header_for(&transactions), transactions)
}

#[test]
fn header_is_146_bytes_and_round_trips() {
    let header = header_for(&[coinbase(0)]);
    let bytes = header.to_bytes();
    assert_eq!(bytes.len(), 146);
    assert_eq!(decode_exact::<BlockHeader>(&bytes, 146), Ok(header));

    let mut version_two = bytes.clone();
    version_two[1] = 2;
    assert_eq!(
        decode_exact::<BlockHeader>(&version_two, 146),
        Err(BlockError::UnsupportedVersion(2))
    );
}

#[test]
fn block_round_trips_and_is_canonical() {
    let key = KeyPair::generate().unwrap();
    let block = block(vec![coinbase(3), spend(&key, 1), spend(&key, 2)]).unwrap();
    let bytes = block.to_bytes();
    assert_eq!(bytes.len(), block.encoded_len());
    let decoded = Block::from_bytes(&bytes).unwrap();
    assert_eq!(decoded, block);
    assert_eq!(decoded.to_bytes(), bytes);
    assert_eq!(decoded.height(), 3);
    assert_eq!(decoded.id(), block.header().id());

    let mut trailing = bytes.clone();
    trailing.push(0);
    assert_eq!(
        Block::from_bytes(&trailing),
        Err(BlockError::Codec(CodecError::TrailingBytes { count: 1 }))
    );
    for length in [0, 1, HEADER_BYTES, HEADER_BYTES + 4, bytes.len() - 1] {
        assert!(Block::from_bytes(&bytes[..length]).is_err(), "{length}");
    }
}

#[test]
fn coinbase_placement_is_enforced() {
    let key = KeyPair::generate().unwrap();
    assert_eq!(block(vec![]), Err(BlockError::NoTransactions));
    assert_eq!(
        block(vec![spend(&key, 1)]),
        Err(BlockError::MissingCoinbase)
    );
    assert_eq!(
        block(vec![coinbase(1), coinbase(2)]),
        Err(BlockError::ExtraCoinbase { transaction: 1 })
    );
}

#[test]
fn double_spend_across_transactions_is_refused() {
    let key = KeyPair::generate().unwrap();
    assert_eq!(
        block(vec![coinbase(1), spend(&key, 1), spend(&key, 1)]),
        Err(BlockError::DuplicateSpend { transaction: 2 })
    );
}

#[test]
fn roots_must_match_the_transactions() {
    let key = KeyPair::generate().unwrap();
    let transactions = vec![coinbase(1), spend(&key, 1)];
    let header = header_for(&transactions);

    let mut wrong_tx_root = header;
    wrong_tx_root.tx_root = Hash256::new([1; 32]);
    assert_eq!(
        Block::new(wrong_tx_root, transactions.clone()),
        Err(BlockError::TxRootMismatch)
    );

    // Re-signing leaves the txid, and so the tx root, unchanged; only the
    // witness root detects swapped witnesses.
    let resigned = vec![coinbase(1), spend(&key, 1)];
    assert_eq!(
        Block::roots(&resigned).unwrap().0,
        Block::roots(&transactions).unwrap().0
    );
    assert_eq!(
        Block::new(header, resigned),
        Err(BlockError::WitnessRootMismatch)
    );
}

#[test]
fn signature_verifications_are_limited() {
    let key = KeyPair::generate().unwrap();
    let mut transactions = vec![coinbase(1)];
    transactions.extend((0..=MAX_BLOCK_SIG_VERIFICATIONS).map(|index| {
        let mut tx = spend(&key, 0);
        if let Transaction::Normal(normal) = &tx {
            let unsigned = UnsignedTransaction::new(
                vec![Input {
                    previous_output: OutPoint {
                        txid: TransactionId::new(Hash256::new([0; 32])),
                        index: u16::try_from(index).unwrap(),
                    },
                    witness_index: 0,
                }],
                normal.unsigned().outputs().to_vec(),
            )
            .unwrap();
            tx = Transaction::Normal(
                unsigned
                    .with_witnesses(normal.witnesses().to_vec())
                    .unwrap(),
            );
        }
        tx
    }));
    assert_eq!(
        block(transactions),
        Err(BlockError::TooManySignatures(
            MAX_BLOCK_SIG_VERIFICATIONS + 1
        ))
    );
}

#[test]
fn oversized_input_is_refused_before_parsing() {
    assert!(matches!(
        Block::from_bytes(&vec![0; MAX_BLOCK_BYTES + 1]),
        Err(BlockError::Codec(CodecError::TooLarge { .. }))
    ));
}

#[test]
fn golden_block_id() {
    // A change here is a consensus change.
    let header = header_for(&[coinbase(1)]);
    assert_eq!(
        header.tx_root.to_string(),
        "e216457fc71faa46f79e42568342adfa58158f31c85274c15aba1069a1efd888"
    );
    assert_eq!(
        header.id().to_string(),
        "b653a5fd2b280694d2ab2729c6f4d6c65d6a43460a65eb9ea0f13dbe2afa4002"
    );
}
