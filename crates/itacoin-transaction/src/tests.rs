use itacoin_crypto::KeyPair;
use itacoin_primitives::{COIN, MAX_SUPPLY};

use super::*;

const CHAIN: Hash256 = Hash256::new([7; 32]);

fn sats(value: u64) -> Amount {
    Amount::from_satoshis(value).unwrap()
}

fn txid(byte: u8) -> TransactionId {
    TransactionId::new(Hash256::new([byte; 32]))
}

fn input(byte: u8, index: u16, witness_index: u16) -> Input {
    Input {
        previous_output: OutPoint {
            txid: txid(byte),
            index,
        },
        witness_index,
    }
}

fn pay(value: u64, wallet_id: WalletId) -> Output {
    Output {
        amount: sats(value),
        wallet_id,
    }
}

fn wallet(byte: u8) -> WalletId {
    WalletId::new(Hash256::new([byte; 32]))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn sign(unsigned: UnsignedTransaction, keys: &[&KeyPair], spent: &[Output]) -> NormalTransaction {
    let message = unsigned.sighash(&CHAIN, spent).unwrap();
    let witnesses = keys
        .iter()
        .map(|key| Witness {
            public_key: key.public_key.clone(),
            signature: key
                .private_key
                .sign(SigningDomain::Transaction, message.as_bytes())
                .unwrap(),
        })
        .collect();
    unsigned.with_witnesses(witnesses).unwrap()
}

/// One key spending two of its outputs, paying two recipients.
fn spend_two(key: &KeyPair) -> (NormalTransaction, Vec<Output>) {
    let owner = key.public_key.wallet_id();
    let spent = vec![pay(70, owner), pay(50, owner)];
    let unsigned = UnsignedTransaction::new(
        vec![input(1, 0, 0), input(2, 3, 0)],
        vec![pay(100, wallet(9)), pay(15, owner)],
    )
    .unwrap();
    (sign(unsigned, &[key], &spent), spent)
}

#[test]
fn sizes_match_the_proposal() {
    let key = KeyPair::generate().unwrap();
    let one_in_two_out = sign(
        UnsignedTransaction::new(
            vec![input(1, 0, 0)],
            vec![pay(1, wallet(1)), pay(2, wallet(2))],
        )
        .unwrap(),
        &[&key],
        &[pay(3, key.public_key.wallet_id())],
    );
    assert_eq!(one_in_two_out.to_bytes().len(), 5386);

    let inputs = (0..10).map(|byte| input(byte, 0, 0)).collect();
    let spent = vec![pay(1, key.public_key.wallet_id()); 10];
    let consolidation = sign(
        UnsignedTransaction::new(inputs, vec![pay(10, wallet(1))]).unwrap(),
        &[&key],
        &spent,
    );
    assert_eq!(consolidation.to_bytes().len(), 5669);

    let coinbase = CoinbaseTransaction::new(0, vec![pay(1, wallet(1))]).unwrap();
    assert_eq!(coinbase.to_bytes().len(), 54);
    assert_eq!(MIN_TX_BYTES, 54);
}

#[test]
fn encoding_round_trips_and_is_canonical() {
    let key = KeyPair::generate().unwrap();
    let (normal, _) = spend_two(&key);
    let coinbase = CoinbaseTransaction::new(42, vec![pay(5 * COIN, wallet(3))]).unwrap();
    for transaction in [Transaction::Normal(normal), Transaction::Coinbase(coinbase)] {
        let bytes = transaction.to_bytes();
        assert_eq!(bytes.len(), transaction.encoded_len());
        let decoded = Transaction::from_bytes(&bytes).unwrap();
        assert_eq!(decoded, transaction);
        assert_eq!(decoded.to_bytes(), bytes);
        assert_eq!(decoded.txid(), transaction.txid());
    }
}

#[test]
fn txid_excludes_witnesses() {
    // Regression for requirement 1.2: re-signing (hedged) changes the bytes
    // and the witness hash, never the txid.
    let key = KeyPair::generate().unwrap();
    let (first, spent) = spend_two(&key);
    let second = sign(first.unsigned().clone(), &[&key], &spent);
    let (first, second) = (Transaction::Normal(first), Transaction::Normal(second));
    assert_ne!(first.to_bytes(), second.to_bytes());
    assert_ne!(first.witness_hash(), second.witness_hash());
    assert_eq!(first.txid(), second.txid());
}

#[test]
fn witness_indices_must_be_canonical() {
    let outputs = || vec![pay(1, wallet(1))];
    let witnesses = |indices: &[u16]| {
        let inputs = indices
            .iter()
            .enumerate()
            .map(|(byte, &witness)| input(u8::try_from(byte).unwrap(), 0, witness))
            .collect();
        UnsignedTransaction::new(inputs, outputs()).map(|tx| tx.witness_count())
    };
    assert_eq!(witnesses(&[0]), Ok(1));
    assert_eq!(witnesses(&[0, 0, 1]), Ok(2));
    assert_eq!(witnesses(&[0, 1, 0, 2, 1]), Ok(3));
    assert_eq!(
        witnesses(&[1]),
        Err(TransactionError::WitnessOrder { input: 0 })
    );
    assert_eq!(
        witnesses(&[0, 2]),
        Err(TransactionError::WitnessOrder { input: 1 })
    );
}

#[test]
fn stateless_rules_are_enforced_on_construction() {
    let out = || vec![pay(1, wallet(1))];
    assert_eq!(
        UnsignedTransaction::new(vec![], out()),
        Err(TransactionError::InputCount(0))
    );
    assert_eq!(
        UnsignedTransaction::new(vec![input(1, 0, 0)], vec![]),
        Err(TransactionError::OutputCount(0))
    );
    assert_eq!(
        UnsignedTransaction::new(vec![input(1, 0, 0), input(1, 0, 0)], out()),
        Err(TransactionError::DuplicateOutPoint(OutPoint {
            txid: txid(1),
            index: 0
        }))
    );
    assert_eq!(
        UnsignedTransaction::new(vec![input(1, 0, 0)], vec![pay(0, wallet(1))]),
        Err(TransactionError::ZeroOutput { output: 0 })
    );
    assert!(matches!(
        CoinbaseTransaction::new(0, vec![pay(MAX_SUPPLY, wallet(1)), pay(1, wallet(2))]),
        Err(TransactionError::Amount(_))
    ));
    let unsigned = UnsignedTransaction::new(vec![input(1, 0, 0)], out()).unwrap();
    assert_eq!(
        unsigned.with_witnesses(vec![]),
        Err(TransactionError::WitnessCount {
            expected: 1,
            actual: 0
        })
    );
}

#[test]
fn oversized_transactions_are_refused() {
    let key = KeyPair::generate().unwrap();
    let witness = spend_two(&key).0.witnesses()[0].clone();
    // 19 witnesses exceed MAX_TX_BYTES (19 × 5261 > 100 000).
    let inputs = (0..19).map(|index| input(1, index, index)).collect();
    let unsigned = UnsignedTransaction::new(inputs, vec![pay(1, wallet(1))]).unwrap();
    assert!(matches!(
        unsigned.with_witnesses(vec![witness; 19]),
        Err(TransactionError::Codec(CodecError::TooLarge { .. }))
    ));
    assert!(matches!(
        Transaction::from_bytes(&vec![0; MAX_TX_BYTES + 1]),
        Err(TransactionError::Codec(CodecError::TooLarge { .. }))
    ));
}

#[test]
fn validate_spend_returns_the_fee() {
    let key = KeyPair::generate().unwrap();
    let (transaction, spent) = spend_two(&key);
    assert_eq!(transaction.validate_spend(&CHAIN, &spent), Ok(sats(5)));
}

#[test]
fn validate_spend_rejects_each_failure() {
    let key = KeyPair::generate().unwrap();
    let other = KeyPair::generate().unwrap();
    let (transaction, spent) = spend_two(&key);

    assert_eq!(
        transaction.validate_spend(&CHAIN, &spent[..1]),
        Err(TransactionError::SpentOutputCount {
            expected: 2,
            actual: 1
        })
    );

    let mut not_owned = spent.clone();
    not_owned[1].wallet_id = other.public_key.wallet_id();
    assert_eq!(
        transaction.validate_spend(&CHAIN, &not_owned),
        Err(TransactionError::WrongKey { input: 1 })
    );

    let mut too_little = spent.clone();
    too_little[0].amount = sats(10);
    assert_eq!(
        transaction.validate_spend(&CHAIN, &too_little),
        Err(TransactionError::InsufficientInputs)
    );

    // The signature commits to the spent values: a signer told a different
    // amount produced a signature that does not verify for the real one.
    let mut lied = spent.clone();
    lied[0].amount = sats(1_000);
    assert!(matches!(
        transaction.validate_spend(&CHAIN, &lied),
        Err(TransactionError::InvalidSignature { witness: 0, .. })
    ));

    // Replay on another chain fails.
    assert!(matches!(
        transaction.validate_spend(&Hash256::new([8; 32]), &spent),
        Err(TransactionError::InvalidSignature { witness: 0, .. })
    ));

    // A wrong signature from the right key fails.
    let mut forged = transaction.clone();
    forged.witnesses[0].signature = other
        .private_key
        .sign(SigningDomain::Transaction, b"other")
        .unwrap();
    assert!(matches!(
        forged.validate_spend(&CHAIN, &spent),
        Err(TransactionError::InvalidSignature { witness: 0, .. })
    ));
}

#[test]
fn validate_spend_rejects_repeated_witness_keys() {
    let key = KeyPair::generate().unwrap();
    let owner = key.public_key.wallet_id();
    let spent = vec![pay(5, owner), pay(5, owner)];
    let unsigned = UnsignedTransaction::new(
        vec![input(1, 0, 0), input(2, 0, 1)],
        vec![pay(10, wallet(1))],
    )
    .unwrap();
    let transaction = sign(unsigned, &[&key, &key], &spent);
    assert_eq!(
        transaction.validate_spend(&CHAIN, &spent),
        Err(TransactionError::DuplicateWitness { witness: 1 })
    );
}

#[test]
fn decoder_rejects_non_canonical_bytes() {
    let coinbase =
        Transaction::Coinbase(CoinbaseTransaction::new(1, vec![pay(1, wallet(1))]).unwrap());
    let bytes = coinbase.to_bytes();
    let mutate = |offset: usize, value: u8| {
        let mut changed = bytes.clone();
        changed[offset] = value;
        Transaction::from_bytes(&changed)
    };
    assert_eq!(mutate(1, 2), Err(TransactionError::UnsupportedVersion(2)));
    assert_eq!(mutate(2, 2), Err(TransactionError::UnknownKind(2)));
    // Output kind sits after version, kind, height and the output count.
    assert_eq!(mutate(13, 1), Err(TransactionError::UnknownOutputKind(1)));
    // Last byte of the amount: 1 → 0.
    assert_eq!(
        mutate(21, 0),
        Err(TransactionError::ZeroOutput { output: 0 })
    );

    let mut trailing = bytes.clone();
    trailing.push(0);
    assert_eq!(
        Transaction::from_bytes(&trailing),
        Err(TransactionError::Codec(CodecError::TrailingBytes {
            count: 1
        }))
    );
    for length in 0..bytes.len() {
        assert!(
            Transaction::from_bytes(&bytes[..length]).is_err(),
            "{length}"
        );
    }

    // A normal transaction whose only input names witness 1.
    let unsigned = UnsignedTransaction::new(vec![input(1, 0, 0)], vec![pay(1, wallet(1))]).unwrap();
    let mut writer = Writer::default();
    unsigned.encode_body(&mut writer);
    let mut body = writer.into_bytes();
    body[PREFIX_BYTES + 2 + 35] = 1;
    assert_eq!(
        Transaction::from_bytes(&body),
        Err(TransactionError::WitnessOrder { input: 0 })
    );
}

/// Deterministic xorshift64 generator for randomized round trips.
struct Rng(u64);

impl Rng {
    fn below(&mut self, bound: u64) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0 % bound
    }
}

#[test]
fn randomized_transactions_round_trip() {
    let key = KeyPair::generate().unwrap();
    let witness = spend_two(&key).0.witnesses()[0].clone();
    let mut rng = Rng(0x1234_5678_9abc_def1);
    for _ in 0..300 {
        let input_count = 1 + rng.below(20) as usize;
        let mut witness_count = 0_u16;
        let inputs: Vec<Input> = (0..input_count)
            .map(|index| {
                // Reuse an existing witness or introduce the next one, at
                // most 10 so the transaction stays under the size limit.
                let witness_index = if witness_count < 10 && rng.below(2) == 0 {
                    witness_count += 1;
                    witness_count - 1
                } else if witness_count == 0 {
                    witness_count = 1;
                    0
                } else {
                    rng.below(u64::from(witness_count)) as u16
                };
                Input {
                    previous_output: OutPoint {
                        txid: txid(rng.below(256) as u8),
                        index: u16::try_from(index).unwrap(),
                    },
                    witness_index,
                }
            })
            .collect();
        let outputs = (0..1 + rng.below(20))
            .map(|_| pay(1 + rng.below(COIN), wallet(rng.below(256) as u8)))
            .collect();
        let unsigned = UnsignedTransaction::new(inputs, outputs).unwrap();
        let witnesses = vec![witness.clone(); unsigned.witness_count()];
        let transaction = Transaction::Normal(unsigned.with_witnesses(witnesses).unwrap());
        let bytes = transaction.to_bytes();
        assert_eq!(bytes.len(), transaction.encoded_len());
        assert_eq!(Transaction::from_bytes(&bytes).unwrap(), transaction);
    }
}

#[test]
fn golden_vectors() {
    // Fixed encodings and identifiers. A change here is a consensus change.
    let coinbase = Transaction::Coinbase(
        CoinbaseTransaction::new(1, vec![pay(50 * COIN, wallet(0x11))]).unwrap(),
    );
    assert_eq!(
        hex(&coinbase.to_bytes()),
        concat!(
            "0001",
            "01",
            "0000000000000001",
            "0001",
            "00",
            "000000012a05f200",
            "1111111111111111111111111111111111111111111111111111111111111111",
        )
    );
    assert_eq!(
        coinbase.txid().to_string(),
        "85292347a3ddca8087befd7acecba706799b1e43d617a7adc09fd3b8351e5cc0"
    );
    assert_eq!(
        coinbase.witness_hash().to_string(),
        "f1125199ea907c7a93768d94b9c1111597287b4af9b49870693fe0593415a7e0"
    );

    let unsigned = UnsignedTransaction::new(
        vec![input(0xaa, 1, 0), input(0xbb, 2, 0)],
        vec![pay(7, wallet(0x22))],
    )
    .unwrap();
    assert_eq!(
        unsigned.txid().to_string(),
        "fa44573719c98a0b66c9250e20f4be7b5352da8784418dff808e5cc51ef4df09"
    );
    let spent = [pay(4, wallet(0x33)), pay(5, wallet(0x33))];
    assert_eq!(
        unsigned.sighash(&CHAIN, &spent).unwrap().to_string(),
        "b1d51da101c43a4b838ce713c4718585e2d0d0ce80d8a2a16e32e581c783a357"
    );
}
