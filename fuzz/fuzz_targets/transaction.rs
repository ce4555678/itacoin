//! Transaction decoding must never panic, and the format is canonical:
//! accepted bytes re-encode to exactly the same bytes.
#![no_main]

use itacoin_codec::Encode;
use itacoin_transaction::Transaction;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(transaction) = Transaction::from_bytes(data) {
        assert_eq!(transaction.to_bytes(), data);
        let _ = transaction.txid();
        let _ = transaction.witness_hash();
    }
});
