//! `PublicKey::from_bytes` must never panic, and accepted bytes round-trip.
#![no_main]

use itacoin_crypto::PublicKey;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(key) = PublicKey::from_bytes(data) {
        assert_eq!(key.as_bytes(), data);
        let _ = key.wallet_id();
    }
});
