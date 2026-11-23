//! `Signature::from_bytes` must never panic, and accepted bytes round-trip.
#![no_main]

use itacoin_crypto::Signature;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(signature) = Signature::from_bytes(data) {
        assert_eq!(signature.as_bytes(), data);
    }
});
