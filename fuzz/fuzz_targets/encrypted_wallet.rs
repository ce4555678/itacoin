//! `EncryptedWallet::from_bytes` must never panic, and the format is
//! canonical: accepted bytes re-encode to exactly the same bytes.
//!
//! Decryption is not fuzzed: Argon2id at the accepted parameters is far too
//! slow per iteration, and authentication rejects any altered ciphertext.
#![no_main]

use itacoin_wallet::EncryptedWallet;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(wallet) = EncryptedWallet::from_bytes(data) {
        assert_eq!(wallet.to_bytes(), data);
    }
});
