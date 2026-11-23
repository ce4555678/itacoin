//! Backup decoding never panics, and an accepted backup has one encoding.
#![no_main]

use itacoin_wallet::backup;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = core::str::from_utf8(data) else {
        return;
    };
    if let Ok(master) = backup::decode(text) {
        assert_eq!(backup::encode(&master).as_str(), text.trim().to_ascii_lowercase());
    }
});
