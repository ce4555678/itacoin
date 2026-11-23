//! Address parsing must never panic. Bech32m is case-insensitive, so an
//! accepted address prints as the lowercase form of its input.
#![no_main]

use itacoin_primitives::Address;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(address) = input.parse::<Address>() {
        let printed = address.to_string();
        assert_eq!(printed, input.to_ascii_lowercase());
        assert_eq!(printed.parse::<Address>().unwrap(), address);
    }
});
