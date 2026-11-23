//! Decimal ITC parsing must never panic, and every accepted amount prints in a
//! form that parses back to the same value.
#![no_main]

use itacoin_primitives::{Amount, MAX_SUPPLY};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(amount) = input.parse::<Amount>() {
        assert!(amount.as_satoshis() <= MAX_SUPPLY);
        assert_eq!(amount.to_string().parse::<Amount>().unwrap(), amount);
    }
});
