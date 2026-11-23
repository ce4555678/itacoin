//! RPC request parsing and the strict text decoders must never panic, and
//! every accepted text value has a single encoding.
#![no_main]

use itacoin_rpc::{parse_request, text};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = parse_request(data);
    if let Ok(input) = core::str::from_utf8(data) {
        if let Ok(bytes) = text::decode_base64url(input, 4096) {
            assert_eq!(text::encode_base64url(&bytes), input);
        }
        if let Ok(amount) = text::parse_sat(input) {
            assert_eq!(text::format_sat(amount), input);
        }
        if let Ok(hash) = text::decode_hash(input) {
            assert_eq!(hash.to_string(), input.to_ascii_lowercase());
        }
    }
});
