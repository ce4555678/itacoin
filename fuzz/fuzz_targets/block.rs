//! Block decoding must never panic, and accepted bytes re-encode exactly.
#![no_main]

use itacoin_blockchain::Block;
use itacoin_codec::Encode;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(block) = Block::from_bytes(data) {
        assert_eq!(block.to_bytes(), data);
        let _ = block.id();
    }
});
