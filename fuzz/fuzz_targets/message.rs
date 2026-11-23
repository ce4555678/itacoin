//! Network message decoding must never panic, for any command, and accepted
//! payloads re-encode to exactly the same bytes.
#![no_main]

use itacoin_network::message::{Command, Message};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&command, payload)) = data.split_first() else {
        return;
    };
    let Ok(command) = Command::from_u8(command) else {
        return;
    };
    if let Ok(message) = Message::decode(command, payload) {
        assert_eq!(message.command(), command);
        assert_eq!(message.encode_payload(), payload);
    }
});
