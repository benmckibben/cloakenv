#![no_main]
//! Text into the parser of the rollback-protection file. Whatever it accepts must serialise to something that
//! parses back to the same state, and serialising that again must give the same text.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        cloakenv::vault::state::fuzz_parse(text);
    }
});
