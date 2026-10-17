#![no_main]
//! Raw bytes into the version 2 header parser. It must never panic, and whatever it accepts must encode back to
//! exactly the same bytes (no two files decode to one header).

use cloakenv::vault::v2::Header;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok((header, len)) = Header::parse(data) {
        assert_eq!(header.encode().expect("a parsed header encodes"), &data[..len]);
    }
});
