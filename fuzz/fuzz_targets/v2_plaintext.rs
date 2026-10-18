#![no_main]
//! Raw bytes into the decoder of the authenticated plaintext, with the key derivation and the AEAD out of the way.
//! The other target mutates whole files, and every mutation of one fails the tag long before the plaintext decoder
//! runs; this one is what exercises it. Whatever it accepts must be exactly what the encoder writes back.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    cloakenv::vault::v2::fuzz_plaintext(data);
});
