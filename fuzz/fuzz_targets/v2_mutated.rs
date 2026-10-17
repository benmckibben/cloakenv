#![no_main]
//! Structure-aware: start from a valid file and let the input choose which bytes to overwrite, so the fuzzer
//! spends its time on the header and ciphertext rather than rediscovering the magic. Runs the full `open` (the KDF
//! included) whenever the header survives, with the KDF cost capped so one input stays fast.

use std::sync::OnceLock;

use cloakenv::crypto::KdfParams;
use cloakenv::vault::v2::{self, Extension, Header};
use cloakenv::vault::Vault;
use libfuzzer_sys::fuzz_target;
use zeroize::Zeroizing;

const PASS: &[u8] = b"fuzz passphrase";

fn base() -> &'static Vec<u8> {
    static BASE: OnceLock<Vec<u8>> = OnceLock::new();
    BASE.get_or_init(|| {
        let mut vault = Vault::with_params(KdfParams::MIN).unwrap();
        vault.set("ALPHA", Zeroizing::new("one".to_owned())).unwrap();
        vault.set("BETA", Zeroizing::new("two".to_owned())).unwrap();
        let ext = [Extension { kind: 3, value: vec![1, 2, 3] }];
        v2::seal(&vault, &[7; 16], 5, &ext, PASS).unwrap()
    })
}

fuzz_target!(|data: &[u8]| {
    let mut file = base().clone();
    // each 3 input bytes: a two-byte offset (modulo the file length) and the byte to write there
    for chunk in data.chunks_exact(3) {
        let at = usize::from(u16::from_le_bytes([chunk[0], chunk[1]])) % file.len();
        file[at] = chunk[2];
    }
    if let Ok((h, n)) = Header::parse(&file) {
        assert_eq!(h.encode().unwrap(), &file[..n]);
        if h.params.m_cost_kib > 32 * 1024 || h.params.t_cost > 3 {
            return;
        }
    }
    if let Ok(opened) = v2::open(&file, PASS) {
        // an accepted file must reseal and open to the same contents
        let again = v2::seal(&opened.vault, &opened.vault_id, opened.generation, &opened.extensions, PASS).unwrap();
        let second = v2::open(&again, PASS).unwrap();
        assert_eq!(second.generation, opened.generation);
        assert_eq!(second.vault.len(), opened.vault.len());
    }
});
