//! Vault file format, version 2: the codec.
//!
//! Design and reasons: `docs/design/vault-format-v2.md`. This module only turns a [`Vault`] and its metadata into
//! bytes and back. Nothing in the CLI uses it yet; the commands, the rollback state file and the migration come in
//! later changes. Version 1 (the parent module) is untouched.
//!
//! # Layout (all integers little-endian)
//!
//! | offset | size | field |
//! |-------:|-----:|-------|
//! |      0 |    8 | magic `CLOAKENV` |
//! |      8 |    1 | format version (`2`) |
//! |      9 |    1 | KDF id (`1` = Argon2id v1.3) |
//! |     10 |    1 | AEAD id (`1` = XChaCha20-Poly1305) |
//! |     11 |    1 | padding scheme (`1` = Padmé with a 4 KiB floor) |
//! |     12 |    4 | Argon2 memory cost (KiB) |
//! |     16 |    4 | Argon2 time cost |
//! |     20 |    4 | Argon2 parallelism |
//! |     24 |   16 | salt (fresh on every save) |
//! |     40 |   24 | nonce (fresh on every save) |
//! |     64 |   16 | vault id (random when the vault is created, never changes) |
//! |     80 |    8 | generation (starts at 1, +1 on every save) |
//! |     88 |    4 | flags, reserved, must be 0 |
//! |     92 |    4 | extension area length (at most 4096) |
//! |     96 |  ext | extension records: `u16 type, u16 length, value` |
//! | 96+ext |    n | ciphertext, then the 16-byte Poly1305 tag |
//!
//! The whole header, extensions included, is the AEAD's associated data. The plaintext is `u32 count`, the entries
//! (`u32 key_len, key, u32 value_len, value`, as in version 1), then zero bytes up to the padded length.
//!
//! # What is checked, and when
//!
//! Everything that can be checked from the (still unauthenticated) header alone is checked before the KDF runs, so
//! a hostile file cannot make us spend memory or time on a header that could never be valid. What the header
//! says (generation, vault id, extensions) is never *acted on* before the tag verifies; the caller gets it in
//! [`Opened`], after authentication. After decryption the entries are checked as in version 1 and the padding
//! must be exactly the canonical length and all zero, so one plaintext has exactly one valid file form.

use std::collections::BTreeMap;

use zeroize::Zeroizing;

use super::{MAGIC, MAX_VAULT_LEN, Vault, VaultError, check_entry};
use crate::crypto::{self, KdfParams, NONCE_LEN, SALT_LEN, TAG_LEN};

/// The format version this module reads and writes.
pub const FORMAT_VERSION: u8 = 2;
const KDF_ARGON2ID: u8 = 1;
const AEAD_XCHACHA20POLY1305: u8 = 1;
const PADDING_PADME: u8 = 1;
/// Header length without extensions.
pub const FIXED_HEADER_LEN: usize = 96;
/// Largest extension area, in bytes.
pub const MAX_EXTENSIONS_LEN: usize = 4096;
/// Smallest padded plaintext, in bytes.
pub const PAD_FLOOR: u64 = 4096;
/// Length of the vault id.
pub const VAULT_ID_LEN: usize = 16;
/// An extension type with this bit set is *critical*: a reader that does not know it must refuse the file.
pub const CRITICAL_EXTENSION: u16 = 0x8000;
/// Extension types this version understands. None are defined yet; the rule exists so that later versions can add
/// optional fields (top bit clear) without breaking readers of this one.
const KNOWN_EXTENSIONS: &[u16] = &[];

/// Padmé padding (Nikitin et al., "Reducing Metadata Leakage from Encrypted Files and Communication with PURBs",
/// PETS 2019): `len` rounded up to a multiple of `2^(E - S)`, where `E = floor(log2 len)` and
/// `S = floor(log2 E) + 1`. The overhead is below 12% and the length is only revealed up to one of about `2^S`
/// steps. Lengths below 2 are returned as they are. Meant for lengths up to the 16 MiB vault limit (it never
/// overflows below 2^62).
pub fn padme(len: u64) -> u64 {
    if len < 2 {
        return len;
    }
    let e = 63 - len.leading_zeros();
    let s = 63 - u64::from(e).leading_zeros() + 1;
    let mask = (1u64 << (e - s)) - 1;
    len.saturating_add(mask) & !mask
}

/// The padded plaintext length for an unpadded length: Padmé, but never below [`PAD_FLOOR`].
pub fn padded_len(unpadded: u64) -> u64 {
    padme(unpadded).max(PAD_FLOOR)
}

/// Length of the plaintext before padding: the count and every entry.
pub fn unpadded_len(vault: &Vault) -> u64 {
    4 + vault
        .entries
        .iter()
        .map(|(k, v)| 8 + k.len() as u64 + v.len() as u64)
        .sum::<u64>()
}

/// The exact size of the file that sealing `vault` with an extension area of `ext_len` bytes produces.
pub fn sealed_len(vault: &Vault, ext_len: usize) -> u64 {
    (FIXED_HEADER_LEN + ext_len) as u64 + padded_len(unpadded_len(vault)) + TAG_LEN as u64
}

/// One header extension record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extension {
    /// Record type. The top bit ([`CRITICAL_EXTENSION`]) marks a record a reader must understand.
    pub kind: u16,
    pub value: Vec<u8>,
}

/// The decoded header. Everything in it is unauthenticated until the tag has been verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub params: KdfParams,
    pub salt: [u8; SALT_LEN],
    pub nonce: [u8; NONCE_LEN],
    pub vault_id: [u8; VAULT_ID_LEN],
    pub generation: u64,
    pub extensions: Vec<Extension>,
}

/// A vault read from a version 2 file, with the authenticated metadata.
#[derive(Debug)]
pub struct Opened {
    pub vault: Vault,
    pub vault_id: [u8; VAULT_ID_LEN],
    pub generation: u64,
    /// Extensions as read (non-critical unknown ones included), so that a caller that saves the vault again can
    /// keep them.
    pub extensions: Vec<Extension>,
    /// The Poly1305 tag: it identifies this exact version of the file.
    pub tag: [u8; TAG_LEN],
}

fn encode_extensions(exts: &[Extension]) -> Result<Vec<u8>, VaultError> {
    let mut out = Vec::new();
    let mut seen: Vec<u16> = Vec::new();
    for e in exts {
        if seen.contains(&e.kind) || e.value.len() > usize::from(u16::MAX) {
            return Err(VaultError::Malformed);
        }
        seen.push(e.kind);
        out.extend_from_slice(&e.kind.to_le_bytes());
        out.extend_from_slice(&(e.value.len() as u16).to_le_bytes());
        out.extend_from_slice(&e.value);
        if out.len() > MAX_EXTENSIONS_LEN {
            return Err(VaultError::Malformed);
        }
    }
    Ok(out)
}

fn parse_extensions(area: &[u8]) -> Result<Vec<Extension>, VaultError> {
    let mut out: Vec<Extension> = Vec::new();
    let mut pos = 0usize;
    while pos < area.len() {
        if area.len() - pos < 4 {
            return Err(VaultError::Malformed);
        }
        let kind = u16::from_le_bytes([area[pos], area[pos + 1]]);
        let len = usize::from(u16::from_le_bytes([area[pos + 2], area[pos + 3]]));
        pos += 4;
        if area.len() - pos < len || out.iter().any(|e| e.kind == kind) {
            return Err(VaultError::Malformed);
        }
        if kind & CRITICAL_EXTENSION != 0 && !KNOWN_EXTENSIONS.contains(&kind) {
            return Err(VaultError::UnsupportedExtension(kind));
        }
        out.push(Extension {
            kind,
            value: area[pos..pos + len].to_vec(),
        });
        pos += len;
    }
    Ok(out)
}

impl Header {
    /// The header bytes (`FIXED_HEADER_LEN` plus the extension area). Fails on generation 0, duplicate
    /// extension types, or an extension area over [`MAX_EXTENSIONS_LEN`].
    pub fn encode(&self) -> Result<Vec<u8>, VaultError> {
        if self.generation == 0 {
            return Err(VaultError::Malformed);
        }
        let ext = encode_extensions(&self.extensions)?;
        let mut h = Vec::with_capacity(FIXED_HEADER_LEN + ext.len());
        h.extend_from_slice(MAGIC);
        h.extend_from_slice(&[
            FORMAT_VERSION,
            KDF_ARGON2ID,
            AEAD_XCHACHA20POLY1305,
            PADDING_PADME,
        ]);
        h.extend_from_slice(&self.params.m_cost_kib.to_le_bytes());
        h.extend_from_slice(&self.params.t_cost.to_le_bytes());
        h.extend_from_slice(&self.params.p_cost.to_le_bytes());
        h.extend_from_slice(&self.salt);
        h.extend_from_slice(&self.nonce);
        h.extend_from_slice(&self.vault_id);
        h.extend_from_slice(&self.generation.to_le_bytes());
        h.extend_from_slice(&0u32.to_le_bytes());
        h.extend_from_slice(&(ext.len() as u32).to_le_bytes());
        h.extend_from_slice(&ext);
        debug_assert_eq!(h.len(), FIXED_HEADER_LEN + ext.len());
        Ok(h)
    }

    /// Decodes and checks the header of a complete file, without touching the KDF or the ciphertext. Returns the
    /// header and its length in bytes. Errors are the ones documented in the module header.
    pub fn parse(bytes: &[u8]) -> Result<(Header, usize), VaultError> {
        if bytes.len() < MAGIC.len() || &bytes[..MAGIC.len()] != MAGIC {
            return Err(VaultError::BadMagic);
        }
        let Some(&version) = bytes.get(MAGIC.len()) else {
            return Err(VaultError::Malformed);
        };
        if version != FORMAT_VERSION {
            return Err(VaultError::UnsupportedVersion(version));
        }
        if bytes.len() < FIXED_HEADER_LEN + TAG_LEN {
            return Err(VaultError::Malformed);
        }
        let (kdf, aead) = (bytes[9], bytes[10]);
        if kdf != KDF_ARGON2ID || aead != AEAD_XCHACHA20POLY1305 {
            return Err(VaultError::UnsupportedAlgorithm { kdf, aead });
        }
        if bytes[11] != PADDING_PADME {
            return Err(VaultError::UnsupportedPadding(bytes[11]));
        }
        let u32_at =
            |i: usize| u32::from_le_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]]);
        let params = KdfParams {
            m_cost_kib: u32_at(12),
            t_cost: u32_at(16),
            p_cost: u32_at(20),
        }
        .validate_for_open()?;
        let generation = u64::from_le_bytes(bytes[80..88].try_into().expect("8 bytes"));
        if generation == 0 || u32_at(88) != 0 {
            return Err(VaultError::Malformed);
        }
        let ext_len = u32_at(92) as usize;
        if ext_len > MAX_EXTENSIONS_LEN {
            return Err(VaultError::Malformed);
        }
        let header_len = FIXED_HEADER_LEN + ext_len;
        // the ciphertext holds at least the padding floor and the tag
        if (bytes.len() as u64) < header_len as u64 + PAD_FLOOR + TAG_LEN as u64 {
            return Err(VaultError::Malformed);
        }
        let extensions = parse_extensions(&bytes[FIXED_HEADER_LEN..header_len])?;
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&bytes[24..40]);
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&bytes[40..64]);
        let mut vault_id = [0u8; VAULT_ID_LEN];
        vault_id.copy_from_slice(&bytes[64..80]);
        Ok((
            Header {
                params,
                salt,
                nonce,
                vault_id,
                generation,
                extensions,
            },
            header_len,
        ))
    }
}

/// The format version of a file (`1` or `2`, or whatever a later release wrote), after checking the magic.
pub fn format_version(bytes: &[u8]) -> Result<u8, VaultError> {
    if bytes.len() < MAGIC.len() || &bytes[..MAGIC.len()] != MAGIC {
        return Err(VaultError::BadMagic);
    }
    bytes.get(MAGIC.len()).copied().ok_or(VaultError::Malformed)
}

fn encode_plaintext(vault: &Vault) -> Zeroizing<Vec<u8>> {
    let total = padded_len(unpadded_len(vault)) as usize;
    let mut out = Zeroizing::new(Vec::with_capacity(total));
    out.extend_from_slice(&(vault.entries.len() as u32).to_le_bytes());
    for (k, v) in &vault.entries {
        out.extend_from_slice(&(k.len() as u32).to_le_bytes());
        out.extend_from_slice(k.as_bytes());
        out.extend_from_slice(&(v.len() as u32).to_le_bytes());
        out.extend_from_slice(v.as_bytes());
    }
    out.resize(total, 0);
    out
}

fn decode_plaintext(buf: &[u8], params: KdfParams) -> Result<Vault, VaultError> {
    fn take<'a>(buf: &'a [u8], pos: &mut usize, n: usize) -> Result<&'a [u8], VaultError> {
        let end = pos
            .checked_add(n)
            .filter(|end| *end <= buf.len())
            .ok_or(VaultError::Malformed)?;
        let s = &buf[*pos..end];
        *pos = end;
        Ok(s)
    }
    fn take_u32(buf: &[u8], pos: &mut usize) -> Result<usize, VaultError> {
        let b = take(buf, pos, 4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize)
    }
    let mut pos = 0usize;
    let count = take_u32(buf, &mut pos)?;
    let mut vault = Vault {
        entries: BTreeMap::new(),
        params,
    };
    for _ in 0..count {
        let klen = take_u32(buf, &mut pos)?;
        let key =
            std::str::from_utf8(take(buf, &mut pos, klen)?).map_err(|_| VaultError::Malformed)?;
        let vlen = take_u32(buf, &mut pos)?;
        let value =
            std::str::from_utf8(take(buf, &mut pos, vlen)?).map_err(|_| VaultError::Malformed)?;
        // valid name, no NUL, entry size cap: the same rules as `set`; the error is deliberately not echoed
        if check_entry(key, value).is_err() || vault.entries.contains_key(key) {
            return Err(VaultError::Malformed);
        }
        vault
            .entries
            .insert(key.to_owned(), Zeroizing::new(value.to_owned()));
    }
    if buf.len() as u64 != padded_len(pos as u64) || buf[pos..].iter().any(|b| *b != 0) {
        return Err(VaultError::Malformed);
    }
    Ok(vault)
}

/// Encrypts `vault` with the given salt and nonce. Deterministic; for known-answer tests. Use [`seal`] otherwise:
/// reusing a salt and nonce with the same passphrase is the one thing that must never happen.
pub fn seal_with(
    vault: &Vault,
    vault_id: &[u8; VAULT_ID_LEN],
    generation: u64,
    extensions: &[Extension],
    passphrase: &[u8],
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
) -> Result<Vec<u8>, VaultError> {
    let ext_len = encode_extensions(extensions)?.len();
    let size = sealed_len(vault, ext_len);
    if size > MAX_VAULT_LEN {
        return Err(VaultError::VaultFull { size });
    }
    // never write settings weaker than the current minimum, as in version 1
    let params = vault.params.at_least(KdfParams::MIN).validate()?;
    let header = Header {
        params,
        salt,
        nonce,
        vault_id: *vault_id,
        generation,
        extensions: extensions.to_vec(),
    }
    .encode()?;
    let key = crypto::derive_key(passphrase, &salt, params)?;
    let ciphertext = crypto::seal(&key, &nonce, &header, &encode_plaintext(vault))?;
    let mut out = header;
    out.extend_from_slice(&ciphertext);
    debug_assert_eq!(out.len() as u64, size);
    Ok(out)
}

/// Encrypts `vault` with a fresh random salt and nonce, returning the complete file contents.
pub fn seal(
    vault: &Vault,
    vault_id: &[u8; VAULT_ID_LEN],
    generation: u64,
    extensions: &[Extension],
    passphrase: &[u8],
) -> Result<Vec<u8>, VaultError> {
    let salt = crypto::random_bytes()?;
    let nonce = crypto::random_bytes()?;
    seal_with(
        vault, vault_id, generation, extensions, passphrase, salt, nonce,
    )
}

/// Authenticates and decrypts the complete contents of a version 2 file.
pub fn open(bytes: &[u8], passphrase: &[u8]) -> Result<Opened, VaultError> {
    if bytes.len() as u64 > MAX_VAULT_LEN {
        return Err(VaultError::TooLarge);
    }
    let (header, header_len) = Header::parse(bytes)?;
    let key = crypto::derive_key(passphrase, &header.salt, header.params)?;
    let plaintext = crypto::open(
        &key,
        &header.nonce,
        &bytes[..header_len],
        &bytes[header_len..],
    )?;
    let vault = decode_plaintext(&plaintext, header.params)?;
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&bytes[bytes.len() - TAG_LEN..]);
    Ok(Opened {
        vault,
        vault_id: header.vault_id,
        generation: header.generation,
        extensions: header.extensions,
        tag,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::CryptoError;

    const PASS: &[u8] = b"v2 test passphrase";
    const ID: [u8; VAULT_ID_LEN] = [0xa5; VAULT_ID_LEN];

    fn vault_with(entries: &[(&str, &str)]) -> Vault {
        let mut v = Vault::with_params(KdfParams::MIN).unwrap();
        for (k, val) in entries {
            v.set(k, Zeroizing::new((*val).to_owned())).unwrap();
        }
        v
    }

    fn contents(v: &Vault) -> Vec<(String, String)> {
        v.iter()
            .map(|(k, val)| (k.to_owned(), val.to_owned()))
            .collect()
    }

    fn sealed(entries: &[(&str, &str)]) -> Vec<u8> {
        seal(&vault_with(entries), &ID, 1, &[], PASS).unwrap()
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // ---- padding ----

    #[test]
    fn padme_known_values() {
        for (len, want) in [
            (0, 0),
            (1, 1),
            (2, 2),
            (3, 3),
            (5, 5),
            (8, 8),
            (9, 10),
            (17, 18),
            (4096, 4096),
            (4097, 4352),
            (5000, 5120),
            (20000, 20480),
            (100_000, 100_352),
            (16 * 1024 * 1024, 16 * 1024 * 1024),
        ] {
            assert_eq!(padme(len), want, "padme({len})");
        }
    }

    #[test]
    fn padme_properties() {
        let mut worst = 0.0f64;
        for len in 0u64..=300_000 {
            let p = padme(len);
            assert!(p >= len, "never shrinks: {len}");
            assert!(padme(len + 1) >= p, "monotonic at {len}");
            assert_eq!(padme(p), p, "idempotent at {len}");
            if len >= PAD_FLOOR {
                worst = worst.max((p - len) as f64 / len as f64);
            }
        }
        assert!(
            worst <= 0.0625 + 1e-9,
            "overhead above the floor was {worst}"
        );
        // coarse sweep up to the vault limit
        let mut len = 300_001u64;
        while len < MAX_VAULT_LEN {
            let p = padme(len);
            assert!(p >= len && (p - len) as f64 / len as f64 <= 0.0625 + 1e-9 && padme(p) == p);
            len += 4_099;
        }
    }

    #[test]
    fn padded_len_has_a_4_kib_floor() {
        assert_eq!(padded_len(4), 4096);
        assert_eq!(padded_len(4096), 4096);
        assert_eq!(padded_len(4097), 4352);
    }

    #[test]
    fn an_empty_vault_is_exactly_header_floor_and_tag() {
        let b = sealed(&[]);
        assert_eq!(b.len(), 96 + 4096 + 16);
        assert_eq!(sealed_len(&vault_with(&[]), 0), b.len() as u64);
    }

    #[test]
    fn sealed_len_is_the_real_size_around_the_floor() {
        // one entry with a one-byte name: unpadded length is 13 + value length
        for (vlen, padded) in [(0usize, 4096u64), (4083, 4096), (4084, 4352)] {
            let value = "x".repeat(vlen);
            let v = vault_with(&[("K", &value)]);
            let b = seal(&v, &ID, 1, &[], PASS).unwrap();
            assert_eq!(b.len() as u64, 96 + padded + 16, "value length {vlen}");
            assert_eq!(sealed_len(&v, 0), b.len() as u64);
        }
    }

    #[test]
    fn rotating_a_value_inside_a_bucket_does_not_change_the_file_size() {
        // 20 entries of 1014 bytes each plus the count: 20284 bytes. The padded length is 20480 for every unpadded
        // length from 19457 to 20480, so rotating one value to a length up to 196 bytes longer changes nothing.
        let base = "v".repeat(1000);
        let mut sizes = Vec::new();
        for extra in [0usize, 7, 40, 150, 196] {
            let rotated = "r".repeat(1000 + extra);
            let names: Vec<String> = (0..20).map(|i| format!("KEY_{i:02}")).collect();
            let mut entries: Vec<(&str, &str)> =
                names.iter().map(|n| (n.as_str(), base.as_str())).collect();
            entries[3].1 = rotated.as_str();
            let v = vault_with(&entries);
            assert_eq!(
                padded_len(unpadded_len(&v)),
                20480,
                "unpadded {}",
                unpadded_len(&v)
            );
            sizes.push(seal(&v, &ID, 1, &[], PASS).unwrap().len());
        }
        assert!(sizes.iter().all(|s| *s == sizes[0]), "{sizes:?}");
        // and the leak that remains: crossing a bucket boundary is visible (20481 bytes pad to 21504)
        let names: Vec<String> = (0..20).map(|i| format!("KEY_{i:02}")).collect();
        let crossing = "r".repeat(1000 + 197);
        let mut entries: Vec<(&str, &str)> =
            names.iter().map(|n| (n.as_str(), base.as_str())).collect();
        entries[3].1 = crossing.as_str();
        let v = vault_with(&entries);
        assert_eq!(unpadded_len(&v), 20481);
        assert_eq!(padded_len(20481), 21504);
        assert_ne!(seal(&v, &ID, 1, &[], PASS).unwrap().len(), sizes[0]);
    }

    // ---- known answer ----

    fn kat_salt() -> [u8; SALT_LEN] {
        std::array::from_fn(|i| i as u8)
    }
    fn kat_nonce() -> [u8; NONCE_LEN] {
        std::array::from_fn(|i| 0x20 + i as u8)
    }
    fn kat_id() -> [u8; VAULT_ID_LEN] {
        std::array::from_fn(|i| 0xa0 + i as u8)
    }

    /// Fixed passphrase, salt, nonce, vault id and generation: the exact bytes are asserted, so any change to the
    /// layout, the AAD, the padding or the primitives fails here. The header is spelled out by hand below, and the
    /// plaintext is checked with an independent decryption, so the vector does not merely echo the encoder.
    #[test]
    fn known_answer_vector() {
        let v = vault_with(&[("GREETING", "hello")]);
        let file = seal_with(
            &v,
            &kat_id(),
            7,
            &[],
            b"known answer passphrase",
            kat_salt(),
            kat_nonce(),
        )
        .unwrap();

        let want_header = concat!(
            "434c4f414b454e56",
            "02010101",
            "004c0000",
            "02000000",
            "01000000",
            "000102030405060708090a0b0c0d0e0f",
            "202122232425262728292a2b2c2d2e2f3031323334353637",
            "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
            "0700000000000000",
            "00000000",
            "00000000",
        );
        assert_eq!(hex(&file[..96]), want_header);
        assert_eq!(file.len(), 96 + 4096 + 16);

        // independent decryption with a key derived here, against a plaintext written out by hand
        let key =
            crypto::derive_key(b"known answer passphrase", &kat_salt(), KdfParams::MIN).unwrap();
        let pt = crypto::open(&key, &kat_nonce(), &unhex(want_header), &file[96..]).unwrap();
        let mut want_pt = Vec::new();
        want_pt.extend_from_slice(&unhex("01000000"));
        want_pt.extend_from_slice(&unhex("08000000"));
        want_pt.extend_from_slice(b"GREETING");
        want_pt.extend_from_slice(&unhex("05000000"));
        want_pt.extend_from_slice(b"hello");
        want_pt.resize(4096, 0);
        assert_eq!(&pt[..], &want_pt[..]);

        assert_eq!(
            hex(&file[96..96 + 24]),
            KAT_CIPHERTEXT_START,
            "first 24 ciphertext bytes"
        );
        assert_eq!(hex(&file[file.len() - 16..]), KAT_TAG, "tag");
        let opened = open(&file, b"known answer passphrase").unwrap();
        assert_eq!((opened.generation, opened.vault_id), (7, kat_id()));
        assert_eq!(hex(&opened.tag), KAT_TAG);
    }

    const KAT_CIPHERTEXT_START: &str = "74ecc880bbec52770e299d9770b81ba471488d1903a5cc0c";
    const KAT_TAG: &str = "d35b599f3d3003e2c01fa6014721dfc3";

    // ---- round trips and basic behaviour ----

    #[test]
    fn round_trip_keeps_entries_id_generation_extensions_and_tag() {
        let entries = [
            ("ALPHA", "one"),
            ("beta", "t=wo"),
            ("UNICODE", "caf\u{e9}-\u{65e5}\u{672c}"),
        ];
        let ext = vec![
            Extension {
                kind: 0x0007,
                value: vec![1, 2, 3],
            },
            Extension {
                kind: 0x0009,
                value: vec![],
            },
        ];
        let v = vault_with(&entries);
        let file = seal(&v, &kat_id(), 41, &ext, PASS).unwrap();
        let o = open(&file, PASS).unwrap();
        assert_eq!(contents(&o.vault), contents(&v));
        assert_eq!((o.vault_id, o.generation), (kat_id(), 41));
        assert_eq!(
            o.extensions, ext,
            "non-critical unknown extensions are kept"
        );
        assert_eq!(&o.tag[..], &file[file.len() - 16..]);
        assert_eq!(o.vault.params(), KdfParams::MIN);
    }

    #[test]
    fn every_seal_uses_a_fresh_salt_and_nonce() {
        let (a, b) = (sealed(&[("K", "v")]), sealed(&[("K", "v")]));
        assert_ne!(&a[24..40], &b[24..40], "salt");
        assert_ne!(&a[40..64], &b[40..64], "nonce");
        assert_ne!(a, b);
    }

    #[test]
    fn a_wrong_passphrase_is_the_authentication_error() {
        let file = sealed(&[("K", "v")]);
        assert!(matches!(
            open(&file, b"nope"),
            Err(VaultError::Crypto(CryptoError::Decrypt))
        ));
    }

    #[test]
    fn debug_output_never_shows_values() {
        let file = sealed(&[("API_KEY", "super-secret-value")]);
        let shown = format!("{:?}", open(&file, PASS).unwrap());
        assert!(!shown.contains("super-secret-value"), "{shown}");
    }

    #[test]
    fn a_v1_file_is_refused_with_its_version_and_identified_without_decrypting() {
        let v1 = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/v1/one.bin"
        ));
        assert!(matches!(
            open(v1, b"x"),
            Err(VaultError::UnsupportedVersion(1))
        ));
        assert_eq!(format_version(v1).unwrap(), 1);
        assert_eq!(format_version(&sealed(&[])).unwrap(), 2);
        assert!(matches!(
            format_version(b"CLOAKEN"),
            Err(VaultError::BadMagic)
        ));
        assert!(matches!(
            format_version(b"CLOAKENV"),
            Err(VaultError::Malformed)
        ));
    }

    #[test]
    fn the_writer_refuses_what_the_reader_would_refuse() {
        let v = vault_with(&[("K", "v")]);
        assert!(
            matches!(seal(&v, &ID, 0, &[], PASS), Err(VaultError::Malformed)),
            "generation 0"
        );
        let dup = [
            Extension {
                kind: 1,
                value: vec![],
            },
            Extension {
                kind: 1,
                value: vec![],
            },
        ];
        assert!(
            matches!(seal(&v, &ID, 1, &dup, PASS), Err(VaultError::Malformed)),
            "duplicate type"
        );
        let big = [Extension {
            kind: 1,
            value: vec![0; 4093],
        }];
        assert!(
            matches!(seal(&v, &ID, 1, &big, PASS), Err(VaultError::Malformed)),
            "4097-byte area"
        );
        let max = [Extension {
            kind: 1,
            value: vec![0; 4092],
        }];
        assert!(
            open(&seal(&v, &ID, 1, &max, PASS).unwrap(), PASS).is_ok(),
            "4096-byte area is the limit"
        );
    }

    #[test]
    fn a_vault_over_the_limit_is_refused_before_any_key_derivation() {
        let value = "x".repeat(131_000);
        let names: Vec<String> = (0..130).map(|i| format!("K{i:03}")).collect();
        let entries: Vec<(&str, &str)> =
            names.iter().map(|n| (n.as_str(), value.as_str())).collect();
        let v = vault_with(&entries);
        let started = std::time::Instant::now();
        match seal(&v, &ID, 1, &[], PASS) {
            Err(VaultError::VaultFull { size }) => assert!(size > MAX_VAULT_LEN),
            other => panic!("{:?}", other.map(|b| b.len())),
        }
        assert!(started.elapsed().as_millis() < 2000, "must not run the KDF");
    }

    // ---- rejection: header checks, all before the KDF ----

    fn patched(file: &[u8], at: usize, bytes: &[u8]) -> Vec<u8> {
        let mut b = file.to_vec();
        b[at..at + bytes.len()].copy_from_slice(bytes);
        b
    }

    type ErrorCheck = fn(&VaultError) -> bool;

    #[test]
    fn header_rejection_table() {
        let good = sealed(&[("K", "v")]);
        let started = std::time::Instant::now();
        let mut cases: Vec<(&str, Vec<u8>, ErrorCheck)> = vec![
            ("empty file", vec![], |e| matches!(e, VaultError::BadMagic)),
            ("short magic", good[..7].to_vec(), |e| {
                matches!(e, VaultError::BadMagic)
            }),
            ("wrong magic", patched(&good, 0, b"CLOAKENW"), |e| {
                matches!(e, VaultError::BadMagic)
            }),
            ("magic only", good[..8].to_vec(), |e| {
                matches!(e, VaultError::Malformed)
            }),
            ("version 1", patched(&good, 8, &[1]), |e| {
                matches!(e, VaultError::UnsupportedVersion(1))
            }),
            ("version 3", patched(&good, 8, &[3]), |e| {
                matches!(e, VaultError::UnsupportedVersion(3))
            }),
            ("version 255", patched(&good, 8, &[255]), |e| {
                matches!(e, VaultError::UnsupportedVersion(255))
            }),
            ("kdf id 2", patched(&good, 9, &[2]), |e| {
                matches!(e, VaultError::UnsupportedAlgorithm { kdf: 2, aead: 1 })
            }),
            ("kdf id 0", patched(&good, 9, &[0]), |e| {
                matches!(e, VaultError::UnsupportedAlgorithm { kdf: 0, .. })
            }),
            ("aead id 2", patched(&good, 10, &[2]), |e| {
                matches!(e, VaultError::UnsupportedAlgorithm { kdf: 1, aead: 2 })
            }),
            ("padding id 0", patched(&good, 11, &[0]), |e| {
                matches!(e, VaultError::UnsupportedPadding(0))
            }),
            ("padding id 2", patched(&good, 11, &[2]), |e| {
                matches!(e, VaultError::UnsupportedPadding(2))
            }),
            ("memory 0", patched(&good, 12, &0u32.to_le_bytes()), |e| {
                matches!(e, VaultError::Crypto(CryptoError::InvalidKdfParams { .. }))
            }),
            (
                "memory below the floor",
                patched(&good, 12, &1024u32.to_le_bytes()),
                |e| matches!(e, VaultError::Crypto(CryptoError::InvalidKdfParams { .. })),
            ),
            (
                "memory above the maximum",
                patched(&good, 12, &(256u32 * 1024 + 1).to_le_bytes()),
                |e| matches!(e, VaultError::Crypto(CryptoError::InvalidKdfParams { .. })),
            ),
            (
                "memory u32::MAX",
                patched(&good, 12, &u32::MAX.to_le_bytes()),
                |e| matches!(e, VaultError::Crypto(CryptoError::InvalidKdfParams { .. })),
            ),
            ("time 0", patched(&good, 16, &0u32.to_le_bytes()), |e| {
                matches!(e, VaultError::Crypto(CryptoError::InvalidKdfParams { .. }))
            }),
            ("time 9", patched(&good, 16, &9u32.to_le_bytes()), |e| {
                matches!(e, VaultError::Crypto(CryptoError::InvalidKdfParams { .. }))
            }),
            ("lanes 0", patched(&good, 20, &0u32.to_le_bytes()), |e| {
                matches!(e, VaultError::Crypto(CryptoError::InvalidKdfParams { .. }))
            }),
            ("lanes 9", patched(&good, 20, &9u32.to_le_bytes()), |e| {
                matches!(e, VaultError::Crypto(CryptoError::InvalidKdfParams { .. }))
            }),
            (
                "generation 0",
                patched(&good, 80, &0u64.to_le_bytes()),
                |e| matches!(e, VaultError::Malformed),
            ),
            (
                "flags bit 0",
                patched(&good, 88, &1u32.to_le_bytes()),
                |e| matches!(e, VaultError::Malformed),
            ),
            (
                "flags bit 31",
                patched(&good, 88, &0x8000_0000u32.to_le_bytes()),
                |e| matches!(e, VaultError::Malformed),
            ),
            (
                "extension area 4097",
                patched(&good, 92, &4097u32.to_le_bytes()),
                |e| matches!(e, VaultError::Malformed),
            ),
            (
                "extension area u32::MAX",
                patched(&good, 92, &u32::MAX.to_le_bytes()),
                |e| matches!(e, VaultError::Malformed),
            ),
            (
                "extension area runs past the file",
                patched(&good, 92, &4096u32.to_le_bytes()),
                |e| matches!(e, VaultError::Malformed),
            ),
            ("header only", good[..96].to_vec(), |e| {
                matches!(e, VaultError::Malformed)
            }),
            ("header and tag only", good[..96 + 16].to_vec(), |e| {
                matches!(e, VaultError::Malformed)
            }),
            (
                "ciphertext one byte under the floor",
                good[..96 + 4095 + 16].to_vec(),
                |e| matches!(e, VaultError::Malformed),
            ),
        ];
        let mut too_large = vec![0u8; MAX_VAULT_LEN as usize + 1];
        too_large[..8].copy_from_slice(MAGIC);
        cases.push(("one byte over 16 MiB", too_large, |e| {
            matches!(e, VaultError::TooLarge)
        }));
        for (name, bytes, ok) in &cases {
            match open(bytes, PASS) {
                Err(e) if ok(&e) => {}
                Err(e) => panic!("{name}: wrong error {e:?}"),
                Ok(_) => panic!("{name}: accepted"),
            }
        }
        assert!(
            started.elapsed().as_millis() < 3000,
            "these are all refused before the KDF runs"
        );
    }

    #[test]
    fn extension_rejection_table() {
        let ext = [Extension {
            kind: 5,
            value: vec![9, 9],
        }];
        let good = seal(&vault_with(&[("K", "v")]), &ID, 1, &ext, PASS).unwrap();
        assert_eq!(u32::from_le_bytes(good[92..96].try_into().unwrap()), 6);
        // the 6-byte record at 96: type 5, length 2, value 9 9
        let cases: Vec<(&str, Vec<u8>)> = vec![
            (
                "record length runs past the area",
                patched(&good, 98, &3u16.to_le_bytes()),
            ),
            (
                "record header cut short (area of 3 bytes)",
                patched(&good, 92, &3u32.to_le_bytes()),
            ),
            (
                "one stray byte after the record (area of 7 bytes)",
                patched(&good, 92, &7u32.to_le_bytes()),
            ),
            (
                "area of 0 bytes with the record left in the ciphertext",
                patched(&good, 92, &0u32.to_le_bytes()),
            ),
        ];
        for (name, bytes) in &cases {
            assert!(open(bytes, PASS).is_err(), "{name}");
        }
        // two records of the same type
        let dup = {
            let mut b = Vec::new();
            for _ in 0..2 {
                b.extend_from_slice(&5u16.to_le_bytes());
                b.extend_from_slice(&0u16.to_le_bytes());
            }
            b
        };
        let mut f = good[..96].to_vec();
        f[92..96].copy_from_slice(&(dup.len() as u32).to_le_bytes());
        f.extend_from_slice(&dup);
        f.extend_from_slice(&good[96 + 6..]);
        assert!(
            matches!(open(&f, PASS), Err(VaultError::Malformed)),
            "duplicate extension type"
        );
    }

    #[test]
    fn a_critical_unknown_extension_is_refused_and_a_non_critical_one_is_not() {
        let v = vault_with(&[("K", "v")]);
        for kind in [0x8000u16, 0x8001, 0xffff] {
            let file = seal(
                &v,
                &ID,
                1,
                &[Extension {
                    kind,
                    value: vec![1],
                }],
                PASS,
            )
            .unwrap();
            assert!(
                matches!(open(&file, PASS), Err(VaultError::UnsupportedExtension(k)) if k == kind),
                "{kind:#06x}"
            );
        }
        for kind in [0x0000u16, 0x0001, 0x7fff] {
            let file = seal(
                &v,
                &ID,
                1,
                &[Extension {
                    kind,
                    value: vec![1],
                }],
                PASS,
            )
            .unwrap();
            assert!(open(&file, PASS).is_ok(), "{kind:#06x}");
        }
    }

    // ---- rejection: after authentication ----

    fn forge(plaintext: &[u8]) -> Vec<u8> {
        let h = Header {
            params: KdfParams::MIN,
            salt: kat_salt(),
            nonce: kat_nonce(),
            vault_id: ID,
            generation: 1,
            extensions: vec![],
        };
        let head = h.encode().unwrap();
        let key = crypto::derive_key(PASS, &h.salt, h.params).unwrap();
        [
            head.clone(),
            crypto::seal(&key, &h.nonce, &head, plaintext).unwrap(),
        ]
        .concat()
    }

    fn entry(k: &[u8], v: &[u8]) -> Vec<u8> {
        [
            &(k.len() as u32).to_le_bytes()[..],
            k,
            &(v.len() as u32).to_le_bytes()[..],
            v,
        ]
        .concat()
    }

    /// count, entries, then zero padding up to the canonical length
    fn plaintext(count: u32, entries: &[Vec<u8>]) -> Vec<u8> {
        let mut p = count.to_le_bytes().to_vec();
        for e in entries {
            p.extend_from_slice(e);
        }
        let total = padded_len(p.len() as u64) as usize;
        p.resize(total, 0);
        p
    }

    #[test]
    fn authenticated_but_invalid_plaintexts_are_refused() {
        // control: the forging helper itself produces something that opens
        let ok = forge(&plaintext(1, &[entry(b"K", b"v")]));
        assert_eq!(
            contents(&open(&ok, PASS).unwrap().vault),
            vec![("K".to_owned(), "v".to_owned())]
        );

        let mut nonzero_padding = plaintext(1, &[entry(b"K", b"v")]);
        *nonzero_padding.last_mut().unwrap() = 1;
        let mut nonzero_first_pad = plaintext(0, &[]);
        nonzero_first_pad[4] = 0x80;
        let mut too_long = plaintext(1, &[entry(b"K", b"v")]);
        too_long.push(0);
        let mut doubled = plaintext(1, &[entry(b"K", b"v")]);
        doubled.resize(8192, 0);
        let huge = vec![b'x'; 131_071];
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("padding byte that is not zero (last)", nonzero_padding),
            ("padding byte that is not zero (first)", nonzero_first_pad),
            ("one zero byte too many", too_long),
            ("padded to twice the canonical length", doubled),
            (
                "count larger than the entries present",
                plaintext(2, &[entry(b"K", b"v")]),
            ),
            ("count of u32::MAX", plaintext(u32::MAX, &[])),
            (
                "duplicate key",
                plaintext(2, &[entry(b"K", b"1"), entry(b"K", b"2")]),
            ),
            (
                "name starting with a digit",
                plaintext(1, &[entry(b"1K", b"v")]),
            ),
            ("empty name", plaintext(1, &[entry(b"", b"v")])),
            ("name with a dash", plaintext(1, &[entry(b"A-B", b"v")])),
            (
                "name that is not UTF-8",
                plaintext(1, &[entry(&[0xff, 0xfe], b"v")]),
            ),
            (
                "value with a NUL byte",
                plaintext(1, &[entry(b"K", b"a\0b")]),
            ),
            (
                "value that is not UTF-8",
                plaintext(1, &[entry(b"K", &[0xc3, 0x28])]),
            ),
            (
                "entry over the size cap",
                plaintext(1, &[entry(b"K", &huge)]),
            ),
            (
                "key length larger than the plaintext",
                plaintext(1, &[[&u32::MAX.to_le_bytes()[..], b"K"].concat()]),
            ),
        ];
        for (name, pt) in &cases {
            assert!(
                matches!(open(&forge(pt), PASS), Err(VaultError::Malformed)),
                "{name}"
            );
        }
        // an entry exactly at the cap is fine
        let at_cap = vec![b'x'; 131_071 - 2];
        assert!(open(&forge(&plaintext(1, &[entry(b"K", &at_cap)])), PASS).is_ok());
    }

    // ---- damage sweeps ----

    #[test]
    fn a_flipped_bit_anywhere_in_the_header_or_at_sampled_ciphertext_offsets_is_refused() {
        let good = sealed(&[("K", "v")]);
        let mut offsets: Vec<usize> = (0..FIXED_HEADER_LEN).collect();
        offsets.extend([
            96,
            97,
            120,
            1000,
            2047,
            4095,
            4096 + 95,
            good.len() - 17,
            good.len() - 16,
            good.len() - 1,
        ]);
        for off in offsets {
            for bit in [0x01u8, 0x80] {
                let mut b = good.clone();
                b[off] ^= bit;
                assert!(
                    open(&b, PASS).is_err(),
                    "bit {bit:#04x} at offset {off} was accepted"
                );
            }
        }
    }

    #[test]
    fn truncation_and_appending_are_refused() {
        let good = sealed(&[("K", "v")]);
        for len in (0..=130).chain([
            good.len() - 17,
            good.len() - 16,
            good.len() - 2,
            good.len() - 1,
        ]) {
            assert!(open(&good[..len], PASS).is_err(), "truncated to {len}");
        }
        let mut b = good.clone();
        b.push(0);
        assert!(open(&b, PASS).is_err(), "one byte appended");
    }

    /// Whatever the header parser accepts must encode back to the same bytes: no two files decode to one header.
    #[test]
    fn parse_then_encode_is_the_identity_under_random_mutation() {
        let ext = vec![
            Extension {
                kind: 3,
                value: vec![1, 2, 3, 4, 5],
            },
            Extension {
                kind: 0x70,
                value: vec![],
            },
        ];
        let base = Header {
            params: KdfParams::MIN,
            salt: kat_salt(),
            nonce: kat_nonce(),
            vault_id: kat_id(),
            generation: 9,
            extensions: ext,
        }
        .encode()
        .unwrap();
        let mut file = base.clone();
        file.resize(base.len() + 4096 + 16, 0);
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let (mut accepted, mut rejected) = (0u32, 0u32);
        for _ in 0..200_000 {
            let mut b = file.clone();
            for _ in 0..(1 + next() % 4) {
                let at = (next() % (base.len() as u64)) as usize;
                b[at] = next() as u8;
            }
            match Header::parse(&b) {
                Ok((h, n)) => {
                    assert_eq!(h.encode().unwrap(), b[..n], "re-encoding differs");
                    accepted += 1;
                }
                Err(_) => rejected += 1,
            }
        }
        assert!(
            accepted > 1000 && rejected > 1000,
            "{accepted} accepted, {rejected} rejected: the mutation is not exercising both"
        );
    }
}
