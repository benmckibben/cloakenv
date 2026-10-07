//! Vault file format, in-memory key/value storage and `.env` import.
//!
//! # On-disk format (version 1)
//!
//! All integers are little-endian. The entire 64-byte header is bound to the
//! ciphertext as AEAD associated data, so any modification of the header
//! (including the KDF parameters, salt or nonce) causes decryption to fail.
//!
//! | offset | size | field                                          |
//! |-------:|-----:|------------------------------------------------|
//! |      0 |    8 | magic `CLOAKENV`                                 |
//! |      8 |    1 | format version (`1`)                           |
//! |      9 |    1 | KDF id (`1` = Argon2id v1.3)                   |
//! |     10 |    1 | AEAD id (`1` = XChaCha20-Poly1305)             |
//! |     11 |    1 | reserved, must be zero                         |
//! |     12 |    4 | Argon2 memory cost (KiB)                       |
//! |     16 |    4 | Argon2 time cost                               |
//! |     20 |    4 | Argon2 parallelism                             |
//! |     24 |   16 | salt                                           |
//! |     40 |   24 | nonce                                          |
//! |     64 |    n | ciphertext ‖ 16-byte Poly1305 tag              |
//!
//! The plaintext payload is `u32 count` followed by `count` entries of
//! `u32 key_len, key, u32 value_len, value`.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use thiserror::Error;
use zeroize::Zeroizing;

use crate::crypto::{self, CryptoError, KdfParams, NONCE_LEN, SALT_LEN, TAG_LEN};

/// File magic.
pub const MAGIC: &[u8; 8] = b"CLOAKENV";
/// Current format version.
pub const FORMAT_VERSION: u8 = 1;
const KDF_ARGON2ID: u8 = 1;
const AEAD_XCHACHA20POLY1305: u8 = 1;
/// Size of the authenticated header in bytes.
pub const HEADER_LEN: usize = 64;
/// Upper bound on vault file size we are willing to read (16 MiB).
pub const MAX_VAULT_LEN: u64 = 16 * 1024 * 1024;

/// Errors produced by the vault layer. Secret values are never included;
/// keys (variable names) and line numbers may be.
#[derive(Debug, Error)]
pub enum VaultError {
    #[error("not a cloakenv vault (bad magic)")]
    BadMagic,
    #[error("unsupported vault format version {0}")]
    UnsupportedVersion(u8),
    #[error("unsupported vault algorithm (kdf id {kdf}, aead id {aead})")]
    UnsupportedAlgorithm { kdf: u8, aead: u8 },
    #[error("vault file is truncated or malformed")]
    Malformed,
    #[error("vault file is too large")]
    TooLarge,
    // The rejected name is deliberately not echoed: a user who swaps the
    // KEY and VALUE arguments would otherwise see their secret in the error.
    #[error("invalid variable name: must match [A-Za-z_][A-Za-z0-9_]*")]
    InvalidKey,
    #[error("value for {0} contains a NUL byte, which cannot be placed in an environment")]
    NulInValue(String),
    #[error(".env parse error on line {line}: {reason}")]
    Dotenv { line: usize, reason: &'static str },
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error("{action} {path}: {source}")]
    Io {
        action: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

impl VaultError {
    fn io(action: &'static str, path: &Path, source: io::Error) -> Self {
        Self::Io {
            action,
            path: path.to_path_buf(),
            source,
        }
    }
}

/// Returns true if `key` is a portable environment variable name.
pub fn is_valid_key(key: &str) -> bool {
    let mut chars = key.chars();
    matches!(chars.next(), Some(c) if c == '_' || c.is_ascii_alphabetic())
        && chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
}

/// Decrypted vault contents. Values are zeroized on drop and never shown by
/// `Debug`.
#[derive(Default)]
pub struct Vault {
    entries: BTreeMap<String, Zeroizing<String>>,
    params: KdfParams,
}

impl fmt::Debug for Vault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Vault")
            .field("keys", &self.entries.keys().collect::<Vec<_>>())
            .field("params", &self.params)
            .finish_non_exhaustive()
    }
}

impl Vault {
    /// Creates an empty vault using the default KDF parameters.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates an empty vault with explicit KDF parameters.
    pub fn with_params(params: KdfParams) -> Result<Self, VaultError> {
        Ok(Self {
            entries: BTreeMap::new(),
            params: params.validate()?,
        })
    }

    /// KDF parameters used when sealing this vault.
    pub fn params(&self) -> KdfParams {
        self.params
    }

    /// Inserts or replaces a secret.
    pub fn set(&mut self, key: &str, value: Zeroizing<String>) -> Result<(), VaultError> {
        if !is_valid_key(key) {
            return Err(VaultError::InvalidKey);
        }
        if value.contains('\0') {
            return Err(VaultError::NulInValue(key.to_owned()));
        }
        self.entries.insert(key.to_owned(), value);
        Ok(())
    }

    /// Removes a secret, returning whether it existed.
    pub fn remove(&mut self, key: &str) -> bool {
        self.entries.remove(key).is_some()
    }

    /// Looks up a secret value.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.entries.get(key).map(|v| v.as_str())
    }

    /// Iterates over variable names in sorted order.
    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.entries.keys().map(String::as_str)
    }

    /// Iterates over `(name, value)` pairs in sorted order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.entries.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// Number of secrets stored.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the vault holds no secrets.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn encode_payload(&self) -> Zeroizing<Vec<u8>> {
        let size = 4 + self
            .entries
            .iter()
            .map(|(k, v)| 8 + k.len() + v.len())
            .sum::<usize>();
        let mut out = Zeroizing::new(Vec::with_capacity(size));
        out.extend_from_slice(&(self.entries.len() as u32).to_le_bytes());
        for (k, v) in &self.entries {
            out.extend_from_slice(&(k.len() as u32).to_le_bytes());
            out.extend_from_slice(k.as_bytes());
            out.extend_from_slice(&(v.len() as u32).to_le_bytes());
            out.extend_from_slice(v.as_bytes());
        }
        out
    }

    fn decode_payload(mut buf: &[u8], params: KdfParams) -> Result<Self, VaultError> {
        fn take<'a>(buf: &mut &'a [u8], n: usize) -> Result<&'a [u8], VaultError> {
            if buf.len() < n {
                return Err(VaultError::Malformed);
            }
            let (head, tail) = buf.split_at(n);
            *buf = tail;
            Ok(head)
        }
        fn take_u32(buf: &mut &[u8]) -> Result<usize, VaultError> {
            let b = take(buf, 4)?;
            Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize)
        }

        let count = take_u32(&mut buf)?;
        let mut vault = Self {
            entries: BTreeMap::new(),
            params,
        };
        for _ in 0..count {
            let klen = take_u32(&mut buf)?;
            let key =
                std::str::from_utf8(take(&mut buf, klen)?).map_err(|_| VaultError::Malformed)?;
            let vlen = take_u32(&mut buf)?;
            let value =
                std::str::from_utf8(take(&mut buf, vlen)?).map_err(|_| VaultError::Malformed)?;
            if !is_valid_key(key) || value.contains('\0') || vault.entries.contains_key(key) {
                return Err(VaultError::Malformed);
            }
            vault
                .entries
                .insert(key.to_owned(), Zeroizing::new(value.to_owned()));
        }
        if !buf.is_empty() {
            return Err(VaultError::Malformed);
        }
        Ok(vault)
    }

    /// Encrypts the vault with a fresh salt and nonce, returning the complete
    /// file contents.
    pub fn seal(&self, passphrase: &[u8]) -> Result<Vec<u8>, VaultError> {
        let salt: [u8; SALT_LEN] = crypto::random_bytes()?;
        let nonce: [u8; NONCE_LEN] = crypto::random_bytes()?;
        let header = encode_header(self.params, &salt, &nonce);
        let key = crypto::derive_key(passphrase, &salt, self.params)?;
        let payload = self.encode_payload();
        let ciphertext = crypto::seal(&key, &nonce, &header, &payload)?;
        let mut out = Vec::with_capacity(HEADER_LEN + ciphertext.len());
        out.extend_from_slice(&header);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Authenticates and decrypts complete vault file contents.
    pub fn open(bytes: &[u8], passphrase: &[u8]) -> Result<Self, VaultError> {
        if bytes.len() < MAGIC.len() || &bytes[..MAGIC.len()] != MAGIC {
            return Err(VaultError::BadMagic);
        }
        if bytes.len() < HEADER_LEN + TAG_LEN {
            return Err(VaultError::Malformed);
        }
        let (header, ciphertext) = bytes.split_at(HEADER_LEN);
        let (params, salt, nonce) = decode_header(header)?;
        let key = crypto::derive_key(passphrase, &salt, params)?;
        let payload = crypto::open(&key, &nonce, header, ciphertext)?;
        Self::decode_payload(&payload, params)
    }

    /// Reads and decrypts a vault file.
    pub fn load(path: &Path, passphrase: &[u8]) -> Result<Self, VaultError> {
        let meta = fs::metadata(path).map_err(|e| VaultError::io("cannot read vault", path, e))?;
        if meta.len() > MAX_VAULT_LEN {
            return Err(VaultError::TooLarge);
        }
        let bytes = fs::read(path).map_err(|e| VaultError::io("cannot read vault", path, e))?;
        Self::open(&bytes, passphrase)
    }

    /// Encrypts and atomically writes the vault to `path` with mode 0600,
    /// creating the parent directory with mode 0700 if needed.
    pub fn save(&self, path: &Path, passphrase: &[u8]) -> Result<(), VaultError> {
        let bytes = self.seal(passphrase)?;
        write_atomic_private(path, &bytes)
    }
}

fn encode_header(
    params: KdfParams,
    salt: &[u8; SALT_LEN],
    nonce: &[u8; NONCE_LEN],
) -> [u8; HEADER_LEN] {
    let mut h = [0u8; HEADER_LEN];
    h[0..8].copy_from_slice(MAGIC);
    h[8] = FORMAT_VERSION;
    h[9] = KDF_ARGON2ID;
    h[10] = AEAD_XCHACHA20POLY1305;
    h[11] = 0;
    h[12..16].copy_from_slice(&params.m_cost_kib.to_le_bytes());
    h[16..20].copy_from_slice(&params.t_cost.to_le_bytes());
    h[20..24].copy_from_slice(&params.p_cost.to_le_bytes());
    h[24..40].copy_from_slice(salt);
    h[40..64].copy_from_slice(nonce);
    h
}

fn decode_header(h: &[u8]) -> Result<(KdfParams, [u8; SALT_LEN], [u8; NONCE_LEN]), VaultError> {
    debug_assert_eq!(h.len(), HEADER_LEN);
    if &h[0..8] != MAGIC {
        return Err(VaultError::BadMagic);
    }
    if h[8] != FORMAT_VERSION {
        return Err(VaultError::UnsupportedVersion(h[8]));
    }
    if h[9] != KDF_ARGON2ID || h[10] != AEAD_XCHACHA20POLY1305 {
        return Err(VaultError::UnsupportedAlgorithm {
            kdf: h[9],
            aead: h[10],
        });
    }
    if h[11] != 0 {
        return Err(VaultError::Malformed);
    }
    let u32_at = |i: usize| u32::from_le_bytes([h[i], h[i + 1], h[i + 2], h[i + 3]]);
    let params = KdfParams {
        m_cost_kib: u32_at(12),
        t_cost: u32_at(16),
        p_cost: u32_at(20),
    }
    .validate()?;
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&h[24..40]);
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&h[40..64]);
    Ok((params, salt, nonce))
}

/// Writes `bytes` to a sibling temp file created with mode 0600, fsyncs it,
/// then renames it over `path`. Only ever used for ciphertext.
fn write_atomic_private(path: &Path, bytes: &[u8]) -> Result<(), VaultError> {
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    create_private_dir(&parent)
        .map_err(|e| VaultError::io("cannot create vault directory", &parent, e))?;

    let file_name = path.file_name().ok_or_else(|| {
        VaultError::io(
            "invalid vault path",
            path,
            io::ErrorKind::InvalidInput.into(),
        )
    })?;
    let suffix: [u8; 6] = crypto::random_bytes()?;
    let suffix: String = suffix.iter().map(|b| format!("{b:02x}")).collect();
    let mut tmp_name = std::ffi::OsString::from(".");
    tmp_name.push(file_name);
    tmp_name.push(format!(".tmp-{suffix}"));
    let tmp = parent.join(tmp_name);

    let result = (|| -> io::Result<()> {
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        drop(f);
        fs::rename(&tmp, path)?;
        #[cfg(unix)]
        if let Ok(dir) = fs::File::open(&parent) {
            let _ = dir.sync_all();
        }
        Ok(())
    })();
    if let Err(e) = result {
        let _ = fs::remove_file(&tmp);
        return Err(VaultError::io("cannot write vault", path, e));
    }
    Ok(())
}

fn create_private_dir(dir: &Path) -> io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(dir)
}

/// Parses `.env`-style content into `(KEY, value)` pairs.
///
/// Supported syntax: blank lines, `# comments`, an optional `export ` prefix,
/// unquoted values (trailing ` # comment` stripped), single-quoted literal
/// values and double-quoted values with `\n \r \t \\ \"` escapes. Multi-line
/// values are not supported. Errors reference line numbers only, never content.
pub fn parse_dotenv(content: &str) -> Result<Vec<(String, Zeroizing<String>)>, VaultError> {
    let mut out = Vec::new();
    for (idx, raw) in content.lines().enumerate() {
        let line_no = idx + 1;
        let err = |reason| VaultError::Dotenv {
            line: line_no,
            reason,
        };
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line
            .strip_prefix("export")
            .filter(|rest| rest.starts_with([' ', '\t']))
            .map(str::trim_start)
            .unwrap_or(line);
        let (key, rest) = line
            .split_once('=')
            .ok_or_else(|| err("expected KEY=VALUE"))?;
        let key = key.trim();
        if !is_valid_key(key) {
            return Err(err("invalid variable name"));
        }
        let rest = rest.trim_start();
        let value = if let Some(body) = rest.strip_prefix('\'') {
            let end = body
                .find('\'')
                .ok_or_else(|| err("unterminated single quote"))?;
            if !trailing_ok(&body[end + 1..]) {
                return Err(err("unexpected characters after closing quote"));
            }
            Zeroizing::new(body[..end].to_owned())
        } else if let Some(body) = rest.strip_prefix('"') {
            let mut value = Zeroizing::new(String::with_capacity(body.len()));
            let mut chars = body.char_indices();
            let mut closed_at = None;
            while let Some((i, c)) = chars.next() {
                match c {
                    '"' => {
                        closed_at = Some(i);
                        break;
                    }
                    '\\' => match chars.next().map(|(_, c)| c) {
                        Some('n') => value.push('\n'),
                        Some('r') => value.push('\r'),
                        Some('t') => value.push('\t'),
                        Some('\\') => value.push('\\'),
                        Some('"') => value.push('"'),
                        Some(other) => {
                            value.push('\\');
                            value.push(other);
                        }
                        None => return Err(err("unterminated double quote")),
                    },
                    c => value.push(c),
                }
            }
            let end = closed_at.ok_or_else(|| err("unterminated double quote"))?;
            if !trailing_ok(&body[end + 1..]) {
                return Err(err("unexpected characters after closing quote"));
            }
            value
        } else {
            let value = match rest.find(" #").or_else(|| rest.find("\t#")) {
                Some(i) => &rest[..i],
                None => rest,
            };
            Zeroizing::new(value.trim_end().to_owned())
        };
        if value.contains('\0') {
            return Err(err("value contains a NUL byte"));
        }
        out.push((key.to_owned(), value));
    }
    Ok(out)
}

fn trailing_ok(rest: &str) -> bool {
    let rest = rest.trim();
    rest.is_empty() || rest.starts_with('#')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_validation() {
        for ok in ["A", "_", "API_KEY", "a1_b2"] {
            assert!(is_valid_key(ok), "{ok}");
        }
        for bad in ["", "1A", "A-B", "A B", "A=B", "ÄPI"] {
            assert!(!is_valid_key(bad), "{bad}");
        }
    }

    #[test]
    fn payload_roundtrip() {
        let mut v = Vault::new();
        v.set("A", Zeroizing::new("1".into())).unwrap();
        v.set("EMPTY", Zeroizing::new(String::new())).unwrap();
        v.set("UNI", Zeroizing::new("ünï=cødé 🔐".into())).unwrap();
        let bytes = v.encode_payload();
        let back = Vault::decode_payload(&bytes, KdfParams::MIN).unwrap();
        assert_eq!(
            back.iter().collect::<Vec<_>>(),
            v.iter().collect::<Vec<_>>()
        );
    }

    #[test]
    fn payload_rejects_trailing_or_truncated() {
        let mut v = Vault::new();
        v.set("A", Zeroizing::new("1".into())).unwrap();
        let mut bytes = v.encode_payload().to_vec();
        bytes.push(0);
        assert!(matches!(
            Vault::decode_payload(&bytes, KdfParams::MIN),
            Err(VaultError::Malformed)
        ));
        bytes.truncate(bytes.len() - 3);
        assert!(matches!(
            Vault::decode_payload(&bytes, KdfParams::MIN),
            Err(VaultError::Malformed)
        ));
    }

    fn parsed(input: &str) -> Vec<(String, String)> {
        parse_dotenv(input)
            .unwrap()
            .into_iter()
            .map(|(k, v)| (k, v.to_string()))
            .collect()
    }

    #[test]
    fn dotenv_syntax() {
        let input = concat!(
            "# header\n",
            "\n",
            "PLAIN=value\n",
            "  SPACED = padded value  \n",
            "export EXPORTED=1\n",
            "exporter=not-an-export\n",
            "COMMENTED=abc # note\n",
            "HASH=abc#def\n",
            r"SQ='a \n # b'",
            "\n",
            r#"DQ="tab\tquote\" nl\n" # note"#,
            "\n",
            "EMPTY=\n",
            "EQ=a=b=c\n",
            "CRLF=x\r\n",
        );
        let want: Vec<(String, String)> = [
            ("PLAIN", "value"),
            ("SPACED", "padded value"),
            ("EXPORTED", "1"),
            ("exporter", "not-an-export"),
            ("COMMENTED", "abc"),
            ("HASH", "abc#def"),
            ("SQ", r"a \n # b"),
            ("DQ", "tab\tquote\" nl\n"),
            ("EMPTY", ""),
            ("EQ", "a=b=c"),
            ("CRLF", "x"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();
        assert_eq!(parsed(input), want);
    }

    #[test]
    fn dotenv_errors_report_line_only() {
        for (input, line) in [
            ("A=1\nnot a pair\n", 2),
            ("1BAD=x\n", 1),
            ("A=1\nB=\"open\n", 2),
            ("A='open\n", 1),
            ("A='x' trailing\n", 1),
        ] {
            match parse_dotenv(input) {
                Err(VaultError::Dotenv { line: l, .. }) => assert_eq!(l, line, "{input:?}"),
                other => panic!("{input:?}: unexpected {other:?}"),
            }
        }
    }

    #[test]
    fn debug_hides_values() {
        let mut v = Vault::new();
        v.set("TOKEN", Zeroizing::new("s3cr3t-value".into()))
            .unwrap();
        let dbg = format!("{v:?}");
        assert!(dbg.contains("TOKEN"));
        assert!(!dbg.contains("s3cr3t-value"));
    }
}
