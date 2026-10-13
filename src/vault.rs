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
//!
//! # Concurrency
//!
//! Every save replaces the vault with `rename`, so readers always see a
//! complete file. Writers (`init`, `set`, `unset`, `import`) additionally
//! hold a [`VaultLock`] across their whole load → modify → save cycle so two
//! concurrent updates cannot silently drop one another's changes.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use thiserror::Error;
use zeroize::Zeroizing;

use crate::crypto::{self, CryptoError, KdfParams, NONCE_LEN, SALT_LEN, TAG_LEN};

pub use crate::dotenv::{DotenvEntry, parse_dotenv, parse_dotenv_entries};

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
/// Upper bound on the size of a `.env` file `import` will read (16 MiB).
pub const MAX_ENV_FILE_LEN: u64 = 16 * 1024 * 1024;
/// Longest `KEY=VALUE` environment string (not counting the terminating NUL)
/// that can be stored: 128 KiB minus one byte. Linux refuses to start a
/// program (`E2BIG`, "Argument list too long") if any single environment
/// string is larger (`MAX_ARG_STRLEN`, 32 pages of at least 4 KiB). The same
/// limit is applied everywhere, so a vault stays usable on every platform it
/// is copied to. It bounds the length of a key and of a value together.
pub const MAX_ENV_ENTRY_LEN: usize = 128 * 1024 - 1;

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
    #[error("vault file is too large (the limit is 16 MiB)")]
    TooLarge,
    // Carries only sizes, never any content.
    #[error(
        "the vault would be {size} bytes, over the 16 MiB limit (16777216 bytes) that cloakenv can open again; nothing was written. Remove entries you no longer need, or keep some of them in a second vault (`--vault`)"
    )]
    VaultFull { size: u64 },
    #[error(
        "{key}: the variable would be {len} bytes as KEY=VALUE, over the limit of {max} bytes for one environment variable (Linux cannot start a command with a larger one)"
    )]
    EntryTooLarge { key: String, len: usize, max: usize },
    #[error(
        "the environment for the command would be {total} bytes, over the {limit} bytes this system lets a program start with (a quarter of the stack limit, see `ulimit -s`, at most 6 MiB). Largest vault entries: {largest}. Remove or shrink some with `cloakenv unset KEY`"
    )]
    EnvironmentTooLarge {
        total: usize,
        limit: usize,
        largest: String,
    },
    #[error(
        "{first} and {second} differ only in case, and environment variable names are not case-sensitive on Windows, so only one of them would reach the command; unset or rename one (`cloakenv unset`)"
    )]
    KeysDifferOnlyInCase { first: String, second: String },
    #[error(
        "{} is not a regular file (it is a directory, device, pipe or socket); refusing to import it",
        .0.display()
    )]
    EnvNotRegularFile(PathBuf),
    #[error(".env file {} is too large (the limit is 16 MiB)", .0.display())]
    EnvTooLarge(PathBuf),
    #[error("{} is not valid UTF-8", .0.display())]
    NotUtf8(PathBuf),
    #[error(
        "{} is not a regular file (it is a directory, device, pipe or socket); refusing to read it as a vault",
        .0.display()
    )]
    NotRegularFile(PathBuf),
    // The rejected name is deliberately not echoed: a user who swaps the
    // KEY and VALUE arguments would otherwise see their secret in the error.
    #[error("invalid variable name: must match [A-Za-z_][A-Za-z0-9_]*")]
    InvalidKey,
    #[error("value for {0} contains a NUL byte, which cannot be placed in an environment")]
    NulInValue(String),
    #[error(".env parse error on line {line}: {reason}")]
    Dotenv { line: usize, reason: &'static str },
    // Lines only: a name could be a misplaced secret.
    #[error(
        ".env parse error on line {line}: this variable is already set on line {first}; remove one of them (a duplicate is never resolved silently)"
    )]
    DotenvDuplicate { line: usize, first: usize },
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    // The cause is the `source`, not part of this message, so `{:#}` (which
    // walks the chain) does not print it twice.
    #[error("{action} {path}")]
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

/// Checks one entry against the rules every stored variable must meet: a
/// valid name, no NUL byte in the value, and `KEY=VALUE` no longer than
/// [`MAX_ENV_ENTRY_LEN`]. Errors name the key and give sizes, never the value.
pub fn check_entry(key: &str, value: &str) -> Result<(), VaultError> {
    if !is_valid_key(key) {
        return Err(VaultError::InvalidKey);
    }
    if value.contains('\0') {
        return Err(VaultError::NulInValue(key.to_owned()));
    }
    let len = key.len() + 1 + value.len();
    if len > MAX_ENV_ENTRY_LEN {
        return Err(VaultError::EntryTooLarge {
            key: key.to_owned(),
            len,
            max: MAX_ENV_ENTRY_LEN,
        });
    }
    Ok(())
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
    /// The parameters must lie within [`KdfParams::MIN`] and
    /// [`KdfParams::MAX`].
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

    /// Raises every KDF parameter to at least [`KdfParams::DEFAULT`] (never
    /// lowering any), so the next [`Vault::save`] re-encrypts older or weaker
    /// vaults with current settings. Returns whether anything changed. A
    /// vault already stronger than the default keeps its own settings.
    pub fn upgrade_kdf_params(&mut self) -> bool {
        let upgraded = self.params.at_least(KdfParams::DEFAULT);
        let changed = upgraded != self.params;
        self.params = upgraded;
        changed
    }

    /// Inserts or replaces a secret. Refuses an invalid name, a value with a
    /// NUL byte and an entry over [`MAX_ENV_ENTRY_LEN`] (see [`check_entry`]);
    /// the error names the key, never the value.
    pub fn set(&mut self, key: &str, value: Zeroizing<String>) -> Result<(), VaultError> {
        check_entry(key, &value)?;
        self.entries.insert(key.to_owned(), value);
        Ok(())
    }

    /// Size in bytes of the vault file that [`Vault::seal`] would produce.
    pub fn sealed_len(&self) -> u64 {
        let payload: u64 = 4 + self
            .entries
            .iter()
            .map(|(k, v)| 8 + k.len() as u64 + v.len() as u64)
            .sum::<u64>();
        HEADER_LEN as u64 + payload + TAG_LEN as u64
    }

    /// Fails if the sealed vault would be larger than [`MAX_VAULT_LEN`], the
    /// size [`Vault::load`] accepts. A vault that can be written but never
    /// opened again would lock its owner out of every secret in it, so this
    /// is checked before anything is encrypted or written.
    pub fn check_size(&self) -> Result<(), VaultError> {
        let size = self.sealed_len();
        if size > MAX_VAULT_LEN {
            return Err(VaultError::VaultFull { size });
        }
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
        self.check_size()?;
        let salt: [u8; SALT_LEN] = crypto::random_bytes()?;
        let nonce: [u8; NONCE_LEN] = crypto::random_bytes()?;
        // Never write settings weaker than the current minimum, even for a
        // vault that was loaded with older, weaker ones.
        let params = self.params.at_least(KdfParams::MIN).validate()?;
        let header = encode_header(params, &salt, &nonce);
        let key = crypto::derive_key(passphrase, &salt, params)?;
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
    ///
    /// The file is opened once and every check is made on that open handle
    /// (no check-then-open race): it must be a regular file no larger than
    /// [`MAX_VAULT_LEN`], and the read itself is capped at that size too.
    /// Symbolic links are followed. Devices, pipes, sockets and directories
    /// are refused without being read, so `--vault /dev/zero` or a FIFO fails
    /// closed instead of exhausting memory or hanging.
    pub fn load(path: &Path, passphrase: &[u8]) -> Result<Self, VaultError> {
        let bytes = read_vault_file(path)?;
        Self::open(&bytes, passphrase)
    }

    /// Encrypts and atomically writes the vault to `path`, creating the parent
    /// directory if needed. Refuses (before writing anything) a vault larger
    /// than [`MAX_VAULT_LEN`], which could not be opened again. On Unix the file has mode 0600 and a directory
    /// created here 0700; other platforms get default permissions. An existing
    /// symlink at `path` is replaced, never written through.
    pub fn save(&self, path: &Path, passphrase: &[u8]) -> Result<(), VaultError> {
        let bytes = self.seal(passphrase)?;
        write_atomic_private(path, &bytes)
    }
}

/// Which kind of file is being opened, for its limits and error messages.
#[derive(Clone, Copy)]
enum FileKind {
    Vault,
    EnvFile,
}

impl FileKind {
    fn limit(self) -> u64 {
        match self {
            FileKind::Vault => MAX_VAULT_LEN,
            FileKind::EnvFile => MAX_ENV_FILE_LEN,
        }
    }

    fn io(self, path: &Path, source: io::Error) -> VaultError {
        let action = match self {
            FileKind::Vault => "cannot read vault",
            FileKind::EnvFile => "cannot read",
        };
        VaultError::io(action, path, source)
    }

    fn not_regular(self, path: &Path) -> VaultError {
        match self {
            FileKind::Vault => VaultError::NotRegularFile(path.to_path_buf()),
            FileKind::EnvFile => VaultError::EnvNotRegularFile(path.to_path_buf()),
        }
    }

    fn too_large(self, path: &Path) -> VaultError {
        match self {
            FileKind::Vault => VaultError::TooLarge,
            FileKind::EnvFile => VaultError::EnvTooLarge(path.to_path_buf()),
        }
    }
}

/// Opens `path` once and, on the open handle (no check-then-open race),
/// checks that it is a regular file within the size limit for `kind`.
/// Returns the handle and its size.
fn open_regular(path: &Path, kind: FileKind) -> Result<(fs::File, u64), VaultError> {
    let mut opts = fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use rustix::fs::OFlags;
        use std::os::unix::fs::OpenOptionsExt;
        // O_NONBLOCK: opening a FIFO for reading must not wait for a writer.
        // O_NOCTTY: opening a terminal device must not make it our
        // controlling terminal. Both are irrelevant for a regular file.
        opts.custom_flags((OFlags::NONBLOCK | OFlags::NOCTTY).bits() as i32);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // Without FILE_FLAG_BACKUP_SEMANTICS, CreateFileW refuses to open a
        // directory at all ("Access is denied"), which would hide the
        // "not a regular file" check below behind a confusing I/O error.
        const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
        opts.custom_flags(FILE_FLAG_BACKUP_SEMANTICS);
    }
    let file = opts.open(path).map_err(|e| kind.io(path, e))?;
    let meta = file.metadata().map_err(|e| kind.io(path, e))?;
    if !meta.is_file() {
        return Err(kind.not_regular(path));
    }
    if meta.len() > kind.limit() {
        return Err(kind.too_large(path));
    }
    Ok((file, meta.len()))
}

/// Opens `path` once and reads at most [`MAX_VAULT_LEN`] bytes from it, after
/// checking on the open handle that it is a regular file.
fn read_vault_file(path: &Path) -> Result<Vec<u8>, VaultError> {
    let (file, _) = open_regular(path, FileKind::Vault)?;
    // The size above can be stale (a file that grows) or untrue, so the read
    // is bounded independently.
    read_capped(file, MAX_VAULT_LEN).map_err(|e| match e {
        CapError::TooLarge => VaultError::TooLarge,
        CapError::Io(e) => FileKind::Vault.io(path, e),
    })
}

/// Reads a `.env` file for `import`: it must be a regular file (checked on
/// the open handle, so `/dev/zero`, a FIFO or a directory is refused without
/// being read) of at most [`MAX_ENV_FILE_LEN`] bytes.
///
/// The contents are plaintext secrets, so they are read straight into one
/// buffer allocated up front for exactly the size seen on the handle (plus
/// one byte to notice growth) and wiped on drop. Never growing the buffer
/// means no reallocation, and so no stray, unwiped copy of the file.
pub fn read_env_file(path: &Path) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    let (file, len) = open_regular(path, FileKind::EnvFile)?;
    let cap = usize::try_from(len).map_err(|_| FileKind::EnvFile.too_large(path))?;
    let mut buf = Zeroizing::new(Vec::with_capacity(cap + 1));
    (&file)
        .take(len + 1)
        .read_to_end(&mut buf)
        .map_err(|e| FileKind::EnvFile.io(path, e))?;
    if buf.len() > cap {
        // Grew between fstat and read: refuse rather than reallocate.
        return Err(FileKind::EnvFile.io(
            path,
            io::Error::new(
                io::ErrorKind::InvalidData,
                "file changed while it was being read",
            ),
        ));
    }
    Ok(buf)
}

enum CapError {
    TooLarge,
    Io(io::Error),
}

/// Reads `reader` to the end, failing if it yields more than `max` bytes
/// (without ever buffering more than `max + 1`).
fn read_capped(reader: impl Read, max: u64) -> Result<Vec<u8>, CapError> {
    let mut bytes = Vec::new();
    reader
        .take(max + 1)
        .read_to_end(&mut bytes)
        .map_err(CapError::Io)?;
    if bytes.len() as u64 > max {
        return Err(CapError::TooLarge);
    }
    Ok(bytes)
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
    .validate_for_open()?;
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&h[24..40]);
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&h[40..64]);
    Ok((params, salt, nonce))
}

/// An exclusive advisory lock (`flock(2)`) serialising read-modify-write
/// cycles on one vault. Released when dropped (or when the process exits).
///
/// The lock is taken on a sibling `.<vault>.lock` file rather than the vault
/// itself, because saves `rename` a new file over the vault and a lock on the
/// old inode would protect nothing. The lock file is empty, mode 0600, and is
/// intentionally never removed: deleting it would let a waiter and a newcomer
/// lock two different inodes at once.
///
/// The lock is advisory: it coordinates cloakenv processes only. It is
/// `flock` on Unix and `LockFileEx` on Windows; on any other platform it is a
/// no-op.
#[derive(Debug)]
pub struct VaultLock {
    _file: fs::File,
}

impl VaultLock {
    /// Path of the lock file guarding the vault at `vault`.
    pub fn path_for(vault: &Path) -> PathBuf {
        let mut name = std::ffi::OsString::from(".");
        name.push(vault.file_name().unwrap_or_else(|| "vault".as_ref()));
        name.push(".lock");
        vault.with_file_name(name)
    }

    /// Blocks until the exclusive lock for `vault` is acquired, creating the
    /// vault directory (0700) and lock file (0600) if needed.
    pub fn acquire(vault: &Path) -> Result<Self, VaultError> {
        let file = open_lock_file(vault)?;
        lock_file(&file, true).map_err(|e| lock_error(vault, e))?;
        remove_stale_temp_files(vault);
        Ok(Self { _file: file })
    }

    /// Like [`VaultLock::acquire`] but returns `Ok(None)` instead of
    /// blocking when another process holds the lock.
    pub fn try_acquire(vault: &Path) -> Result<Option<Self>, VaultError> {
        let file = open_lock_file(vault)?;
        match lock_file(&file, false) {
            Ok(()) => {
                remove_stale_temp_files(vault);
                Ok(Some(Self { _file: file }))
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(lock_error(vault, e)),
        }
    }
}

/// Copies the vault file at `path` to a new file next to it before it is
/// replaced (`init --force`), and returns the copy's path. The copy is named
/// `<vault file name>.bak-YYYYMMDDTHHMMSSZ` (UTC; a counter is added if that
/// name is taken), created with mode 0600, and is only ever the ciphertext. It
/// is never overwritten or removed by cloakenv, and it does not match the
/// pattern of the temporary files that are cleaned up. Fails, leaving
/// everything as it was, if the copy cannot be made.
pub fn backup_vault(path: &Path) -> Result<PathBuf, VaultError> {
    let secs = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    backup_vault_at(path, secs)
}

fn backup_vault_at(path: &Path, unix_secs: u64) -> Result<PathBuf, VaultError> {
    let mut source =
        fs::File::open(path).map_err(|e| VaultError::io("cannot back up the vault", path, e))?;
    let name = path.file_name().ok_or_else(|| {
        VaultError::io(
            "invalid vault path",
            path,
            io::ErrorKind::InvalidInput.into(),
        )
    })?;
    let stamp = utc_stamp(unix_secs);
    for attempt in 0..1000u32 {
        let mut backup_name = name.to_os_string();
        backup_name.push(format!(".bak-{stamp}"));
        if attempt > 0 {
            backup_name.push(format!("-{attempt}"));
        }
        let backup = path.with_file_name(backup_name);
        let mut dest = match open_private_file(&backup, Create::New, false) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(VaultError::io("cannot back up the vault", &backup, e)),
        };
        let copied = io::copy(&mut source, &mut dest).and_then(|_| dest.sync_all());
        if let Err(e) = copied {
            drop(dest);
            let _ = fs::remove_file(&backup);
            return Err(VaultError::io("cannot back up the vault", &backup, e));
        }
        return Ok(backup);
    }
    Err(VaultError::io(
        "cannot back up the vault (too many backups with this timestamp)",
        path,
        io::ErrorKind::AlreadyExists.into(),
    ))
}

/// `YYYYMMDDTHHMMSSZ` for a Unix time, in UTC (civil-from-days, after
/// H. Hinnant), so that no date library is needed for one file name.
fn utc_stamp(unix_secs: u64) -> String {
    let days = i64::try_from(unix_secs / 86_400).unwrap_or(0);
    let rem = unix_secs % 86_400;
    let (hour, minute, second) = (rem / 3600, rem % 3600 / 60, rem % 60);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let mp = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    format!("{year:04}{month:02}{day:02}T{hour:02}{minute:02}{second:02}Z")
}

/// A temporary file left by a save that was killed (`SIGKILL`, power loss, an
/// out-of-memory kill) between creating it and renaming it over the vault is
/// never reused and never removed by the save that made it. It holds only
/// ciphertext, but it is as large as the vault and would stay forever. Every
/// writer holds the lock for its whole load-modify-save cycle, so the one that
/// has just taken it removes such leftovers.
///
/// Deliberately conservative: only a *regular file* (not a link, not a
/// directory) whose name is exactly what a save generates for this vault
/// (`.<vault file name>.tmp-` and twelve lowercase hex digits), owned by the
/// current user, and not modified for [`STALE_TEMP_AFTER`], is removed. Errors
/// are ignored: cleaning up must never make a save fail.
fn remove_stale_temp_files(vault: &Path) {
    let Some(vault_name) = vault.file_name() else {
        return;
    };
    let Ok(entries) = fs::read_dir(parent_dir(vault)) else {
        return;
    };
    for entry in entries.flatten() {
        let Ok(meta) = fs::symlink_metadata(entry.path()) else {
            continue;
        };
        if is_stale_temp_file(&entry.file_name(), vault_name, &meta, SystemTime::now()) {
            let _ = fs::remove_file(entry.path());
        }
    }
}

/// How long a temporary file must have been untouched before it counts as
/// abandoned. A live save writes and renames it within seconds.
pub const STALE_TEMP_AFTER: Duration = Duration::from_secs(5 * 60);

/// Does `name`, with metadata `meta`, look like an abandoned temporary file
/// of the vault called `vault_name`? See [`remove_stale_temp_files`].
fn is_stale_temp_file(
    name: &std::ffi::OsStr,
    vault_name: &std::ffi::OsStr,
    meta: &fs::Metadata,
    now: SystemTime,
) -> bool {
    if !meta.file_type().is_file() {
        return false; // a directory, a symlink, a socket...: never ours
    }
    if !is_temp_file_name(name, vault_name) {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.uid() != rustix::process::geteuid().as_raw() {
            return false;
        }
    }
    meta.modified()
        .ok()
        .and_then(|modified| now.duration_since(modified).ok())
        .is_some_and(|age| age >= STALE_TEMP_AFTER)
}

/// True for exactly the names `write_atomic_private` generates for the vault
/// `vault_name`: `.`, the name, `.tmp-` and twelve lowercase hex digits.
fn is_temp_file_name(name: &std::ffi::OsStr, vault_name: &std::ffi::OsStr) -> bool {
    let (Some(name), Some(vault_name)) = (name.to_str(), vault_name.to_str()) else {
        return false;
    };
    let Some(rest) = name
        .strip_prefix('.')
        .and_then(|n| n.strip_prefix(vault_name))
        .and_then(|n| n.strip_prefix(".tmp-"))
    else {
        return false;
    };
    rest.len() == 12 && rest.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn lock_error(vault: &Path, e: io::Error) -> VaultError {
    VaultError::io("cannot lock vault", &VaultLock::path_for(vault), e)
}

fn open_lock_file(vault: &Path) -> Result<fs::File, VaultError> {
    let parent = parent_dir(vault);
    create_private_dir(&parent)
        .map_err(|e| VaultError::io("cannot create vault directory", &parent, e))?;
    let lock_path = VaultLock::path_for(vault);
    // Rust opens files with O_CLOEXEC, so the lock never leaks into children.
    open_private_file(&lock_path, Create::OpenOrCreate, true)
        .map_err(|e| VaultError::io("cannot open vault lock", &lock_path, e))
}

#[cfg(unix)]
fn lock_file(file: &fs::File, block: bool) -> io::Result<()> {
    use rustix::fs::{FlockOperation, flock};
    let op = if block {
        FlockOperation::LockExclusive
    } else {
        FlockOperation::NonBlockingLockExclusive
    };
    loop {
        match flock(file, op) {
            Err(rustix::io::Errno::INTR) => continue,
            other => return other.map_err(io::Error::from),
        }
    }
}

#[cfg(windows)]
fn lock_file(file: &fs::File, block: bool) -> io::Result<()> {
    crate::winsys::lock_file(file, block)
}

/// No locking primitive is wired up for this platform.
#[cfg(not(any(unix, windows)))]
fn lock_file(_file: &fs::File, _block: bool) -> io::Result<()> {
    Ok(())
}

fn parent_dir(path: &Path) -> PathBuf {
    vault_dir(path)
}

/// The directory that holds the vault at `vault` (`.` for a bare file name).
pub fn vault_dir(vault: &Path) -> PathBuf {
    match vault.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

/// Contents of the `.gitignore` written next to a new vault: everything in
/// the directory (including the `.gitignore` itself) is ignored by git.
pub const GITIGNORE_CONTENTS: &str = "*\n";

/// Writes `<vault dir>/.gitignore` containing `*`, so a plain `git add .`
/// can never pick up the vault (committed ciphertext can be attacked offline
/// with passphrase guesses).
///
/// This is only done for a directory that is plainly cloakenv's own: one named
/// `.cloak` (the default), or one that did not exist before this `init`
/// (`dir_preexisted` is false). For a vault dropped into some existing
/// directory such as the project root, a `*` ignore file would hide the whole
/// project, so nothing is written.
///
/// An existing `.gitignore` is never touched and a symlink at that path is
/// never followed (`O_EXCL`). Returns whether a file was written.
pub fn write_gitignore(vault: &Path, dir_preexisted: bool) -> io::Result<bool> {
    let dir = vault_dir(vault);
    let ours = dir.file_name().is_some_and(|n| n == ".cloak") || !dir_preexisted;
    if !ours {
        return Ok(false);
    }
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    match opts.open(dir.join(".gitignore")) {
        Ok(mut f) => {
            f.write_all(GITIGNORE_CONTENTS.as_bytes())?;
            Ok(true)
        }
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(false),
        Err(e) => Err(e),
    }
}

/// Writes `bytes` to a sibling temp file created with mode 0600, fsyncs it,
/// then renames it over `path`. Only ever used for ciphertext.
fn write_atomic_private(path: &Path, bytes: &[u8]) -> Result<(), VaultError> {
    let parent = parent_dir(path);
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
        let mut f = open_private_file(&tmp, Create::New, false)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        drop(f);
        replace_file(&tmp, path)?;
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

/// Renames `from` over `to`. On Windows this also waits for the move to reach
/// the disk (the counterpart of the directory fsync on Unix).
fn replace_file(from: &Path, to: &Path) -> io::Result<()> {
    #[cfg(windows)]
    {
        crate::winsys::replace_file(from, to)
    }
    #[cfg(not(windows))]
    {
        fs::rename(from, to)
    }
}

/// Whether `open_private_file` may open a file that already exists.
#[derive(Clone, Copy)]
enum Create {
    /// Fail with `AlreadyExists` if the file is there.
    New,
    /// Open the file, creating it if it is missing.
    OpenOrCreate,
}

/// Opens (and if need be creates) a file for writing, plus reading if `read`,
/// that only its creator may use: mode 0600 on Unix, and on Windows a protected
/// ACL for the current user, SYSTEM and Administrators only, set at creation.
/// An existing file keeps its mode or ACL.
fn open_private_file(path: &Path, how: Create, read: bool) -> io::Result<fs::File> {
    #[cfg(windows)]
    {
        crate::winsys::open_private_file(path, matches!(how, Create::New), read)
    }
    #[cfg(not(windows))]
    {
        let mut opts = fs::OpenOptions::new();
        opts.read(read).write(true);
        match how {
            Create::New => opts.create_new(true),
            Create::OpenOrCreate => opts.create(true).truncate(false),
        };
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        opts.open(path)
    }
}

/// Creates `dir` and missing parents that only their creator may use: mode 0700
/// on Unix, and on Windows a protected ACL for the current user, SYSTEM and
/// Administrators only. An existing directory is left as it is.
fn create_private_dir(dir: &Path) -> io::Result<()> {
    #[cfg(windows)]
    {
        crate::winsys::create_private_dir(dir)
    }
    #[cfg(not(windows))]
    {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(dir)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a vault file the way an older version would have: with
    /// arbitrary (valid-for-open) KDF parameters.
    fn legacy_vault_bytes(params: KdfParams, pass: &[u8], entries: &[(&str, &str)]) -> Vec<u8> {
        let mut v = Vault::new();
        for (k, val) in entries {
            v.set(k, Zeroizing::new((*val).to_owned())).unwrap();
        }
        let salt = [3u8; SALT_LEN];
        let nonce = [4u8; NONCE_LEN];
        let header = encode_header(params, &salt, &nonce);
        let key = crypto::derive_key(pass, &salt, params).unwrap();
        let ct = crypto::seal(&key, &nonce, &header, &v.encode_payload()).unwrap();
        [header.as_slice(), &ct].concat()
    }

    #[test]
    fn new_vaults_must_meet_the_current_minimum() {
        assert!(Vault::with_params(KdfParams::FLOOR).is_err());
        assert!(Vault::with_params(KdfParams::MIN).is_ok());
        assert!(Vault::with_params(KdfParams::DEFAULT).is_ok());
    }

    #[test]
    fn legacy_weak_vault_loads_and_is_never_written_back_weak() {
        let bytes = legacy_vault_bytes(KdfParams::FLOOR, b"pw", &[("A", "1")]);
        let mut v = Vault::open(&bytes, b"pw").unwrap();
        assert_eq!(v.params(), KdfParams::FLOOR);
        assert_eq!(v.get("A"), Some("1"));

        // A plain save never writes below MIN...
        let resealed = v.seal(b"pw").unwrap();
        let (p, _, _) = decode_header(&resealed[..HEADER_LEN]).unwrap();
        assert_eq!(p, KdfParams::MIN);
        // ...and the explicit upgrade moves it to (at least) the default.
        assert!(v.upgrade_kdf_params());
        assert_eq!(v.params(), KdfParams::DEFAULT);
        assert!(!v.upgrade_kdf_params(), "already upgraded");
        let resealed = v.seal(b"pw").unwrap();
        let (p, _, _) = decode_header(&resealed[..HEADER_LEN]).unwrap();
        assert_eq!(p, KdfParams::DEFAULT);
        assert_eq!(Vault::open(&resealed, b"pw").unwrap().get("A"), Some("1"));
    }

    #[test]
    fn upgrade_never_lowers_a_stronger_setting() {
        let strong = KdfParams {
            m_cost_kib: 128 * 1024,
            t_cost: 2,
            p_cost: 2,
        };
        let mut v = Vault::with_params(strong).unwrap();
        assert!(v.upgrade_kdf_params());
        assert_eq!(
            v.params(),
            KdfParams {
                m_cost_kib: 128 * 1024,
                t_cost: KdfParams::DEFAULT.t_cost,
                p_cost: 2,
            }
        );
    }

    #[test]
    fn header_below_the_floor_is_rejected_on_open() {
        let weak = KdfParams {
            m_cost_kib: 4 * 1024,
            ..KdfParams::FLOOR
        };
        let mut h = encode_header(weak, &[0; SALT_LEN], &[0; NONCE_LEN]).to_vec();
        h.extend_from_slice(&[0u8; 32]);
        assert!(matches!(
            Vault::open(&h, b"pw"),
            Err(VaultError::Crypto(CryptoError::InvalidKdfParams { .. }))
        ));
    }

    #[test]
    fn read_is_capped_even_for_an_endless_stream() {
        // An endless reader (what /dev/zero would be) stops at max + 1 bytes.
        assert!(matches!(
            read_capped(io::repeat(0), 1000),
            Err(CapError::TooLarge)
        ));
        assert_eq!(
            read_capped(&[7u8; 1000][..], 1000).ok().unwrap().len(),
            1000
        );
        assert!(matches!(
            read_capped(&[7u8; 1001][..], 1000),
            Err(CapError::TooLarge)
        ));
        assert!(read_capped(io::empty(), 1000).ok().unwrap().is_empty());
    }

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

    #[test]
    fn gitignore_failure_is_reported_not_panicked() {
        let t = tempfile::tempdir().unwrap();
        // The directory does not exist, so the file cannot be created.
        let vault = t.path().join("missing").join("vault.bin");
        assert!(write_gitignore(&vault, false).is_err());
        // An ordinary pre-existing directory that is not `.cloak` is left alone.
        let vault = t.path().join("vault.bin");
        assert!(!write_gitignore(&vault, true).unwrap());
        assert!(!t.path().join(".gitignore").exists());
    }

    #[test]
    fn vault_lock_is_exclusive_and_released_on_drop() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join("sub").join("vault.bin");
        let held = VaultLock::acquire(&vault).unwrap();
        let lock_path = VaultLock::path_for(&vault);
        assert_eq!(lock_path, dir.path().join("sub").join(".vault.bin.lock"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&lock_path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        // flock and LockFileEx locks belong to the open handle, so a second
        // open in the same process contends exactly like another process would.
        assert!(VaultLock::try_acquire(&vault).unwrap().is_none());

        let waiter = std::thread::spawn({
            let vault = vault.clone();
            move || VaultLock::acquire(&vault).unwrap()
        });
        std::thread::sleep(std::time::Duration::from_millis(100));
        assert!(!waiter.is_finished(), "acquire must block while held");
        drop(held);
        let second = waiter.join().unwrap();
        assert!(VaultLock::try_acquire(&vault).unwrap().is_none());
        drop(second);
        assert!(VaultLock::try_acquire(&vault).unwrap().is_some());
    }

    #[cfg(unix)]
    #[test]
    fn lock_fd_is_close_on_exec() {
        // A command started while a lock is held (or any child of a writer)
        // must not inherit the lock: it would keep the vault locked after
        // cloakenv exits.
        let dir = tempfile::tempdir().unwrap();
        let lock = VaultLock::acquire(&dir.path().join("vault.bin")).unwrap();
        let flags = rustix::io::fcntl_getfd(&lock._file).unwrap();
        assert!(flags.contains(rustix::io::FdFlags::CLOEXEC));
    }

    #[test]
    fn env_file_reads_are_bounded_and_regular_only() {
        let dir = tempfile::tempdir().unwrap();
        let ok = dir.path().join("a.env");
        fs::write(&ok, "A=1\n").unwrap();
        assert_eq!(&**read_env_file(&ok).unwrap(), b"A=1\n");
        let empty = dir.path().join("empty.env");
        fs::write(&empty, "").unwrap();
        assert!(read_env_file(&empty).unwrap().is_empty());
        assert!(matches!(
            read_env_file(dir.path()),
            Err(VaultError::EnvNotRegularFile(_))
        ));
        assert!(matches!(
            read_env_file(&dir.path().join("missing")),
            Err(VaultError::Io { .. })
        ));
        // One byte over the limit is refused from the size alone, one byte
        // under is read (sparse files keep this cheap).
        let big = dir.path().join("big.env");
        let f = fs::File::create(&big).unwrap();
        f.set_len(MAX_ENV_FILE_LEN + 1).unwrap();
        assert!(matches!(
            read_env_file(&big),
            Err(VaultError::EnvTooLarge(_))
        ));
        f.set_len(MAX_ENV_FILE_LEN).unwrap();
        assert_eq!(read_env_file(&big).unwrap().len() as u64, MAX_ENV_FILE_LEN);
    }

    fn big(key: &str, value_len: usize) -> (String, Zeroizing<String>) {
        (key.to_owned(), Zeroizing::new("v".repeat(value_len)))
    }

    #[test]
    fn one_variable_may_be_at_most_128_kib_minus_one_as_key_equals_value() {
        let mut v = Vault::new();
        // "BIG" + "=" + value: exactly at the limit is fine...
        let (k, ok) = big("BIG", MAX_ENV_ENTRY_LEN - 4);
        v.set(&k, ok).unwrap();
        // ...one byte more is refused, naming the key and never the value.
        let (k, over) = big("BIG", MAX_ENV_ENTRY_LEN - 3);
        match v.set(&k, over) {
            Err(e @ VaultError::EntryTooLarge { .. }) => {
                let shown = e.to_string();
                assert!(shown.contains("BIG") && shown.contains("131071"), "{shown}");
                assert!(!shown.contains("vvvv"), "{shown}");
            }
            other => panic!("unexpected {other:?}"),
        }
        // The key counts: a longer key leaves less room for the value.
        let (k, ok) = big("LONGER_KEY", MAX_ENV_ENTRY_LEN - 11);
        v.set(&k, ok).unwrap();
        let (k, over) = big("LONGER_KEY", MAX_ENV_ENTRY_LEN - 10);
        assert!(matches!(
            v.set(&k, over),
            Err(VaultError::EntryTooLarge { .. })
        ));
        // A refused entry changes nothing.
        assert_eq!(v.len(), 2);
    }

    #[test]
    fn entry_checks_cover_name_nul_and_size_without_echoing_the_value() {
        assert!(matches!(
            check_entry("1BAD", "x"),
            Err(VaultError::InvalidKey)
        ));
        assert!(matches!(
            check_entry("K", "a\0b"),
            Err(VaultError::NulInValue(k)) if k == "K"
        ));
        assert!(check_entry("K", "").is_ok());
    }

    /// A vault whose sealed size is exactly MAX_VAULT_LEN plus extra.
    fn vault_of_sealed_len(extra: u64) -> Vault {
        let mut v = Vault::new();
        let fixed = v.sealed_len();
        let target = MAX_VAULT_LEN + extra;
        let mut remaining = target - fixed;
        let mut i = 0;
        while remaining > 0 {
            // Each entry costs 8 bytes of framing + key + value.
            let key = format!("K{i:04}");
            let overhead = 8 + key.len() as u64;
            let value_len = (remaining - overhead).min(100_000);
            let (k, val) = big(&key, value_len as usize);
            v.set(&k, val).unwrap();
            remaining -= overhead + value_len;
            i += 1;
        }
        assert_eq!(v.sealed_len(), target);
        v
    }

    #[test]
    fn a_vault_of_exactly_16_mib_is_saved_and_opened_again_and_one_byte_more_is_refused() {
        let at_limit = vault_of_sealed_len(0);
        assert!(at_limit.check_size().is_ok());
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.bin");
        at_limit.save(&path, b"pw").unwrap();
        assert_eq!(fs::metadata(&path).unwrap().len(), MAX_VAULT_LEN);
        let back = Vault::load(&path, b"pw").unwrap();
        assert_eq!(back.len(), at_limit.len());

        // One byte over: refused before anything is written.
        let over = vault_of_sealed_len(1);
        let other = dir.path().join("over.bin");
        match over.save(&other, b"pw") {
            Err(e @ VaultError::VaultFull { size }) => {
                assert_eq!(size, MAX_VAULT_LEN + 1);
                assert!(e.to_string().contains("16 MiB"), "{e}");
            }
            other => panic!("unexpected {other:?}"),
        }
        assert!(!other.exists(), "nothing may be written");
        // No temporary file is left behind either.
        let names: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names.len(), 1, "{names:?}");
    }

    #[test]
    fn sealed_len_is_the_real_file_size() {
        let mut v = Vault::new();
        assert_eq!(v.seal(b"pw").unwrap().len() as u64, v.sealed_len());
        v.set("A", Zeroizing::new("1".into())).unwrap();
        v.set("B", Zeroizing::new("ünï🔐".into())).unwrap();
        assert_eq!(v.seal(b"pw").unwrap().len() as u64, v.sealed_len());
    }

    /// A vault written before the per-variable limit existed can hold an
    /// entry that no command can be started with; opening it still works and
    /// the run-time check names the key.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn an_old_vault_with_an_oversized_entry_opens_and_run_names_the_key() {
        let value = "s3cr3t".repeat(30_000);
        let mut payload = Vec::new();
        payload.extend_from_slice(&1u32.to_le_bytes());
        payload.extend_from_slice(&3u32.to_le_bytes());
        payload.extend_from_slice(b"OLD");
        payload.extend_from_slice(&(value.len() as u32).to_le_bytes());
        payload.extend_from_slice(value.as_bytes());
        let vault = Vault::decode_payload(&payload, KdfParams::MIN).unwrap();
        assert_eq!(vault.len(), 1);
        let err = crate::envcheck::check_run_environment(&vault, &[]).unwrap_err();
        let shown = err.to_string();
        assert!(shown.starts_with("OLD: the variable would be"), "{shown}");
        assert!(!shown.contains("s3cr3t"), "{shown}");
    }

    fn touch(path: &Path, age: Duration) {
        let f = fs::File::create(path).unwrap();
        f.set_modified(SystemTime::now() - age).unwrap();
    }

    #[test]
    fn temp_file_names_are_matched_exactly() {
        use std::ffi::OsStr;
        let yes = |n: &str| is_temp_file_name(OsStr::new(n), OsStr::new("vault.bin"));
        assert!(yes(".vault.bin.tmp-0123456789ab"));
        assert!(yes(".vault.bin.tmp-ffffffffffff"));
        assert!(!yes(".vault.bin.tmp-0123456789a")); // 11 digits
        assert!(!yes(".vault.bin.tmp-0123456789abc")); // 13
        assert!(!yes(".vault.bin.tmp-0123456789AB")); // upper case
        assert!(!yes(".vault.bin.tmp-0123456789ag")); // not hex
        assert!(!yes("vault.bin.tmp-0123456789ab")); // no leading dot
        assert!(!yes(".vault.bin.tmp-0123456789ab.keep"));
        assert!(!yes(".vault.bin.lock"));
        assert!(!yes(".other.bin.tmp-0123456789ab")); // another vault's
        assert!(!yes(".vault.bin.tmp-"));
        assert!(!yes("vault.bin"));
        // The generated name is always recognised.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.bin");
        Vault::new().save(&path, b"pw").unwrap();
        // (a successful save leaves nothing behind)
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn taking_the_lock_removes_only_old_leftover_temp_files_of_this_vault() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let vault = d.join("vault.bin");
        Vault::new().save(&vault, b"pw").unwrap();
        let hour = Duration::from_secs(3600);

        let stale = d.join(".vault.bin.tmp-0123456789ab");
        touch(&stale, hour);
        let stale_too = d.join(".vault.bin.tmp-ffffffffffff");
        touch(&stale_too, STALE_TEMP_AFTER + Duration::from_secs(5));
        // Everything below must survive.
        let fresh = d.join(".vault.bin.tmp-0123456789ac");
        touch(&fresh, Duration::from_secs(10)); // a save that may still be running
        let almost = d.join(".vault.bin.tmp-0123456789ad");
        touch(&almost, STALE_TEMP_AFTER - Duration::from_secs(60));
        let others = [
            ".vault.bin.tmp-xyz",
            // (upper case, but a different name from every file above, since
            // a case-insensitive file system, macOS, would merge the two)
            ".vault.bin.tmp-FEDCBA987654",
            ".vault.bin.tmp-0123456789abc",
            "vault.bin.tmp-0123456789ab",
            ".other.bin.tmp-0123456789ab",
            ".vault.bin.tmp-0123456789ab.keep",
            "notes.txt",
        ];
        for name in others {
            touch(&d.join(name), hour);
        }
        // A directory and a symbolic link with a matching name are never removed.
        let dir_named = d.join(".vault.bin.tmp-0123456789ae");
        fs::create_dir(&dir_named).unwrap();
        #[cfg(unix)]
        let (link, target) = {
            let target = d.join("precious.txt");
            touch(&target, hour);
            let link = d.join(".vault.bin.tmp-0123456789af");
            std::os::unix::fs::symlink(&target, &link).unwrap();
            (link, target)
        };

        let _lock = VaultLock::acquire(&vault).unwrap();

        assert!(
            !stale.exists() && !stale_too.exists(),
            "stale files must go"
        );
        assert!(fresh.exists() && almost.exists(), "recent files must stay");
        for name in others {
            assert!(d.join(name).exists(), "{name} must stay");
        }
        assert!(dir_named.is_dir());
        #[cfg(unix)]
        {
            assert!(fs::symlink_metadata(&link).is_ok(), "the link must stay");
            assert!(target.exists());
        }
        assert!(vault.exists());
        assert!(VaultLock::path_for(&vault).exists());
        assert!(Vault::load(&vault, b"pw").is_ok());
    }

    #[test]
    fn try_acquire_cleans_too_and_another_vaults_files_are_left_alone() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let hour = Duration::from_secs(3600);
        let mine = d.join("a.bin");
        let theirs = d.join("b.bin");
        touch(&d.join(".a.bin.tmp-000000000001"), hour);
        touch(&d.join(".b.bin.tmp-000000000001"), hour);
        let lock = VaultLock::try_acquire(&mine).unwrap();
        assert!(lock.is_some());
        assert!(!d.join(".a.bin.tmp-000000000001").exists());
        assert!(d.join(".b.bin.tmp-000000000001").exists());
        // A lock that could not be taken cleans nothing.
        touch(&d.join(".a.bin.tmp-000000000002"), hour);
        assert!(VaultLock::try_acquire(&mine).unwrap().is_none());
        assert!(d.join(".a.bin.tmp-000000000002").exists());
        drop(lock);
        let _ = theirs;
    }

    #[test]
    fn utc_stamps_are_right_around_leap_days_and_epochs() {
        for (secs, want) in [
            (0, "19700101T000000Z"),
            (86_399, "19700101T235959Z"),
            (951_782_400, "20000229T000000Z"),
            (1_000_000_000, "20010909T014640Z"),
            (1_700_000_000, "20231114T221320Z"),
            (4_102_444_800, "21000101T000000Z"),
        ] {
            assert_eq!(utc_stamp(secs), want, "{secs}");
        }
    }

    #[test]
    fn a_backup_is_a_private_byte_for_byte_copy_and_never_overwrites() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join("vault.bin");
        let mut v = Vault::new();
        v.set("K", Zeroizing::new("old secret".into())).unwrap();
        v.save(&vault, b"old passphrase").unwrap();
        let original = fs::read(&vault).unwrap();

        let first = backup_vault_at(&vault, 1_700_000_000).unwrap();
        let second = backup_vault_at(&vault, 1_700_000_000).unwrap();
        assert_eq!(first.file_name().unwrap(), "vault.bin.bak-20231114T221320Z");
        assert_eq!(
            second.file_name().unwrap(),
            "vault.bin.bak-20231114T221320Z-1"
        );
        for b in [&first, &second] {
            assert_eq!(fs::read(b).unwrap(), original);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(fs::metadata(b).unwrap().permissions().mode() & 0o777, 0o600);
            }
        }
        // The copy is a vault in its own right, under the old passphrase.
        assert_eq!(Vault::load(&first, b"old passphrase").unwrap().len(), 1);
        // The original is untouched, and a missing vault is an error.
        assert_eq!(fs::read(&vault).unwrap(), original);
        assert!(backup_vault_at(&dir.path().join("nope.bin"), 0).is_err());
        // A backup never looks like a temporary file to the cleanup.
        let name = first.file_name().unwrap();
        assert!(!is_temp_file_name(name, std::ffi::OsStr::new("vault.bin")));
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
