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
/// Upper bound on the size of a `.env` file `import` will read (16 MiB).
pub const MAX_ENV_FILE_LEN: u64 = 16 * 1024 * 1024;

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
    /// directory if needed. On Unix the file has mode 0600 and a directory
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
/// The lock is advisory: it coordinates cloakenv processes only. On non-Unix
/// platforms it is currently a no-op.
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
        Ok(Self { _file: file })
    }

    /// Like [`VaultLock::acquire`] but returns `Ok(None)` instead of
    /// blocking when another process holds the lock.
    pub fn try_acquire(vault: &Path) -> Result<Option<Self>, VaultError> {
        let file = open_lock_file(vault)?;
        match lock_file(&file, false) {
            Ok(()) => Ok(Some(Self { _file: file })),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(lock_error(vault, e)),
        }
    }
}

fn lock_error(vault: &Path, e: io::Error) -> VaultError {
    VaultError::io("cannot lock vault", &VaultLock::path_for(vault), e)
}

fn open_lock_file(vault: &Path) -> Result<fs::File, VaultError> {
    let parent = parent_dir(vault);
    create_private_dir(&parent)
        .map_err(|e| VaultError::io("cannot create vault directory", &parent, e))?;
    let lock_path = VaultLock::path_for(vault);
    let mut opts = fs::OpenOptions::new();
    // Rust opens files with O_CLOEXEC, so the lock never leaks into children.
    opts.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(&lock_path)
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

#[cfg(not(unix))]
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
/// unquoted values (the earliest trailing ` #` or `\t#` comment is stripped),
/// single-quoted literal values and double-quoted values with `\n \r \t \\ \"`
/// escapes. Multi-line values are not supported. Errors reference line numbers
/// only, never content.
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
            // Earliest marker wins. `or_else` would ignore a leading `\t#`
            // whenever a later ` #` is also present.
            let value = match rest.find(" #").into_iter().chain(rest.find("\t#")).min() {
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
    fn unquoted_comment_uses_earliest_marker() {
        let cases = [
            ("TAB=val\t# comment\n", "TAB", "val"),
            ("BOTH=val\t#comment #note\n", "BOTH", "val"),
            ("SPACE_FIRST=val #note\t#later\n", "SPACE_FIRST", "val"),
            ("HASH=abc#def\n", "HASH", "abc#def"),
        ];
        for (input, key, value) in cases {
            assert_eq!(
                parsed(input),
                vec![(key.to_owned(), value.to_owned())],
                "{input:?}"
            );
        }
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

    #[cfg(unix)]
    #[test]
    fn vault_lock_is_exclusive_and_released_on_drop() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join("sub").join("vault.bin");
        let held = VaultLock::acquire(&vault).unwrap();
        let lock_path = VaultLock::path_for(&vault);
        assert_eq!(lock_path, dir.path().join("sub").join(".vault.bin.lock"));
        let mode = fs::metadata(&lock_path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        // flock locks belong to the open file description, so a second open in
        // the same process contends exactly like another process would.
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
