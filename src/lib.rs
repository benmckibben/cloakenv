//! `cloakenv`: a lightweight encrypted local secret vault and zero-leak
//! process injection engine.
//!
//! The crate is split into three layers:
//!
//! * [`crypto`]: Argon2id key derivation and XChaCha20-Poly1305 AEAD.
//! * [`vault`]: the on-disk vault format, in-memory key/value storage and
//!   `.env` import parsing.
//! * [`runner`]: spawning child processes with secrets injected straight into
//!   their environment, plus the `--shield` streaming redactor.
//! * [`hardening`]: process-level protections (non-dumpable on Linux) applied
//!   before any secret is handled.
//!
//! Invariant: decrypted secret values only ever live in process memory
//! (wrapped in [`zeroize::Zeroizing`]) and in the child's environment block.
//! They are never written to disk, and never included in error messages.

#![forbid(unsafe_code)]

pub mod crypto;
pub mod hardening;
pub mod runner;
pub mod vault;

/// Environment variable consulted for the vault passphrase.
///
/// It is always stripped from the environment of child processes.
pub const PASSPHRASE_ENV: &str = "CLOAKENV_PASSPHRASE";

/// Environment variable naming a file whose contents are the vault passphrase
/// (e.g. a machine-local random key file). Also stripped from children.
pub const PASSPHRASE_FILE_ENV: &str = "CLOAKENV_PASSPHRASE_FILE";

/// True for the names cloakenv reads its own passphrase from. They are always
/// stripped from child environments, so the CLI refuses to store them: a
/// vault entry under either name would be silently dropped at `run` time.
pub fn is_reserved_key(key: &str) -> bool {
    key == PASSPHRASE_ENV || key == PASSPHRASE_FILE_ENV
}
