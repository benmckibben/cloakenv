//! `cloakenv`: a lightweight encrypted local secret vault and zero-leak
//! process injection engine.
//!
//! The crate is split into three layers:
//!
//! * [`crypto`]: Argon2id key derivation and XChaCha20-Poly1305 AEAD.
//! * [`dotenv`]: the `.env` grammar of `import`.
//! * [`vault`]: the on-disk vault format, in-memory key/value storage and
//!   `.env` import parsing.
//! * [`runner`]: running commands with secrets injected straight into their
//!   environment (replacing cloakenv with the command via `exec`, or, under
//!   `--shield`, supervising it as a child with signal forwarding), plus the
//!   `--shield` streaming redactor.
//! * [`input`]: reading secret text (stdin, passphrase files) into a single
//!   wiped buffer, with a size cap.
//! * [`envcheck`]: pre-flight checks of the environment `run` will build.
//! * [`prompt`]: the hidden terminal prompt, with the terminal restored on every exit.
//! * [`hardening`]: process-level protections (non-dumpable on Linux) applied
//!   before any secret is handled.
//! * [`perms`]: advisory warnings about loose permissions on the vault, its
//!   directory and the passphrase file (Unix).
//!
//! Invariant: decrypted secret values only ever live in process memory
//! (wrapped in [`zeroize::Zeroizing`]) and in the child's environment block.
//! They are never written to disk, and never included in error messages.

// `unsafe` is denied crate-wide; the few calls that need it live in `sys`
// (Unix only), each with a SAFETY comment.
#![deny(unsafe_code)]

pub mod crypto;
pub mod diag;
pub mod dotenv;
pub mod envcheck;
#[cfg(unix)]
mod fdio;
pub mod hardening;
pub mod input;
pub mod passphrase;
pub mod perms;
pub mod prompt;
pub mod runner;
#[cfg(unix)]
mod supervise;
#[cfg(unix)]
mod sys;
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
