//! Process-level hardening applied by the CLI before it touches any secret.
//!
//! On Linux, cloakenv marks itself non-dumpable (`PR_SET_DUMPABLE = 0`).
//! This makes the kernel treat every `/proc/<pid>` entry that needs
//! ptrace-level access as root-owned, so other processes running as the same
//! user (including the very commands `cloakenv run` spawns) can no longer:
//!
//! * read `/proc/<pid>/environ`, which holds `CLOAKENV_PASSPHRASE` or the
//!   `CLOAKENV_PASSPHRASE_FILE` path;
//! * read `/proc/<pid>/mem` or attach with `ptrace` to scrape decrypted
//!   secrets from memory;
//! * open `/proc/<pid>/fd/1` to write straight to cloakenv's own stdout and
//!   bypass `--shield` redaction;
//! * receive a core dump containing plaintext secrets if cloakenv crashes.
//!
//! The flag is reset by `execve`, so spawned commands run with their normal
//! dumpable state. Root (`CAP_SYS_PTRACE`) is unaffected, as always.
//!
//! On other platforms (including macOS) this is a no-op, so none of the
//! protections above apply there; see "Platform support" in the README and
//! `docs/ARCHITECTURE.md`.

use std::io;

/// Applies the hardening described in the module docs. Callers should treat
/// failure as fatal (fail closed).
pub fn harden_process() -> io::Result<()> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        use rustix::process::{DumpableBehavior, set_dumpable_behavior};
        set_dumpable_behavior(DumpableBehavior::NotDumpable)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn process_becomes_non_dumpable() {
        use rustix::process::{DumpableBehavior, dumpable_behavior};

        super::harden_process().unwrap();
        assert_eq!(dumpable_behavior().unwrap(), DumpableBehavior::NotDumpable);
        // Idempotent.
        super::harden_process().unwrap();
    }
}
