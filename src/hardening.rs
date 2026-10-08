//! Process-level hardening applied by the CLI before it touches any secret.
//!
//! On Linux, cloakenv marks itself non-dumpable (`PR_SET_DUMPABLE = 0`).
//! This makes the kernel treat every `/proc/<pid>` entry that needs
//! ptrace-level access as root-owned, so other processes running as the same
//! user (including the very commands `cloakenv run --shield` spawns) can no
//! longer:
//!
//! * read `/proc/<pid>/environ`, which holds `CLOAKENV_PASSPHRASE` or the
//!   `CLOAKENV_PASSPHRASE_FILE` path;
//! * read `/proc/<pid>/mem` or attach with `ptrace` to scrape decrypted
//!   secrets from memory;
//! * open `/proc/<pid>/fd/1` to write straight to cloakenv's own stdout and
//!   bypass `--shield` redaction;
//! * receive a core dump containing plaintext secrets if cloakenv crashes.
//!
//! On every Unix (Linux and macOS) cloakenv also lowers its *soft* core-file
//! size limit to 0. Non-dumpable already prevents a core file on a default
//! Linux configuration, but with `fs.suid_dumpable=2` (a common distribution
//! default when a crash reporter is installed) the kernel writes a
//! root-readable core for non-dumpable processes anyway, and macOS has no
//! dumpable flag at all; a zero limit stops both. The hard limit is left
//! alone, and the original soft limit is handed back to the commands cloakenv
//! starts (`saved_core_limit`), so they keep dumping core exactly as if
//! they had been started directly.
//!
//! The dumpable flag is reset by `execve`, so spawned commands run with their
//! normal dumpable state. Root (`CAP_SYS_PTRACE`) is unaffected, as always.
//!
//! On other platforms (including macOS) the dumpable part is a no-op, so the
//! `/proc`/ptrace protections above do not apply there; see "Platform
//! support" in the README and `docs/ARCHITECTURE.md`.

use std::io;

#[cfg(unix)]
use rustix::process::Rlimit;

/// The core-file limit cloakenv inherited, recorded the first time
/// [`harden_process`] lowers it.
#[cfg(unix)]
static ORIGINAL_CORE_LIMIT: std::sync::OnceLock<Rlimit> = std::sync::OnceLock::new();

/// Applies the hardening described in the module docs. Callers should treat
/// failure as fatal (fail closed).
pub fn harden_process() -> io::Result<()> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        use rustix::process::{DumpableBehavior, set_dumpable_behavior};
        set_dumpable_behavior(DumpableBehavior::NotDumpable)?;
    }
    #[cfg(unix)]
    {
        use rustix::process::{Resource, getrlimit, setrlimit};
        // Recorded once: a second call must not overwrite the real original
        // with the zero we set the first time.
        let original = *ORIGINAL_CORE_LIMIT.get_or_init(|| getrlimit(Resource::Core));
        setrlimit(
            Resource::Core,
            Rlimit {
                current: Some(0),
                maximum: original.maximum,
            },
        )?;
    }
    Ok(())
}

/// The core-file limit to give back to a command started by cloakenv, or
/// `None` if [`harden_process`] has not lowered it.
#[cfg(unix)]
pub fn saved_core_limit() -> Option<Rlimit> {
    ORIGINAL_CORE_LIMIT.get().copied()
}

/// Gives the current process back the core-file limit it had before
/// [`harden_process`]. Used right before replacing cloakenv with the command.
/// Failure is ignored: the worst outcome is a command that cannot dump core.
#[cfg(unix)]
pub fn restore_core_limit() {
    if let Some(limit) = saved_core_limit() {
        let _ = rustix::process::setrlimit(rustix::process::Resource::Core, limit);
    }
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

    #[cfg(unix)]
    #[test]
    fn core_limit_is_zeroed_and_the_original_remembered() {
        use rustix::process::{Resource, getrlimit};

        let before = getrlimit(Resource::Core);
        super::harden_process().unwrap();
        assert_eq!(getrlimit(Resource::Core).current, Some(0));
        assert_eq!(getrlimit(Resource::Core).maximum, before.maximum);
        super::harden_process().unwrap(); // idempotent: keeps the first original
        let saved = super::saved_core_limit().unwrap();
        assert_eq!(saved.maximum, before.maximum);
        super::restore_core_limit();
        assert_eq!(getrlimit(Resource::Core).current, saved.current);
    }
}
