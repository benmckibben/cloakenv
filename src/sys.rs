//! The only module in the crate that uses `unsafe`, and only for calls that
//! have no safe wrapper in std or rustix. Everything here is Unix-only.
//!
//! * [`signal_is_ignored`]: `sigaction(sig, NULL, &old)`, to read (never change) a
//!   signal's current disposition, so a signal that was ignored when cloakenv
//!   started (`nohup`, a background job in a non-interactive shell) stays
//!   ignored for the command instead of being turned into a forwarded one.
//! * [`default_sigchld`]: `signal(SIGCHLD, SIG_DFL)` when it was inherited as
//!   ignored, which would make waiting for the child fail.
//! * [`arm_child`]: a `pre_exec` hook, run in the forked child just before
//!   `execve`, that asks the kernel to kill the command if cloakenv dies
//!   (`PR_SET_PDEATHSIG`, Linux) and gives the command back the core-dump limit
//!   cloakenv lowered for itself (and, if cloakenv reset an inherited ignored
//!   SIGCHLD, ignores it again in the command).

#[cfg(any(target_os = "linux", target_os = "android"))]
use std::io;
use std::os::raw::c_int;
use std::os::unix::process::CommandExt;
use std::process::Command;

use crate::hardening;

/// True if `sig` is currently set to `SIG_IGN`. Never modifies anything.
#[allow(unsafe_code)]
pub fn signal_is_ignored(sig: c_int) -> bool {
    // SAFETY: `sigaction` with a null new-action pointer only writes the
    // current action into `old`, a zero-initialised struct that we own and that
    // is valid for any bit pattern. It installs nothing.
    unsafe {
        let mut old: libc::sigaction = std::mem::zeroed();
        libc::sigaction(sig, std::ptr::null(), &mut old) == 0 && old.sa_sigaction == libc::SIG_IGN
    }
}

/// Sets SIGCHLD back to its default action if it is currently `SIG_IGN`, and
/// says whether it was. A process that inherited SIGCHLD as ignored (a
/// Python `preexec_fn`, some launchers and init wrappers) has its children
/// reaped by the kernel the moment they exit, so `waitpid` fails with
/// `ECHILD` and the exit status is lost. Only cloakenv's own disposition
/// changes, and only under `--shield` (the one mode that waits for the
/// child); [`arm_child`] gives it back to the command.
#[allow(unsafe_code)]
pub fn default_sigchld() -> bool {
    if !signal_is_ignored(libc::SIGCHLD) {
        return false;
    }
    // SAFETY: `signal` with a valid signal number and `SIG_DFL`; no handler
    // function is involved.
    unsafe {
        libc::signal(libc::SIGCHLD, libc::SIG_DFL);
    }
    true
}

/// Makes `cmd` die with cloakenv (Linux only: `PR_SET_PDEATHSIG` with
/// `SIGKILL`) and restores the core-dump limit to what cloakenv inherited.
///
/// Must be called on the thread that will call `spawn` and that outlives the
/// child, because the kernel ties the death signal to that *thread* (cloakenv
/// spawns from its main thread, which only ends with the process).
///
/// With `sigchld_ignored` the command also gets SIGCHLD back as `SIG_IGN`, as
/// its caller left it (see [`default_sigchld`]).
#[allow(unsafe_code)]
pub fn arm_child(cmd: &mut Command, sigchld_ignored: bool) {
    let core = hardening::saved_core_limit();
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let parent = rustix::process::getpid();
    // SAFETY: the closure runs between fork and exec in the child, where only
    // async-signal-safe calls are allowed. It makes nothing but raw syscalls
    // through rustix (prctl, getppid, setrlimit) and one `signal(2)` call
    // (async-signal-safe): no allocation, no locks, no access to any state
    // shared with other threads. `core`, `parent` and `sigchld_ignored` are
    // plain `Copy` values moved in.
    unsafe {
        cmd.pre_exec(move || {
            #[cfg(any(target_os = "linux", target_os = "android"))]
            {
                use rustix::process::{Signal, getppid, set_parent_process_death_signal};
                set_parent_process_death_signal(Some(Signal::KILL))?;
                // cloakenv may have died between fork and the prctl above, in
                // which case no death signal will ever arrive: do not run.
                if getppid() != Some(parent) {
                    return Err(io::Error::from(io::ErrorKind::BrokenPipe));
                }
            }
            if let Some(limit) = core {
                rustix::process::setrlimit(rustix::process::Resource::Core, limit)?;
            }
            if sigchld_ignored {
                libc::signal(libc::SIGCHLD, libc::SIG_IGN);
            }
            Ok(())
        });
    }
}
