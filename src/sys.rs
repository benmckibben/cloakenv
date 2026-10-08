//! The only module in the crate that uses `unsafe`, and only for two calls
//! that have no safe wrapper in std or rustix. Everything here is Unix-only.
//!
//! * [`signal_is_ignored`]: `sigaction(sig, NULL, &old)`, to read (never change) a
//!   signal's current disposition, so a signal that was ignored when cloakenv
//!   started (`nohup`, a background job in a non-interactive shell) stays
//!   ignored for the command instead of being turned into a forwarded one.
//! * [`arm_child`]: a `pre_exec` hook, run in the forked child just before
//!   `execve`, that asks the kernel to kill the command if cloakenv dies
//!   (`PR_SET_PDEATHSIG`, Linux).

use std::io;
use std::os::raw::c_int;
use std::os::unix::process::CommandExt;
use std::process::Command;

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

/// Makes `cmd` die with cloakenv (Linux only: `PR_SET_PDEATHSIG` with
/// `SIGKILL`).
///
/// Must be called on the thread that will call `spawn` and that outlives the
/// child, because the kernel ties the death signal to that *thread* (cloakenv
/// spawns from its main thread, which only ends with the process).
#[allow(unsafe_code)]
pub fn arm_child(cmd: &mut Command) {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let parent = rustix::process::getpid();
    // SAFETY: the closure runs between fork and exec in the child, where only
    // async-signal-safe calls are allowed. It makes nothing but raw syscalls
    // through rustix (prctl, getppid, setrlimit): no allocation, no locks, no
    // access to any state shared with other threads. `parent` is a plain
    // `Copy` value moved in.
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
            Ok(())
        });
    }
}
