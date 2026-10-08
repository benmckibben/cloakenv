//! Supervision of a command that cloakenv runs as a child (Unix): signal
//! forwarding, race-free reaping and the `--shield` output pumps.
//!
//! This is the `--shield` path. Without `--shield` the CLI does not get here at
//! all: it replaces itself with the command ([`crate::runner::exec_replace`]).
//!
//! # Signals
//!
//! `SIGTERM`, `SIGHUP`, `SIGINT`, `SIGQUIT`, `SIGUSR1` and `SIGUSR2` are caught before
//! the child is created and forwarded to it by a dedicated thread, so one that
//! arrives while the child is being started is delivered as soon as it exists
//! rather than lost. cloakenv keeps waiting and exits with the child's own
//! status (`128 + N` if the child died from the signal), exactly as if the
//! signal had been sent to the command. A signal that was ignored when cloakenv
//! started is left ignored (`nohup` keeps working).
//!
//! The pid is only signalled while the child has not been reaped: the main
//! thread first waits for the exit *without* reaping it (`waitid(WNOWAIT)`),
//! marks the child gone under the same lock the forwarder takes for every
//! `kill`, and only then reaps. A forwarded signal therefore can never hit a
//! recycled pid.
//!
//! A Ctrl-C at a terminal is sent by the terminal to the whole foreground
//! process group, which contains both cloakenv and the command, so the command
//! receives it twice (once from the terminal, once forwarded). cloakenv cannot
//! tell the two apart without the signal's sender, which needs non-portable
//! `siginfo` plumbing. Not forwarding would be worse: a `kill -INT` aimed at
//! cloakenv alone would be swallowed.
//!
//! # Output after the command exits
//!
//! The pumps normally end at EOF, when every holder of the pipes' write ends
//! has exited. A leftover background process (a daemon, `cmd &`) inherits the
//! pipes and would otherwise keep cloakenv waiting for as long as it lives.
//! Once the command itself has exited, the pumps therefore keep draining only
//! until the pipe has been quiet for [`DRAIN_IDLE`] or [`DRAIN_MAX`] (not counting
//! time spent blocked writing to our own stdout/stderr) has passed, flush what
//! they hold, and let cloakenv exit. Leftover processes are not killed; their
//! later writes fail with `EPIPE`/`SIGPIPE` because the read end is gone.

use std::ffi::OsStr;
use std::io::{self, Read, Write};
use std::os::fd::AsFd;
use std::os::raw::c_int;
use std::process::{Child, Command, ExitStatus};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::io::Errno;
use rustix::process::{Pid, Signal, WaitId, WaitIdOptions, kill_process, waitid};
use signal_hook::consts::{SIGHUP, SIGINT, SIGQUIT, SIGTERM, SIGUSR1, SIGUSR2};
use signal_hook::iterator::{Handle, Signals};

use zeroize::{Zeroize, Zeroizing};

use crate::runner::{CHUNK, Redactor, RunError, spawn_error};
use crate::sys;
use crate::vault::Vault;

/// Once the command has exited, how long the output pipes may stay silent
/// before the pumps give up on leftover holders and finish.
pub const DRAIN_IDLE: Duration = Duration::from_millis(250);

/// Upper bound on how long the pumps keep draining after the command exited,
/// however chatty a leftover background process is.
pub const DRAIN_MAX: Duration = Duration::from_secs(3);

/// How often a pump wakes up to check whether the command has exited.
const POLL_TICK: Duration = Duration::from_millis(50);

/// Signals forwarded to the command, with their rustix names.
const FORWARDED: [(c_int, Signal); 6] = [
    (SIGTERM, Signal::TERM),
    (SIGHUP, Signal::HUP),
    (SIGINT, Signal::INT),
    (SIGQUIT, Signal::QUIT),
    (SIGUSR1, Signal::USR1),
    (SIGUSR2, Signal::USR2),
];

/// What the supervising threads share about the child.
struct ChildState {
    pid: Option<Pid>,
    /// True from the moment the child has exited (it may still be an
    /// unreaped zombie) until the end. Held across every `kill`.
    gone: Mutex<bool>,
    exited_at: OnceLock<Instant>,
}

impl ChildState {
    fn forward(&self, raw: c_int) {
        let gone = self.gone.lock().unwrap_or_else(PoisonError::into_inner);
        if *gone {
            return;
        }
        let (Some(pid), Some(&(_, sig))) = (self.pid, FORWARDED.iter().find(|(r, _)| *r == raw))
        else {
            return;
        };
        let _ = kill_process(pid, sig);
    }

    /// Called once the child has exited, before it is reaped.
    fn mark_gone(&self) {
        *self.gone.lock().unwrap_or_else(PoisonError::into_inner) = true;
        let _ = self.exited_at.set(Instant::now());
    }
}

struct Forwarder {
    handle: Handle,
    thread: JoinHandle<()>,
}

impl Forwarder {
    fn start(mut signals: Signals, state: Arc<ChildState>) -> Self {
        let handle = signals.handle();
        let thread = thread::spawn(move || {
            for raw in signals.forever() {
                state.forward(raw);
            }
        });
        Self { handle, thread }
    }

    fn stop(self) {
        self.handle.close();
        let _ = self.thread.join();
    }
}

/// Catches the forwarded signals, except those that were ignored on entry.
fn catch_signals() -> Result<Option<Signals>, RunError> {
    let wanted: Vec<c_int> = FORWARDED
        .iter()
        .map(|(raw, _)| *raw)
        .filter(|raw| !sys::signal_is_ignored(*raw))
        .collect();
    if wanted.is_empty() {
        return Ok(None);
    }
    Signals::new(&wanted).map(Some).map_err(RunError::Signals)
}

/// Waits for the child to exit and reaps it, without ever leaving a window in
/// which a forwarded signal could reach a recycled pid.
fn wait(child: &mut Child, state: &ChildState) -> io::Result<ExitStatus> {
    if let Some(pid) = state.pid {
        // Retry on EINTR. Any other outcome is fine: it exited, or there is
        // nothing left to wait for (e.g. SIGCHLD is ignored, so it was
        // auto-reaped), which the plain wait below reports either way.
        while let Err(Errno::INTR) = waitid(
            WaitId::Pid(pid),
            WaitIdOptions::EXITED | WaitIdOptions::NOWAIT,
        ) {}
    }
    state.mark_gone();
    child.wait()
}

/// Copies `reader` to `writer` through a redactor, flushing after each chunk so
/// interactive output is not delayed more than necessary. Ends at EOF, on a
/// write error, or (see the module docs) shortly after the command exited.
fn pump<R: Read + AsFd, W: Write>(
    mut reader: R,
    mut writer: W,
    mut redactor: Redactor,
    state: &ChildState,
) {
    // Raw (unredacted) child output: wiped after every use and on drop.
    let mut buf = Zeroizing::new(vec![0u8; CHUNK]);
    let tick = Timespec {
        tv_sec: 0,
        tv_nsec: POLL_TICK.subsec_nanos().into(),
    };
    let mut last_data = Instant::now();
    let mut blocked_after_exit = Duration::ZERO;
    loop {
        if let Some(exited) = state.exited_at.get() {
            if exited.elapsed().saturating_sub(blocked_after_exit) >= DRAIN_MAX {
                break;
            }
        }
        let mut fds = [PollFd::new(&reader, PollFlags::IN)];
        match poll(&mut fds, Some(&tick)) {
            Ok(0) => {
                if let Some(exited) = state.exited_at.get() {
                    if last_data.max(*exited).elapsed() >= DRAIN_IDLE {
                        break;
                    }
                }
                continue;
            }
            Ok(_) => {}
            Err(Errno::INTR) => continue,
            Err(_) => break,
        }
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let started = Instant::now();
                let failed = redactor
                    .push(&buf[..n], &mut writer)
                    .and_then(|()| writer.flush())
                    .is_err();
                buf[..n].zeroize();
                if failed {
                    // Parent stream is gone (e.g. EPIPE). Stop reading so the
                    // child observes a broken pipe too.
                    return;
                }
                if state.exited_at.get().is_some() {
                    blocked_after_exit += started.elapsed();
                }
                last_data = Instant::now();
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    let _ = redactor.finish(&mut writer).and_then(|()| writer.flush());
}

/// Runs `cmd` as a supervised child and returns its exit status. `redactors`
/// (stdout, stderr) is `Some` when the command's output was set up as pipes.
/// `vault` (whose values `cmd` was built from) is dropped, and so wiped, as
/// soon as the child exists, along with `cmd`.
pub(crate) fn run(
    mut cmd: Command,
    program: &OsStr,
    redactors: Option<(Redactor, Redactor)>,
    vault: Vault,
) -> Result<ExitStatus, RunError> {
    // Before the child exists, so no signal can fall between the two: one
    // arriving early waits in the handler's queue until the forwarder starts.
    let signals = catch_signals()?;
    sys::arm_child(&mut cmd);
    let mut child = cmd.spawn().map_err(|e| spawn_error(e, program))?;
    // The child has its own copy of the environment now. Nothing here needs
    // the plaintext any more (the automaton has what it needs to redact):
    // wipe the vault and free the Command's copies instead of holding them for
    // as long as the command runs.
    drop(cmd);
    drop(vault);

    let state = Arc::new(ChildState {
        pid: i32::try_from(child.id()).ok().and_then(Pid::from_raw),
        gone: Mutex::new(false),
        exited_at: OnceLock::new(),
    });
    let forwarder = signals.map(|s| Forwarder::start(s, Arc::clone(&state)));

    let pumps = redactors.map(|(out_redactor, err_redactor)| {
        let stdout = child.stdout.take().expect("stdout is piped");
        let stderr = child.stderr.take().expect("stderr is piped");
        let (s1, s2) = (Arc::clone(&state), Arc::clone(&state));
        (
            thread::spawn(move || pump(stdout, io::stdout(), out_redactor, &s1)),
            thread::spawn(move || pump(stderr, io::stderr(), err_redactor, &s2)),
        )
    });

    let status = wait(&mut child, &state).map_err(RunError::Wait);

    if let Some((out_thread, err_thread)) = pumps {
        let _ = out_thread.join();
        let _ = err_thread.join();
    }
    if let Some(forwarder) = forwarder {
        forwarder.stop();
    }
    status
}
