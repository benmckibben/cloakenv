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
//! # Where the output goes
//!
//! Under `--shield` the command's stdout and stderr are pipes that cloakenv
//! reads, redacts and writes to its own stdout and stderr, one thread per
//! pipe. If cloakenv's own stdout and stderr are the same file, pipe or
//! terminal (`> log 2>&1`, `2>&1 | tee`), two independent threads writing
//! unaligned chunks to it would cut lines of one stream in two with lines of
//! the other, and could not catch a secret whose halves went to different
//! streams. So in that case the command gets **one** pipe for both its stdout
//! and its stderr, exactly as `2>&1` would give it: one thread, one redactor,
//! the command's own order of writes kept, nothing to splice.
//!
//! cloakenv's own stdout or stderr may be non-blocking (the flag belongs to the
//! open file description, which a parent shares with its children): writes
//! wait for the descriptor to become writable instead of failing with
//! `EAGAIN` (see [`crate::fdio`]). A write that fails because the reader went
//! away (`EPIPE`) ends that stream quietly, as for `cat`: the command gets
//! `SIGPIPE` on its next write and cloakenv exits with the command's status.
//! Any other write error (a full disk, say) is reported and makes cloakenv
//! exit 125, whatever the command's own status was.
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
use std::io::{self, PipeReader, Read, Write};
use std::os::fd::{AsFd, BorrowedFd};
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

use crate::fdio::{self, FdWriter};
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
        // nothing to wait for, which the plain wait below reports either way.
        // (A SIGCHLD that is ignored makes the kernel reap children by
        // itself and `wait` fail with ECHILD; `run` sets it back to the
        // default before spawning, see `sys::default_sigchld`.)
        while let Err(Errno::INTR) = waitid(
            WaitId::Pid(pid),
            WaitIdOptions::EXITED | WaitIdOptions::NOWAIT,
        ) {}
    }
    state.mark_gone();
    child.wait()
}

/// One of our own output streams.
#[derive(Clone, Copy)]
enum Dest {
    Stdout,
    Stderr,
}

impl Dest {
    fn fd(self) -> BorrowedFd<'static> {
        match self {
            Dest::Stdout => rustix::stdio::stdout(),
            Dest::Stderr => rustix::stdio::stderr(),
        }
    }
}

/// What ends a pump early: nothing (EOF), or a write that failed. A reader
/// that went away (`EPIPE`) is not an error to report: the pump just stops, so
/// the command's next write meets a closed pipe, as it would for `cat`.
fn write_failure(error: io::Error) -> Option<io::Error> {
    (error.kind() != io::ErrorKind::BrokenPipe).then_some(error)
}

/// Copies `reader` to our own `dest` through a redactor, writing after each
/// chunk so interactive output is not delayed more than necessary. Ends at
/// EOF, on a write error, or (see the module docs) shortly after the command
/// exited. Returns the write error that ended it, if it was a real one.
fn pump<R: Read + AsFd>(
    mut reader: R,
    dest: Dest,
    mut redactor: Redactor,
    state: &ChildState,
) -> Option<io::Error> {
    // Raw (unredacted) child output: wiped after every use and on drop.
    let mut buf = Zeroizing::new(vec![0u8; CHUNK]);
    // The redacted bytes of one chunk, written in one go.
    let mut out: Vec<u8> = Vec::with_capacity(2 * CHUNK);
    let mut writer = FdWriter::new(dest.fd());
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
                out.clear();
                // Pushing into a Vec only fails if the redactor itself does.
                let written = redactor
                    .push(&buf[..n], &mut out)
                    .and_then(|()| writer.write_all(&out));
                buf[..n].zeroize();
                if let Err(e) = written {
                    // Stop reading: if the reader is gone the command meets
                    // a broken pipe too; for anything else it is told so.
                    return write_failure(e);
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
    out.clear();
    redactor
        .finish(&mut out)
        .and_then(|()| writer.write_all(&out))
        .err()
        .and_then(write_failure)
}

/// The pump threads of one run.
enum Pumps {
    None,
    /// stdout and stderr share one pipe: one pump.
    One(JoinHandle<Option<io::Error>>),
    Two(JoinHandle<Option<io::Error>>, JoinHandle<Option<io::Error>>),
}

impl Pumps {
    /// Waits for the pumps; the first real write error, if any.
    fn join(self) -> Option<io::Error> {
        let handles = match self {
            Pumps::None => return None,
            Pumps::One(a) => vec![a],
            Pumps::Two(a, b) => vec![a, b],
        };
        let mut first = None;
        for handle in handles {
            let result = handle
                .join()
                .unwrap_or_else(|_| Some(io::Error::other("the output thread failed")));
            first = first.or(result);
        }
        first
    }
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
    // A SIGCHLD inherited as "ignore" would make the kernel reap the child on
    // its own and our wait fail. The command gets it back as it was.
    let sigchld_was_ignored = sys::default_sigchld();
    sys::arm_child(&mut cmd, sigchld_was_ignored);
    // One pipe for both of the command's streams if both of ours are one
    // destination (see the module docs).
    let shared = if redactors.is_some() && fdio::stdout_and_stderr_are_one() {
        let (reader, writer) = io::pipe().map_err(RunError::Pipe)?;
        let second = writer.try_clone().map_err(RunError::Pipe)?;
        cmd.stdout(writer).stderr(second);
        Some(reader)
    } else {
        None
    };
    let mut child = cmd.spawn().map_err(|e| spawn_error(e, program))?;
    // The child has its own copy of the environment now. Nothing here needs
    // the plaintext any more (the automaton has what it needs to redact):
    // wipe the vault and free the Command's copies instead of holding them for
    // as long as the command runs. (Dropping the Command also closes our
    // copies of the output pipe's write end, so that EOF can arrive.)
    drop(cmd);
    drop(vault);

    let state = Arc::new(ChildState {
        pid: i32::try_from(child.id()).ok().and_then(Pid::from_raw),
        gone: Mutex::new(false),
        exited_at: OnceLock::new(),
    });
    let forwarder = signals.map(|s| Forwarder::start(s, Arc::clone(&state)));

    let pumps = start_pumps(redactors, shared, &mut child, &state);
    let pumps = match pumps {
        Ok(pumps) => pumps,
        Err(e) => {
            // No thread to read its output: do not leave it running with a
            // pipe nobody drains.
            let _ = child.kill();
            let _ = child.wait();
            if let Some(forwarder) = forwarder {
                forwarder.stop();
            }
            return Err(RunError::Output(e));
        }
    };

    let status = wait(&mut child, &state).map_err(RunError::Wait);

    let write_error = pumps.join();
    if let Some(forwarder) = forwarder {
        forwarder.stop();
    }
    let status = status?;
    match write_error {
        Some(e) => Err(RunError::Output(e)),
        None => Ok(status),
    }
}

fn start_pumps(
    redactors: Option<(Redactor, Redactor)>,
    shared: Option<PipeReader>,
    child: &mut Child,
    state: &Arc<ChildState>,
) -> io::Result<Pumps> {
    let Some((out_redactor, err_redactor)) = redactors else {
        return Ok(Pumps::None);
    };
    if let Some(reader) = shared {
        // One pipe, one redactor: the other is not needed.
        drop(err_redactor);
        return start_pump(reader, Dest::Stdout, out_redactor, state).map(Pumps::One);
    }
    // Both are piped whenever redactors are given.
    let (Some(stdout), Some(stderr)) = (child.stdout.take(), child.stderr.take()) else {
        return Ok(Pumps::None);
    };
    let out = start_pump(stdout, Dest::Stdout, out_redactor, state)?;
    let err = start_pump(stderr, Dest::Stderr, err_redactor, state)?;
    Ok(Pumps::Two(out, err))
}

fn start_pump<R: Read + AsFd + Send + 'static>(
    reader: R,
    dest: Dest,
    redactor: Redactor,
    state: &Arc<ChildState>,
) -> io::Result<JoinHandle<Option<io::Error>>> {
    let state = Arc::clone(state);
    thread::Builder::new().spawn(move || pump(reader, dest, redactor, &state))
}
