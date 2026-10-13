//! Child process spawning with in-memory secret injection, and the
//! `--shield` streaming redactor.

use std::ffi::{OsStr, OsString};
#[cfg(not(unix))]
use std::io::Read;
use std::io::{self, Write};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::Arc;
#[cfg(not(unix))]
use std::sync::mpsc;
#[cfg(not(unix))]
use std::thread;
#[cfg(not(unix))]
use std::time::Instant;

use aho_corasick::automaton::Automaton;
use aho_corasick::dfa;
use aho_corasick::nfa::contiguous;
use aho_corasick::{Anchored, Input, MatchKind, StartKind};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

use crate::vault::Vault;
use crate::{PASSPHRASE_ENV, PASSPHRASE_FILE_ENV};

/// Replacement text written in place of any secret value under `--shield`.
pub const REDACTION: &[u8] = b"[REDACTED_BY_CLOAKENV]";

pub(crate) const CHUNK: usize = 8 * 1024;

/// Under `--shield`, values shorter than this many bytes are flagged by the
/// CLI. Redaction matches literal substrings, so a short value (`1`, `80`,
/// `true`, `prod`) matches ordinary output all the time and every match
/// becomes a 22-byte marker; and the marker appearing for a guessed string
/// confirms the guess, which for a few bytes is cheap to brute-force. Six
/// bytes is a line between "plausibly a token or password" and "probably a
/// flag, port or word"; common non-secret settings (`true`, `false`, `dev`,
/// `8080`) fall below it. This is advice only: redaction is unchanged.
pub const SHORT_VALUE_LEN: usize = 6;

/// Keys (in sorted order) whose non-empty values are shorter than
/// [`SHORT_VALUE_LEN`] bytes. Only names are returned, never values. Empty
/// values are skipped: the redactor ignores them, so they neither mangle
/// output nor leak anything.
///
/// Every vault entry is considered, since `--shield` redacts all of them.
pub fn short_value_keys(vault: &Vault) -> Vec<&str> {
    vault
        .iter()
        .filter(|(_, v)| !v.is_empty() && v.len() < SHORT_VALUE_LEN)
        .map(|(k, _)| k)
        .collect()
}

/// Errors produced while running a child process.
#[derive(Debug, Error)]
pub enum RunError {
    #[error("no command given")]
    NoCommand,
    #[error("failed to build the redaction filter")]
    Shield,
    #[error("{program}: command not found")]
    NotFound { program: String },
    #[error("{program}: permission denied")]
    PermissionDenied { program: String },
    // The OS error is the `source`; `{:#}` prints the chain.
    #[error("failed to spawn {program}")]
    Spawn {
        program: String,
        #[source]
        source: io::Error,
    },
    #[error("failed to wait for child process")]
    Wait(#[source] io::Error),
    #[error("failed to create a pipe for the command's output")]
    Pipe(#[source] io::Error),
    /// Writing the command's (redacted) output to our own stdout or stderr
    /// failed, for a reason other than the reader having gone away.
    #[error("failed to write the command's output")]
    Output(#[source] io::Error),
    #[error("failed to install signal handlers")]
    Signals(#[source] io::Error),
}

impl RunError {
    /// Shell-conventional exit code for this failure.
    pub fn exit_code(&self) -> i32 {
        match self {
            RunError::NotFound { .. } => 127,
            RunError::PermissionDenied { .. } => 126,
            _ => 125,
        }
    }
}

/// Total secret bytes up to which the matcher is a full DFA (fastest scan).
/// A DFA is built by following failure links for every state and byte class, which
/// is quadratic for a long value that overlaps itself (`xxxx…`): 16 KiB of
/// `x` took 0.5 s and 64 KiB took 8 s. Up to this size even that worst case
/// builds in about 0.1 s; above it the matcher is a contiguous NFA,
/// which builds in linear time (1 MiB of `x` in a few milliseconds) and scans
/// about as fast on typical output.
const DFA_MAX_PATTERN_BYTES: usize = 8192;

/// The compiled automaton, either flavour.
enum Engine {
    Dfa(dfa::DFA),
    Nfa(contiguous::NFA),
}

/// All secrets compiled into one leftmost-longest automaton, plus what the
/// redactor needs to know about their *prefixes*.
struct Matcher {
    engine: Engine,
    max_len: usize,
    /// Which bytes can begin a secret. A byte that cannot is never held
    /// back. (Derived from the automaton's own start state, so no separate
    /// copy of the secrets exists.)
    first: [bool; 256],
}

impl Matcher {
    fn build(patterns: &[&[u8]], max_len: usize) -> Result<Self, RunError> {
        let total: usize = patterns.iter().map(|p| p.len()).sum();
        let engine = if total <= DFA_MAX_PATTERN_BYTES {
            // Both starts: the anchored one is how prefixes are tested.
            dfa::DFA::builder()
                .match_kind(MatchKind::LeftmostLongest)
                .start_kind(StartKind::Both)
                // The prefilter (memchr/Teddy/Rabin-Karp) is a speed-up that
                // keeps its own contiguous copy of the patterns; without it
                // the secrets exist only as automaton transitions, which a
                // plain scan of the process's memory for the secret does not
                // find.
                .prefilter(false)
                .build(patterns)
                .map(Engine::Dfa)
        } else {
            contiguous::NFA::builder()
                .match_kind(MatchKind::LeftmostLongest)
                .prefilter(false)
                .build(patterns)
                .map(Engine::Nfa)
        }
        .map_err(|_| RunError::Shield)?;
        let mut matcher = Matcher {
            engine,
            max_len,
            first: [false; 256],
        };
        // Fail closed: both kinds of search must be possible.
        match &matcher.engine {
            Engine::Dfa(a) => prepare(a, &mut matcher.first),
            Engine::Nfa(a) => prepare(a, &mut matcher.first),
        }?;
        Ok(matcher)
    }

    /// Calls `f(start, end)` for every leftmost-longest match in `hay`, in
    /// order, until `f` returns false.
    fn for_each_match(&self, hay: &[u8], f: impl FnMut(usize, usize) -> bool) -> io::Result<()> {
        match &self.engine {
            Engine::Dfa(a) => scan(a, hay, f),
            Engine::Nfa(a) => scan(a, hay, f),
        }
    }

    /// The index in `hay` (at least `from`) from which everything must be held
    /// back: the start of the longest suffix of `hay[from..]` that is a
    /// *proper* prefix of some secret, i.e. that more input could still
    /// complete into a match. `hay.len()` if there is none. Bytes before it
    /// cannot take part in a match that is not already fully in `hay`.
    fn hold_start(&self, hay: &[u8], from: usize) -> usize {
        match &self.engine {
            Engine::Dfa(a) => hold_start(a, &self.first, self.max_len, hay, from),
            Engine::Nfa(a) => hold_start(a, &self.first, self.max_len, hay, from),
        }
    }
}

/// Checks that `a` supports unanchored and anchored searches, and fills
/// `first` from the anchored start state.
fn prepare<A: Automaton>(a: &A, first: &mut [bool; 256]) -> Result<(), RunError> {
    a.start_state(Anchored::No).map_err(|_| RunError::Shield)?;
    let start = a.start_state(Anchored::Yes).map_err(|_| RunError::Shield)?;
    for (byte, slot) in (0..=u8::MAX).zip(first.iter_mut()) {
        *slot = !a.is_dead(a.next_state(Anchored::Yes, start, byte));
    }
    Ok(())
}

fn scan<A: Automaton>(
    a: &A,
    hay: &[u8],
    mut f: impl FnMut(usize, usize) -> bool,
) -> io::Result<()> {
    // Cannot fail for a searchable automaton (checked in `prepare`); if it
    // ever did, failing the write is the closed way out: nothing unredacted
    // is printed.
    let iter = a
        .try_find_iter(Input::new(hay))
        .map_err(|_| io::Error::other("the redaction filter failed"))?;
    for m in iter {
        if !f(m.start(), m.end()) {
            break;
        }
    }
    Ok(())
}

fn hold_start<A: Automaton>(
    a: &A,
    first: &[bool; 256],
    max_len: usize,
    hay: &[u8],
    from: usize,
) -> usize {
    let len = hay.len();
    // A proper prefix of a secret is at most `max_len - 1` bytes long.
    let window = len.saturating_sub(max_len.saturating_sub(1)).max(from);
    let Ok(start) = a.start_state(Anchored::Yes) else {
        return window;
    };
    // Typical output costs a handful of steps; a stream built to look like
    // the start of a self-overlapping secret (`xxxx…` against `xxxx…y`) would
    // cost quadratic time. Past this budget fall back to holding the whole
    // window, which is always a safe superset.
    let mut budget = 8 * (len - window) + 1024;
    for p in window..len {
        if !first[usize::from(hay[p])] {
            continue;
        }
        let mut sid = start;
        let mut alive = true;
        for &byte in &hay[p..] {
            if budget == 0 {
                return window;
            }
            budget -= 1;
            sid = a.next_state(Anchored::Yes, sid, byte);
            if a.is_dead(sid) {
                alive = false;
                break;
            }
        }
        if !alive {
            continue;
        }
        // `hay[p..]` is a prefix of some secret. It is a *proper* one (so more
        // input could still extend it) unless it is a secret that nothing
        // longer continues. A state that is not a match state cannot be a
        // leaf, so only a match state needs the look at its successors.
        if !a.is_match(sid) {
            return p;
        }
        if budget < 256 {
            return window;
        }
        budget -= 256;
        if (0..=u8::MAX).any(|b| !a.is_dead(a.next_state(Anchored::Yes, sid, b))) {
            return p;
        }
    }
    len
}

/// Streaming find-and-replace of secret values over an arbitrary byte stream.
///
/// Matches can straddle chunk boundaries, so the redactor holds back exactly
/// those trailing bytes that could still turn out to be the beginning of a
/// secret: the longest suffix of the input that is a proper prefix of some
/// secret (`sk-li` of an `sk-live-…` token, say). Every other byte (a line
/// of ordinary output, a prompt) is released at once. Held bytes wait for
/// more input or for the end of the stream; there is deliberately no timer
/// that releases them, because they are precisely the bytes that begin a
/// secret, and a slow writer would otherwise leak its first half.
/// Matching is leftmost-longest, so when one secret is a prefix of another the
/// longer one is redacted whole.
///
/// The buffer of held-back input (raw child output, which may contain secrets
/// that have not been redacted yet) is allocated once and wiped on drop, and
/// the bytes that are shifted out of it are wiped as they go. The Aho-Corasick
/// automaton itself cannot be wiped: the library has no way to do it (see
/// "Memory hygiene" in `docs/ARCHITECTURE.md`).
pub struct Redactor {
    matcher: Option<Arc<Matcher>>,
    pending: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for Redactor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Redactor")
            .field("active", &self.matcher.is_some())
            .finish_non_exhaustive()
    }
}

impl Redactor {
    /// Builds a redactor for the given secret values. Empty values are
    /// ignored (they would match everywhere).
    pub fn new<I, P>(secrets: I) -> Result<Self, RunError>
    where
        I: IntoIterator<Item = P>,
        P: AsRef<[u8]>,
    {
        Ok(Self::with_matcher(build_matcher(secrets)?))
    }

    /// Builds two independent redactors (one per output stream) that share a
    /// single automaton, so the secrets are compiled into memory once, not
    /// twice. Each has its own held-back buffer.
    pub fn new_pair<I, P>(secrets: I) -> Result<(Self, Self), RunError>
    where
        I: IntoIterator<Item = P>,
        P: AsRef<[u8]>,
    {
        let matcher = build_matcher(secrets)?;
        Ok((
            Self::with_matcher(matcher.clone()),
            Self::with_matcher(matcher),
        ))
    }

    fn with_matcher(matcher: Option<Arc<Matcher>>) -> Self {
        let max_len = matcher.as_ref().map_or(0, |m| m.max_len);
        Self {
            matcher,
            pending: Zeroizing::new(Vec::with_capacity(CHUNK + max_len)),
        }
    }

    /// How many bytes are being held back right now, waiting to find out
    /// whether they start a secret.
    pub fn held(&self) -> usize {
        self.pending.len()
    }

    /// Feeds a chunk of input, writing every byte that is now known to be
    /// safe (or redacted) to `out`.
    pub fn push<W: Write + ?Sized>(&mut self, chunk: &[u8], out: &mut W) -> io::Result<()> {
        self.reserve(chunk.len());
        self.pending.extend_from_slice(chunk);
        self.drain(out, false)
    }

    /// Makes room for `extra` more bytes without ever leaving the old buffer
    /// behind unwiped. With the chunk sizes the pumps use the initial
    /// allocation always suffices; this only matters for callers that push
    /// large chunks (e.g. [`redact_all`]).
    fn reserve(&mut self, extra: usize) {
        let need = self.pending.len() + extra;
        if need > self.pending.capacity() {
            let mut bigger =
                Zeroizing::new(Vec::with_capacity(need.max(2 * self.pending.capacity())));
            bigger.extend_from_slice(&self.pending);
            // Dropping the old buffer wipes it.
            self.pending = bigger;
        }
    }

    /// Flushes all remaining buffered input at end of stream.
    pub fn finish<W: Write + ?Sized>(&mut self, out: &mut W) -> io::Result<()> {
        self.drain(out, true)
    }

    fn drain<W: Write + ?Sized>(&mut self, out: &mut W, eof: bool) -> io::Result<()> {
        let Some(matcher) = self.matcher.clone() else {
            out.write_all(&self.pending)?;
            self.pending.zeroize();
            return Ok(());
        };
        let len = self.pending.len();
        // Everything before `hold` is settled: a match starting there is
        // fully inside the buffer (it, and any longer alternative at the same
        // start, would otherwise make that start a proper prefix and hold it).
        let mut hold = if eof {
            len
        } else {
            matcher.hold_start(&self.pending, 0)
        };
        let mut cursor = 0;
        let mut failed = None;
        matcher.for_each_match(&self.pending, |start, end| {
            if start >= hold {
                return false;
            }
            let wrote = out
                .write_all(&self.pending[cursor..start])
                .and_then(|()| out.write_all(REDACTION));
            if let Err(e) = wrote {
                failed = Some(e);
                return false;
            }
            cursor = end;
            if cursor > hold {
                // The match swallowed the old hold point; what is left of the
                // buffer needs its own.
                hold = matcher.hold_start(&self.pending, cursor);
            }
            true
        })?;
        if let Some(e) = failed {
            return Err(e);
        }
        let emit_to = cursor.max(hold);
        out.write_all(&self.pending[cursor..emit_to])?;
        // Shift the held-back tail to the front and wipe what is left behind it
        // (`Vec::drain` would leave stale copies of the emitted bytes there).
        self.pending.copy_within(emit_to.., 0);
        let new_len = len - emit_to;
        self.pending[new_len..].zeroize();
        self.pending.truncate(new_len);
        Ok(())
    }
}

/// Compiles the non-empty `secrets` into one automaton (`None` if there is
/// nothing to match).
fn build_matcher<I, P>(secrets: I) -> Result<Option<Arc<Matcher>>, RunError>
where
    I: IntoIterator<Item = P>,
    P: AsRef<[u8]>,
{
    let owned: Vec<P> = secrets
        .into_iter()
        .filter(|s| !s.as_ref().is_empty())
        .collect();
    if owned.is_empty() {
        return Ok(None);
    }
    let patterns: Vec<&[u8]> = owned.iter().map(AsRef::as_ref).collect();
    let max_len = patterns.iter().map(|p| p.len()).max().unwrap_or(0);
    Matcher::build(&patterns, max_len).map(|m| Some(Arc::new(m)))
}

/// Redacts a complete in-memory buffer. Convenience wrapper over [`Redactor`].
pub fn redact_all<I, P>(secrets: I, input: &[u8]) -> Result<Vec<u8>, RunError>
where
    I: IntoIterator<Item = P>,
    P: AsRef<[u8]>,
{
    let mut r = Redactor::new(secrets)?;
    let mut out = Vec::with_capacity(input.len());
    // Writing to a Vec cannot fail; an error here would be the filter's own.
    r.push(input, &mut out).map_err(|_| RunError::Shield)?;
    r.finish(&mut out).map_err(|_| RunError::Shield)?;
    Ok(out)
}

/// Blocking copy of `reader` to `writer` through a redactor, flushing after each
/// chunk. Only used where there is no supervising poll loop (non-Unix).
#[cfg(not(unix))]
fn pump<R: Read, W: Write>(mut reader: R, mut writer: W, mut redactor: Redactor) {
    // Raw (unredacted) child output: wiped after every use and on drop.
    let mut buf = Zeroizing::new(vec![0u8; CHUNK]);
    loop {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let failed = redactor
                    .push(&buf[..n], &mut writer)
                    .and_then(|()| writer.flush())
                    .is_err();
                buf[..n].zeroize();
                if failed {
                    return;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    let _ = redactor.finish(&mut writer).and_then(|()| writer.flush());
}

/// Builds the command with every vault entry injected into its environment
/// and the cloakenv passphrase variables removed.
fn build_command(program: &OsStr, args: &[OsString], vault: &Vault) -> Command {
    let mut cmd = Command::new(program);
    // Removals come after `envs` so a vault entry cannot put the passphrase
    // variables back. `Command` applies these mutations in call order.
    cmd.args(args)
        .envs(vault.iter())
        .env_remove(PASSPHRASE_ENV)
        .env_remove(PASSPHRASE_FILE_ENV)
        .stdin(Stdio::inherit());
    cmd
}

/// Spawns `command[0]` with `command[1..]` as arguments and every vault entry
/// injected into its environment, then waits for it to exit.
///
/// The cloakenv passphrase variables are removed from the child's
/// environment. When `shield` is set, the child's stdout and stderr are piped
/// through a [`Redactor`] before reaching our own stdout and stderr.
///
/// The vault is taken by value and dropped (wiped) as soon as the command has
/// been spawned, together with the `Command` that holds a copy of it: the
/// supervising process keeps only the redaction automaton.
///
/// On Unix, cloakenv stays the child's parent for the whole run and
///
/// * forwards `SIGTERM`, `SIGHUP`, `SIGINT`, `SIGQUIT`, `SIGUSR1` and `SIGUSR2` to it
///   (a signal that was ignored when cloakenv started stays ignored, and
///   the child inherits that, as with `nohup`);
/// * on Linux, has the kernel kill the child if cloakenv itself dies
///   (`PR_SET_PDEATHSIG`);
/// * reports the child's own exit status (see [`exit_code`]);
/// * with `shield`, stops pumping output a short grace period after the
///   command exits even if a leftover background process still holds the
///   pipes open (see `DRAIN_IDLE` / `DRAIN_MAX` in the supervisor).
///
/// On Windows cloakenv also stays the parent, with or without `--shield`: the
/// command runs in a job object that kills it and its descendants if cloakenv
/// dies, Ctrl-C and Ctrl-Break are left to the command, and its full 32-bit
/// exit code is reported (see [`exit_code`]).
///
/// On Unix the CLI only uses this for `--shield`; without it, it replaces
/// itself with the command via [`exec_replace`].
pub fn run(command: &[OsString], vault: Vault, shield: bool) -> Result<ExitStatus, RunError> {
    let (program, args) = command.split_first().ok_or(RunError::NoCommand)?;

    // Build the redactors before spawning so a failure here fails closed. One
    // automaton serves both streams.
    let redactors = if shield {
        let values: Vec<&[u8]> = vault.iter().map(|(_, v)| v.as_bytes()).collect();
        Some(Redactor::new_pair(&values)?)
    } else {
        None
    };

    let mut cmd = build_command(program, args, &vault);
    if shield {
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    }

    #[cfg(unix)]
    {
        crate::supervise::run(cmd, program, redactors, vault)
    }
    #[cfg(not(unix))]
    {
        supervise_portable(cmd, program, redactors, vault)
    }
}

/// How long to keep pumping output after the command has exited, when a
/// leftover background process still holds the pipes open (the counterpart of
/// `DRAIN_MAX` in the Unix supervisor).
#[cfg(not(unix))]
const DRAIN_MAX: std::time::Duration = std::time::Duration::from_secs(3);

/// `run` where there is no Unix supervisor (Windows). The command is a child of
/// cloakenv for the whole run.
///
/// On Windows it runs inside a job object that kills it and everything it
/// started if cloakenv dies, and cloakenv stays alive through Ctrl-C and
/// Ctrl-Break so the command, which receives them from the console itself,
/// handles them and cloakenv reports how it ended. When the command exits
/// normally the job is released, so a background process it left behind keeps
/// running, as on Unix.
#[cfg(not(unix))]
fn supervise_portable(
    mut cmd: Command,
    program: &OsStr,
    redactors: Option<(Redactor, Redactor)>,
    vault: Vault,
) -> Result<ExitStatus, RunError> {
    #[cfg(windows)]
    let _interrupts = crate::winsys::InterruptGuard::install();
    #[cfg(windows)]
    let (mut child, job) =
        crate::winsys::spawn_confined(&mut cmd).map_err(|e| spawn_error(e, program))?;
    #[cfg(not(windows))]
    let mut child = cmd.spawn().map_err(|e| spawn_error(e, program))?;
    // The child has its copy; wipe ours (and free the Command's).
    drop(cmd);
    drop(vault);
    let Some((out_redactor, err_redactor)) = redactors else {
        let status = child.wait().map_err(RunError::Wait);
        #[cfg(windows)]
        if let Some(job) = job {
            job.release();
        }
        return status;
    };
    let stdout = child.stdout.take().expect("stdout is piped");
    let stderr = child.stderr.take().expect("stderr is piped");
    let (done_tx, done_rx) = mpsc::channel::<()>();
    let out_done = done_tx.clone();
    let out_thread = thread::spawn(move || {
        pump(stdout, io::stdout(), out_redactor);
        let _ = out_done.send(());
    });
    let err_thread = thread::spawn(move || {
        pump(stderr, io::stderr(), err_redactor);
        let _ = done_tx.send(());
    });
    let status = child.wait().map_err(RunError::Wait);
    #[cfg(windows)]
    if let Some(job) = job {
        job.release();
    }
    // Normally both pipes reach EOF as the command exits. A leftover background
    // process that inherited them keeps them open, so wait for a bounded time
    // and then leave the pumps behind (they end with the process).
    let deadline = Instant::now() + DRAIN_MAX;
    let mut finished = 0;
    while finished < 2 {
        match done_rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(()) => finished += 1,
            Err(_) => break,
        }
    }
    if finished == 2 {
        let _ = out_thread.join();
        let _ = err_thread.join();
    }
    status
}

/// Replaces the cloakenv process with `command` (`execve`), with every vault
/// entry in its environment and the passphrase variables removed. Used for
/// `cloakenv run` without `--shield` on Unix.
///
/// On success this never returns: there is no cloakenv process left, so
/// nothing is orphaned, every signal goes straight to the command, the exit
/// status is the command's own, and neither cloakenv's memory (including
/// the passphrase and its copy of the secrets) nor its environment block
/// outlives the call. The vault is taken by value and wiped (`Zeroizing`)
/// before the exec; the copies inside [`Command`] cannot be wiped from here but
/// vanish with the old address space. Stdin, stdout, stderr, the
/// controlling terminal, the working directory and the process id are all
/// inherited unchanged.
///
/// It only returns if the exec failed, with the error to report (127 for a
/// missing command, 126 for one that cannot be executed, 125 otherwise).
/// After a failed exec the process environment must not be read again: std
/// has pointed `environ` at the command's environment block, which it frees on
/// return. Callers should just report the error and exit.
#[cfg(unix)]
pub fn exec_replace(command: &[OsString], vault: Vault) -> RunError {
    use std::os::unix::process::CommandExt;

    let Some((program, args)) = command.split_first() else {
        return RunError::NoCommand;
    };
    let mut cmd = build_command(program, args, &vault);
    drop(vault);
    // The command keeps the core-dump limit it would have had without us.
    crate::hardening::restore_core_limit();
    let err = cmd.exec();
    spawn_error(err, program)
}

/// Classifies a failure to start (or exec) `program`: 127 for a missing command,
/// 126 for one that cannot be executed, 125 for anything else.
pub(crate) fn spawn_error(source: io::Error, program: &OsStr) -> RunError {
    let program = program.to_string_lossy().into_owned();
    match source.kind() {
        io::ErrorKind::NotFound => RunError::NotFound { program },
        io::ErrorKind::PermissionDenied => RunError::PermissionDenied { program },
        _ => RunError::Spawn { program, source },
    }
}

/// Maps a child's exit status to our own exit code (`128 + signal` for
/// signal deaths on Unix, as shells do).
pub fn exit_code(status: ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        return code;
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(sig) = status.signal() {
            return 128 + sig;
        }
    }
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_secrets_is_passthrough() {
        let none: [&[u8]; 0] = [];
        assert_eq!(redact_all(none, b"hello").unwrap(), b"hello");
        assert_eq!(redact_all([b"".as_slice()], b"hello").unwrap(), b"hello");
    }

    #[test]
    fn short_value_keys_lists_names_only() {
        use zeroize::Zeroizing;
        let mut v = Vault::new();
        for (k, val) in [
            ("EMPTY", ""),
            ("ONE", "1"),
            ("FIVE", "12345"),
            ("SIX", "123456"),
            ("LONG", "a-much-longer-value"),
            ("UNI", "ü€"), // 5 bytes, not 2 characters
        ] {
            v.set(k, Zeroizing::new(val.to_owned())).unwrap();
        }
        assert_eq!(short_value_keys(&v), ["FIVE", "ONE", "UNI"]);
    }

    /// What is left in a redactor's buffer beyond its length, as bytes.
    #[allow(unsafe_code)]
    fn stale_bytes(r: &Redactor, written: usize) -> &[u8] {
        // SAFETY: the first `written` bytes of the allocation were
        // initialised by the pushes the tests made (nothing has been freed or
        // reallocated), so reading them is sound.
        let all = unsafe { std::slice::from_raw_parts(r.pending.as_ptr(), written) };
        &all[r.pending.len()..]
    }

    #[test]
    fn shifted_out_input_is_wiped_from_the_buffer() {
        let mut r = Redactor::new(["abcdef"]).unwrap();
        let mut out = Vec::new();
        r.push(b"xxxxxxxxxxabc", &mut out).unwrap();
        assert_eq!(out, b"xxxxxxxxxx");
        assert_eq!(&r.pending[..], b"abc");
        assert!(stale_bytes(&r, 13).iter().all(|b| *b == 0));

        // A redacted secret leaves no copy behind either.
        let mut r = Redactor::new(["abcdef"]).unwrap();
        let mut out = Vec::new();
        r.push(b"..abcdef..ab", &mut out).unwrap();
        assert_eq!(out, b"..[REDACTED_BY_CLOAKENV]..");
        assert_eq!(&r.pending[..], b"ab");
        assert!(stale_bytes(&r, 12).iter().all(|b| *b == 0));
    }

    #[test]
    fn a_pair_shares_one_automaton_but_not_buffers() {
        let (mut a, mut b) = Redactor::new_pair(["abcdef"]).unwrap();
        let (mut out_a, mut out_b) = (Vec::new(), Vec::new());
        a.push(b"zzabc", &mut out_a).unwrap();
        b.push(b"yyyyabcdefyy", &mut out_b).unwrap();
        a.push(b"def", &mut out_a).unwrap();
        a.finish(&mut out_a).unwrap();
        b.finish(&mut out_b).unwrap();
        assert_eq!(out_a, b"zz[REDACTED_BY_CLOAKENV]");
        assert_eq!(out_b, b"yyyy[REDACTED_BY_CLOAKENV]yy");
    }

    #[test]
    fn growing_the_buffer_never_leaves_the_old_one_behind() {
        // A chunk larger than the initial allocation forces a new buffer
        // (old one wiped on drop); output is unaffected.
        let big = vec![b'q'; CHUNK * 3];
        let mut r = Redactor::new(["abcdef"]).unwrap();
        let mut out = Vec::new();
        r.push(&big, &mut out).unwrap();
        r.finish(&mut out).unwrap();
        assert_eq!(out, big);
    }

    #[test]
    fn holdback_is_released_at_eof() {
        let mut r = Redactor::new(["abcdef"]).unwrap();
        let mut out = Vec::new();
        r.push(b"xyzabc", &mut out).unwrap();
        assert_eq!(out, b"xyz"); // only "abc" could still begin a match
        r.finish(&mut out).unwrap();
        assert_eq!(out, b"xyzabc");
    }
}
