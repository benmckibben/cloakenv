//! Child process spawning with in-memory secret injection, and the
//! `--shield` streaming redactor.

use std::ffi::{OsStr, OsString};
#[cfg(not(unix))]
use std::io::Read;
use std::io::{self, Write};
use std::process::{Command, ExitStatus, Stdio};
#[cfg(not(unix))]
use std::thread;

use aho_corasick::{AhoCorasick, MatchKind};
use thiserror::Error;

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

/// Streaming find-and-replace of secret values over an arbitrary byte stream.
///
/// Matches can straddle chunk boundaries: the redactor holds back the last
/// `max_secret_len - 1` bytes of input until it can prove that no secret
/// starting inside them is still in flight. Matching is leftmost-longest, so
/// when one secret is a prefix of another the longer one is redacted whole.
pub struct Redactor {
    matcher: Option<AhoCorasick>,
    holdback: usize,
    pending: Vec<u8>,
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
        let patterns: Vec<P> = secrets
            .into_iter()
            .filter(|s| !s.as_ref().is_empty())
            .collect();
        let max_len = patterns.iter().map(|p| p.as_ref().len()).max().unwrap_or(0);
        let matcher = if patterns.is_empty() {
            None
        } else {
            Some(
                AhoCorasick::builder()
                    .match_kind(MatchKind::LeftmostLongest)
                    .build(&patterns)
                    .map_err(|_| RunError::Shield)?,
            )
        };
        Ok(Self {
            matcher,
            holdback: max_len.saturating_sub(1),
            pending: Vec::with_capacity(CHUNK + max_len),
        })
    }

    /// Feeds a chunk of input, writing every byte that is now known to be
    /// safe (or redacted) to `out`.
    pub fn push<W: Write + ?Sized>(&mut self, chunk: &[u8], out: &mut W) -> io::Result<()> {
        self.pending.extend_from_slice(chunk);
        self.drain(out, false)
    }

    /// Flushes all remaining buffered input at end of stream.
    pub fn finish<W: Write + ?Sized>(&mut self, out: &mut W) -> io::Result<()> {
        self.drain(out, true)
    }

    fn drain<W: Write + ?Sized>(&mut self, out: &mut W, eof: bool) -> io::Result<()> {
        let Some(matcher) = &self.matcher else {
            out.write_all(&self.pending)?;
            self.pending.clear();
            return Ok(());
        };
        // Any match starting before "safe" is fully determined by the bytes
        // we already have: it (and any longer alternative at the same start)
        // must end within the buffer.
        let safe = if eof {
            self.pending.len()
        } else {
            self.pending.len().saturating_sub(self.holdback)
        };
        let mut cursor = 0;
        for m in matcher.find_iter(&self.pending) {
            if m.start() >= safe {
                break;
            }
            out.write_all(&self.pending[cursor..m.start()])?;
            out.write_all(REDACTION)?;
            cursor = m.end();
        }
        let emit_to = cursor.max(safe);
        out.write_all(&self.pending[cursor..emit_to])?;
        self.pending.drain(..emit_to);
        Ok(())
    }
}

/// Redacts a complete in-memory buffer. Convenience wrapper over [`Redactor`].
pub fn redact_all<I, P>(secrets: I, input: &[u8]) -> Result<Vec<u8>, RunError>
where
    I: IntoIterator<Item = P>,
    P: AsRef<[u8]>,
{
    let mut r = Redactor::new(secrets)?;
    let mut out = Vec::with_capacity(input.len());
    r.push(input, &mut out).expect("writing to Vec cannot fail");
    r.finish(&mut out).expect("writing to Vec cannot fail");
    Ok(out)
}

/// Blocking copy of `reader` to `writer` through a redactor, flushing after each
/// chunk. Only used where there is no supervising poll loop (non-Unix).
#[cfg(not(unix))]
fn pump<R: Read, W: Write>(mut reader: R, mut writer: W, mut redactor: Redactor) {
    let mut buf = vec![0u8; CHUNK];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if redactor
                    .push(&buf[..n], &mut writer)
                    .and_then(|()| writer.flush())
                    .is_err()
                {
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
/// The CLI only uses this for `--shield`; without it, it replaces itself with
/// the command via [`exec_replace`].
pub fn run(command: &[OsString], vault: &Vault, shield: bool) -> Result<ExitStatus, RunError> {
    let (program, args) = command.split_first().ok_or(RunError::NoCommand)?;

    // Build the redactors before spawning so a failure here fails closed.
    let redactors = if shield {
        let values: Vec<&[u8]> = vault.iter().map(|(_, v)| v.as_bytes()).collect();
        Some((Redactor::new(&values)?, Redactor::new(&values)?))
    } else {
        None
    };

    let mut cmd = build_command(program, args, vault);
    if shield {
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    }

    #[cfg(unix)]
    {
        crate::supervise::run(cmd, program, redactors)
    }
    #[cfg(not(unix))]
    {
        let mut child = cmd.spawn().map_err(|e| spawn_error(e, program))?;
        let Some((out_redactor, err_redactor)) = redactors else {
            return child.wait().map_err(RunError::Wait);
        };
        let stdout = child.stdout.take().expect("stdout is piped");
        let stderr = child.stderr.take().expect("stderr is piped");
        let out_thread = thread::spawn(move || pump(stdout, io::stdout(), out_redactor));
        let err_thread = thread::spawn(move || pump(stderr, io::stderr(), err_redactor));
        let status = child.wait().map_err(RunError::Wait);
        let _ = out_thread.join();
        let _ = err_thread.join();
        status
    }
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

    #[test]
    fn holdback_is_released_at_eof() {
        let mut r = Redactor::new(["abcdef"]).unwrap();
        let mut out = Vec::new();
        r.push(b"xyzabc", &mut out).unwrap();
        assert_eq!(out, b"x"); // "yzabc" could still begin a match
        r.finish(&mut out).unwrap();
        assert_eq!(out, b"xyzabc");
    }
}
