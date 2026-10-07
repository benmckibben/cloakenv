//! Child process spawning with in-memory secret injection, and the
//! `--shield` streaming redactor.

use std::ffi::{OsStr, OsString};
use std::io::{self, Read, Write};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;

use aho_corasick::{AhoCorasick, MatchKind};
use thiserror::Error;

use crate::vault::Vault;
use crate::{PASSPHRASE_ENV, PASSPHRASE_FILE_ENV};

/// Replacement text written in place of any secret value under `--shield`.
pub const REDACTION: &[u8] = b"[REDACTED_BY_CLOAKENV]";

const CHUNK: usize = 8 * 1024;

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
    #[error("failed to spawn {program}: {source}")]
    Spawn {
        program: String,
        #[source]
        source: io::Error,
    },
    #[error("failed to wait for child process: {0}")]
    Wait(#[source] io::Error),
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

/// Copies `reader` to `writer` through a redactor, flushing after each
/// chunk so interactive output is not delayed more than necessary.
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
                    // Parent stream is gone (e.g. EPIPE). Stop reading so the
                    // child observes a broken pipe too.
                    return;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    let _ = redactor.finish(&mut writer).and_then(|()| writer.flush());
}

/// Spawns `command[0]` with `command[1..]` as arguments and every vault entry
/// injected into its environment, then waits for it to exit.
///
/// The cloakenv passphrase variables are removed from the child's
/// environment. When `shield` is set, the child's stdout and stderr are piped
/// through a [`Redactor`] before reaching our own stdout and stderr.
pub fn run(command: &[OsString], vault: &Vault, shield: bool) -> Result<ExitStatus, RunError> {
    let (program, args) = command.split_first().ok_or(RunError::NoCommand)?;

    // Build the redactors before spawning so a failure here fails closed.
    let redactors = if shield {
        let values: Vec<&[u8]> = vault.iter().map(|(_, v)| v.as_bytes()).collect();
        Some((Redactor::new(&values)?, Redactor::new(&values)?))
    } else {
        None
    };

    let mut cmd = Command::new(program);
    // Removals come after `envs` so a vault entry cannot put the passphrase
    // variables back. `Command` applies these mutations in call order.
    cmd.args(args)
        .envs(vault.iter())
        .env_remove(PASSPHRASE_ENV)
        .env_remove(PASSPHRASE_FILE_ENV)
        .stdin(Stdio::inherit());
    if shield {
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    }

    let mut child = spawn(&mut cmd, program)?;

    let Some((out_redactor, err_redactor)) = redactors else {
        return child.wait().map_err(RunError::Wait);
    };

    let stdout = child.stdout.take().expect("stdout is piped");
    let stderr = child.stderr.take().expect("stderr is piped");
    let out_thread = thread::spawn(move || pump(stdout, io::stdout(), out_redactor));
    let err_thread = thread::spawn(move || pump(stderr, io::stderr(), err_redactor));
    let status = child.wait().map_err(RunError::Wait);
    // Pumps finish once every holder of the pipes' write ends has exited.
    let _ = out_thread.join();
    let _ = err_thread.join();
    status
}

fn spawn(cmd: &mut Command, program: &OsStr) -> Result<Child, RunError> {
    cmd.spawn().map_err(|source| {
        let program = program.to_string_lossy().into_owned();
        match source.kind() {
            io::ErrorKind::NotFound => RunError::NotFound { program },
            io::ErrorKind::PermissionDenied => RunError::PermissionDenied { program },
            _ => RunError::Spawn { program, source },
        }
    })
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
    fn holdback_is_released_at_eof() {
        let mut r = Redactor::new(["abcdef"]).unwrap();
        let mut out = Vec::new();
        r.push(b"xyzabc", &mut out).unwrap();
        assert_eq!(out, b"x"); // "yzabc" could still begin a match
        r.finish(&mut out).unwrap();
        assert_eq!(out, b"xyzabc");
    }
}
