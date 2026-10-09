//! The hidden prompt for the passphrase (and for a value typed to `set`).
//!
//! Reading a secret from a terminal means switching the terminal's echo off,
//! and a program that dies with echo off leaves the user's shell unusable
//! (nothing they type is shown). So the terminal settings are restored on
//! *every* way out of the prompt:
//!
//! * normal return, an error, end of input (Ctrl-D): a guard restores the
//!   saved settings when it is dropped;
//! * `SIGINT` (Ctrl-C or `kill`), `SIGTERM`, `SIGHUP`, `SIGQUIT`: a handler
//!   that only writes to a pipe wakes the prompt, which restores the settings
//!   and then gives the signal back its default action, so cloakenv still
//!   dies *by that signal* (a shell reports 130 for Ctrl-C) just without
//!   leaving echo off;
//! * `SIGTSTP` (Ctrl-Z): the settings are restored, the process stops as it
//!   would anyway, and when it is continued echo is turned off again and the
//!   prompt carries on;
//! * `SIGKILL` cannot be handled by anyone; `reset` (or `stty sane`) fixes the
//!   terminal after one.
//!
//! Only echo is switched off: line editing and signal keys (Ctrl-C) keep
//! working as usual. A signal that was ignored when cloakenv started (`nohup`)
//! stays ignored. The text is read from the terminal that is standard input
//! (the caller has checked that it is one), into a buffer that is wiped, and is
//! never echoed in an error.

use thiserror::Error;
#[cfg(not(unix))]
use zeroize::Zeroizing;

/// Why a prompt produced no text. Never carries any of what was typed.
#[derive(Debug, Error)]
pub enum PromptError {
    /// The terminal reported end of input (Ctrl-D) before anything was typed.
    #[error("end of input at the prompt")]
    EndOfInput,
    /// More than the allowed number of bytes were typed.
    #[error("what was typed is too long")]
    TooLong,
    /// What was typed is not valid UTF-8.
    #[error("what was typed is not valid UTF-8")]
    NotUtf8,
    /// The terminal could not be read or configured.
    #[error("cannot use the terminal: {0}")]
    Io(#[from] std::io::Error),
}

/// Most bytes accepted at a prompt (the same limit as a passphrase file).
pub const MAX_PROMPT_LEN: usize = crate::input::MAX_PASSPHRASE_FILE_LEN;

#[cfg(unix)]
pub use unix::read_hidden;

#[cfg(not(unix))]
pub fn read_hidden(prompt: &str) -> Result<Zeroizing<String>, PromptError> {
    rpassword::prompt_password(prompt)
        .map(Zeroizing::new)
        .map_err(PromptError::Io)
}

#[cfg(unix)]
mod unix {
    use std::fs;
    use std::io::{self, Write};
    use std::os::fd::{AsFd, OwnedFd};
    use std::os::raw::c_int;
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::net::UnixStream;

    use rustix::event::{PollFd, PollFlags, poll};
    use rustix::io::Errno;
    use rustix::termios::{LocalModes, OptionalActions, Termios, isatty, tcgetattr, tcsetattr};
    use signal_hook::SigId;
    use signal_hook::consts::{SIGHUP, SIGINT, SIGQUIT, SIGTERM, SIGTSTP};
    use signal_hook::low_level::{emulate_default_handler, pipe, unregister};
    use zeroize::Zeroizing;

    use super::{MAX_PROMPT_LEN, PromptError};

    /// The signals that would otherwise end (or stop) the process with echo off.
    const WATCHED: [c_int; 5] = [SIGINT, SIGTERM, SIGHUP, SIGQUIT, SIGTSTP];

    /// Prints `prompt` (on stderr, or on the controlling terminal when stderr
    /// is redirected) and reads one line from the terminal on standard input
    /// without echoing it. One trailing line feed is removed, nothing else.
    pub fn read_hidden(prompt: &str) -> Result<Zeroizing<String>, PromptError> {
        let mut session = Session::start()?;
        session.show(prompt);
        let line = session.read_line(prompt)?;
        // Normal return: the guard's drop restores the terminal.
        Ok(line)
    }

    /// Terminal state saved at the start and put back when this is dropped,
    /// plus the signal pipes. Everything that can leave the prompt goes
    /// through this value's destructor or [`Session::restore`].
    struct Session {
        tty: OwnedFd,
        original: Termios,
        signals: Vec<(c_int, UnixStream, SigId)>,
    }

    impl Session {
        fn start() -> Result<Self, PromptError> {
            let tty = io::stdin().as_fd().try_clone_to_owned()?;
            let original = tcgetattr(&tty).map_err(io::Error::from)?;
            let mut session = Session {
                tty,
                original,
                signals: Vec::new(),
            };
            // Handlers first, so a signal between turning echo off and waiting
            // for input is queued in its pipe, not lost.
            for sig in WATCHED {
                if crate::sys::signal_is_ignored(sig) {
                    continue;
                }
                let (read, write) = UnixStream::pair()?;
                read.set_nonblocking(true)?;
                let id = pipe::register(sig, write)?;
                session.signals.push((sig, read, id));
            }
            session.echo_off()?;
            Ok(session)
        }

        fn echo_off(&self) -> Result<(), PromptError> {
            let mut hidden = self.original.clone();
            hidden.local_modes.remove(LocalModes::ECHO);
            // Show the Enter key's line break even though nothing else is shown.
            hidden.local_modes.insert(LocalModes::ECHONL);
            tcsetattr(&self.tty, OptionalActions::Now, &hidden).map_err(io::Error::from)?;
            Ok(())
        }

        fn restore(&self) {
            // Best effort: a terminal that has gone away cannot be restored.
            let _ = tcsetattr(&self.tty, OptionalActions::Now, &self.original);
        }

        fn show(&self, text: &str) {
            if !isatty(io::stderr()) {
                if let Ok(mut tty) = fs::OpenOptions::new()
                    .write(true)
                    .custom_flags(rustix::fs::OFlags::NOCTTY.bits() as i32)
                    .open("/dev/tty")
                {
                    let _ = tty.write_all(text.as_bytes());
                    return;
                }
            }
            let _ = io::stderr().write_all(text.as_bytes());
        }

        fn read_line(&mut self, prompt: &str) -> Result<Zeroizing<String>, PromptError> {
            // One buffer, allocated once and wiped on drop (see crate::input).
            let mut buf = Zeroizing::new(vec![0u8; MAX_PROMPT_LEN + 1]);
            let mut filled = 0;
            loop {
                let mut fds = vec![PollFd::new(&self.tty, PollFlags::IN)];
                fds.extend(
                    self.signals
                        .iter()
                        .map(|(_, read, _)| PollFd::new(read, PollFlags::IN)),
                );
                match poll(&mut fds, None) {
                    Ok(_) => {}
                    Err(Errno::INTR) => continue,
                    Err(e) => return Err(io::Error::from(e).into()),
                }
                if let Some(i) = (0..self.signals.len()).find(|&i| !fds[i + 1].revents().is_empty())
                {
                    let sig = self.signals[i].0;
                    self.on_signal(sig, prompt)?;
                    continue;
                }
                if fds[0].revents().is_empty() {
                    continue;
                }
                match rustix::io::read(&self.tty, &mut buf[filled..]) {
                    Ok(0) => {
                        self.show("\n");
                        if filled == 0 {
                            return Err(PromptError::EndOfInput);
                        }
                        break;
                    }
                    Ok(n) => {
                        filled += n;
                        if buf[..filled].last() == Some(&b'\n') {
                            break;
                        }
                        if filled > MAX_PROMPT_LEN {
                            return Err(PromptError::TooLong);
                        }
                    }
                    Err(Errno::INTR | Errno::AGAIN) => continue,
                    Err(e) => return Err(io::Error::from(e).into()),
                }
            }
            if filled > MAX_PROMPT_LEN {
                return Err(PromptError::TooLong);
            }
            buf.truncate(filled);
            crate::input::strip_one_line_ending_lf(&mut buf);
            crate::input::into_text(buf).map_err(|_| PromptError::NotUtf8)
        }

        /// A watched signal arrived: put the terminal right, then let it do
        /// what it would have done without us.
        fn on_signal(&mut self, sig: c_int, prompt: &str) -> Result<(), PromptError> {
            // Consume the wake-up bytes of this signal.
            if let Some((_, read, _)) = self.signals.iter().find(|(s, _, _)| *s == sig) {
                let mut sink = [0u8; 16];
                while let Ok(n) = rustix::io::read(read, &mut sink) {
                    if n == 0 {
                        break;
                    }
                }
            }
            self.show("\n");
            self.restore();
            if sig == SIGTSTP {
                // Stop here, as Ctrl-Z would have; carry on when continued.
                let _ = emulate_default_handler(sig);
                self.echo_off()?;
                self.show(prompt);
                return Ok(());
            }
            // Give back the default action and re-raise: the process ends by
            // this signal, and the user's shell sees that.
            for (_, _, id) in self.signals.drain(..) {
                unregister(id);
            }
            let _ = emulate_default_handler(sig);
            // Still here: the default action is to ignore it (not for the
            // signals watched, but never loop forever).
            Err(PromptError::Io(io::Error::from(io::ErrorKind::Interrupted)))
        }
    }

    impl Drop for Session {
        fn drop(&mut self) {
            self.restore();
            for (_, _, id) in self.signals.drain(..) {
                unregister(id);
            }
        }
    }
}
