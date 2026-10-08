//! Writing our own diagnostics to stderr without ever panicking.
//!
//! `eprintln!` panics when the write fails, and Rust ignores `SIGPIPE`, so a
//! closed stderr pipe (`cloakenv … 2>&1 | head -0`) turned a perfectly good run
//! into an exit status of 101 and a panic message. Our own messages are
//! best-effort by nature: if nobody is reading them there is nobody to tell,
//! and the exit code still reports success or failure. Write errors on stdout
//! are different (they may be real) and are handled where the data is written.

use std::fmt;
use std::io::{self, Write};

/// Writes `args` and a newline to stderr in one go; failure (a closed pipe,
/// a full disk) is ignored.
pub fn stderr_line(args: fmt::Arguments<'_>) {
    let mut line = args.to_string();
    line.push('\n');
    stderr_text(&line);
}

/// Writes `text` as is to stderr; failure is ignored.
pub fn stderr_text(text: &str) {
    let _ = io::stderr().write_all(text.as_bytes());
}

/// Like `eprintln!`, but never panics.
#[macro_export]
macro_rules! elog {
    ($($arg:tt)*) => {
        $crate::diag::stderr_line(::std::format_args!($($arg)*))
    };
}

/// Runs `write` on stdout; a broken pipe (the reader exited early, as in
/// `cloakenv list | head -1`) is a quiet success, like `cat` being cut short,
/// and any other error is returned.
pub fn stdout_until_closed(write: impl FnOnce(&mut dyn Write) -> io::Result<()>) -> io::Result<()> {
    let mut out = io::stdout().lock();
    let result = write(&mut out).and_then(|()| out.flush());
    match result {
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => Ok(()),
        other => other,
    }
}
