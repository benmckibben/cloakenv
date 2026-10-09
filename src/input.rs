//! Reading secret text (a value piped to `set`, a passphrase file) without
//! leaving stray copies behind.
//!
//! `Read::read_to_string` grows its buffer as data arrives, and every growth
//! copies the bytes read so far into a new allocation and frees the old one
//! *without wiping it*. Here the whole buffer is allocated once, up front, at the
//! size limit plus one byte (so "too large" can be told from "exactly at the
//! limit"), is filled in place and is wiped when dropped, whole capacity
//! included. The text is then moved, not copied, into the `String` that is handed
//! out.

use std::io::{self, Read};

use thiserror::Error;
use zeroize::Zeroizing;

/// Upper bound on a secret value read from stdin by `set` (1 MiB).
pub const MAX_STDIN_VALUE_LEN: usize = 1024 * 1024;

/// Upper bound on the size of a passphrase file (64 KiB).
pub const MAX_PASSPHRASE_FILE_LEN: usize = 64 * 1024;

/// Why secret text could not be read. Never carries any of the input.
#[derive(Debug, Error)]
pub enum InputError {
    /// More than the allowed number of bytes were available.
    #[error("input is too large")]
    TooLarge,
    /// The input is not valid UTF-8.
    #[error("input is not valid UTF-8")]
    NotUtf8,
    /// The underlying read failed.
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// Reads `reader` to the end into a buffer that is allocated once (for
/// `max + 1` bytes, never reallocated) and wiped on drop. Fails with
/// [`InputError::TooLarge`] if more than `max` bytes arrive.
pub fn read_limited(mut reader: impl Read, max: usize) -> Result<Zeroizing<Vec<u8>>, InputError> {
    let mut buf = Zeroizing::new(vec![0u8; max + 1]);
    let mut filled = 0;
    loop {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => {
                filled += n;
                if filled > max {
                    return Err(InputError::TooLarge);
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(InputError::Io(e)),
        }
    }
    // Only shortens the length: the capacity (all of it zero past `filled`) is
    // still wiped on drop.
    buf.truncate(filled);
    Ok(buf)
}

/// Removes a single trailing line ending, `\n` or `\r\n` (a lone `\r` is not
/// one), and nothing else.
pub fn strip_one_line_ending(bytes: &mut Vec<u8>) {
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
    }
}

/// Removes a single trailing line feed (what a terminal's Enter key sends)
/// and nothing else: a `\r` before it stays, as the passphrase rules say.
pub fn strip_one_line_ending_lf(bytes: &mut Vec<u8>) {
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
    }
}

/// Turns the buffer into text without copying it. Fails with
/// [`InputError::NotUtf8`] (the buffer is wiped, nothing is echoed).
pub fn into_text(mut bytes: Zeroizing<Vec<u8>>) -> Result<Zeroizing<String>, InputError> {
    if std::str::from_utf8(&bytes).is_err() {
        return Err(InputError::NotUtf8);
    }
    // `bytes` is left empty (nothing to wipe); the Vec's allocation moves into
    // the String.
    let owned = std::mem::take(&mut *bytes);
    match String::from_utf8(owned) {
        Ok(s) => Ok(Zeroizing::new(s)),
        Err(e) => {
            // Cannot happen (validated above); never let the bytes reach a
            // message, and wipe them.
            drop(Zeroizing::new(e.into_bytes()));
            Err(InputError::NotUtf8)
        }
    }
}

/// Reads all of stdin, at most `max` bytes. On Unix this reads through a
/// duplicate of the stdin descriptor, bypassing std's 8 KiB stdin buffer,
/// which would keep an unwiped copy of the first bytes for the life of the
/// process.
pub fn read_stdin_limited(max: usize) -> Result<Zeroizing<Vec<u8>>, InputError> {
    #[cfg(unix)]
    {
        use std::os::fd::AsFd;
        let file = std::fs::File::from(io::stdin().as_fd().try_clone_to_owned()?);
        read_limited(file, max)
    }
    #[cfg(not(unix))]
    {
        read_limited(io::stdin().lock(), max)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Yields its data a few bytes at a time, like a slow pipe.
    struct Trickle<'a>(&'a [u8], usize);

    impl Read for Trickle<'_> {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            let n = self.1.min(self.0.len()).min(out.len());
            out[..n].copy_from_slice(&self.0[..n]);
            self.0 = &self.0[n..];
            Ok(n)
        }
    }

    #[test]
    fn reads_everything_up_to_the_limit() {
        let data = vec![b'a'; 100];
        assert_eq!(&**read_limited(Trickle(&data, 7), 100).unwrap(), &data[..]);
        assert!(read_limited(Trickle(&[], 7), 100).unwrap().is_empty());
    }

    #[test]
    fn one_byte_over_the_limit_is_refused() {
        let data = vec![b'a'; 101];
        assert!(matches!(
            read_limited(Trickle(&data, 7), 100),
            Err(InputError::TooLarge)
        ));
        // Stops as soon as the limit is passed, whatever is left.
        let endless = io::repeat(b'z');
        assert!(matches!(
            read_limited(endless, 100),
            Err(InputError::TooLarge)
        ));
    }

    #[test]
    fn the_buffer_is_never_reallocated() {
        let data = vec![b'a'; 100];
        let buf = read_limited(Trickle(&data, 3), 100).unwrap();
        assert_eq!(buf.capacity(), 101);
    }

    #[test]
    fn strips_exactly_one_line_ending() {
        let strip = |s: &str| {
            let mut v = s.as_bytes().to_vec();
            strip_one_line_ending(&mut v);
            String::from_utf8(v).unwrap()
        };
        assert_eq!(strip("x\n"), "x");
        assert_eq!(strip("x\r\n"), "x");
        assert_eq!(strip("x\n\n"), "x\n");
        assert_eq!(strip("x\r\n\r\n"), "x\r\n");
        assert_eq!(strip("x\r"), "x\r");
        assert_eq!(strip("x"), "x");
        assert_eq!(strip("\n"), "");
        assert_eq!(strip(""), "");
    }

    #[test]
    fn text_conversion_moves_the_allocation_and_refuses_bad_utf8() {
        let buf = read_limited(Trickle("héllo".as_bytes(), 2), 64).unwrap();
        let ptr = buf.as_ptr();
        let text = into_text(buf).unwrap();
        assert_eq!(&*text, "héllo");
        assert_eq!(text.as_ptr(), ptr, "text must not be a copy");

        let bad = read_limited(Trickle(&[b'a', 0xff, 0xfe], 2), 64).unwrap();
        assert!(matches!(into_text(bad), Err(InputError::NotUtf8)));
    }
}
