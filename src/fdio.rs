//! Writing to our own stdout and stderr (Unix) the way a command-line tool
//! has to: with the file descriptor as it is, not as we would like it.
//!
//! `O_NONBLOCK` is a property of the open file *description*, which is shared
//! with every process that inherited or duplicated the descriptor. A parent
//! that made a pipe non-blocking for its own reading (a Node or Python event
//! loop, say) hands cloakenv a stdout on which a full pipe makes `write` fail
//! with `EAGAIN` instead of waiting. `std`'s `write_all` treats that as an
//! error, and cannot say how much of the buffer was written before it, so
//! the output was cut short. [`FdWriter`] instead waits until the descriptor
//! is writable (`poll`) and carries on from exactly where the partial write
//! stopped.

use std::io::{self, Write};
use std::os::fd::BorrowedFd;
use std::time::Duration;

use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::io::Errno;

/// A [`Write`] over a raw descriptor that retries `EINTR` and waits out
/// `EAGAIN`.
pub(crate) struct FdWriter<'a> {
    fd: BorrowedFd<'a>,
    /// How long one wait for a non-blocking descriptor may last before the
    /// write gives up with `WouldBlock`. `None`: as long as it takes, which
    /// is what a blocking descriptor does too.
    patience: Option<Duration>,
}

impl<'a> FdWriter<'a> {
    /// Waits as long as the reader needs.
    pub(crate) fn new(fd: BorrowedFd<'a>) -> Self {
        Self { fd, patience: None }
    }

    /// Gives up (with `WouldBlock`) once a non-blocking descriptor has stayed
    /// unwritable for `patience`: for our own diagnostics, which are
    /// best-effort and must not hold the program up for ever.
    pub(crate) fn with_patience(fd: BorrowedFd<'a>, patience: Duration) -> Self {
        Self {
            fd,
            patience: Some(patience),
        }
    }

    fn wait_writable(&self) -> io::Result<()> {
        let timeout = self.patience.map(|d| Timespec {
            tv_sec: i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
            tv_nsec: d.subsec_nanos().into(),
        });
        loop {
            let mut fds = [PollFd::new(&self.fd, PollFlags::OUT)];
            match poll(&mut fds, timeout.as_ref()) {
                Ok(0) => return Err(io::ErrorKind::WouldBlock.into()),
                Ok(_) => {
                    // Writable, or in an error state (the reader is gone):
                    // the next `write` reports which. A descriptor that
                    // cannot be polled at all (`POLLNVAL`) would make this
                    // a busy loop; slow it to something harmless.
                    if fds[0].revents().contains(PollFlags::NVAL) {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    return Ok(());
                }
                Err(Errno::INTR) => continue,
                Err(e) => return Err(e.into()),
            }
        }
    }
}

impl Write for FdWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            match rustix::io::write(self.fd, buf) {
                Ok(n) => return Ok(n),
                Err(Errno::INTR) => {}
                Err(Errno::AGAIN) => self.wait_writable()?,
                Err(e) => return Err(e.into()),
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// True if our stdout and stderr are the same open file, pipe, socket or
/// terminal (`cmd > out 2>&1`, `2>&1 | tee`, or two separate opens of one
/// file): compared by device and inode, which also sees through `dup`.
///
/// An inode number of 0 means the platform does not number the object (not
/// seen on the supported ones); then the answer is "no", the conservative one.
pub(crate) fn stdout_and_stderr_are_one() -> bool {
    let (Ok(out), Ok(err)) = (
        rustix::fs::fstat(rustix::stdio::stdout()),
        rustix::fs::fstat(rustix::stdio::stderr()),
    ) else {
        return false;
    };
    out.st_ino != 0 && out.st_ino == err.st_ino && out.st_dev == err.st_dev
}
