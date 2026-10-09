//! A running `cloakenv` whose output can be watched as it arrives, for tests
//! about *when* output shows up. Nothing here depends on timing for success:
//! the command waits on its stdin for the test to say "go" after the test has
//! seen the output it is looking for, so a redactor that holds output back
//! makes the test hang (until the guard below fails it), never flake.
#![allow(dead_code)]
#![cfg(unix)]

use std::io::{Read, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// How long to wait for something that should happen at once before calling
/// it a hang.
pub const GUARD: Duration = Duration::from_secs(30);

pub struct Live {
    pub child: Child,
    stdin: Option<ChildStdin>,
    chunks: Receiver<Vec<u8>>,
    reader: Option<JoinHandle<()>>,
    /// Everything read from stdout so far.
    pub seen: Vec<u8>,
}

impl Live {
    /// Starts `cmd` (stdin and stdout are replaced by pipes).
    pub fn start(mut cmd: Command) -> Self {
        cmd.stdin(Stdio::piped()).stdout(Stdio::piped());
        let mut child = cmd.spawn().expect("spawn cloakenv");
        let stdin = child.stdin.take();
        let mut stdout = child.stdout.take().expect("stdout");
        let (tx, chunks) = mpsc::channel();
        let reader = std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok(n) = stdout.read(&mut buf) {
                if n == 0 || tx.send(buf[..n].to_vec()).is_err() {
                    break;
                }
            }
        });
        Self {
            child,
            stdin,
            chunks,
            reader: Some(reader),
            seen: Vec::new(),
        }
    }

    /// Reads until stdout contains `needle`; panics after [`GUARD`].
    pub fn wait_for(&mut self, needle: &str) {
        let deadline = Instant::now() + GUARD;
        while !contains(&self.seen, needle.as_bytes()) {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.chunks.recv_timeout(left) {
                Ok(chunk) => self.seen.extend_from_slice(&chunk),
                Err(RecvTimeoutError::Timeout) => panic!(
                    "{needle:?} never appeared (output was held back); seen so far: {:?}",
                    String::from_utf8_lossy(&self.seen)
                ),
                Err(RecvTimeoutError::Disconnected) => panic!(
                    "output ended without {needle:?}; seen: {:?}",
                    String::from_utf8_lossy(&self.seen)
                ),
            }
        }
    }

    /// Collects whatever else arrives within `window` (never fails: used to
    /// look for output that must *not* appear).
    pub fn collect_for(&mut self, window: Duration) {
        let deadline = Instant::now() + window;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.chunks.recv_timeout(left) {
                Ok(chunk) => self.seen.extend_from_slice(&chunk),
                Err(_) => return,
            }
        }
    }

    /// Writes `text` to the command's stdin.
    pub fn send(&mut self, text: &str) {
        let stdin = self.stdin.as_mut().expect("stdin open");
        stdin.write_all(text.as_bytes()).expect("write stdin");
        stdin.flush().expect("flush stdin");
    }

    /// Closes stdin, waits for cloakenv to exit (guarded) and returns its
    /// status with all of stdout.
    pub fn finish(mut self) -> (std::process::ExitStatus, Vec<u8>) {
        drop(self.stdin.take());
        let deadline = Instant::now() + GUARD;
        let status = loop {
            if let Some(status) = self.child.try_wait().expect("try_wait") {
                break status;
            }
            assert!(Instant::now() < deadline, "cloakenv did not exit");
            std::thread::sleep(Duration::from_millis(10));
        };
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
        while let Ok(chunk) = self.chunks.try_recv() {
            self.seen.extend_from_slice(&chunk);
        }
        (status, std::mem::take(&mut self.seen))
    }
}

impl Drop for Live {
    fn drop(&mut self) {
        // A failed test must not leave the command behind.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}
