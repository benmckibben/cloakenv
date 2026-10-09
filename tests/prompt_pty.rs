//! The hidden prompt on a real (pseudo-)terminal: nothing typed is echoed, and
//! the terminal's settings are put back on every way out of the prompt: a
//! normal return, end of input, a wrong passphrase, and SIGINT, SIGTERM,
//! SIGHUP, Ctrl-C and Ctrl-Z. Before, a signal at the prompt left the user's
//! terminal with echo (and line editing) off.
//!
//! The terminal is a pty pair made with openpty(3); the child gets the slave as
//! stdin, stdout and stderr and as its controlling terminal (own session), so
//! Ctrl-C written to the master makes the terminal send SIGINT to it, exactly
//! as at a keyboard. The prompt text itself is the synchronisation point: it
//! is only printed once echo is already off, so nothing here sleeps and
//! guesses.
#![cfg(unix)]

mod common;

use std::io;
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Child, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use common::*;
use rustix::termios::{LocalModes, tcgetattr};

const WAIT: Duration = Duration::from_secs(30);

struct Pty {
    master: OwnedFd,
    slave: OwnedFd,
}

fn open_pty() -> Pty {
    let (mut m, mut s) = (0, 0);
    // SAFETY: openpty writes two valid descriptors into the integers we pass
    // (null name, termios and winsize mean "defaults"); on success we take
    // ownership of both exactly once.
    let (master, slave) = unsafe {
        let rc = libc::openpty(
            &mut m,
            &mut s,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );
        assert_eq!(rc, 0, "openpty: {}", io::Error::last_os_error());
        (OwnedFd::from_raw_fd(m), OwnedFd::from_raw_fd(s))
    };
    // Reads from the master must never block the test.
    rustix::fs::fcntl_setfl(&master, rustix::fs::OFlags::NONBLOCK).unwrap();
    Pty { master, slave }
}

/// A cloakenv child on a pty, killed if the test fails before it is reaped.
struct Session {
    child: Child,
    pty: Pty,
    output: Vec<u8>,
    original: rustix::termios::Termios,
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Session {
    /// Starts cloakenv with the given arguments in `env`, with no passphrase
    /// in the environment, so it has to prompt.
    fn start(env: &Env, args: &[&str]) -> Session {
        let mut cmd = env.cmd(None);
        cmd.args(args);
        Session::launch(cmd)
    }

    /// Runs `cmd` with a fresh pty as its controlling terminal.
    fn launch(mut cmd: std::process::Command) -> Session {
        let pty = open_pty();
        let original = tcgetattr(&pty.slave).unwrap();
        cmd.stdin(Stdio::from(pty.slave.try_clone().unwrap()))
            .stdout(Stdio::from(pty.slave.try_clone().unwrap()))
            .stderr(Stdio::from(pty.slave.try_clone().unwrap()));
        // SAFETY: only async-signal-safe calls (setsid, ioctl) between fork
        // and exec, no allocation.
        unsafe {
            cmd.pre_exec(|| {
                if libc::setsid() < 0 {
                    return Err(io::Error::last_os_error());
                }
                // Make the slave (stdin) the controlling terminal.
                if libc::ioctl(0, libc::TIOCSCTTY as _, 0) < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = cmd.spawn().expect("spawn cloakenv");
        Session {
            child,
            pty,
            output: Vec::new(),
            original,
        }
    }

    fn drain(&mut self) {
        let mut buf = [0u8; 4096];
        while let Ok(n) = rustix::io::read(&self.pty.master, &mut buf) {
            if n == 0 {
                break;
            }
            self.output.extend_from_slice(&buf[..n]);
        }
    }

    fn text(&mut self) -> String {
        self.drain();
        String::from_utf8_lossy(&self.output).into_owned()
    }

    /// Waits until the terminal output contains `needle` (counted from the
    /// start of the session).
    fn wait_for(&mut self, needle: &str) {
        let deadline = Instant::now() + WAIT;
        loop {
            if self.text().contains(needle) {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for {needle:?}; saw {:?}",
                self.text()
            );
            if let Ok(Some(status)) = self.child.try_wait() {
                panic!(
                    "cloakenv exited ({status}) before printing {needle:?}; saw {:?}",
                    self.text()
                );
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// Types `text` at the terminal (the master side).
    fn type_text(&self, text: &str) {
        let mut rest = text.as_bytes();
        while !rest.is_empty() {
            match rustix::io::write(&self.pty.master, rest) {
                Ok(n) => rest = &rest[n..],
                Err(rustix::io::Errno::AGAIN) => std::thread::sleep(Duration::from_millis(2)),
                Err(e) => panic!("write to the terminal: {e}"),
            }
        }
    }

    fn signal(&self, sig: rustix::process::Signal) {
        let pid = rustix::process::Pid::from_raw(self.child.id() as i32).unwrap();
        rustix::process::kill_process(pid, sig).unwrap();
    }

    fn finish(&mut self) -> ExitStatus {
        let deadline = Instant::now() + WAIT;
        loop {
            // Keep reading the terminal while waiting: on BSD-derived systems
            // (macOS) a session leader that exits with output still unread on
            // its terminal does not finish exiting, as a real terminal
            // emulator would always be reading it.
            self.drain();
            if let Some(status) = self.child.try_wait().unwrap() {
                self.drain();
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "cloakenv did not exit; saw {:?}",
                self.text()
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// The terminal's local modes (echo, canonical mode, signal keys), while
    /// the child is alive.
    fn modes(&self) -> LocalModes {
        tcgetattr(&self.pty.slave).unwrap().local_modes
    }

    /// The same after the child has exited. When a session leader that has
    /// this terminal as its controlling terminal exits, macOS revokes every
    /// open descriptor of the terminal (including ours), so it is opened again
    /// by name; if even that is not possible the settings cannot be read on
    /// that OS and `None` is returned. On Linux it always works.
    fn modes_after_exit(&self) -> Option<LocalModes> {
        if let Ok(t) = tcgetattr(&self.pty.slave) {
            return Some(t.local_modes);
        }
        let name = rustix::termios::ttyname(&self.pty.slave, Vec::new()).ok()?;
        let path = std::path::Path::new(std::ffi::OsStr::from_bytes(name.to_bytes()));
        let reopened = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(rustix::fs::OFlags::NOCTTY.bits() as i32)
            .open(path)
            .ok()?;
        tcgetattr(&reopened).ok().map(|t| t.local_modes)
    }

    fn assert_terminal_untouched(&self, when: &str) {
        let Some(now) = self.modes_after_exit() else {
            if cfg!(target_os = "linux") {
                panic!("cannot read the terminal settings {when}");
            }
            eprintln!("note: terminal settings are unreadable {when} on this OS; not checked");
            return;
        };
        let was = self.original.local_modes;
        assert_eq!(
            now,
            was,
            "the terminal was left changed {when}: ECHO {} (was {}), ICANON {} (was {}), ISIG {} (was {})",
            now.contains(LocalModes::ECHO),
            was.contains(LocalModes::ECHO),
            now.contains(LocalModes::ICANON),
            was.contains(LocalModes::ICANON),
            now.contains(LocalModes::ISIG),
            was.contains(LocalModes::ISIG),
        );
    }
}

const PROMPT: &str = "cloakenv passphrase: ";

#[test]
fn the_prompt_hides_what_is_typed_and_leaves_the_terminal_as_it_was() {
    let env = Env::init();
    env.set("A_NAME", "a value");
    let mut s = Session::start(&env, &["list"]);
    s.wait_for(PROMPT);
    // The prompt is shown, so echo is off by now.
    assert!(!s.modes().contains(LocalModes::ECHO), "echo must be off");
    assert!(
        s.modes().contains(LocalModes::ICANON),
        "line editing must stay on"
    );
    assert!(
        s.modes().contains(LocalModes::ISIG),
        "Ctrl-C must keep working"
    );
    s.type_text(&format!("{PASS}\n"));
    let status = s.finish();
    let out = s.text();
    assert!(status.success(), "{status}: {out}");
    assert!(out.contains("A_NAME"), "{out}");
    assert!(
        !out.contains("correct horse"),
        "the passphrase was echoed: {out}"
    );
    s.assert_terminal_untouched("after a normal return");
}

#[test]
fn a_wrong_passphrase_fails_cleanly_and_restores_the_terminal() {
    let env = Env::init();
    let marker = env.path().join("ran");
    let mut s = Session::start(&env, &["run", "--", "touch", marker.to_str().unwrap()]);
    s.wait_for(PROMPT);
    s.type_text("not the passphrase\n");
    let status = s.finish();
    let out = s.text();
    assert_eq!(status.code(), Some(125), "{out}");
    assert!(!out.contains("not the passphrase"), "echoed: {out}");
    assert!(!marker.exists(), "the command must not run");
    s.assert_terminal_untouched("after a wrong passphrase");
}

#[test]
fn end_of_input_says_so_and_restores_the_terminal() {
    let env = Env::init();
    let mut s = Session::start(&env, &["list"]);
    s.wait_for(PROMPT);
    s.type_text("\u{4}"); // Ctrl-D on an empty line
    let status = s.finish();
    let out = s.text();
    assert_eq!(status.code(), Some(1), "{out}");
    assert!(
        out.contains("no passphrase entered (end of input at the prompt)"),
        "{out}"
    );
    assert!(
        !out.contains("run on a terminal") && !out.contains("unexpected end of file"),
        "misleading message: {out}"
    );
    s.assert_terminal_untouched("after end of input");
}

#[test]
fn a_signal_at_the_prompt_ends_the_process_by_that_signal_with_the_terminal_restored() {
    use rustix::process::Signal;
    let env = Env::init();
    for (name, sig, number) in [
        ("SIGINT", Signal::INT, libc::SIGINT),
        ("SIGTERM", Signal::TERM, libc::SIGTERM),
        ("SIGHUP", Signal::HUP, libc::SIGHUP),
        ("SIGQUIT", Signal::QUIT, libc::SIGQUIT),
    ] {
        let mut s = Session::start(&env, &["list"]);
        s.wait_for(PROMPT);
        assert!(!s.modes().contains(LocalModes::ECHO), "{name}: echo is off");
        s.signal(sig);
        let status = s.finish();
        assert_eq!(status.signal(), Some(number), "{name}: {status}");
        s.assert_terminal_untouched(&format!("after {name}"));
    }
}

#[test]
fn ctrl_c_typed_at_the_prompt_ends_it_and_restores_the_terminal() {
    let env = Env::init();
    let mut s = Session::start(&env, &["list"]);
    s.wait_for(PROMPT);
    s.type_text("\u{3}"); // the terminal turns this into SIGINT for the foreground group
    let status = s.finish();
    assert_eq!(
        status.signal(),
        Some(libc::SIGINT),
        "{status}: {}",
        s.text()
    );
    s.assert_terminal_untouched("after Ctrl-C");
}

#[test]
fn the_confirmation_prompt_of_init_rejects_a_mismatch_and_creates_nothing() {
    let env = Env::new();
    let mut s = Session::start(&env, &["init"]);
    s.wait_for(PROMPT);
    s.type_text("first long passphrase\n");
    s.wait_for("confirm passphrase: ");
    assert!(
        !s.modes().contains(LocalModes::ECHO),
        "confirm prompt hides input too"
    );
    s.type_text("a different passphrase\n");
    let status = s.finish();
    let out = s.text();
    assert_eq!(status.code(), Some(1), "{out}");
    assert!(out.contains("passphrases do not match"), "{out}");
    assert!(
        !out.contains("first long") && !out.contains("different passphrase"),
        "{out}"
    );
    assert!(!env.vault().exists(), "no vault may be created");
    s.assert_terminal_untouched("after a mismatch");
}

#[test]
fn init_with_matching_passphrases_creates_a_vault_that_opens() {
    let env = Env::new();
    let mut s = Session::start(&env, &["init"]);
    s.wait_for(PROMPT);
    s.type_text("a long enough passphrase\n");
    s.wait_for("confirm passphrase: ");
    s.type_text("a long enough passphrase\n");
    let status = s.finish();
    assert!(status.success(), "{status}: {}", s.text());
    assert!(env.vault().exists());
    s.assert_terminal_untouched("after init");
    let out = env
        .cmd(Some("a long enough passphrase"))
        .arg("list")
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
}

#[test]
fn the_value_prompt_of_set_hides_the_value_and_refuses_an_empty_answer() {
    let env = Env::init();
    // The passphrase comes from the environment, the value from the prompt.
    let cmd_env = |args: &[&str]| {
        let mut cmd = env.cmd(Some(PASS));
        cmd.args(args);
        Session::launch(cmd)
    };

    let mut s = cmd_env(&["set", "TOKEN"]);
    s.wait_for("value for TOKEN: ");
    assert!(!s.modes().contains(LocalModes::ECHO));
    s.type_text("tok-secret-value-123\n");
    let status = s.finish();
    let out = s.text();
    assert!(status.success(), "{out}");
    assert!(!out.contains("tok-secret-value"), "echoed: {out}");
    s.assert_terminal_untouched("after set");
    let shown = env.ok(&["run", "--", "sh", "-c", "printf %s \"$TOKEN\""]);
    assert_eq!(stdout(&shown), "tok-secret-value-123");

    // Enter on an empty line: refused, and the old value stays.
    let mut s = cmd_env(&["set", "TOKEN"]);
    s.wait_for("value for TOKEN: ");
    s.type_text("\n");
    let status = s.finish();
    let out = s.text();
    assert_eq!(status.code(), Some(1), "{out}");
    assert!(
        out.contains("the value is empty, so nothing was stored"),
        "{out}"
    );
    s.assert_terminal_untouched("after an empty answer");
    let shown = env.ok(&["run", "--", "sh", "-c", "printf %s \"$TOKEN\""]);
    assert_eq!(stdout(&shown), "tok-secret-value-123");

    // ...unless asked for.
    let mut s = cmd_env(&["set", "--allow-empty", "TOKEN"]);
    s.wait_for("value for TOKEN: ");
    s.type_text("\n");
    assert!(s.finish().success(), "{}", s.text());
    let shown = env.ok(&["run", "--", "sh", "-c", "printf '[%s]' \"$TOKEN\""]);
    assert_eq!(stdout(&shown), "[]");
}

/// Ctrl-Z stops the process with the terminal restored (so the shell is
/// usable while it is stopped); continuing it hides the input again and the
/// prompt carries on. Linux only: job control on a bare pty is the least
/// portable corner of this file.
#[cfg(target_os = "linux")]
#[test]
fn ctrl_z_restores_the_terminal_while_stopped_and_hides_input_again_after_continuing() {
    let env = Env::init();
    env.set("K", "v");
    let mut s = Session::start(&env, &["list"]);
    s.wait_for(PROMPT);
    s.type_text("\u{1a}"); // Ctrl-Z: SIGTSTP for the foreground group
    // Wait for the child to stop.
    let pid = s.child.id() as libc::pid_t;
    let deadline = Instant::now() + WAIT;
    loop {
        let mut status = 0;
        // SAFETY: waitpid on our own child with a valid status pointer;
        // WNOHANG so that a child that never stops fails the test by
        // timeout instead of hanging it.
        let rc = unsafe { libc::waitpid(pid, &mut status, libc::WUNTRACED | libc::WNOHANG) };
        assert!(rc >= 0, "waitpid: {}", io::Error::last_os_error());
        if rc == pid {
            assert!(
                libc::WIFSTOPPED(status),
                "the child exited instead of stopping: {status:#x}; saw {:?}",
                s.text()
            );
            break;
        }
        assert!(Instant::now() < deadline, "the child never stopped");
        std::thread::sleep(Duration::from_millis(5));
    }
    s.assert_terminal_untouched("while stopped by Ctrl-Z");
    s.signal(rustix::process::Signal::CONT);
    // Echo goes off again once it is running; wait for that, not for a delay.
    let deadline = Instant::now() + WAIT;
    while s.modes().contains(LocalModes::ECHO) {
        assert!(
            Instant::now() < deadline,
            "echo never went off after SIGCONT"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    s.type_text(&format!("{PASS}\n"));
    let status = s.finish();
    let out = s.text();
    assert!(status.success(), "{status}: {out}");
    assert!(out.contains('K'), "{out}");
    assert!(!out.contains("correct horse"), "{out}");
    s.assert_terminal_untouched("after continuing and finishing");
}
