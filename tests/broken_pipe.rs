//! A reader that goes away early (`cloakenv list | head -1`) must not turn
//! into a panic (exit 101): the output side is simply closed, as it is for `cat`.
//! Real errors still are errors.
#![cfg(unix)]

mod common;

use std::io::pipe;
use std::os::unix::process::ExitStatusExt;
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::time::{Duration, Instant};

use common::*;

/// A stdio whose read end is already closed: every write fails with EPIPE.
fn closed_pipe() -> Stdio {
    let (reader, writer) = pipe().unwrap();
    drop(reader);
    Stdio::from(writer)
}

fn finish(mut child: Child) -> Output {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if child.try_wait().unwrap().is_some() {
            return child.wait_with_output().unwrap();
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("cloakenv did not exit when its output was closed");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn no_panic(out: &Output) {
    let err = stderr(out);
    assert!(
        !err.contains("panicked")
            && !err.contains("Broken pipe")
            && !err.contains("RUST_BACKTRACE"),
        "{err}"
    );
}

fn run_closed(env: &Env, closed_stdout: bool, closed_stderr: bool, args: &[&str]) -> Output {
    let mut cmd = env.cmd(Some(PASS));
    cmd.args(args);
    if closed_stdout {
        cmd.stdout(closed_pipe());
    } else {
        cmd.stdout(Stdio::piped());
    }
    if closed_stderr {
        cmd.stderr(closed_pipe());
    } else {
        cmd.stderr(Stdio::piped());
    }
    finish(cmd.spawn().unwrap())
}

#[test]
fn list_into_a_closed_stdout_is_a_quiet_success() {
    let env = Env::init();
    for key in ["A", "B", "C"] {
        env.set(key, "v");
    }
    let out = run_closed(&env, true, false, &["list"]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert!(out.stderr.is_empty(), "{}", stderr(&out));
}

#[test]
fn list_piped_into_head_is_quiet() {
    let env = Env::init();
    for i in 0..40 {
        env.set(&format!("KEY_{i:02}"), "v");
    }
    let mut sh = Command::new("sh");
    sh.current_dir(env.path())
        .env_remove("CLOAKENV_PASSPHRASE_FILE")
        .env_remove("CLOAKENV_VAULT")
        .env("CLOAKENV_PASSPHRASE", PASS)
        .env("CE_BIN", env!("CARGO_BIN_EXE_cloakenv"))
        .args(["-c", r#""$CE_BIN" list 2>err.txt | head -1; cat err.txt"#]);
    let out = sh.output().unwrap();
    assert_eq!(stdout(&out), "KEY_00\n");
}

#[test]
fn a_real_write_error_on_stdout_is_still_an_error() {
    // /dev/full accepts the open and fails every write with ENOSPC.
    let env = Env::init();
    env.set("A", "v");
    let full = std::fs::OpenOptions::new().write(true).open("/dev/full");
    let Ok(full) = full else {
        eprintln!("skipping: no /dev/full");
        return;
    };
    let mut cmd = env.cmd(Some(PASS));
    cmd.arg("list")
        .stdout(Stdio::from(full))
        .stderr(Stdio::piped());
    let out = finish(cmd.spawn().unwrap());
    assert_eq!(out.status.code(), Some(1));
    let err = stderr(&out);
    assert!(err.contains("cannot write to stdout"), "{err}");
    no_panic(&out);
}

#[test]
fn messages_into_a_closed_stderr_do_not_panic() {
    let env = Env::new();
    // init says "initialized vault" on stderr.
    let out = run_closed(&env, false, true, &["init"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(env.vault().exists());
    // set says "set KEY".
    let mut cmd = env.cmd(Some(PASS));
    cmd.args(["set", "K"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(closed_pipe());
    let mut child = cmd.spawn().unwrap();
    {
        use std::io::Write;
        child.stdin.take().unwrap().write_all(b"v").unwrap();
    }
    let out = finish(child);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(stdout(&env.ok(&["list"])), "K\n");
    // Failures keep their exit code (and are not turned into a panic).
    let mut cmd = env.cmd(Some("not the passphrase"));
    cmd.arg("list").stdout(Stdio::piped()).stderr(closed_pipe());
    let out = finish(cmd.spawn().unwrap());
    assert_eq!(out.status.code(), Some(1));
    let mut cmd = env.cmd(Some("not the passphrase"));
    cmd.args(["run", "--", "true"])
        .stdout(Stdio::piped())
        .stderr(closed_pipe());
    let out = finish(cmd.spawn().unwrap());
    assert_eq!(out.status.code(), Some(125));
    // A usage error.
    let out = run_closed(&env, false, true, &["bogus"]);
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn help_and_version_into_a_closed_stdout_do_not_panic() {
    let env = Env::new();
    for arg in ["--help", "--version"] {
        let out = run_closed(&env, true, false, &[arg]);
        no_panic(&out);
        assert_ne!(out.status.code(), Some(101), "{arg}");
    }
}

#[test]
fn shield_warning_into_a_closed_stderr_does_not_panic() {
    let env = Env::init();
    env.set("PORT", "80"); // shorter than 6 bytes: --shield warns on stderr
    let out = run_closed(&env, false, true, &["run", "--shield", "--", "true"]);
    assert_eq!(out.status.code(), Some(0));
}

fn signal_of(status: ExitStatus) -> Option<i32> {
    status.signal()
}

const FLOOD: &str = "while :; do echo 0123456789012345678901234567890123456789; done";

#[test]
fn shielded_command_whose_output_reader_left_ends_without_a_panic() {
    let env = Env::init();
    env.set("SECRET", "never-printed-secret-value");
    let out = run_closed(
        &env,
        true,
        false,
        &["run", "--shield", "--", "sh", "-c", FLOOD],
    );
    no_panic(&out);
    // The command is cut off by SIGPIPE, the usual end of a producer whose
    // consumer has gone; cloakenv reports it like a shell: 128 + 13.
    assert_eq!(out.status.code(), Some(128 + 13), "{}", stderr(&out));
}

#[test]
fn shielded_command_whose_error_reader_left_ends_without_a_panic() {
    let env = Env::init();
    env.set("SECRET", "never-printed-secret-value");
    let script = "while :; do echo 0123456789012345678901234567890123456789 >&2; done";
    let out = run_closed(
        &env,
        false,
        true,
        &["run", "--shield", "--", "sh", "-c", script],
    );
    assert_eq!(out.status.code(), Some(128 + 13));
}

#[test]
fn unshielded_command_whose_output_reader_left_dies_of_sigpipe_like_any_command() {
    let env = Env::init();
    env.set("SECRET", "never-printed-secret-value");
    let out = run_closed(&env, true, false, &["run", "--", "sh", "-c", FLOOD]);
    no_panic(&out);
    // cloakenv has become the command, which was killed by SIGPIPE.
    assert_eq!(signal_of(out.status), Some(13), "{:?}", out.status);
}
