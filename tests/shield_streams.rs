//! `--shield` and the plumbing around the command's output: stdout and stderr
//! going to the same place, a non-blocking stdout, a failing stdout, and
//! inherited signal dispositions.
#![cfg(unix)]

mod common;

use std::fs::File;
use std::io::{Read, pipe};
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::process::{ExitStatus, Stdio};
use std::sync::mpsc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use common::*;

const SECRET: &str = "sk-live-0123456789";
const R: &str = "[REDACTED_BY_CLOAKENV]";
const GUARD: Duration = Duration::from_secs(120);
const PAIRS: usize = 20_000;

/// Each iteration writes one whole line to stdout and one to stderr. A shell
/// builtin `echo` is a single write(2), so lines are never split by the
/// command itself.
fn pairs_script() -> String {
    format!(
        r#"i=0; while [ $i -lt {PAIRS} ]; do echo "out line $i ....................."; echo "err line $i ....................." >&2; i=$((i+1)); done"#
    )
}

fn expected_pairs() -> String {
    let mut s = String::new();
    for i in 0..PAIRS {
        s.push_str(&format!("out line {i} .....................\n"));
        s.push_str(&format!("err line {i} .....................\n"));
    }
    s
}

fn shielded() -> Env {
    let env = Env::init();
    env.set("API_KEY", SECRET);
    env
}

/// Reads `source` to the end on a thread, optionally napping between reads
/// (a slow consumer).
fn drain(mut source: impl Read + Send + 'static, nap: Duration) -> JoinHandle<Vec<u8>> {
    thread::spawn(move || {
        let mut all = Vec::new();
        let mut buf = vec![0u8; 4096];
        loop {
            match source.read(&mut buf) {
                Ok(0) | Err(_) => return all,
                Ok(n) => all.extend_from_slice(&buf[..n]),
            }
            if !nap.is_zero() {
                thread::sleep(nap);
            }
        }
    })
}

fn join_guarded(handle: JoinHandle<Vec<u8>>) -> Vec<u8> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let _ = tx.send(handle.join().unwrap());
    });
    rx.recv_timeout(GUARD).expect("reader did not finish")
}

fn wait_guarded(mut child: std::process::Child) -> ExitStatus {
    let deadline = std::time::Instant::now() + GUARD;
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        if std::time::Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("cloakenv did not exit");
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn set_nonblocking(fd: &impl AsRawFd) {
    // SAFETY: fcntl(F_GETFL/F_SETFL) on a descriptor we own, no pointers.
    unsafe {
        let flags = libc::fcntl(fd.as_raw_fd(), libc::F_GETFL);
        assert!(flags >= 0);
        assert_eq!(
            libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK),
            0
        );
    }
}

fn is_nonblocking(fd: &impl AsRawFd) -> bool {
    // SAFETY: as above.
    unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) & libc::O_NONBLOCK != 0 }
}

// ---- stdout and stderr to the same place --------------------------------

#[test]
fn stdout_and_stderr_into_one_file_never_splice_and_keep_their_order() {
    let env = shielded();
    let path = env.path().join("both.txt");
    let file = File::create(&path).unwrap();
    let mut cmd = env.cmd(Some(PASS));
    cmd.args(["run", "--shield", "--", "sh", "-c", &pairs_script()])
        .stdout(file.try_clone().unwrap())
        .stderr(file);
    let status = wait_guarded(cmd.spawn().unwrap());
    assert!(status.success());
    let text = std::fs::read_to_string(&path).unwrap();
    assert_eq!(text.lines().count(), 2 * PAIRS);
    // No line is cut by one from the other stream, and since both streams are
    // one destination the command's own order is kept.
    assert!(
        text == expected_pairs(),
        "output differs from what the command wrote"
    );
}

#[test]
fn stdout_and_stderr_into_one_pipe_never_splice_and_keep_their_order() {
    let env = shielded();
    let (reader, writer) = pipe().unwrap();
    let mut cmd = env.cmd(Some(PASS));
    cmd.args(["run", "--shield", "--", "sh", "-c", &pairs_script()])
        .stdout(writer.try_clone().unwrap())
        .stderr(writer);
    let child = cmd.spawn().unwrap();
    drop(cmd);
    let reader = drain(reader, Duration::ZERO);
    assert!(wait_guarded(child).success());
    let out = join_guarded(reader);
    assert_eq!(out.len(), expected_pairs().len());
    assert!(out == expected_pairs().as_bytes());
}

#[test]
fn a_slow_reader_of_a_shared_destination_neither_loses_data_nor_deadlocks() {
    let env = shielded();
    let (reader, writer) = pipe().unwrap();
    let mut cmd = env.cmd(Some(PASS));
    cmd.args(["run", "--shield", "--", "sh", "-c", &pairs_script()])
        .stdout(writer.try_clone().unwrap())
        .stderr(writer);
    let child = cmd.spawn().unwrap();
    drop(cmd);
    // 4 KiB every millisecond or so: far slower than the command writes.
    let reader = drain(reader, Duration::from_millis(1));
    assert!(wait_guarded(child).success());
    let out = join_guarded(reader);
    assert!(out == expected_pairs().as_bytes());
}

#[test]
fn a_secret_split_across_stdout_and_stderr_is_caught_when_they_are_one_destination() {
    let env = shielded();
    let (reader, writer) = pipe().unwrap();
    let script = format!(
        "printf 'a {}'; printf '{} b\\n' >&2",
        &SECRET[..9],
        &SECRET[9..]
    );
    let mut cmd = env.cmd(Some(PASS));
    cmd.args(["run", "--shield", "--", "sh", "-c", &script])
        .stdout(writer.try_clone().unwrap())
        .stderr(writer);
    let child = cmd.spawn().unwrap();
    drop(cmd);
    let reader = drain(reader, Duration::ZERO);
    assert!(wait_guarded(child).success());
    let out = join_guarded(reader);
    assert_eq!(String::from_utf8_lossy(&out), format!("a {R} b\n"));
}

#[test]
fn separate_destinations_stay_separate_and_each_stream_is_redacted() {
    let env = shielded();
    let (out_r, out_w) = pipe().unwrap();
    let (err_r, err_w) = pipe().unwrap();
    let script = format!(
        r#"i=0; while [ $i -lt 5000 ]; do echo "out $i {SECRET}"; echo "err $i {SECRET}" >&2; i=$((i+1)); done"#
    );
    let mut cmd = env.cmd(Some(PASS));
    cmd.args(["run", "--shield", "--", "sh", "-c", &script])
        .stdout(out_w)
        .stderr(err_w);
    let child = cmd.spawn().unwrap();
    drop(cmd);
    let (out_t, err_t) = (drain(out_r, Duration::ZERO), drain(err_r, Duration::ZERO));
    assert!(wait_guarded(child).success());
    let (out, err) = (join_guarded(out_t), join_guarded(err_t));
    let (out, err) = (
        String::from_utf8(out).unwrap(),
        String::from_utf8(err).unwrap(),
    );
    assert_eq!(out.lines().count(), 5000);
    assert_eq!(err.lines().count(), 5000);
    assert!(
        out.lines()
            .enumerate()
            .all(|(i, l)| l == format!("out {i} {R}"))
    );
    assert!(
        err.lines()
            .enumerate()
            .all(|(i, l)| l == format!("err {i} {R}"))
    );
}

// ---- a non-blocking stdout ---------------------------------------------

const MEGABYTE: usize = 1024 * 1024;
const MEGABYTE_OF_X: &str = r#"head -c 1048576 /dev/zero | tr '\0' x"#;

#[test]
fn a_nonblocking_stdout_gets_all_the_output() {
    let env = shielded();
    let (reader, writer) = pipe().unwrap();
    set_nonblocking(&writer);
    let mut cmd = env.cmd(Some(PASS));
    cmd.args(["run", "--shield", "--", "sh", "-c", MEGABYTE_OF_X])
        .stdout(writer)
        .stderr(Stdio::piped());
    let child = cmd.spawn().unwrap();
    drop(cmd);
    // Let the pipe fill up, so that cloakenv's write meets EAGAIN.
    thread::sleep(Duration::from_millis(400));
    let reader = drain(reader, Duration::from_millis(1));
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert!(out.stderr.is_empty(), "{}", stderr(&out));
    let data = join_guarded(reader);
    assert_eq!(data.len(), MEGABYTE);
    assert!(data.iter().all(|b| *b == b'x'));
}

#[test]
fn a_nonblocking_stderr_gets_all_the_output() {
    let env = shielded();
    let (reader, writer) = pipe().unwrap();
    set_nonblocking(&writer);
    let script = format!("{MEGABYTE_OF_X} >&2");
    let mut cmd = env.cmd(Some(PASS));
    cmd.args(["run", "--shield", "--", "sh", "-c", &script])
        .stdout(Stdio::piped())
        .stderr(writer);
    let child = cmd.spawn().unwrap();
    drop(cmd);
    thread::sleep(Duration::from_millis(400));
    let reader = drain(reader, Duration::from_millis(1));
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(join_guarded(reader).len(), MEGABYTE);
}

#[test]
fn a_nonblocking_shared_destination_gets_all_the_output() {
    let env = shielded();
    let (reader, writer) = pipe().unwrap();
    set_nonblocking(&writer);
    let script = format!("{MEGABYTE_OF_X}; {MEGABYTE_OF_X} >&2");
    let mut cmd = env.cmd(Some(PASS));
    cmd.args(["run", "--shield", "--", "sh", "-c", &script])
        .stdout(writer.try_clone().unwrap())
        .stderr(writer);
    let child = cmd.spawn().unwrap();
    drop(cmd);
    thread::sleep(Duration::from_millis(400));
    let reader = drain(reader, Duration::from_millis(1));
    assert!(wait_guarded(child).success());
    assert_eq!(join_guarded(reader).len(), 2 * MEGABYTE);
}

#[test]
fn the_command_does_not_get_a_nonblocking_pipe_from_the_shield() {
    // The command's own output pipes are fresh and blocking whatever the
    // flags on cloakenv's stdout: the command must not see EAGAIN.
    let env = shielded();
    let (reader, writer) = pipe().unwrap();
    set_nonblocking(&writer);
    assert!(is_nonblocking(&writer));
    let mut cmd = env.cmd(Some(PASS));
    cmd.args(["run", "--shield", "--", "sh", "-c", MEGABYTE_OF_X])
        .stdout(writer)
        .stderr(Stdio::null());
    let child = cmd.spawn().unwrap();
    drop(cmd);
    let reader = drain(reader, Duration::ZERO);
    assert!(wait_guarded(child).success());
    assert_eq!(join_guarded(reader).len(), MEGABYTE);
}

// ---- a stdout that fails -----------------------------------------------

#[test]
fn a_failing_stdout_is_an_error_not_a_silent_success() {
    // /dev/full accepts the open and fails every write with ENOSPC.
    let Ok(full) = std::fs::OpenOptions::new().write(true).open("/dev/full") else {
        eprintln!("skipping: no /dev/full");
        return;
    };
    let env = shielded();
    let mut cmd = env.cmd(Some(PASS));
    cmd.args(["run", "--shield", "--", "sh", "-c", "echo hello; exit 0"])
        .stdout(full)
        .stderr(Stdio::piped());
    let out = cmd.spawn().unwrap().wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(125), "{}", stderr(&out));
    let err = stderr(&out);
    assert!(
        err.contains("failed to write the command's output"),
        "{err}"
    );
    assert!(!err.contains(SECRET));
}

#[test]
fn a_failing_stderr_is_an_error_too() {
    let Ok(full) = std::fs::OpenOptions::new().write(true).open("/dev/full") else {
        eprintln!("skipping: no /dev/full");
        return;
    };
    let env = shielded();
    let mut cmd = env.cmd(Some(PASS));
    cmd.args([
        "run",
        "--shield",
        "--",
        "sh",
        "-c",
        "echo hello >&2; exit 0",
    ])
    .stdout(Stdio::piped())
    .stderr(full);
    let out = cmd.spawn().unwrap().wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(125));
}

// ---- inherited signal dispositions -------------------------------------

/// Starts `cloakenv run` with SIGCHLD set to `SIG_IGN` (as Python's
/// `preexec_fn` tricks and some launchers leave it).
fn run_with_sigchld_ignored(env: &Env, args: &[&str]) -> std::process::Output {
    let mut cmd = env.cmd(Some(PASS));
    cmd.arg("run").args(args);
    // SAFETY: only async-signal-safe `signal(2)` between fork and exec.
    unsafe {
        cmd.pre_exec(|| {
            libc::signal(libc::SIGCHLD, libc::SIG_IGN);
            Ok(())
        });
    }
    cmd.output().unwrap()
}

#[test]
fn shield_works_when_sigchld_was_inherited_as_ignored() {
    let env = shielded();
    for (script, code) in [("exit 0", 0), ("exit 3", 3), ("kill -TERM $$", 128 + 15)] {
        let out = run_with_sigchld_ignored(&env, &["--shield", "--", "sh", "-c", script]);
        assert_eq!(out.status.code(), Some(code), "{script}: {}", stderr(&out));
        assert!(out.stderr.is_empty(), "{script}: {}", stderr(&out));
    }
    // Output is still redacted and complete.
    let out = run_with_sigchld_ignored(
        &env,
        &[
            "--shield",
            "--",
            "sh",
            "-c",
            r#"echo "$API_KEY"; echo "$API_KEY" >&2"#,
        ],
    );
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(stdout(&out), format!("{R}\n"));
    assert_eq!(stderr(&out), format!("{R}\n"));
}

#[test]
fn without_shield_sigchld_ignored_is_no_problem_either() {
    let env = shielded();
    let out = run_with_sigchld_ignored(&env, &["--", "sh", "-c", "exit 3"]);
    assert_eq!(out.status.code(), Some(3));
}

/// The command sees SIGCHLD the way cloakenv's caller left it, with and
/// without `--shield` (cloakenv only resets it for itself).
#[cfg(target_os = "linux")]
#[test]
fn the_command_inherits_the_callers_sigchld_disposition_in_both_modes() {
    fn chld_ignored(out: &std::process::Output) -> bool {
        let text = stdout(out);
        let mask = text
            .lines()
            .find_map(|l| l.strip_prefix("SigIgn:"))
            .map(|m| u64::from_str_radix(m.trim(), 16).unwrap())
            .unwrap_or_else(|| panic!("no SigIgn in {text}"));
        mask & (1 << (libc::SIGCHLD - 1)) != 0
    }
    let env = shielded();
    for mode in [&["--shield"][..], &[][..]] {
        let mut args = mode.to_vec();
        args.extend(["--", "cat", "/proc/self/status"]);
        let ignored = run_with_sigchld_ignored(&env, &args);
        assert!(chld_ignored(&ignored), "{mode:?}: caller ignored SIGCHLD");
        let mut cmd = env.cmd(Some(PASS));
        cmd.arg("run").args(&args);
        let default = cmd.output().unwrap();
        assert!(!chld_ignored(&default), "{mode:?}: caller did not");
    }
}
