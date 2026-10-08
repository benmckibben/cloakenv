//! `--vault` pointing at something that is not a regular file (device,
//! FIFO, directory) or at a huge file must fail closed, quickly, without
//! reading unbounded data and without blocking. Each run has a hard timeout so
//! a regression fails the test instead of hanging CI or exhausting memory.
#![cfg(unix)]

mod common;

use std::os::unix::fs::symlink;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use cloakenv::vault::MAX_VAULT_LEN;
use common::*;

const TIMEOUT: Duration = Duration::from_secs(15);

/// Runs `cmd`, killing it and failing the test if it takes longer than
/// [`TIMEOUT`].
fn output_with_timeout(mut cmd: Command) -> Output {
    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let started = Instant::now();
    loop {
        if child.try_wait().unwrap().is_some() {
            return child.wait_with_output().unwrap();
        }
        if started.elapsed() > TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            panic!("cloakenv did not exit within {TIMEOUT:?} (read or blocked on a special file?)");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// `cloakenv --vault <path> run -- sh -c 'touch child-ran'`
fn run_on(env: &Env, vault: &Path) -> (Output, bool) {
    let mut cmd = env.cmd(Some(PASS));
    cmd.arg("--vault")
        .arg(vault)
        .args(["run", "--", "sh", "-c", "touch child-ran"]);
    let out = output_with_timeout(cmd);
    (out, env.path().join("child-ran").exists())
}

fn assert_refused(env: &Env, vault: &Path, expect: &str) {
    let (out, ran) = run_on(env, vault);
    let err = stderr(&out);
    assert!(!ran, "child must not run for {}", vault.display());
    assert_eq!(out.status.code(), Some(125), "{}: {err}", vault.display());
    assert!(out.stdout.is_empty());
    assert!(err.contains(expect), "{}: {err}", vault.display());
}

const NOT_REGULAR: &str = "is not a regular file";

#[test]
fn dev_zero_is_refused() {
    assert_refused(&Env::new(), Path::new("/dev/zero"), NOT_REGULAR);
}

#[test]
fn dev_urandom_is_refused() {
    assert_refused(&Env::new(), Path::new("/dev/urandom"), NOT_REGULAR);
}

#[test]
fn fifo_is_refused_without_blocking() {
    let env = Env::new();
    let fifo = env.path().join("vault.fifo");
    let status = Command::new("mkfifo").arg(&fifo).status().unwrap();
    assert!(status.success(), "mkfifo failed");
    // No writer ever opens the FIFO: a blocking open or read would hang.
    assert_refused(&env, &fifo, NOT_REGULAR);
}

#[test]
fn directory_is_refused() {
    let env = Env::new();
    let dir = env.path().join("a-directory");
    std::fs::create_dir(&dir).unwrap();
    assert_refused(&env, &dir, NOT_REGULAR);
}

#[test]
fn symlink_to_special_file_is_refused() {
    let env = Env::new();
    let link = env.path().join("link-to-zero");
    symlink("/dev/zero", &link).unwrap();
    assert_refused(&env, &link, NOT_REGULAR);
}

#[test]
fn oversized_regular_file_is_refused() {
    let env = Env::new();
    let big = env.path().join("big.bin");
    // Sparse: no real disk or memory use.
    let f = std::fs::File::create(&big).unwrap();
    f.set_len(MAX_VAULT_LEN + 1).unwrap();
    drop(f);
    assert_refused(&env, &big, "too large");
}

#[test]
fn file_at_the_size_limit_is_read_and_rejected_as_not_a_vault() {
    let env = Env::new();
    let exact = env.path().join("exact.bin");
    let f = std::fs::File::create(&exact).unwrap();
    f.set_len(MAX_VAULT_LEN).unwrap();
    drop(f);
    // Not "too large": it was read, and it is simply not a vault.
    assert_refused(&env, &exact, "not a cloakenv vault");
}

#[test]
fn list_and_set_also_refuse_special_files() {
    let env = Env::new();
    // `set` takes a lock file next to the vault, so give it a directory we own.
    let dir = env.path().join("a-directory");
    std::fs::create_dir(&dir).unwrap();
    let cases = [
        ("/dev/zero", ["list"].as_slice()),
        (dir.to_str().unwrap(), ["unset", "KEY"].as_slice()),
        (dir.to_str().unwrap(), ["set", "KEY"].as_slice()),
    ];
    for (vault, sub) in cases {
        let mut cmd = env.cmd(Some(PASS));
        cmd.args(["--vault", vault]).args(sub);
        let out = Env::output_with_stdin(cmd, "dummy");
        assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
        assert!(stderr(&out).contains(NOT_REGULAR), "{}", stderr(&out));
    }
}

#[test]
fn symlink_to_a_regular_vault_still_works() {
    // Following a symlinked vault is deliberate (and warned about).
    let env = Env::init();
    env.set("TOKEN", "dummy-token-value");
    let link = env.path().join("vault-link");
    symlink(env.vault(), &link).unwrap();
    let mut cmd = env.cmd(Some(PASS));
    cmd.arg("--vault").arg(&link).arg("list");
    let out = output_with_timeout(cmd);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), "TOKEN\n");
    assert!(stderr(&out).contains("symbolic link"), "{}", stderr(&out));
}
