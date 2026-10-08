//! Bounded, non-echoing reads of secret text: a value piped to `set` and the
//! passphrase file.
#![cfg(unix)]

mod common;

use std::io::Write;
use std::process::{Command, Output, Stdio};

use common::*;

const MIB: usize = 1024 * 1024;

fn with_stdin_bytes(mut cmd: Command, input: &[u8]) -> Output {
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    // The child may refuse (and exit) before it has read everything.
    let _ = stdin.write_all(input);
    drop(stdin);
    child.wait_with_output().unwrap()
}

fn set_bytes(env: &Env, key: &str, input: &[u8]) -> Output {
    let mut cmd = env.cmd(Some(PASS));
    cmd.args(["set", key]);
    with_stdin_bytes(cmd, input)
}

#[test]
fn a_value_of_exactly_one_mib_is_accepted() {
    let env = Env::init();
    let value = "v".repeat(MIB);
    let out = set_bytes(&env, "BIG", value.as_bytes());
    assert!(out.status.success(), "{}", stderr(&out));
    // (Whether a command can then be started with it is up to the OS: Linux
    // limits a single environment string to 128 KiB.)
    assert_eq!(stdout(&env.ok(&["list"])), "BIG\n");
}

#[test]
fn the_limit_is_on_the_value_not_on_its_trailing_newline() {
    let env = Env::init();
    let value = "v".repeat(MIB);
    for newline in ["\n", "\r\n"] {
        let out = set_bytes(&env, "BIG", format!("{value}{newline}").as_bytes());
        assert!(out.status.success(), "{}", stderr(&out));
    }
    // One byte more is too much, with or without a newline.
    for input in [
        format!("{value}v"),
        format!("{value}v\n"),
        format!("{value}v\r\n"),
    ] {
        let out = set_bytes(&env, "BIG", input.as_bytes());
        assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
        assert!(stderr(&out).contains("larger than 1 MiB"));
    }
}

#[test]
fn a_value_over_the_limit_is_refused_without_echo_and_nothing_is_stored() {
    let env = Env::init();
    env.set("KEEP", "kept");
    let mut value = b"sk-oversize-".to_vec();
    value.resize(MIB + 1, b'x');
    let out = set_bytes(&env, "BIG", &value);
    assert_eq!(out.status.code(), Some(1));
    let err = stderr(&out);
    assert!(
        err.contains("larger than 1 MiB") && err.contains("nothing was stored"),
        "{err}"
    );
    assert!(
        !err.contains("sk-oversize") && !err.contains("xxxx"),
        "{err}"
    );
    assert!(out.stdout.is_empty());
    assert_eq!(stdout(&env.ok(&["list"])), "KEEP\n");
}

#[test]
fn a_value_that_is_not_utf8_is_refused_without_echo() {
    let env = Env::init();
    let out = set_bytes(&env, "BAD", b"sk-before-\xff\xfe-after");
    assert_eq!(out.status.code(), Some(1));
    let err = stderr(&out);
    assert!(
        err.contains("not valid UTF-8") && err.contains("nothing was stored"),
        "{err}"
    );
    assert!(
        !err.contains("sk-before") && !err.contains("after"),
        "{err}"
    );
    assert_eq!(stdout(&env.ok(&["list"])), "");
}

#[test]
fn exactly_one_trailing_newline_is_stripped() {
    let env = Env::init();
    for (key, input, want) in [
        ("A", "v\n", "v"),
        ("B", "v\r\n", "v"),
        ("C", "v\n\n", "v\n"),
        ("D", "v", "v"),
        ("E", "", ""),
    ] {
        env.set(key, input);
        let script = format!("printf %s \"${key}\"");
        let out = env.ok(&["run", "--", "sh", "-c", &script]);
        assert_eq!(stdout(&out), want, "{input:?}");
    }
}

#[test]
fn passphrase_file_that_is_too_large_or_not_utf8_is_refused_without_echo() {
    let env = Env::new();
    let key = env.path().join("big.key");
    let mut big = b"pw-oversize-".to_vec();
    big.resize(64 * 1024 + 1, b'y');
    std::fs::write(&key, &big).unwrap();
    let out = env
        .cmd(None)
        .env("CLOAKENV_PASSPHRASE_FILE", &key)
        .arg("init")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let err = stderr(&out);
    assert!(err.contains("larger than 64 KiB"), "{err}");
    assert!(!err.contains("pw-oversize"), "{err}");
    assert!(!env.vault().exists());

    std::fs::write(&key, b"pw-before-\xff-after\n").unwrap();
    let out = env
        .cmd(None)
        .env("CLOAKENV_PASSPHRASE_FILE", &key)
        .arg("init")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let err = stderr(&out);
    assert!(err.contains("not valid UTF-8"), "{err}");
    assert!(
        !err.contains("pw-before") && !err.contains("after"),
        "{err}"
    );
    assert!(!env.vault().exists());
}
