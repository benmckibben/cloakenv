//! `cloakenv set` refuses empty input, so a failed producer in a pipeline
//! (`false | cloakenv set KEY`, a `pass show` that could not decrypt) cannot
//! silently replace a good secret with an empty string. `--allow-empty` opts in.
#![cfg(unix)]

mod common;

use std::fs;

use common::*;

const EMPTY_HINT: &str = "the value is empty, so nothing was stored";

fn value_of(env: &Env, key: &str) -> String {
    let script = format!("printf '[%s]' \"${key}\"");
    stdout(&env.ok(&["run", "--", "sh", "-c", &script]))
}

#[test]
fn empty_stdin_is_refused_and_the_existing_secret_survives() {
    let env = Env::init();
    env.set("API_KEY", "the-good-secret");
    let before = fs::read(env.vault()).unwrap();
    // Empty stdin, an empty line, and a lone CRLF: what a failed producer or
    // an accidental Enter leaves behind.
    for input in ["", "\n", "\r\n"] {
        let out = env.run_stdin(&["set", "API_KEY"], input);
        assert_eq!(out.status.code(), Some(1), "{input:?}: {}", stderr(&out));
        let err = stderr(&out);
        assert!(err.contains(EMPTY_HINT), "{input:?}: {err}");
        assert!(err.contains("--allow-empty"), "{err}");
        assert!(out.stdout.is_empty());
    }
    assert_eq!(fs::read(env.vault()).unwrap(), before, "vault untouched");
    assert_eq!(value_of(&env, "API_KEY"), "[the-good-secret]");
}

#[test]
fn a_new_key_is_not_created_from_empty_input() {
    let env = Env::init();
    let out = env.run_stdin(&["set", "FRESH"], "");
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(stdout(&env.ok(&["list"])), "");
}

#[test]
fn allow_empty_stores_an_empty_value_on_purpose() {
    let env = Env::init();
    env.set("OPT", "was-set");
    for input in ["", "\n"] {
        let out = env.run_stdin(&["set", "--allow-empty", "OPT"], input);
        assert!(out.status.success(), "{input:?}: {}", stderr(&out));
        assert_eq!(value_of(&env, "OPT"), "[]");
        // It is set (to nothing), not unset.
        let out = env.ok(&["run", "--", "sh", "-c", "printf %s \"${OPT+set}\""]);
        assert_eq!(stdout(&out), "set");
        env.set("OPT", "was-set");
    }
    // The flag may also come after the key.
    let out = env.run_stdin(&["set", "OPT", "--allow-empty"], "");
    assert!(out.status.success(), "{}", stderr(&out));
}

#[test]
fn allow_empty_does_not_change_anything_for_a_non_empty_value() {
    let env = Env::init();
    let out = env.run_stdin(&["set", "--allow-empty", "K"], "v\n");
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(value_of(&env, "K"), "[v]");
}

#[test]
fn a_failing_producer_in_a_real_pipeline_keeps_the_old_value() {
    use std::process::{Command, Stdio};
    let env = Env::init();
    env.set("API_KEY", "keep-me");
    let mut cmd = Command::new("sh");
    cmd.current_dir(env.path())
        .env("CLOAKENV_PASSPHRASE", PASS)
        .env_remove("CLOAKENV_PASSPHRASE_FILE")
        .env_remove("CLOAKENV_VAULT")
        .arg("-c")
        .arg(format!(
            "false | {} set API_KEY",
            env!("CARGO_BIN_EXE_cloakenv")
        ))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let out = cmd.output().unwrap();
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert_eq!(value_of(&env, "API_KEY"), "[keep-me]");
}
