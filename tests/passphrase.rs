//! Passphrase rules: the same text means the same passphrase from every
//! source, a passphrase that cannot be entered the same way everywhere is
//! refused at `init`, and a short one only draws a warning.
#![cfg(unix)]

mod common;

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::process::Output;

use cloakenv::vault::Vault;
use common::*;

const GOOD: &str = "a perfectly fine passphrase";

fn with_env(env: &Env, pass: &str, args: &[&str]) -> Output {
    env.cmd(Some(pass)).args(args).output().unwrap()
}

fn with_file(env: &Env, contents: &[u8], args: &[&str]) -> Output {
    let file = env.path().join("pass.key");
    std::fs::write(&file, contents).unwrap();
    env.cmd(None)
        .env("CLOAKENV_PASSPHRASE_FILE", &file)
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn a_passphrase_ending_in_a_line_break_is_refused_at_init_from_every_source() {
    let env = Env::new();
    let out = with_env(&env, "twelve chars plus newline\n", &["init"]);
    assert_eq!(out.status.code(), Some(1));
    let err = stderr(&out);
    assert!(err.contains("ends with a line break"), "{err}");
    assert!(!err.contains("twelve chars"), "{err}");
    assert!(!env.vault().exists());

    // "x\n\n" in a file is the passphrase "x\n": a regression case.
    for contents in [
        &b"a long enough passphrase\n\n"[..],
        b"a long enough passphrase\r\n\r\n",
        b"a long enough passphrase\r",
    ] {
        let out = with_file(&env, contents, &["init"]);
        assert_eq!(out.status.code(), Some(1), "{contents:?}");
        let err = stderr(&out);
        assert!(err.contains("ends with a line break"), "{err}");
        assert!(!err.contains("long enough"), "{err}");
        assert!(!env.vault().exists(), "{contents:?}");
    }
}

#[test]
fn one_trailing_newline_in_a_file_is_not_part_of_the_passphrase() {
    let env = Env::new();
    for contents in [
        GOOD.as_bytes(),
        b"a perfectly fine passphrase\n",
        b"a perfectly fine passphrase\r\n",
    ] {
        let out = with_file(&env, contents, &["init", "--force", "--yes"]);
        assert!(out.status.success(), "{contents:?}: {}", stderr(&out));
        // The same passphrase from every source unlocks it.
        assert!(with_env(&env, GOOD, &["list"]).status.success());
        for again in [
            GOOD.as_bytes(),
            b"a perfectly fine passphrase\n",
            b"a perfectly fine passphrase\r\n",
        ] {
            assert!(
                with_file(&env, again, &["list"]).status.success(),
                "{again:?}"
            );
        }
    }
}

#[test]
fn nothing_else_is_trimmed() {
    let env = Env::new();
    // Leading and trailing spaces are part of the passphrase.
    let out = with_env(&env, "  spaces around the passphrase  ", &["init"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        !with_env(&env, "spaces around the passphrase", &["list"])
            .status
            .success()
    );
    assert!(
        with_env(&env, "  spaces around the passphrase  ", &["list"])
            .status
            .success()
    );
}

#[test]
fn existing_vaults_still_open_whatever_their_passphrase_ends_with() {
    // A vault made through the library (or by an earlier version) with a
    // passphrase ending in a newline is not locked out by the new rules: the
    // environment variable is used exactly as set, a file loses one newline.
    let env = Env::new();
    Vault::new()
        .save(&env.vault(), b"legacy passphrase with newline\n")
        .unwrap();
    assert!(
        with_env(&env, "legacy passphrase with newline\n", &["list"])
            .status
            .success()
    );
    assert!(
        with_file(&env, b"legacy passphrase with newline\n\n", &["list"])
            .status
            .success()
    );
    // And a wrong one still fails closed.
    assert!(
        !with_env(&env, "legacy passphrase with newline", &["list"])
            .status
            .success()
    );
}

#[test]
fn a_failed_unlock_with_a_trailing_line_break_gets_a_hint_without_the_passphrase() {
    let env = Env::new();
    assert!(with_env(&env, GOOD, &["init"]).status.success());
    let out = with_env(&env, "a perfectly fine passphrase\n", &["list"]);
    assert_eq!(out.status.code(), Some(1));
    let err = stderr(&out);
    assert!(err.contains("wrong passphrase"), "{err}");
    assert!(
        err.contains("hint:") && err.contains("ends with a line break"),
        "{err}"
    );
    assert!(!err.contains("perfectly fine"), "{err}");
    // No hint when there is nothing to hint at.
    let out = with_env(&env, "another wrong passphrase", &["list"]);
    assert!(!stderr(&out).contains("hint:"));
    // The same for run, with its own exit code and no command started.
    let out = with_env(
        &env,
        "a perfectly fine passphrase\n",
        &["run", "--", "true"],
    );
    assert_eq!(out.status.code(), Some(125));
    assert!(stderr(&out).contains("hint:"));
}

#[test]
fn a_short_passphrase_draws_a_warning_but_works() {
    let env = Env::new();
    let out = with_env(&env, "abc1234", &["init"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let err = stderr(&out);
    assert!(
        err.contains("cloakenv: warning: the passphrase is shorter than 12 characters"),
        "{err}"
    );
    assert!(!err.contains("abc1234"), "{err}");
    // It is advice only: the vault works, and use never repeats the warning.
    let out = with_env(&env, "abc1234", &["list"]);
    assert!(out.status.success());
    assert!(!stderr(&out).contains("shorter than"), "{}", stderr(&out));
    // A file is judged like the environment (after its newline is removed).
    let out = with_file(&env, b"abc1234\n", &["init", "--force", "--yes"]);
    assert!(stderr(&out).contains("shorter than 12 characters"));
}

#[test]
fn the_warning_counts_characters_and_stops_at_twelve() {
    let env = Env::new();
    for (pass, warns) in [
        ("12345678901", true),
        ("123456789012", false),
        ("ééééééééééé", true), // 11 characters in 22 bytes
        ("éééééééééééé", false),
    ] {
        let out = with_env(&env, pass, &["init", "--force", "--yes"]);
        assert!(out.status.success(), "{pass}: {}", stderr(&out));
        assert_eq!(stderr(&out).contains("shorter than"), warns, "{pass}");
    }
    // The strong test passphrase used everywhere else draws nothing.
    let out = with_env(&env, PASS, &["init", "--force", "--yes"]);
    assert!(!stderr(&out).contains("warning"), "{}", stderr(&out));
}

#[test]
fn a_passphrase_variable_that_is_not_text_is_an_error_not_a_fallback() {
    let env = Env::new();
    let file = env.path().join("pass.key");
    std::fs::write(&file, GOOD).unwrap();
    let out = env
        .cmd(None)
        .env(
            "CLOAKENV_PASSPHRASE",
            OsStr::from_bytes(b"bad-\xff-pass-phrase"),
        )
        .env("CLOAKENV_PASSPHRASE_FILE", &file)
        .arg("init")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let err = stderr(&out);
    assert!(
        err.contains("CLOAKENV_PASSPHRASE is not valid UTF-8"),
        "{err}"
    );
    assert!(!err.contains("bad-"), "{err}");
    assert!(
        !env.vault().exists(),
        "the file must not have been used instead"
    );
}

#[test]
fn an_empty_passphrase_file_is_still_refused() {
    let env = Env::new();
    for contents in [&b""[..], b"\n"] {
        let out = with_file(&env, contents, &["init"]);
        assert_eq!(out.status.code(), Some(1));
        assert!(
            stderr(&out).contains("must not be empty"),
            "{}",
            stderr(&out)
        );
    }
}
