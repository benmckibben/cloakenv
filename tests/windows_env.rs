//! The environment `run` hands to a command on Windows: names are not
//! case-sensitive, and the sizes that matter in practice are not limited.
#![cfg(windows)]

mod common;

use common::*;

#[test]
fn run_refuses_a_vault_with_two_spellings_of_one_name() {
    let env = Env::init();
    env.set("TOKEN", "first-value");
    env.set("token", "second-value");
    let out = env.run(&["run", "--", "cmd", "/c", "exit", "0"]);
    assert_eq!(out.status.code(), Some(125), "{}", stderr(&out));
    let err = stderr(&out);
    assert!(err.contains("TOKEN") && err.contains("token"), "{err}");
    assert!(err.contains("differ only in case"), "{err}");
    assert!(
        !err.contains("first-value") && !err.contains("second-value"),
        "{err}"
    );
    // Once one is gone the command starts.
    env.ok(&["unset", "token"]);
    let out = env.run(&["run", "--", "cmd", "/c", "exit", "0"]);
    assert!(out.status.success(), "{}", stderr(&out));
}

#[test]
fn a_vault_name_replaces_an_inherited_variable_of_another_case() {
    let env = Env::init();
    env.set("myinherited", "from-the-vault");
    let out = env
        .cmd(Some(PASS))
        .env("MYINHERITED", "from-the-parent")
        .args(["run", "--", "cmd", "/c", "echo", "%MYINHERITED%"])
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stdout(&out).contains("from-the-vault"), "{}", stdout(&out));
    assert!(
        !stdout(&out).contains("from-the-parent"),
        "{}",
        stdout(&out)
    );
}

#[test]
fn reserved_passphrase_names_are_matched_in_any_case() {
    assert!(cloakenv::is_reserved_key("CLOAKENV_PASSPHRASE"));
    assert!(cloakenv::is_reserved_key("cloakenv_passphrase"));
    assert!(cloakenv::is_reserved_key("Cloakenv_Passphrase_File"));
    assert!(!cloakenv::is_reserved_key("CLOAKENV_PASSPHRASES"));
}

/// Windows has no 32 KiB limit on a process environment (the 32,767 limit is on
/// setting one variable in the running process): a megabyte of entries, which
/// Linux's default limit would refuse, reaches the command intact.
#[test]
fn a_megabyte_of_environment_reaches_the_command() {
    let env = Env::init();
    let value = "q".repeat(100_000);
    for i in 0..10 {
        env.set(&format!("BIG_{i}"), &value);
    }
    let out = env.run(&[
        "run",
        "--",
        "cmd",
        "/c",
        "if defined BIG_0 (if defined BIG_9 (exit 0))",
    ]);
    assert!(out.status.success(), "{}", stderr(&out));
    // Not just present: a different (larger) variable must be intact end to end.
    let out = env.run(&["run", "--shield", "--", "cmd", "/c", "echo", "%BIG_5%"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(!stdout(&out).contains("qqqq"), "shield leaked a value");
}
