//! How `cloakenv run` splits its own options from the command's: the command
//! comes after `--`, always. Without that rule a `--shield` typed after the
//! command's first word was passed to the command and the output was not
//! redacted, with no warning.
#![cfg(unix)]

mod common;

use common::*;

const SECRET: &str = "sk-arg…4242";

fn env_with_secret() -> Env {
    let env = Env::init();
    env.set("API_KEY", SECRET);
    env
}

/// A usage error: exit 2, the command never ran, and nothing was printed on
/// stdout (in particular not the secret).
fn assert_refused(env: &Env, out: &std::process::Output, what: &str) {
    assert_eq!(out.status.code(), Some(2), "{what}: {}", stderr(out));
    assert!(out.stdout.is_empty(), "{what}: stdout {}", stdout(out));
    assert!(!contains(&out.stderr, SECRET), "{what}: {}", stderr(out));
    assert!(
        !env.path().join("ran").exists(),
        "{what}: the command was started"
    );
}

#[test]
fn shield_after_the_command_is_refused_not_passed_to_it() {
    let env = env_with_secret();
    // The audit's example: this used to print the secret, exit status 0.
    let out = env.run(&["run", "sh", "-c", "touch ran; echo $API_KEY", "--shield"]);
    assert_refused(&env, &out, "run sh -c ... --shield");
    // And the error says how to fix it.
    assert!(
        stderr(&out).contains("the command goes after `--`"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn a_command_without_the_separator_is_refused() {
    let env = env_with_secret();
    for args in [
        vec!["run", "sh", "-c", "touch ran; echo $API_KEY"],
        vec!["run", "--shield", "sh", "-c", "touch ran; echo $API_KEY"],
        vec!["run", "touch", "ran"],
    ] {
        let out = env.run(&args);
        assert_refused(&env, &out, &format!("{args:?}"));
    }
}

#[test]
fn unknown_options_before_the_separator_are_usage_errors() {
    let env = env_with_secret();
    for args in [
        vec!["run", "--sheild", "--", "touch", "ran"],
        vec!["run", "-x", "--", "touch", "ran"],
        vec!["run", "--shield=yes", "--", "touch", "ran"],
    ] {
        let out = env.run(&args);
        assert_refused(&env, &out, &format!("{args:?}"));
    }
}

#[test]
fn no_command_is_a_usage_error() {
    let env = env_with_secret();
    for args in [
        vec!["run"],
        vec!["run", "--shield"],
        vec!["run", "--"],
        vec!["run", "--shield", "--"],
    ] {
        let out = env.run(&args);
        assert_refused(&env, &out, &format!("{args:?}"));
    }
}

#[test]
fn the_error_does_not_echo_the_arguments() {
    let env = env_with_secret();
    let out = env.run(&["run", "echo", SECRET, "--shield"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(!contains(&out.stderr, SECRET), "{}", stderr(&out));
    assert!(!contains(&out.stderr, "echo"), "{}", stderr(&out));
}

#[test]
fn flags_after_the_separator_belong_to_the_command() {
    let env = env_with_secret();
    // Without --shield: --shield is just an argument of echo.
    let out = env.ok(&["run", "--", "echo", "--shield"]);
    assert_eq!(stdout(&out), "--shield\n");
    // With --shield before the separator, one after it is still the command's.
    let out = env.ok(&[
        "run", "--shield", "--", "echo", "--shield", "--vault", "x", "--",
    ]);
    assert_eq!(stdout(&out), "--shield --vault x --\n");
    // Options of cloakenv itself before the separator keep working, in any order.
    let vault = env.vault();
    let out = env.ok(&[
        "run",
        "--vault",
        vault.to_str().unwrap(),
        "--shield",
        "--",
        "sh",
        "-c",
        "echo $API_KEY",
    ]);
    assert_eq!(stdout(&out), "[REDACTED_BY_CLOAKENV]\n");
}

#[test]
fn the_documented_forms_work() {
    let env = env_with_secret();
    let out = env.ok(&["run", "--", "sh", "-c", "echo $API_KEY"]);
    assert_eq!(stdout(&out), format!("{SECRET}\n"));
    let out = env.ok(&["run", "--shield", "--", "sh", "-c", "echo $API_KEY"]);
    assert_eq!(stdout(&out), "[REDACTED_BY_CLOAKENV]\n");
}
