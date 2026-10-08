//! `--shield` warns about vault values that are too short to redact
//! sensibly. The warning is advisory: it names keys (never values), goes to
//! cloakenv's own stderr before the child starts, and changes neither exit
//! codes nor the redacted output.
#![cfg(unix)]

mod common;

use common::*;

const R: &str = "[REDACTED_BY_CLOAKENV]";
const SHORT: &str = "xq7"; // 3 bytes
const LONG: &str = "long-dummy-secret-value";

/// A vault with one short and one long value.
fn vault() -> Env {
    let env = Env::init();
    env.set("SHORT_KEY", SHORT);
    env.set("LONG_KEY", LONG);
    env
}

const SCRIPT: &str =
    r#"printf 'out:%s|%s\n' "$SHORT_KEY" "$LONG_KEY"; printf 'err:%s\n' "$SHORT_KEY" >&2; exit 7"#;

#[test]
fn warns_for_a_short_value_by_key_name_only() {
    let env = vault();
    let out = env.run(&["run", "--shield", "--", "sh", "-c", SCRIPT]);
    let err = stderr(&out);
    let warning = err
        .lines()
        .find(|l| l.contains("warning: --shield"))
        .unwrap_or_else(|| panic!("no warning in: {err}"));
    assert!(warning.starts_with("cloakenv: warning:"), "{warning}");
    assert!(warning.contains("SHORT_KEY"), "{warning}");
    assert!(warning.contains("shorter than 6 bytes"), "{warning}");
    assert!(warning.contains("guessing oracle"), "{warning}");
    assert!(!warning.contains("LONG_KEY"), "{warning}");
    // Neither value appears anywhere in the warning...
    assert!(
        !warning.contains(SHORT) && !warning.contains(LONG),
        "{warning}"
    );
    // ...nor anywhere in what cloakenv itself wrote (the child's redacted
    // stderr is the only other thing there).
    assert!(!contains(&out.stderr, SHORT) && !contains(&out.stderr, LONG));
    // It comes first: before the child could have written anything.
    assert!(err.starts_with("cloakenv: warning:"), "{err}");
}

#[test]
fn warning_does_not_change_exit_code_or_redacted_output() {
    let env = vault();
    let out = env.run(&["run", "--shield", "--", "sh", "-c", SCRIPT]);
    assert_eq!(out.status.code(), Some(7), "child's exit code is untouched");
    assert_eq!(stdout(&out), format!("out:{R}|{R}\n"));
    let err = stderr(&out);
    assert!(err.ends_with(&format!("err:{R}\n")), "{err}");
    // Exactly one cloakenv line precedes the child's own stderr.
    assert_eq!(err.lines().count(), 2, "{err}");
}

#[test]
fn no_warning_when_every_value_is_long_enough() {
    let env = Env::init();
    env.set("LONG_KEY", LONG);
    env.set("SIX", "123456"); // exactly the threshold: not short
    env.set("EMPTY", "");
    let out = env.run(&["run", "--shield", "--", "sh", "-c", "echo hi"]);
    assert!(out.status.success());
    assert_eq!(stderr(&out), "");
    assert_eq!(stdout(&out), "hi\n");
}

#[test]
fn five_bytes_warns() {
    let env = Env::init();
    env.set("FIVE", "12345");
    let out = env.run(&["run", "--shield", "--", "true"]);
    assert!(out.status.success());
    assert!(stderr(&out).contains("FIVE"), "{}", stderr(&out));
}

#[test]
fn several_short_keys_are_listed_in_one_line() {
    let env = Env::init();
    env.set("A_KEY", "1");
    env.set("B_KEY", "yes");
    let out = env.run(&["run", "--shield", "--", "true"]);
    let err = stderr(&out);
    assert_eq!(err.lines().count(), 1, "{err}");
    assert!(
        err.contains("the values of A_KEY, B_KEY are shorter"),
        "{err}"
    );
}

#[test]
fn no_warning_without_shield() {
    let env = vault();
    let out = env.run(&["run", "--", "sh", "-c", "exit 0"]);
    assert!(out.status.success());
    assert_eq!(stderr(&out), "");
}

#[test]
fn other_commands_do_not_warn() {
    let env = vault();
    assert_eq!(stderr(&env.ok(&["list"])), "");
}
