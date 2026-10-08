//! Re-audit of the vault write lock (C1): writers must have no side effects
//! when there is no vault, and error causes must be printed once.
#![cfg(unix)]

mod common;

use std::fs;

use common::*;

fn assert_untouched(env: &Env) {
    assert!(
        !env.path().join(".cloak").exists(),
        "a failed command must not create the vault directory or a lock file"
    );
}

#[test]
fn writers_without_a_vault_leave_no_directory_or_lock_file_behind() {
    let env = Env::new();
    fs::write(env.path().join("a.env"), "A=1\n").unwrap();
    for out in [
        env.run_stdin(&["set", "K"], "value"),
        env.run(&["unset", "K"]),
        env.run(&["import", "a.env"]),
    ] {
        assert_eq!(out.status.code(), Some(1));
        assert!(
            stderr(&out).contains("no vault found at .cloak/vault.bin (run `cloakenv init`"),
            "{}",
            stderr(&out)
        );
        assert_untouched(&env);
    }
}

#[test]
fn a_missing_vault_is_reported_even_when_the_directory_is_read_only() {
    use std::os::unix::fs::PermissionsExt;
    let env = Env::new();
    fs::set_permissions(env.path(), fs::Permissions::from_mode(0o500)).unwrap();
    let out = env.run_stdin(&["set", "K"], "value");
    fs::set_permissions(env.path(), fs::Permissions::from_mode(0o700)).unwrap();
    assert!(
        stderr(&out).contains("no vault found"),
        "misleading error: {}",
        stderr(&out)
    );
}

#[test]
fn error_causes_are_printed_once() {
    let env = Env::init();
    // The lock path is a directory, so opening it fails with an OS error.
    let lock = env.path().join(".cloak").join(".vault.bin.lock");
    fs::remove_file(&lock).unwrap(); // left behind by `init`
    fs::create_dir(&lock).unwrap();
    let out = env.run_stdin(&["set", "K"], "value");
    let err = stderr(&out);
    assert!(err.contains("cannot open vault lock"), "{err}");
    assert_eq!(err.matches("os error").count(), 1, "{err}");
}

// The helper below is the one `tests/import_limits.rs` uses too.
fn run_import(env: &Env, file: &std::path::Path) -> std::process::Output {
    env.cmd(Some(PASS))
        .arg("import")
        .arg(file)
        .output()
        .unwrap()
}

#[test]
fn import_of_a_missing_file_names_the_path_once() {
    let env = Env::init();
    let out = run_import(&env, std::path::Path::new("no-such.env"));
    let err = stderr(&out);
    assert_eq!(
        err.trim_end(),
        "cloakenv: error: cannot read no-such.env: No such file or directory (os error 2)"
    );
}
