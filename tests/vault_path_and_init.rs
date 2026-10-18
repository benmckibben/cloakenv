//! Command-line behaviour around the vault path and "init --force": exit codes
//! in the help text, a clear error for an empty vault path, no search of parent
//! directories (and an error that shows the absolute path that was tried), and
//! "init --force" needing confirmation and keeping a private backup copy.
#![cfg(unix)]

mod common;

use std::fs;
use std::os::unix::fs::PermissionsExt;

use common::*;

fn help(args: &[&str]) -> String {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_cloakenv"))
        .args(args)
        .env_remove("CLOAKENV_VAULT")
        .output()
        .unwrap();
    assert!(out.status.success(), "{args:?}");
    String::from_utf8(out.stdout).unwrap()
}

#[test]
fn help_texts_mention_exit_codes() {
    let top = help(&["--help"]);
    assert!(top.contains("Exit codes:"), "{top}");
    for code in ["125", "126 / 127", "invalid command line"] {
        assert!(top.contains(code), "{code}: {top}");
    }
    assert!(top.contains("never in parent directories"), "{top}");
    for sub in ["init", "set", "unset", "import", "list"] {
        let text = help(&[sub, "--help"]);
        assert!(
            text.contains("Exit codes: 0 success, 1 failure"),
            "{sub}: {text}"
        );
    }
    let init = help(&["init", "--help"]);
    assert!(init.contains("--yes") && init.contains("bak-"), "{init}");
}

#[test]
fn an_empty_vault_path_is_a_clear_error_not_an_argument_error() {
    let env = Env::init();
    for (label, via_env) in [("CLOAKENV_VAULT", true), ("--vault", false)] {
        let mut cmd = env.cmd(Some(PASS));
        if via_env {
            cmd.env("CLOAKENV_VAULT", "");
        } else {
            cmd.args(["--vault", ""]);
        }
        let out = cmd.arg("list").output().unwrap();
        assert_eq!(out.status.code(), Some(1), "{label}: {}", stderr(&out));
        let err = stderr(&out);
        assert!(err.contains("the vault path is empty"), "{label}: {err}");
        assert!(!err.contains("isn't valid"), "{label}: {err}");
        // run keeps its own failure code
        let mut cmd = env.cmd(Some(PASS));
        if via_env {
            cmd.env("CLOAKENV_VAULT", "");
        } else {
            cmd.args(["--vault", ""]);
        }
        let out = cmd.args(["run", "--", "true"]).output().unwrap();
        assert_eq!(out.status.code(), Some(125), "{label}: {}", stderr(&out));
    }
}

#[test]
fn the_vault_is_only_looked_for_where_told_never_in_parent_directories() {
    let env = Env::init();
    env.set("PLANTED", "from-a-parent-directory");
    let child = env.path().join("sub").join("deeper");
    fs::create_dir_all(&child).unwrap();
    for args in [&["list"][..], &["run", "--", "true"][..]] {
        let out = env
            .cmd(Some(PASS))
            .current_dir(&child)
            .args(args)
            .output()
            .unwrap();
        assert_ne!(out.status.code(), Some(0), "{args:?}");
        let err = stderr(&out);
        let expected = fs::canonicalize(&child)
            .unwrap()
            .join(".cloak")
            .join("vault.bin");
        assert!(
            err.contains(&format!("no vault found at {}", expected.display())),
            "absolute path expected: {err}"
        );
        assert!(err.contains("parent directories are not searched"), "{err}");
        assert!(!stdout(&out).contains("PLANTED"));
    }
}

#[test]
fn init_force_needs_yes_when_there_is_no_terminal_and_changes_nothing_without_it() {
    let env = Env::init();
    env.set("K", "v");
    let before = fs::read(env.vault()).unwrap();
    let out = env
        .cmd(Some("another long passphrase"))
        .args(["init", "--force"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let err = stderr(&out);
    assert!(err.contains("Add --yes to confirm"), "{err}");
    assert_eq!(fs::read(env.vault()).unwrap(), before);
    let backups = || {
        fs::read_dir(env.path().join(".cloak"))
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .contains(".bak-")
            })
            .count()
    };
    assert_eq!(backups(), 0);
    // --yes is only meaningful together with --force.
    let out = env
        .cmd(Some(PASS))
        .args(["init", "--yes"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
}

#[test]
fn init_force_yes_keeps_a_private_copy_that_the_old_passphrase_still_opens() {
    let env = Env::init();
    env.set("K", "old-secret");
    let old = fs::read(env.vault()).unwrap();
    let new_pass = "another long passphrase";
    let out = env
        .cmd(Some(new_pass))
        .args(["init", "--force", "--yes"])
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
    let err = stderr(&out);
    assert!(err.contains("kept a copy of the old vault at"), "{err}");

    // the copy is kept in the state directory, not next to the vault
    let beside: Vec<_> = fs::read_dir(env.path().join(".cloak"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains(".bak"))
        .collect();
    assert!(beside.is_empty(), "a copy next to the vault: {beside:?}");
    let dir = env.state_dir().join("backups");
    let backups: Vec<_> = fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| {
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("vault.bin.bak-")
        })
        .collect();
    assert_eq!(backups.len(), 1, "{backups:?}");
    let backup = &backups[0];
    let name = backup.file_name().unwrap().to_string_lossy().into_owned();
    let stamp = name.strip_prefix("vault.bin.bak-").unwrap();
    assert!(
        stamp.len() == 16 && stamp.ends_with('Z') && stamp.as_bytes()[8] == b'T',
        "{name}"
    );
    assert_eq!(
        fs::metadata(backup).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        fs::read(backup).unwrap(),
        old,
        "byte for byte the old vault"
    );
    assert!(err.contains(&name), "the message names the copy: {err}");

    // The new vault is empty under the new passphrase; the old passphrase no
    // longer opens it, but does open the backup.
    let list = env.cmd(Some(new_pass)).arg("list").output().unwrap();
    assert_eq!(stdout(&list), "");
    let wrong = env.cmd(Some(PASS)).arg("list").output().unwrap();
    assert_eq!(wrong.status.code(), Some(1));
    let from_backup = env
        .cmd(Some(PASS))
        .arg("--vault")
        .arg(backup)
        .arg("list")
        .output()
        .unwrap();
    assert_eq!(stdout(&from_backup), "K\n", "{}", stderr(&from_backup));

    // Another replacement keeps another copy; nothing is overwritten.
    let out = env
        .cmd(Some(new_pass))
        .args(["init", "--force", "--yes"])
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
    let count = fs::read_dir(&dir)
        .unwrap()
        .filter(|e| {
            e.as_ref()
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("vault.bin.bak-")
        })
        .count();
    assert_eq!(count, 2);
    assert_eq!(fs::read(backup).unwrap(), old);
}

#[test]
fn init_without_force_still_refuses_an_existing_vault_and_creates_no_backup() {
    let env = Env::init();
    let before = fs::read(env.vault()).unwrap();
    let out = env.cmd(Some(PASS)).arg("init").output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("a vault already exists"),
        "{}",
        stderr(&out)
    );
    assert_eq!(fs::read(env.vault()).unwrap(), before);
    // A first init needs neither flag and makes no backup.
    let fresh = Env::new();
    let out = fresh.cmd(Some(PASS)).arg("init").output().unwrap();
    assert!(out.status.success());
    assert!(!stderr(&out).contains("kept a copy"));
}
