//! Windows ACLs: what cloakenv creates is private to the user (plus SYSTEM and
//! Administrators), an existing file or directory is never changed, and loose
//! ACLs on an existing vault draw a warning. The ACLs are set up and read with
//! `icacls`, which ships with Windows.
#![cfg(windows)]

mod common;

use std::fs;
use std::path::Path;
use std::process::Command;

use common::*;

const USERS: &str = "*S-1-5-32-545";
const AUTHENTICATED_USERS: &str = "*S-1-5-11";

/// What `icacls <path>` prints, without the path and the trailing summary.
fn acl_text(path: &Path) -> String {
    let out = Command::new("icacls")
        .arg(path)
        .output()
        .expect("run icacls");
    assert!(out.status.success(), "icacls {} failed", path.display());
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with("Successfully processed"))
        .map(|l| l.replacen(&path.display().to_string(), "", 1))
        .collect::<Vec<_>>()
        .join("\n")
}

fn grant(path: &Path, who: &str, rights: &str) {
    let out = Command::new("icacls")
        .arg(path)
        .arg("/grant")
        .arg(format!("{who}:{rights}"))
        .output()
        .expect("run icacls");
    assert!(
        out.status.success(),
        "icacls grant failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// An ACL is "private" if it has no entry for the broad groups and nothing in it
/// is inherited ("(I)"): the ACL is protected, so the parent's ACL does not leak in.
fn assert_private(path: &Path) {
    let acl = acl_text(path);
    for broad in ["Everyone", "BUILTIN\\Users", "Authenticated Users"] {
        assert!(
            !acl.contains(broad),
            "{} grants {broad}:\n{acl}",
            path.display()
        );
    }
    assert!(
        !acl.contains("(I)"),
        "{} inherits entries from its parent:\n{acl}",
        path.display()
    );
    assert!(
        acl.contains("NT AUTHORITY\\SYSTEM"),
        "no SYSTEM entry:\n{acl}"
    );
    assert!(
        acl.contains("BUILTIN\\Administrators"),
        "no Administrators entry:\n{acl}"
    );
}

fn warnings(out: &std::process::Output) -> String {
    stderr(out)
        .lines()
        .filter(|l| l.contains("warning"))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn what_init_creates_is_private_and_stays_private_after_a_save() {
    let env = Env::init();
    let dir = env.path().join(".cloak");
    assert_private(&dir);
    assert_private(&env.vault());
    env.set("K1", "value-one");
    // A save replaces the file with a new temporary one, so check it again.
    assert_private(&env.vault());
    assert_private(&dir.join(".vault.bin.lock"));
    let out = env.ok(&["list"]);
    assert_eq!(warnings(&out), "", "a vault cloakenv made must not warn");
}

#[test]
fn the_acl_is_not_inherited_even_when_the_parent_is_open() {
    let env = Env::new();
    let parent = env.path().join("shared");
    fs::create_dir(&parent).unwrap();
    grant(&parent, AUTHENTICATED_USERS, "(OI)(CI)M");
    let vault = parent.join("nested").join(".cloak").join("vault.bin");
    let out = env.run(&["--vault", vault.to_str().unwrap(), "init"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_private(&vault);
    assert_private(vault.parent().unwrap());
    assert_private(vault.parent().unwrap().parent().unwrap());
}

#[test]
fn an_existing_directory_is_left_alone() {
    let env = Env::new();
    let dir = env.path().join("existing");
    fs::create_dir(&dir).unwrap();
    grant(&dir, USERS, "(OI)(CI)R");
    let before = acl_text(&dir);
    let vault = dir.join("vault.bin");
    let out = env.run(&["--vault", vault.to_str().unwrap(), "init"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(
        acl_text(&dir),
        before,
        "cloakenv changed the ACL of a directory it did not create"
    );
    // The vault file itself is still private, whatever the directory allows.
    assert_private(&vault);
}

#[test]
fn a_vault_file_that_users_can_read_draws_a_warning() {
    let env = Env::init();
    grant(&env.vault(), USERS, "R");
    let out = env.ok(&["list"]);
    let w = warnings(&out);
    assert!(w.contains("vault file"), "no warning about the file: {w:?}");
    assert!(
        w.contains("BUILTIN\\Users"),
        "the warning does not name the group: {w:?}"
    );
    // The default vault path is shown as given (relative), not made absolute.
    assert!(w.contains("vault.bin"), "no path in the warning: {w:?}");
}

#[test]
fn a_directory_that_authenticated_users_can_write_to_draws_a_warning() {
    let env = Env::init();
    grant(&env.path().join(".cloak"), AUTHENTICATED_USERS, "(OI)(CI)M");
    let out = env.ok(&["list"]);
    let w = warnings(&out);
    assert!(
        w.contains("vault directory"),
        "no warning about the directory: {w:?}"
    );
    assert!(
        w.contains("Authenticated Users"),
        "the warning does not name the group: {w:?}"
    );
}

#[test]
fn read_only_access_to_the_directory_is_not_reported() {
    let env = Env::init();
    grant(&env.path().join(".cloak"), USERS, "(OI)(CI)RX");
    let out = env.ok(&["list"]);
    let w = warnings(&out);
    assert!(
        !w.contains("vault directory"),
        "read access to the directory was reported: {w:?}"
    );
}

#[test]
fn saving_replaces_a_loose_vault_file_with_a_private_one() {
    let env = Env::init();
    grant(&env.vault(), USERS, "R");
    assert!(acl_text(&env.vault()).contains("BUILTIN\\Users"));
    env.set("K2", "value-two");
    assert_private(&env.vault());
    let out = env.ok(&["list"]);
    assert_eq!(warnings(&out), "");
}

#[test]
fn a_passphrase_file_that_users_can_read_draws_a_warning() {
    let env = Env::init();
    let file = env.path().join("pass.txt");
    fs::write(&file, PASS).unwrap();
    grant(&file, USERS, "R");
    let out = env
        .cmd(None)
        .env("CLOAKENV_PASSPHRASE_FILE", &file)
        .arg("list")
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
    let w = warnings(&out);
    assert!(
        w.contains("passphrase file"),
        "no warning about the passphrase file: {w:?}"
    );
    assert!(
        w.contains("BUILTIN\\Users"),
        "the warning does not name the group: {w:?}"
    );
}

#[test]
fn concurrent_inits_still_create_one_private_directory() {
    let env = Env::new();
    let children: Vec<_> = (0..4)
        .map(|_| {
            env.cmd(Some(PASS))
                .arg("init")
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap()
        })
        .collect();
    let ok = children
        .into_iter()
        .map(|c| c.wait_with_output().unwrap())
        .filter(|o| o.status.success())
        .count();
    assert_eq!(ok, 1);
    assert_private(&env.path().join(".cloak"));
}
