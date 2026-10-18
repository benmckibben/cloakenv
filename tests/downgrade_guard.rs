//! The downgrade guard: a format 1 file where a format 2 vault used to be. A format 1 file has no vault id, so the
//! guard recognises it by the paths a format 2 vault has been opened under and, for a file that was upgraded on this
//! machine, by the file's own identity (its tag). These are the ways an attacker who can write the vault's
//! directory, but not the state directory, would try to put the old file back.

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use common::*;

const V1_PASS: &str = "golden-v1-fixture-passphrase";

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/v1")
        .join(format!("{name}.bin"))
}

/// Copies a fixture to `to` the way a vault file is expected to be (mode 0600).
fn place(from: &Path, to: &Path) {
    fs::create_dir_all(to.parent().unwrap()).unwrap();
    fs::copy(from, to).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(to, fs::Permissions::from_mode(0o600)).unwrap();
    }
}

fn cli(env: &Env, vault: &Path, pass: &str) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_cloakenv"));
    c.arg("--vault")
        .arg(vault)
        .current_dir(env.path())
        .env_remove("CLOAKENV_PASSPHRASE_FILE")
        .env_remove("CLOAKENV_NEW_PASSPHRASE_FILE")
        .env_remove("CLOAKENV_VAULT")
        .env("CLOAKENV_STATE_DIR", env.state_dir())
        .env("CLOAKENV_PASSPHRASE", pass)
        .stdin(Stdio::null());
    c
}

/// A vault that was a format 1 fixture and has been upgraded on this machine.
fn upgraded(env: &Env, fixture_name: &str) -> PathBuf {
    let vault = env.vault();
    place(&fixture(fixture_name), &vault);
    let out = cli(env, &vault, V1_PASS)
        .arg("upgrade")
        .output()
        .expect("spawn");
    assert!(out.status.success(), "upgrade: {}", stderr(&out));
    vault
}

fn assert_refused_as_downgrade(out: &Output, what: &str) {
    let err = stderr(out);
    assert!(
        !out.status.success(),
        "{what} was accepted; stdout: {} stderr: {err}",
        stdout(out)
    );
    assert!(
        err.contains("version 1 file") && err.contains("accept-rollback"),
        "{what} was refused, but not as a downgrade: {err}"
    );
}

fn list(env: &Env, vault: &Path) -> Output {
    cli(env, vault, V1_PASS)
        .arg("list")
        .output()
        .expect("spawn")
}

#[test]
fn the_kept_copy_is_in_the_state_directory_and_not_next_to_the_vault() {
    let env = Env::new();
    let vault = upgraded(&env, "one");
    let beside: Vec<_> = fs::read_dir(vault.parent().unwrap())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert!(
        !beside.iter().any(|n| n.contains(".bak")),
        "a copy next to the vault: {beside:?}"
    );
    let kept: Vec<_> = fs::read_dir(env.state_dir().join("backups"))
        .expect("the backups directory in the state directory")
        .map(|e| e.unwrap().path())
        .collect();
    assert_eq!(kept.len(), 1, "{kept:?}");
    assert_eq!(
        fs::read(&kept[0]).unwrap(),
        fs::read(fixture("one")).unwrap(),
        "byte-identical to the original"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&kept[0]).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(env.state_dir().join("backups"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }
}

#[test]
fn the_upgraded_away_file_is_refused_in_a_renamed_directory() {
    let env = Env::new();
    let vault = upgraded(&env, "one");
    assert!(
        list(&env, &vault).status.success(),
        "the upgraded vault itself works"
    );
    let moved = env.path().join("moved");
    fs::rename(vault.parent().unwrap(), &moved).unwrap();
    let moved_vault = moved.join("vault.bin");
    place(&fixture("one"), &moved_vault);
    assert_refused_as_downgrade(
        &list(&env, &moved_vault),
        "the old file in a renamed directory",
    );
}

#[cfg(unix)]
#[test]
fn a_symlink_to_the_upgraded_away_file_is_refused() {
    let env = Env::new();
    let vault = upgraded(&env, "one");
    let dir = vault.parent().unwrap().to_owned();
    fs::remove_file(&vault).unwrap();
    place(&fixture("one"), &dir.join("old-v1.bin"));
    std::os::unix::fs::symlink("old-v1.bin", &vault).unwrap();
    let out = cli(&env, &vault, V1_PASS)
        .args(["run", "--", "sh", "-c", "echo GREETING=$GREETING"])
        .output()
        .expect("spawn");
    assert_refused_as_downgrade(&out, "the old file behind a symlink");
    assert!(
        !stdout(&out).contains("hello"),
        "the old contents reached the command: {}",
        stdout(&out)
    );
}

#[cfg(unix)]
#[test]
fn a_symlink_to_another_version_1_file_is_refused_by_the_name_it_is_opened_under() {
    let env = Env::new();
    let vault = upgraded(&env, "one");
    let dir = vault.parent().unwrap().to_owned();
    fs::remove_file(&vault).unwrap();
    // a different version 1 vault (a different tag, never upgraded here): only the path can give it away
    place(&fixture("many"), &dir.join("other-v1.bin"));
    std::os::unix::fs::symlink("other-v1.bin", &vault).unwrap();
    assert_refused_as_downgrade(
        &list(&env, &vault),
        "another version 1 file behind a symlink",
    );
    // control: the same file opened under its own name is just a format 1 vault that this machine never upgraded
    let plain = list(&env, &dir.join("other-v1.bin"));
    assert!(plain.status.success(), "{}", stderr(&plain));
    assert!(stderr(&plain).contains("this vault uses format 1"));
}

#[test]
fn known_limit_an_older_version_1_snapshot_in_a_renamed_directory_is_not_recognised() {
    // Nothing identifies a format 1 file that was never upgraded on this machine: it has no id, and its path is new.
    // This test records that limit (the documentation says downgrade detection is best effort); if the guard ever
    // learns to catch this, the test should be changed to expect the refusal.
    let env = Env::new();
    let vault = upgraded(&env, "one");
    let moved = env.path().join("moved");
    fs::rename(vault.parent().unwrap(), &moved).unwrap();
    let moved_vault = moved.join("vault.bin");
    place(&fixture("many"), &moved_vault);
    let out = list(&env, &moved_vault);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("this vault uses format 1"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn accepting_the_old_file_makes_it_an_ordinary_format_1_vault_again() {
    let env = Env::new();
    let vault = upgraded(&env, "one");
    place(&fixture("one"), &vault);
    assert_refused_as_downgrade(&list(&env, &vault), "the old file put back");
    let accepted = cli(&env, &vault, V1_PASS)
        .args(["accept-rollback", "--yes"])
        .output()
        .expect("spawn");
    assert!(accepted.status.success(), "{}", stderr(&accepted));
    let again = list(&env, &vault);
    assert!(again.status.success(), "{}", stderr(&again));
    // and the identity went with it: the same file elsewhere is no longer recognised
    let elsewhere = env.path().join("elsewhere").join("vault.bin");
    place(&fixture("one"), &elsewhere);
    let there = list(&env, &elsewhere);
    assert!(there.status.success(), "{}", stderr(&there));
}
