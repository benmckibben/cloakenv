//! Permission hygiene: loose modes and symlinks on the vault
//! directory, the vault file and the passphrase file produce a one-line
//! warning on cloakenv's own stderr, never an error, never a chmod, and never
//! anything inside a shielded child stream.
#![cfg(unix)]

mod common;

use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::Path;

use common::*;

const SECRET: &str = "dummy-secret-value-0001";

fn chmod(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

fn mode(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o7777
}

fn warnings(out: &std::process::Output) -> Vec<String> {
    stderr(out)
        .lines()
        .filter(|l| l.starts_with("cloakenv: warning:"))
        .map(str::to_owned)
        .collect()
}

fn seeded() -> Env {
    let env = Env::init();
    env.set("API_KEY", SECRET);
    env
}

#[test]
fn fresh_init_is_private_and_silent() {
    let env = Env::new();
    let out = env.ok(&["init"]);
    assert!(warnings(&out).is_empty(), "{}", stderr(&out));
    assert_eq!(mode(&env.path().join(".cloak")), 0o700);
    assert_eq!(mode(&env.vault()), 0o600);
    // And it stays silent for every later command.
    env.set("API_KEY", SECRET);
    for args in [&["list"][..], &["run", "--", "true"]] {
        let out = env.ok(args);
        assert!(warnings(&out).is_empty(), "{args:?}: {}", stderr(&out));
    }
}

#[test]
fn world_writable_vault_dir_warns_but_works() {
    let env = seeded();
    let dir = env.path().join(".cloak");
    for dir_mode in [0o707, 0o777, 0o702] {
        chmod(&dir, dir_mode);
        let out = env.ok(&["list"]);
        assert_eq!(stdout(&out), "API_KEY\n");
        let w = warnings(&out);
        assert_eq!(w.len(), 1, "{dir_mode:o}: {}", stderr(&out));
        assert!(w[0].contains("vault directory"), "{w:?}");
        assert!(w[0].contains("world-writable"), "{w:?}");
        assert!(w[0].contains(&format!("{dir_mode:04o}")), "{w:?}");
        // We only warn: the mode is left exactly as the user had it.
        assert_eq!(mode(&dir), dir_mode);
    }
    // Writers warn too, and still succeed.
    let out = env.run_stdin(&["set", "OTHER"], "dummy-two\n");
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(warnings(&out).len(), 1, "{}", stderr(&out));
    assert_eq!(mode(&dir), 0o702);
    // Group/world-readable but not writable is fine.
    chmod(&dir, 0o755);
    assert!(warnings(&env.ok(&["list"])).is_empty());
}

/// The sticky bit (as on /tmp itself) means others cannot rename or delete our
/// files, so a world-writable but sticky directory is not reported.
#[test]
fn a_sticky_world_writable_vault_dir_is_quiet() {
    let env = seeded();
    chmod(&env.path().join(".cloak"), 0o1707);
    assert!(warnings(&env.ok(&["list"])).is_empty());
}

/// A group-writable directory is the normal state of a project directory
/// under the common umask 0002, with the group being the user's own private
/// group. This machine's group setup decides the outcome, so check only that
/// the answer is a single, well-formed warning or none, and that it never
/// depends on the file mode of the vault itself.
#[test]
fn a_group_writable_vault_dir_gets_at_most_one_well_formed_warning() {
    let env = seeded();
    let dir = env.path().join(".cloak");
    chmod(&dir, 0o770);
    let out = env.ok(&["list"]);
    let w = warnings(&out);
    assert!(w.len() <= 1, "{w:?}");
    if let Some(line) = w.first() {
        assert!(
            line.contains("not private to you") && line.contains("0770"),
            "{line}"
        );
    }
    assert_eq!(mode(&dir), 0o770, "never chmod user directories");
}

#[test]
fn loose_vault_file_warns_but_works() {
    let env = seeded();
    for file_mode in [0o640, 0o604, 0o644, 0o660, 0o666] {
        chmod(&env.vault(), file_mode);
        let out = env.ok(&["list"]);
        assert_eq!(stdout(&out), "API_KEY\n");
        let w = warnings(&out);
        assert_eq!(w.len(), 1, "{file_mode:o}: {}", stderr(&out));
        assert!(w[0].contains("vault file"), "{w:?}");
        assert!(w[0].contains(&format!("{file_mode:04o}")), "{w:?}");
        assert_eq!(mode(&env.vault()), file_mode, "never chmod user files");
    }
}

#[test]
fn warnings_do_not_change_exit_codes() {
    let env = seeded();
    chmod(&env.path().join(".cloak"), 0o777);
    chmod(&env.vault(), 0o666);

    // Child's code is passed through.
    let out = env
        .cmd(Some(PASS))
        .args(["run", "--", "sh", "-c", "exit 7"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(7));
    assert_eq!(warnings(&out).len(), 2, "{}", stderr(&out));

    // Failures keep their codes: wrong passphrase (125 for run, 1 otherwise).
    let out = env
        .cmd(Some("not the passphrase"))
        .args(["run", "--", "true"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(125));
    let out = env
        .cmd(Some("not the passphrase"))
        .arg("list")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn warnings_stay_out_of_the_shielded_stream() {
    let env = seeded();
    chmod(&env.vault(), 0o644);
    chmod(&env.path().join(".cloak"), 0o777);
    let out = env
        .cmd(Some(PASS))
        .args([
            "run",
            "--shield",
            "--",
            "sh",
            "-c",
            "echo $API_KEY; echo err-$API_KEY >&2; exit 3",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3));
    assert_eq!(stdout(&out), "[REDACTED_BY_CLOAKENV]\n");
    let err = stderr(&out);
    let lines: Vec<&str> = err.lines().collect();
    // Our two warnings come first (before the child existed), then the
    // child's redacted stderr, untouched.
    assert!(lines[0].starts_with("cloakenv: warning:"), "{err}");
    assert!(lines[1].starts_with("cloakenv: warning:"), "{err}");
    assert_eq!(lines[2], "err-[REDACTED_BY_CLOAKENV]", "{err}");
    assert_eq!(lines.len(), 3, "{err}");
    assert!(!contains(&out.stderr, SECRET));
    assert!(!contains(&out.stderr, PASS));
}

#[test]
fn existing_loose_dir_is_warned_about_on_init_and_never_tightened() {
    let env = Env::new();
    let dir = env.path().join(".cloak");
    fs::create_dir(&dir).unwrap();
    chmod(&dir, 0o777);
    let out = env.ok(&["init"]);
    assert_eq!(warnings(&out).len(), 1, "{}", stderr(&out));
    assert!(warnings(&out)[0].contains("vault directory"));
    assert_eq!(mode(&dir), 0o777);
    // The new vault itself is private; re-initialising over an old loose
    // vault does not warn about the file that is about to be replaced.
    assert_eq!(mode(&env.vault()), 0o600);
    chmod(&env.vault(), 0o666);
    chmod(&dir, 0o700);
    let out = env.ok(&["init", "--force"]);
    assert!(warnings(&out).is_empty(), "{}", stderr(&out));
    assert_eq!(mode(&env.vault()), 0o600);
}

#[test]
fn passphrase_file_modes() {
    let env = seeded();
    let key = env.path().join("pass.key");
    fs::write(&key, format!("{PASS}\n")).unwrap();
    let run = |m: u32| {
        chmod(&key, m);
        env.cmd(None)
            .env("CLOAKENV_PASSPHRASE_FILE", &key)
            .arg("list")
            .output()
            .unwrap()
    };
    for m in [0o600, 0o400] {
        let out = run(m);
        assert!(out.status.success());
        assert!(warnings(&out).is_empty(), "{m:o}: {}", stderr(&out));
    }
    for m in [0o640, 0o604, 0o644, 0o660, 0o666] {
        let out = run(m);
        // A warning, not an error: it still decrypts.
        assert!(out.status.success(), "{m:o}: {}", stderr(&out));
        assert_eq!(stdout(&out), "API_KEY\n");
        let w = warnings(&out);
        assert_eq!(w.len(), 1, "{m:o}: {}", stderr(&out));
        assert!(w[0].contains("passphrase file"), "{w:?}");
        assert!(w[0].contains(&format!("{m:04o}")), "{w:?}");
        assert!(!contains(&out.stderr, PASS), "passphrase leaked in warning");
        assert_eq!(mode(&key), m, "never chmod user files");
    }
}

#[test]
fn passphrase_file_is_not_checked_when_the_env_passphrase_wins() {
    let env = seeded();
    let key = env.path().join("pass.key");
    fs::write(&key, "irrelevant\n").unwrap();
    chmod(&key, 0o666);
    let out = env
        .cmd(Some(PASS))
        .env("CLOAKENV_PASSPHRASE_FILE", &key)
        .arg("list")
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(warnings(&out).is_empty(), "{}", stderr(&out));
}

#[test]
fn symlinked_vault_dir_warns() {
    let env = seeded();
    let real = env.path().join("real-cloak");
    fs::rename(env.path().join(".cloak"), &real).unwrap();
    symlink(&real, env.path().join(".cloak")).unwrap();
    let out = env.ok(&["list"]);
    assert_eq!(stdout(&out), "API_KEY\n");
    let w = warnings(&out);
    assert_eq!(w.len(), 1, "{}", stderr(&out));
    assert!(w[0].contains("vault directory") && w[0].contains("symbolic link"));
}

#[test]
fn symlinked_vault_file_warns_and_saving_replaces_the_link() {
    let env = seeded();
    let target = env.path().join("elsewhere.bin");
    fs::rename(env.vault(), &target).unwrap();
    symlink(&target, env.vault()).unwrap();
    let before = fs::read(&target).unwrap();

    let out = env.ok(&["list"]);
    let w = warnings(&out);
    assert_eq!(w.len(), 1, "{}", stderr(&out));
    assert!(w[0].contains("vault file") && w[0].contains("symbolic link"));

    // A write must replace the symlink with a regular file, never write
    // through it into the link's target.
    let out = env.run_stdin(&["set", "OTHER"], "dummy-two\n");
    assert!(out.status.success(), "{}", stderr(&out));
    let meta = fs::symlink_metadata(env.vault()).unwrap();
    assert!(!meta.file_type().is_symlink(), "link must be replaced");
    assert!(meta.file_type().is_file());
    assert_eq!(mode(&env.vault()), 0o600);
    assert_eq!(fs::read(&target).unwrap(), before, "target was modified");
    assert_eq!(stdout(&env.ok(&["list"])), "API_KEY\nOTHER\n");
}
