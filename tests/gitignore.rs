//! `cloakenv init` keeps the vault out of version control (audit C11).

mod common;

use std::fs;
use std::process::Command;

use common::*;

/// Runs git in the scratch directory with no user/system configuration, so a
/// developer's global excludes file cannot mask a missing ignore rule.
/// Returns None (skipping the test) if git is not installed.
fn git(env: &Env, args: &[&str]) -> Option<String> {
    let home = env.path().join("no-home");
    let out = Command::new("git")
        .args(args)
        .current_dir(env.path())
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &home)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .ok()?;
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Creates (if needed) a 0700 directory, independent of the test umask, so the
/// separate permission warnings do not interfere with what is asserted here.
fn private_dir(dir: &std::path::Path) {
    fs::create_dir_all(dir).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).unwrap();
    }
}

fn git_repo() -> Option<Env> {
    let env = Env::new();
    git(&env, &["init", "-q"])?;
    Some(env)
}

#[test]
fn init_in_a_git_repo_leaves_nothing_to_commit() {
    let Some(env) = git_repo() else {
        eprintln!("skipping: git not available");
        return;
    };
    env.ok(&["init"]);
    assert_eq!(git(&env, &["status", "--porcelain"]).unwrap(), "");
    // Later writes add the lock file and replace the vault: still ignored,
    // even for `git add -A` / `git add .`.
    env.set("API_KEY", "dummy-secret-value-0002");
    git(&env, &["add", "-A"]);
    assert_eq!(git(&env, &["status", "--porcelain"]).unwrap(), "");
    assert_eq!(git(&env, &["ls-files"]).unwrap(), "");
}

#[test]
fn the_gitignore_is_what_hides_the_vault() {
    // Guards the test above against passing for the wrong reason.
    let Some(env) = git_repo() else {
        eprintln!("skipping: git not available");
        return;
    };
    env.ok(&["init"]);
    fs::remove_file(env.path().join(".cloak/.gitignore")).unwrap();
    assert_eq!(
        git(&env, &["status", "--porcelain"]).unwrap(),
        "?? .cloak/\n"
    );
}

#[test]
fn gitignore_contents_and_mode() {
    let env = Env::new();
    let out = env.ok(&["init"]);
    let file = env.path().join(".cloak/.gitignore");
    assert_eq!(fs::read_to_string(&file).unwrap(), "*\n");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // 0600 minus whatever the umask removes; never group/other-accessible.
        let mode = fs::metadata(&file).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode & 0o177, 0, "mode {mode:o}");
    }
    // Nothing about it is noisy, and no secret-bearing text is printed.
    assert!(!stderr(&out).contains("warning"), "{}", stderr(&out));
    assert!(out.stdout.is_empty());
}

#[test]
fn an_existing_gitignore_is_not_clobbered() {
    let env = Env::new();
    private_dir(&env.path().join(".cloak"));
    fs::write(env.path().join(".cloak/.gitignore"), "custom\n").unwrap();
    let out = env.ok(&["init"]);
    assert_eq!(
        fs::read_to_string(env.path().join(".cloak/.gitignore")).unwrap(),
        "custom\n"
    );
    assert!(!stderr(&out).contains("warning"), "{}", stderr(&out));
    // Nor on a forced re-init.
    env.ok(&["init", "--force", "--yes"]);
    assert_eq!(
        fs::read_to_string(env.path().join(".cloak/.gitignore")).unwrap(),
        "custom\n"
    );
}

#[cfg(unix)]
#[test]
fn a_symlinked_gitignore_is_not_followed() {
    let env = Env::new();
    fs::create_dir(env.path().join(".cloak")).unwrap();
    let victim = env.path().join("victim");
    std::os::unix::fs::symlink(&victim, env.path().join(".cloak/.gitignore")).unwrap();
    env.ok(&["init"]);
    assert!(!victim.exists(), "init wrote through a symlink");
}

#[test]
fn a_vault_in_an_existing_directory_does_not_get_a_star_ignore() {
    // `--vault vault.bin` puts the vault in the project root itself; a `*`
    // ignore file there would hide the whole project from git.
    let env = Env::new();
    private_dir(env.path());
    let out = env.ok(&["--vault", "vault.bin", "init"]);
    assert!(!env.path().join(".gitignore").exists());
    assert!(!stderr(&out).contains("warning"), "{}", stderr(&out));
}

#[test]
fn a_new_custom_vault_directory_gets_its_own_gitignore() {
    let env = Env::new();
    env.ok(&["--vault", "secrets/vault.bin", "init"]);
    assert_eq!(
        fs::read_to_string(env.path().join("secrets/.gitignore")).unwrap(),
        "*\n"
    );
}
