//! In-memory environment injection via `cloakenv run`.
#![cfg(unix)]

mod common;

use std::io::Write;
use std::process::Stdio;

use common::*;

const SECRET: &str = "sk-live-9f8e7d6c5b4a";

#[test]
fn init_creates_private_vault_without_plaintext() {
    use std::os::unix::fs::PermissionsExt;
    let env = Env::init();
    env.set("API_KEY", SECRET);
    let meta = std::fs::metadata(env.vault()).unwrap();
    assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    let dir_meta = std::fs::metadata(env.vault().parent().unwrap()).unwrap();
    assert_eq!(dir_meta.permissions().mode() & 0o777, 0o700);
    let bytes = std::fs::read(env.vault()).unwrap();
    assert!(bytes.starts_with(b"CLOAKENV"));
    assert!(!contains(&bytes, SECRET));
    assert!(!contains(&bytes, "API_KEY"), "key names are encrypted too");
}

#[test]
fn no_stray_files_left_behind() {
    let env = Env::init();
    env.set("API_KEY", SECRET);
    env.ok(&["run", "--", "sh", "-c", "true"]);
    env.ok(&["run", "--shield", "--", "sh", "-c", "echo $API_KEY"]);
    let mut entries: Vec<_> = std::fs::read_dir(env.path().join(".cloak"))
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    entries.sort();
    // The (empty) writer lock file is persistent by design; no temp files.
    assert_eq!(
        entries,
        vec![
            std::ffi::OsString::from(".vault.bin.lock"),
            std::ffi::OsString::from("vault.bin"),
        ]
    );
    assert_eq!(
        std::fs::metadata(env.path().join(".cloak/.vault.bin.lock"))
            .unwrap()
            .len(),
        0
    );
    let top: Vec<_> = std::fs::read_dir(env.path())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(top, vec![std::ffi::OsString::from(".cloak")]);
}

#[test]
fn run_injects_secrets_into_child_env() {
    let env = Env::init();
    env.set("API_KEY", SECRET);
    env.set("DB_URL", "postgres://u:p@h/db");
    let out = env.ok(&[
        "run",
        "--",
        "sh",
        "-c",
        r#"printf '%s|%s' "$API_KEY" "$DB_URL""#,
    ]);
    assert_eq!(stdout(&out), format!("{SECRET}|postgres://u:p@h/db"));
}

#[test]
fn run_preserves_parent_env_and_vault_overrides_it() {
    let env = Env::init();
    env.set("API_KEY", SECRET);
    let out = env
        .cmd(Some(PASS))
        .env("API_KEY", "from-parent")
        .env("UNRELATED", "kept")
        .args([
            "run",
            "--",
            "sh",
            "-c",
            r#"printf '%s|%s' "$API_KEY" "$UNRELATED""#,
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert_eq!(stdout(&out), format!("{SECRET}|kept"));
}

#[test]
fn passphrase_is_not_leaked_to_child() {
    let env = Env::init();
    let out = env.ok(&[
        "run",
        "--",
        "sh",
        "-c",
        r#"printf '%s' "${CLOAKENV_PASSPHRASE-unset}|${CLOAKENV_PASSPHRASE_FILE-unset}""#,
    ]);
    assert_eq!(stdout(&out), "unset|unset");
}

#[test]
fn cli_refuses_to_store_passphrase_vars() {
    let env = Env::init();
    for key in ["CLOAKENV_PASSPHRASE", "CLOAKENV_PASSPHRASE_FILE"] {
        let out = env.run_stdin(&["set", key], "nope");
        assert!(!out.status.success(), "set {key} should fail");
        let err = stderr(&out);
        assert!(err.contains(key) && err.contains("reserved"), "{err}");
        assert!(!err.contains("nope"), "value must not be echoed: {err}");
    }
    // A .env import containing one is refused as a whole: nothing is stored.
    std::fs::write(
        env.path().join("in.env"),
        "KEEP=yes\nCLOAKENV_PASSPHRASE=nope\n",
    )
    .unwrap();
    let out = env.run(&["import", "in.env"]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("reserved"), "{}", stderr(&out));
    assert_eq!(stdout(&env.ok(&["list"])), "");
}

#[test]
fn vault_cannot_reintroduce_passphrase_vars() {
    // The CLI refuses these names, so build the vault through the library, as
    // a vault written by another tool or an older cloakenv could be. `run`
    // must still strip them.
    let env = Env::init();
    let mut vault = cloakenv::vault::Vault::load(&env.vault(), PASS.as_bytes()).unwrap();
    for (k, v) in [
        ("CLOAKENV_PASSPHRASE", "from-vault"),
        ("CLOAKENV_PASSPHRASE_FILE", "from-vault-file"),
        ("KEEP", "yes"),
    ] {
        vault.set(k, zeroize::Zeroizing::new(v.to_owned())).unwrap();
    }
    vault.save(&env.vault(), PASS.as_bytes()).unwrap();
    let out = env.ok(&[
        "run",
        "--",
        "sh",
        "-c",
        r#"printf '%s' "${CLOAKENV_PASSPHRASE-unset}|${CLOAKENV_PASSPHRASE_FILE-unset}|$KEEP""#,
    ]);
    assert_eq!(stdout(&out), "unset|unset|yes");
}

#[test]
fn passphrase_file_is_supported() {
    let env = Env::new();
    let keyfile = env.path().join("machine.key");
    std::fs::write(&keyfile, "machine-local-key\n").unwrap();
    let run = |args: &[&str]| {
        env.cmd(None)
            .env("CLOAKENV_PASSPHRASE_FILE", &keyfile)
            .args(args)
            .output()
            .unwrap()
    };
    assert!(run(&["init"]).status.success());
    let mut set = env.cmd(None);
    set.env("CLOAKENV_PASSPHRASE_FILE", &keyfile)
        .args(["set", "K"]);
    assert!(Env::output_with_stdin(set, "v").status.success());
    let out = run(&["run", "--", "sh", "-c", r#"printf %s "$K""#]);
    assert_eq!(stdout(&out), "v");
    // Trailing newline is stripped, so the env var form is equivalent.
    let out = env
        .cmd(Some("machine-local-key"))
        .args(["list"])
        .output()
        .unwrap();
    assert_eq!(stdout(&out), "K\n");
}

#[test]
fn child_exit_code_is_propagated() {
    let env = Env::init();
    let out = env.run(&["run", "--", "sh", "-c", "exit 42"]);
    assert_eq!(out.status.code(), Some(42));
    let out = env.run(&["run", "--shield", "--", "sh", "-c", "exit 7"]);
    assert_eq!(out.status.code(), Some(7));
}

#[test]
fn signal_death_maps_to_128_plus_signal() {
    let env = Env::init();
    let out = env.run(&["run", "--", "sh", "-c", "kill -TERM $$"]);
    assert_eq!(out.status.code(), Some(128 + 15));
}

#[test]
fn missing_command_exits_127() {
    let env = Env::init();
    let out = env.run(&["run", "--", "definitely-not-a-real-command-xyz"]);
    assert_eq!(out.status.code(), Some(127));
    assert!(stderr(&out).contains("command not found"));
}

#[test]
fn child_args_with_leading_dashes_pass_through() {
    let env = Env::init();
    let out = env.ok(&[
        "run",
        "--",
        "sh",
        "-c",
        r#"printf '%s ' "$@""#,
        "sh",
        "--shield",
        "-x",
    ]);
    assert_eq!(stdout(&out), "--shield -x ");
}

#[test]
fn stdin_is_inherited_by_child() {
    let env = Env::init();
    let mut child = env
        .cmd(Some(PASS))
        .args(["run", "--", "cat"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"piped input")
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!(stdout(&out), "piped input");
}

#[test]
fn set_reads_value_from_stdin_when_omitted() {
    let env = Env::init();
    let mut child = env
        .cmd(Some(PASS))
        .args(["set", "FROM_STDIN"])
        .stdin(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(format!("{SECRET}\n").as_bytes())
        .unwrap();
    assert!(child.wait().unwrap().success());
    let out = env.ok(&["run", "--", "sh", "-c", r#"printf %s "$FROM_STDIN""#]);
    assert_eq!(stdout(&out), SECRET);
}

#[test]
fn set_overwrites_and_unset_removes() {
    let env = Env::init();
    env.set("A", "1");
    env.set("A", "2");
    env.set("B", "3");
    assert_eq!(stdout(&env.ok(&["list"])), "A\nB\n");
    let out = env.ok(&["run", "--", "sh", "-c", r#"printf %s "$A""#]);
    assert_eq!(stdout(&out), "2");
    env.ok(&["unset", "A"]);
    assert_eq!(stdout(&env.ok(&["list"])), "B\n");
    assert!(!env.run(&["unset", "A"]).status.success());
}

#[test]
fn list_never_prints_values() {
    let env = Env::init();
    env.set("API_KEY", SECRET);
    let out = env.ok(&["list"]);
    assert_eq!(stdout(&out), "API_KEY\n");
    assert!(!contains(&out.stderr, SECRET));
}

#[test]
fn import_dotenv_file() {
    let env = Env::init();
    let dotenv = env.path().join(".env.example");
    std::fs::write(
        &dotenv,
        "# comment\n\nexport A=plain # trailing comment\nB='single # not comment'\nC=\"line1\\nline2\"\nD=\n",
    )
    .unwrap();
    let out = env.ok(&["import", dotenv.to_str().unwrap()]);
    assert!(stderr(&out).contains("imported 4 key(s)"));
    let out = env.ok(&[
        "run",
        "--",
        "sh",
        "-c",
        r#"printf '%s|%s|%s|%s' "$A" "$B" "$C" "$D""#,
    ]);
    assert_eq!(stdout(&out), "plain|single # not comment|line1\nline2|");
}

#[test]
fn import_errors_do_not_echo_content() {
    let env = Env::init();
    let dotenv = env.path().join(".env");
    std::fs::write(&dotenv, format!("OK=1\nTOKEN=\"{SECRET}\n")).unwrap();
    let out = env.run(&["import", dotenv.to_str().unwrap()]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("line 2"));
    assert!(!contains(&out.stderr, SECRET));
    // Nothing was imported.
    assert_eq!(stdout(&env.ok(&["list"])), "");
}

#[test]
fn swapped_key_and_value_does_not_echo_secret() {
    let env = Env::init();
    // The value on stdin, but the secret typed where the key goes.
    let out = env.run_stdin(&["set", SECRET], "API_KEY");
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("invalid variable name"));
    assert!(!contains(&out.stderr, SECRET));
    // Rejected before the value is even read.
    let out = env.cmd(None).args(["set", SECRET]).output().unwrap();
    assert!(stderr(&out).contains("invalid variable name"));
    assert!(!contains(&out.stderr, SECRET));
}

#[test]
fn vault_path_override() {
    let env = Env::new();
    let custom = env.path().join("elsewhere").join("my.vault");
    let custom = custom.to_str().unwrap();
    env.ok(&["--vault", custom, "init"]);
    let out = env.run_stdin(&["--vault", custom, "set", "K"], "v");
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(!env.vault().exists());
    let out = env
        .cmd(Some(PASS))
        .env("CLOAKENV_VAULT", custom)
        .args(["run", "--", "sh", "-c", r#"printf %s "$K""#])
        .output()
        .unwrap();
    assert_eq!(stdout(&out), "v");
}

#[test]
fn init_refuses_to_clobber_without_force() {
    let env = Env::init();
    env.set("K", "v");
    let out = env.run(&["init"]);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(stdout(&env.ok(&["list"])), "K\n");
    env.ok(&["init", "--force"]);
    assert_eq!(stdout(&env.ok(&["list"])), "");
}

#[test]
fn empty_or_missing_passphrase_is_rejected() {
    let env = Env::new();
    let out = env.cmd(Some("")).args(["init"]).output().unwrap();
    assert!(!out.status.success());
    assert!(!env.vault().exists());
    // No env var and no terminal: must fail rather than hang or default.
    let out = env.cmd(None).args(["init"]).output().unwrap();
    assert!(!out.status.success());
    assert!(!env.vault().exists());
}
