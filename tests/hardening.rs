//! Linux process hardening: commands spawned by `cloakenv run` (and any other
//! same-user process) must not be able to reach into cloakenv through
//! `/proc/<pid>` to steal the passphrase or bypass `--shield`.
#![cfg(target_os = "linux")]

mod common;

use common::*;

const SECRET: &str = "sk_live_hardening_0123456789";

/// root has CAP_SYS_PTRACE and may read any /proc entry regardless of the
/// dumpable flag, so these checks only make sense for unprivileged users.
fn running_as_root() -> bool {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    let uid_line = status.lines().find(|l| l.starts_with("Uid:")).unwrap();
    uid_line.split_whitespace().nth(2) == Some("0")
}

macro_rules! skip_if_root {
    () => {
        if running_as_root() {
            eprintln!("skipping: running as root (CAP_SYS_PTRACE bypasses /proc checks)");
            return;
        }
    };
}

/// Sanity check that the probes below would succeed against a dumpable
/// parent, so a pass really means cloakenv blocked them.
#[test]
fn probes_work_against_an_ordinary_parent() {
    skip_if_root!();
    let out = std::process::Command::new("sh")
        .args(["-c", r#"sh -c 'cat /proc/$PPID/environ' | tr '\0' '\n'"#])
        .env("PROBE_MARKER", "visible")
        .output()
        .unwrap();
    assert!(stdout(&out).contains("PROBE_MARKER=visible"));
}

#[test]
fn child_cannot_read_passphrase_from_parent_environ() {
    skip_if_root!();
    let env = Env::init();
    env.set("API_KEY", SECRET);
    let out = env.ok(&[
        "run",
        "--",
        "sh",
        "-c",
        r#"cat /proc/$PPID/environ; echo "rc=$?"; ls /proc/$PPID/fd >/dev/null 2>&1; echo "ls=$?""#,
    ]);
    let stdout = stdout(&out);
    assert!(
        !stdout.contains(PASS),
        "passphrase leaked via /proc/PPID/environ"
    );
    assert!(!stdout.contains("CLOAKENV_PASSPHRASE"), "{stdout}");
    assert!(stdout.contains("rc=1"), "environ read must fail: {stdout}");
    assert!(stdout.contains("ls=2"), "fd listing must fail: {stdout}");
}

#[test]
fn child_cannot_read_passphrase_file_path_from_parent_environ() {
    skip_if_root!();
    let env = Env::init();
    let pass_file = env.path().join("secret-pass-location.txt");
    std::fs::write(&pass_file, format!("{PASS}\n")).unwrap();
    let out = env
        .cmd(None)
        .env("CLOAKENV_PASSPHRASE_FILE", &pass_file)
        .args([
            "run",
            "--",
            "sh",
            "-c",
            r#"tr '\0' '\n' < /proc/$PPID/environ; cat "$(tr '\0' '\n' < /proc/$PPID/environ | sed -n 's/^CLOAKENV_PASSPHRASE_FILE=//p')""#,
        ])
        .output()
        .unwrap();
    assert!(out.status.success() || out.status.code() == Some(1));
    assert!(!contains(&out.stdout, "secret-pass-location"));
    assert!(!contains(&out.stdout, PASS), "passphrase leaked");
}

#[test]
fn child_cannot_bypass_shield_via_parent_stdout_fd() {
    skip_if_root!();
    let env = Env::init();
    env.set("API_KEY", SECRET);
    let out = env
        .cmd(Some(PASS))
        .args([
            "run",
            "--shield",
            "--",
            "sh",
            "-c",
            r#"printf '%s\n' "$API_KEY" > /proc/$PPID/fd/1; printf '%s\n' "$API_KEY" > /proc/$PPID/fd/2; echo "direct=$API_KEY""#,
        ])
        .output()
        .unwrap();
    assert!(
        !contains(&out.stdout, SECRET),
        "--shield bypassed on stdout"
    );
    assert!(
        !contains(&out.stderr, SECRET),
        "--shield bypassed on stderr"
    );
    assert!(stdout(&out).contains("direct=[REDACTED_BY_CLOAKENV]"));
}
