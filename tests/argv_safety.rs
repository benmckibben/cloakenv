//! Secrets must never travel through argv (visible in ps and /proc/<pid>/cmdline,
//! saved in shell history), and command-line errors must never echo what was
//! typed, since a misplaced secret is the most likely thing to be there.
#![cfg(unix)]

mod common;

use common::*;

const SECRET: &str = "sk-live-0a1b2c3d4e5f-argv";

/// Every single-quoted token in clap-style output must be one of our own
/// names; anything else could be a fragment of user input.
fn assert_no_echo(args: &[&str], stderr: &str) {
    assert!(
        !stderr.contains(SECRET),
        "{args:?} echoed the secret: {stderr}"
    );
    for frag in [&SECRET[..4], &SECRET[SECRET.len() - 6..]] {
        assert!(!stderr.contains(frag), "{args:?} echoed {frag:?}: {stderr}");
    }
    const OURS: &[&str] = &[
        "--help", "--shield", "--vault", "--force", "init", "set", "unset", "import", "list", "run",
    ];
    for word in stderr.split_whitespace() {
        let word = word.trim_end_matches(['?', '.', ',', ';', ':']);
        if let Some(quoted) = word.strip_prefix('\'').and_then(|w| w.strip_suffix('\'')) {
            assert!(
                OURS.contains(&quoted),
                "{args:?} quoted user input {quoted:?}: {stderr}"
            );
        }
    }
}

#[test]
fn set_refuses_value_argument_without_echo_or_write() {
    let env = Env::init();
    env.set("API_KEY", "old");
    let before = std::fs::read(env.vault()).unwrap();
    for pass in [Some(PASS), None] {
        let out = env
            .cmd(pass)
            .args(["set", "API_KEY", SECRET])
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(1));
        let err = stderr(&out);
        assert!(
            err.contains("refusing to read a secret value from the command line"),
            "{err}"
        );
        assert_no_echo(&["set", "API_KEY", SECRET], &err);
        assert!(!err.contains("API_KEY"), "key is not echoed either: {err}");
        assert!(out.stdout.is_empty());
    }
    assert_eq!(
        std::fs::read(env.vault()).unwrap(),
        before,
        "nothing stored"
    );
    let out = env.ok(&["run", "--", "sh", "-c", r#"printf %s "$API_KEY""#]);
    assert_eq!(stdout(&out), "old");
}

#[test]
fn usage_errors_never_echo_arguments() {
    let env = Env::init();
    std::fs::write(env.path().join("a.env"), "A=1\n").unwrap();
    let before = std::fs::read(env.vault()).unwrap();
    let flag_value = format!("--value={SECRET}");
    let unknown_global = format!("--token={SECRET}");
    let force_value = format!("--force={SECRET}");
    let typo_shield = format!("--shiled={SECRET}");
    let dash_secret = format!("-{SECRET}");
    let short_cluster = format!("-p{SECRET}");
    let cases: Vec<Vec<&str>> = vec![
        vec!["set", "API_KEY", SECRET, "extra"],
        vec!["set", "API_KEY", &flag_value],
        vec![&unknown_global, "list"],
        vec!["init", &force_value],
        vec!["run", &typo_shield, "--", "touch", "child-ran"],
        vec!["run", &short_cluster, "touch", "child-ran"],
        vec![SECRET],
        vec!["list", SECRET],
        vec!["set", &dash_secret],
        vec!["unset", "API_KEY", SECRET],
        vec!["import", "a.env", SECRET],
        vec!["--vault"],
    ];
    for args in &cases {
        let out = env.run(args);
        assert_eq!(out.status.code(), Some(2), "{args:?}: {}", stderr(&out));
        assert!(out.stdout.is_empty(), "{args:?}");
        let err = stderr(&out);
        assert!(err.starts_with("cloakenv: error: "), "{args:?}: {err}");
        assert!(err.contains("Usage: cloakenv"), "{args:?}: {err}");
        assert_no_echo(args, &err);
    }
    assert!(
        !env.path().join("child-ran").exists(),
        "nothing was spawned"
    );
    assert_eq!(std::fs::read(env.vault()).unwrap(), before);
}

#[test]
fn usage_errors_keep_safe_hints() {
    let env = Env::init();
    let err = stderr(&env.run(&["set"]));
    assert!(err.contains("missing: <KEY>"), "{err}");
    let err = stderr(&env.run(&["lst"]));
    assert!(err.contains("did you mean 'list'?"), "{err}");
    let err = stderr(&env.run(&["run", &format!("--shiled={SECRET}"), "x"]));
    assert!(err.contains("did you mean '--shield'?"), "{err}");

    let out = env.run(&["set", "--help"]);
    assert!(out.status.success());
    assert!(stdout(&out).contains("never from argv"), "{}", stdout(&out));
    assert!(!stdout(&out).contains("[VALUE]"), "VALUE stays hidden");
    let out = env.run(&["--version"]);
    assert!(out.status.success() && stdout(&out).starts_with("cloakenv "));
}

/// The value only ever reaches `set` through stdin, so it is never part of
/// the process's command line while it runs.
#[cfg(target_os = "linux")]
#[test]
fn set_value_is_absent_from_proc_cmdline() {
    use std::io::Write;
    use std::process::Stdio;

    let env = Env::init();
    let mut child = env
        .cmd(Some(PASS))
        .args(["set", "API_KEY"])
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // Wait until the exec has happened (cloakenv then blocks reading stdin)
    // and inspect what ps(1) would show.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let cmdline = loop {
        let cmdline = std::fs::read(format!("/proc/{}/cmdline", child.id())).unwrap();
        if contains(&cmdline, "API_KEY") || std::time::Instant::now() > deadline {
            break cmdline;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    };
    assert!(contains(&cmdline, "API_KEY"), "{cmdline:?}");
    assert!(!contains(&cmdline, SECRET));
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(SECRET.as_bytes()).unwrap();
    drop(stdin);
    assert!(child.wait().unwrap().success());
    let out = env.ok(&["run", "--", "sh", "-c", r#"printf %s "$API_KEY""#]);
    assert_eq!(stdout(&out), SECRET);
}
