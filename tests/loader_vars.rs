//! A vault entry that overrides `PATH`, `LD_*`, `DYLD_*` or `BASH_ENV` changes
//! which programs and libraries run, not just what they are told. cloakenv
//! says so, once, on its own stderr, naming the key and never the value:
//! when the entry is stored (`set`, `import`) and on every `run` before the
//! command starts. It is a warning only: nothing is blocked and exit codes
//! are unchanged.
#![cfg(unix)]

mod common;

use std::fs;
use std::os::unix::fs::PermissionsExt;

use common::*;

fn warning_lines(err: &str) -> Vec<&str> {
    err.lines()
        .filter(|l| l.starts_with("cloakenv: warning: the vault sets"))
        .collect()
}

#[test]
fn a_vault_path_that_changes_which_program_runs_is_announced_before_it_runs() {
    let env = Env::init();
    let bin = env.path().join("evil-bin");
    fs::create_dir(&bin).unwrap();
    let fake = bin.join("true");
    fs::write(&fake, "#!/bin/sh\necho the-fake-true-ran\nexit 7\n").unwrap();
    fs::set_permissions(&fake, fs::Permissions::from_mode(0o755)).unwrap();

    let path_value = format!("{}:/usr/bin:/bin", bin.display());
    let out = env.run_stdin(&["set", "PATH"], &path_value);
    assert!(out.status.success(), "{}", stderr(&out));
    let err = stderr(&out);
    assert_eq!(warning_lines(&err).len(), 1, "{err}");
    assert!(
        err.contains("sets PATH, which changes what programs and libraries run"),
        "{err}"
    );
    assert!(
        !err.contains("evil-bin"),
        "the value must not be shown: {err}"
    );

    // The command that gets run is the vault's, and the exit code is its own.
    let out = env.run(&["run", "--", "true"]);
    assert_eq!(stdout(&out), "the-fake-true-ran\n");
    assert_eq!(out.status.code(), Some(7), "exit codes are unchanged");
    let err = stderr(&out);
    assert_eq!(warning_lines(&err).len(), 1, "{err}");
    assert!(err.contains("sets PATH,"), "{err}");
    assert!(!err.contains("evil-bin"), "{err}");
}

#[test]
fn every_listed_variable_warns_and_unrelated_ones_do_not() {
    let env = Env::init();
    for key in [
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
        "BASH_ENV",
    ] {
        // Empty values keep the loader harmless while the test runs.
        let out = env.run_stdin(&["set", "--allow-empty", key], "");
        assert!(out.status.success(), "{key}: {}", stderr(&out));
        assert!(
            stderr(&out).contains(&format!("warning: the vault sets {key},")),
            "{key}: {}",
            stderr(&out)
        );
    }
    for key in [
        "PYTHONPATH",
        "NODE_OPTIONS",
        "ENV",
        "PATHEXT",
        "LDFLAGS",
        "HOME_DIR",
        "API_KEY",
    ] {
        let out = env.run_stdin(&["set", key], "x");
        assert!(out.status.success(), "{key}");
        assert!(!stderr(&out).contains("warning"), "{key}: {}", stderr(&out));
    }
    // One line for the whole run, naming all five.
    let out = env.run(&["run", "--", "true"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let err = stderr(&out);
    assert_eq!(warning_lines(&err).len(), 1, "{err}");
    for key in [
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
        "BASH_ENV",
    ] {
        assert!(err.contains(key), "{key}: {err}");
    }
    assert!(
        !err.contains("PYTHONPATH") && !err.contains("API_KEY"),
        "{err}"
    );
}

#[test]
fn the_warning_is_on_cloakenvs_own_stderr_not_in_the_shield_stream() {
    let env = Env::init();
    env.set("API_KEY", "super-secret-token");
    let out = env.run_stdin(&["set", "--allow-empty", "LD_FOO"], "");
    assert!(out.status.success());
    let out = env.run(&[
        "run",
        "--shield",
        "--",
        "sh",
        "-c",
        "echo out; echo err >&2",
    ]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), "out\n");
    let err = stderr(&out);
    assert_eq!(warning_lines(&err).len(), 1, "{err}");
    assert!(err.contains("err\n"), "{err}");
}

#[test]
fn no_warning_when_the_vault_has_no_such_variable() {
    let env = Env::init();
    env.set("API_KEY", "x");
    let out = env.run(&["run", "--", "true"]);
    assert!(out.status.success());
    assert!(!stderr(&out).contains("warning"), "{}", stderr(&out));
}

#[test]
fn import_warns_about_them_too_by_name_only() {
    let env = Env::init();
    let file = env.path().join("x.env");
    fs::write(
        &file,
        "OK=1\nPATH=/tmp/attacker-dir:/usr/bin\nLD_PRELOAD=/tmp/evil.so\n",
    )
    .unwrap();
    let out = env
        .cmd(Some(PASS))
        .arg("import")
        .arg(&file)
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
    let err = stderr(&out);
    assert!(
        err.contains("the vault sets PATH, LD_PRELOAD, which change what programs"),
        "{err}"
    );
    assert!(
        !err.contains("attacker") && !err.contains("evil.so"),
        "{err}"
    );
}
