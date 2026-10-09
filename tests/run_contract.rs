//! What the README and \`cloakenv run --help\` say \`run\` does at its edges, as
//! tests: exit codes (including the ones a command can produce itself), the
//! SIGPIPE the command always gets, standard descriptors that were closed, and
//! the help text itself.
#![cfg(unix)]

mod common;

use std::os::unix::process::{CommandExt, ExitStatusExt};

use common::*;

const MODES: [&[&str]; 2] = [&[], &["--shield"]];

fn env_with_secret() -> Env {
    let env = Env::init();
    env.set("API_KEY", "sk-contract-0042");
    env
}

fn run_mode(env: &Env, mode: &[&str], command: &[&str]) -> std::process::Output {
    let mut args = vec!["run"];
    args.extend_from_slice(mode);
    args.push("--");
    args.extend_from_slice(command);
    env.run(&args)
}

#[test]
fn help_describes_the_separator_the_modes_and_the_exit_codes() {
    let env = Env::new();
    for flag in ["--help", "-h"] {
        let out = env.run(&["run", flag]);
        assert!(out.status.success());
        let text = stdout(&out);
        for needle in [
            "cloakenv run [OPTIONS] -- <COMMAND>...",
            "--shield",
            "Exit codes of 'run':",
            "125    cloakenv itself failed",
            "126    the command was found but could not be executed",
            "127    the command was not found",
            "128+N",
            "usage error",
        ] {
            assert!(
                text.contains(needle),
                "{flag}: missing {needle:?} in\n{text}"
            );
        }
    }
    // The long form also explains what --shield does to the command's streams.
    let text = stdout(&env.run(&["run", "--help"]));
    for needle in [
        "pipes, not terminals",
        "stdin is inherited",
        "replaces itself with the command",
        "the same destination",
        "not a security boundary",
    ] {
        assert!(text.contains(needle), "missing {needle:?} in\n{text}");
    }
}

#[test]
fn every_row_of_the_exit_code_table_holds_in_both_modes() {
    let env = env_with_secret();
    std::fs::write(env.path().join("not-executable"), "#!/bin/sh\n").unwrap();
    for mode in MODES {
        // The command's own status passes through, including 125, 126, 127.
        for code in [0, 1, 7, 125, 126, 127] {
            let out = run_mode(&env, mode, &["sh", "-c", &format!("exit {code}")]);
            assert_eq!(out.status.code(), Some(code), "{mode:?} exit {code}");
        }
        // cloakenv's own: not found, not executable.
        let out = run_mode(&env, mode, &["no-such-command-anywhere"]);
        assert_eq!(out.status.code(), Some(127), "{mode:?}");
        assert!(
            stderr(&out).starts_with("cloakenv: error:"),
            "{}",
            stderr(&out)
        );
        let out = run_mode(&env, mode, &["./not-executable"]);
        assert_eq!(out.status.code(), Some(126), "{mode:?}: {}", stderr(&out));
        // A wrong passphrase is cloakenv's own failure: 125, nothing started.
        let mut cmd = env.cmd(Some("not the passphrase"));
        cmd.arg("run").args(mode).args(["--", "touch", "started"]);
        let out = cmd.output().unwrap();
        assert_eq!(out.status.code(), Some(125), "{mode:?}");
        assert!(
            stderr(&out).starts_with("cloakenv: error:"),
            "{}",
            stderr(&out)
        );
        assert!(!env.path().join("started").exists());
        // A usage error under \`run\` is 2, not 125.
        let mut args = vec!["run"];
        args.extend_from_slice(mode);
        args.push("--bogus");
        let out = env.run(&args);
        assert_eq!(out.status.code(), Some(2), "{mode:?}");
    }
    // Killed by a signal: 128 + N under --shield (cloakenv waits and reports
    // it), the signal death itself without (cloakenv is gone).
    let out = run_mode(&env, &["--shield"], &["sh", "-c", "kill -TERM $$"]);
    assert_eq!(out.status.code(), Some(128 + 15));
    let out = run_mode(&env, &[], &["sh", "-c", "kill -TERM $$"]);
    assert_eq!(out.status.signal(), Some(15));
}

#[test]
fn other_subcommands_fail_with_1_and_usage_errors_with_2() {
    let env = Env::new(); // no vault
    assert_eq!(env.run(&["list"]).status.code(), Some(1));
    assert_eq!(env.run(&["unset", "KEY"]).status.code(), Some(1));
    assert_eq!(env.run(&["no-such-subcommand"]).status.code(), Some(2));
    // ...while \`run\` reports the same missing vault as 125.
    assert_eq!(env.run(&["run", "--", "true"]).status.code(), Some(125));
}

/// The command always gets SIGPIPE at its default action, even if cloakenv's
/// caller had it ignored: cloakenv itself runs with it ignored (the Rust
/// runtime does that), and what it hands down is the default. (There is no way
/// to tell what the caller had.)
#[test]
fn the_command_gets_default_sigpipe_even_if_the_caller_ignored_it() {
    let env = env_with_secret();
    for mode in MODES {
        let mut cmd = env.cmd(Some(PASS));
        cmd.arg("run")
            .args(mode)
            .args(["--", "sh", "-c", "kill -PIPE $$; echo survived"]);
        // SAFETY: only async-signal-safe signal(2) between fork and exec.
        unsafe {
            cmd.pre_exec(|| {
                libc::signal(libc::SIGPIPE, libc::SIG_IGN);
                Ok(())
            });
        }
        let out = cmd.output().unwrap();
        assert!(
            !stdout(&out).contains("survived"),
            "{mode:?}: SIGPIPE was ignored"
        );
        let died_of_sigpipe =
            out.status.signal() == Some(13) || out.status.code() == Some(128 + 13);
        assert!(died_of_sigpipe, "{mode:?}: {:?}", out.status);
    }
}

/// Standard descriptors that are closed when cloakenv starts are reopened on
/// /dev/null by the Rust runtime before any of our code runs, so the command
/// finds /dev/null there, not a closed descriptor (and not whatever it opens
/// first). Under --shield stdout and stderr are the command's output pipes
/// instead; stdin is /dev/null in both modes.
#[test]
fn closed_standard_descriptors_are_dev_null_for_the_command() {
    let env = env_with_secret();
    for (mode, script) in [
        (
            &[][..],
            "[ -c /dev/fd/0 ] && [ -c /dev/fd/1 ] && [ -c /dev/fd/2 ]",
        ),
        (&["--shield"][..], "[ -c /dev/fd/0 ]"),
    ] {
        let mut cmd = env.cmd(Some(PASS));
        cmd.arg("run").args(mode).args(["--", "sh", "-c", script]);
        // SAFETY: close(2) only.
        unsafe {
            cmd.pre_exec(|| {
                libc::close(0);
                libc::close(1);
                libc::close(2);
                Ok(())
            });
        }
        let status = cmd.status().unwrap();
        assert!(status.success(), "{mode:?}: {status:?}");
    }
}
