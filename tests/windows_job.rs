//! `run` on Windows: the command is confined to a job object that dies with
//! cloakenv, a normally finished command leaves its background processes alone,
//! and the command's full 32-bit exit code is reported.
//!
//! Ctrl-C and Ctrl-Break are not tested here: sending one needs a console shared
//! with the child, which a test harness does not reliably have. They are on the
//! manual checklist instead.
#![cfg(windows)]

mod common;

use std::fs;
use std::path::Path;
use std::thread::sleep;
use std::time::{Duration, Instant};

use common::*;

/// Polls `done` until it is true or `timeout` has passed.
fn wait_until(timeout: Duration, done: impl Fn() -> bool) -> bool {
    let end = Instant::now() + timeout;
    while Instant::now() < end {
        if done() {
            return true;
        }
        sleep(Duration::from_millis(200));
    }
    done()
}

/// Runs `cloakenv <args>` with stdout and stderr sent to files, and returns how
/// long it took to exit, its status and what it printed. `Command::output` is
/// no use for these tests: on Windows a `start /b` child inherits the pipe
/// handles, so `output()` would wait for the background process itself, which
/// is exactly what is being measured.
fn run_to_files(env: &Env, args: &[&str]) -> (Duration, std::process::ExitStatus, String) {
    let out_path = env.path().join("out.txt");
    let out = fs::File::create(&out_path).unwrap();
    let err = out.try_clone().unwrap();
    let start = Instant::now();
    let status = env
        .cmd(Some(PASS))
        .args(args)
        .stdout(out)
        .stderr(err)
        .status()
        .unwrap();
    let elapsed = start.elapsed();
    (
        elapsed,
        status,
        fs::read_to_string(out_path).unwrap_or_default(),
    )
}

fn size(path: &Path) -> u64 {
    fs::metadata(path).map_or(0, |m| m.len())
}

#[test]
fn killing_cloakenv_kills_the_command_and_its_children() {
    let env = Env::init();
    let heartbeat = env.path().join("heartbeat.txt");
    // cmd.exe (the command) runs ping.exe (a child) once a second and appends to
    // a file each time; 90 iterations so a failure cleans itself up eventually.
    let script = env.path().join("beat.bat");
    fs::write(
        &script,
        "@echo off\r\nfor /l %%i in (1,1,90) do (\r\n  echo x>>\"%~dp0heartbeat.txt\"\r\n  ping -n 2 127.0.0.1 >nul\r\n)\r\n",
    )
    .unwrap();

    let mut cloakenv = env
        .cmd(Some(PASS))
        .args(["run", "--"])
        .arg(&script)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    assert!(
        wait_until(Duration::from_secs(60), || size(&heartbeat) >= 6),
        "the command never started"
    );

    // TerminateProcess: no handler or destructor runs, like a crash or a kill.
    cloakenv.kill().unwrap();
    cloakenv.wait().unwrap();

    sleep(Duration::from_millis(1500)); // let anything already past the check finish
    let before = size(&heartbeat);
    sleep(Duration::from_secs(4));
    let after = size(&heartbeat);
    assert_eq!(
        before, after,
        "the command kept running after cloakenv was killed"
    );
}

#[test]
fn a_background_process_outlives_a_command_that_finished_normally() {
    let env = Env::init();
    let survivor = env.path().join("survivor.txt");
    fs::write(
        env.path().join("survivor.bat"),
        "@echo off\r\nping -n 4 127.0.0.1 >nul\r\necho done>\"%~dp0survivor.txt\"\r\n",
    )
    .unwrap();
    let launcher = env.path().join("launcher.bat");
    fs::write(
        &launcher,
        "@echo off\r\nstart \"\" /b cmd /c \"%~dp0survivor.bat\"\r\n",
    )
    .unwrap();

    let (_, status, output) = run_to_files(&env, &["run", "--", launcher.to_str().unwrap()]);
    assert!(status.success(), "launcher failed: {output}");
    assert!(
        !survivor.exists(),
        "the background process was too quick to prove anything"
    );
    assert!(
        wait_until(Duration::from_secs(30), || survivor.exists()),
        "a background process the command left behind was killed when cloakenv exited"
    );
}

#[test]
fn the_full_32_bit_exit_code_is_reported() {
    let env = Env::init();
    for code in [0, 7, 255, 256, 1000, 70_000] {
        let out = env.run(&["run", "--", "cmd", "/c", &format!("exit {code}")]);
        assert_eq!(out.status.code(), Some(code), "exit {code}");
    }
}

#[test]
fn the_exit_code_is_reported_with_shield_too() {
    let env = Env::init();
    let out = env.run(&["run", "--shield", "--", "cmd", "/c", "exit 1000"]);
    assert_eq!(out.status.code(), Some(1000));
}

#[test]
fn shield_does_not_hang_on_a_background_process_holding_the_pipes() {
    let env = Env::init();
    // The launcher exits at once; its child keeps stdout/stderr open for ~8 s.
    fs::write(
        env.path().join("holder.bat"),
        "@echo off\r\nping -n 9 127.0.0.1 >nul\r\n",
    )
    .unwrap();
    let launcher = env.path().join("launch_holder.bat");
    fs::write(
        &launcher,
        "@echo off\r\necho started\r\nstart \"\" /b cmd /c \"%~dp0holder.bat\"\r\n",
    )
    .unwrap();
    let (elapsed, status, output) =
        run_to_files(&env, &["run", "--shield", "--", launcher.to_str().unwrap()]);
    assert!(status.success(), "{output}");
    assert!(output.contains("started"), "{output}");
    assert!(
        elapsed < Duration::from_secs(6),
        "run waited for the leftover process ({elapsed:?}); the drain is meant to be bounded to ~3 s"
    );
}
