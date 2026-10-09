//! `--shield` must not sit on output that cannot be the start of a secret:
//! a line, a prompt without a newline, a server's "listening" message all have
//! to show up while the command is still running. It must still hold back a
//! trailing partial secret, and must never release it on a timer.
#![cfg(unix)]

mod common;
mod live;

use std::time::Duration;

use common::*;
use live::Live;

const SECRET: &str = "sk-live-0123456789";
const R: &str = "[REDACTED_BY_CLOAKENV]";

fn shielded(script: &str) -> (Env, Live) {
    let env = Env::init();
    env.set("API_KEY", SECRET);
    let mut cmd = env.cmd(Some(PASS));
    cmd.args(["run", "--shield", "--", "sh", "-c", script]);
    let live = Live::start(cmd);
    (env, live)
}

#[test]
fn a_line_appears_while_the_command_is_still_running() {
    // The command stays alive until the test has seen the line.
    let (_env, mut live) = shielded("echo ready; read go; echo \"after $go\"");
    live.wait_for("ready\n");
    live.send("now\n");
    let (status, out) = live.finish();
    assert!(status.success());
    assert_eq!(String::from_utf8_lossy(&out), "ready\nafter now\n");
}

#[test]
fn a_prompt_without_a_newline_appears() {
    let (_env, mut live) = shielded("printf 'Enter name: '; read name; echo \"hello $name\"");
    live.wait_for("Enter name: ");
    live.send("bob\n");
    let (status, out) = live.finish();
    assert!(status.success());
    assert_eq!(String::from_utf8_lossy(&out), "Enter name: hello bob\n");
}

#[test]
fn a_servers_listening_line_appears_before_it_exits() {
    let (_env, mut live) = shielded("echo 'listening on 127.0.0.1:8080'; read stop");
    live.wait_for("listening on 127.0.0.1:8080\n");
    live.send("stop\n");
    let (status, _) = live.finish();
    assert!(status.success());
}

#[test]
fn output_ending_in_a_letter_that_starts_the_secret_waits_only_for_that_letter() {
    // "s" begins the secret ("sk-live-..."), so the final "s" is held; the
    // rest is not.
    let (_env, mut live) = shielded("printf 'all systems go, s'; read go; printf 'o\\n'");
    live.wait_for("all systems go, ");
    live.collect_for(Duration::from_millis(200));
    assert_eq!(String::from_utf8_lossy(&live.seen), "all systems go, ");
    live.send("go\n");
    let (status, out) = live.finish();
    assert!(status.success());
    assert_eq!(String::from_utf8_lossy(&out), "all systems go, so\n");
}

#[test]
fn a_trailing_partial_secret_is_held_and_never_released_by_waiting() {
    // The command prints the first part of the secret and then waits. That
    // part must stay hidden for as long as it waits; once the rest arrives
    // the whole is redacted.
    let script = format!(
        "printf 'visible-text {}'; read go; printf '{} done\\n'",
        &SECRET[..10],
        &SECRET[10..]
    );
    let (_env, mut live) = shielded(&script);
    live.wait_for("visible-text ");
    // Wait long enough for any timer-driven release to have happened.
    live.collect_for(Duration::from_millis(500));
    assert_eq!(String::from_utf8_lossy(&live.seen), "visible-text ");
    live.send("go\n");
    let (status, out) = live.finish();
    assert!(status.success());
    assert_eq!(
        String::from_utf8_lossy(&out),
        format!("visible-text {R} done\n")
    );
}

#[test]
fn a_secret_cut_off_at_exit_is_written_as_is_at_the_end() {
    // Not redactable (it is not the secret), and nothing waits for more.
    let (_env, live) = shielded(&format!("printf '{}'", &SECRET[..8]));
    let (status, out) = live.finish();
    assert!(status.success());
    assert_eq!(String::from_utf8_lossy(&out), &SECRET[..8]);
}
