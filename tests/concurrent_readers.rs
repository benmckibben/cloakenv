//! Commands that only read a vault (`list`, `run`) do not hold its write lock. A writer can therefore save the next
//! generation and record it in the rollback state between a reader's read and its comparison, and the copy the
//! reader holds is then one generation behind. That is not a rollback, and these tests run real processes (not
//! threads) to show that it is not reported as one, while a copy that really is old still is.

mod common;

use std::fs;
use std::process::Stdio;
use std::time::{Duration, Instant};

use common::*;

const ROUNDS: u64 = 20;
const ROLLBACK_TEXT: &str = "older than one this machine has already seen";

fn run_true_args() -> Vec<&'static str> {
    let mut v = vec!["run", "--"];
    if cfg!(windows) {
        v.extend(["cmd", "/C", "exit", "0"]);
    } else {
        v.push("true");
    }
    v
}

#[test]
fn readers_racing_a_writer_are_never_refused_as_rolled_back() {
    let env = Env::init();
    let mut problems = Vec::new();
    for round in 0..ROUNDS {
        // The writer is in its two key derivations for about a quarter of a second; the readers start at a
        // different point of that span in every round.
        let writer = env.spawn_set(&format!("K{round}"), "value");
        std::thread::sleep(Duration::from_millis(round * 14));
        let spawn_reader = |args: &[&str]| {
            env.cmd(Some(PASS))
                .args(args)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("spawn cloakenv")
        };
        let list = spawn_reader(&["list"]);
        let run = spawn_reader(&run_true_args());
        let written = writer.wait_with_output().expect("wait for set");
        if !written.status.success() {
            problems.push(format!("round {round}: set failed: {}", stderr(&written)));
        }
        for (name, child) in [("list", list), ("run", run)] {
            let out = child.wait_with_output().expect("wait for the reader");
            if !out.status.success() {
                problems.push(format!(
                    "round {round}: {name} exited {:?}: {}",
                    out.status.code(),
                    stderr(&out)
                ));
            }
        }
    }
    assert!(
        problems.is_empty(),
        "{} of {ROUNDS} rounds had a reader refused or a writer failed:\n{}",
        problems.len(),
        problems.join("\n")
    );
    // nothing was lost on the way
    let listed = stdout(&env.ok(&["list"]));
    for round in 0..ROUNDS {
        assert!(
            listed.lines().any(|l| l == format!("K{round}")),
            "K{round} is missing from:\n{listed}"
        );
    }
}

#[test]
fn an_older_copy_is_still_refused_after_the_reads_are_repeated() {
    let env = Env::init();
    env.set("A", "1");
    let old = fs::read(env.vault()).unwrap();
    env.set("B", "2");
    fs::write(env.vault(), &old).unwrap();
    let before = fs::read(env.vault()).unwrap();

    let started = Instant::now();
    let list = env.run(&["list"]);
    assert_eq!(list.status.code(), Some(1), "stderr: {}", stderr(&list));
    let err = stderr(&list);
    assert!(
        err.contains(ROLLBACK_TEXT) && err.contains("accept-rollback"),
        "{err}"
    );
    assert_eq!(
        err.matches(ROLLBACK_TEXT).count(),
        1,
        "the repeated reads say it once: {err}"
    );
    let run = env.run(&run_true_args());
    assert_eq!(run.status.code(), Some(125), "stderr: {}", stderr(&run));
    assert!(stderr(&run).contains(ROLLBACK_TEXT));
    assert!(
        started.elapsed() < Duration::from_secs(60),
        "the repeats are bounded: took {:?}",
        started.elapsed()
    );
    assert_eq!(
        fs::read(env.vault()).unwrap(),
        before,
        "a refusal never changes the vault"
    );
}
