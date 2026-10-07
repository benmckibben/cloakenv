//! Concurrent writers must not lose each other's updates (vault locking).
#![cfg(unix)]

mod common;

use std::process::Child;

use common::*;

const WRITERS: usize = 8;

fn wait_all(children: Vec<Child>) {
    for child in children {
        let out = child.wait_with_output().unwrap();
        assert!(
            out.status.success(),
            "concurrent writer failed: {}\nstderr: {}",
            out.status,
            stderr(&out)
        );
    }
}

fn keys(env: &Env) -> Vec<String> {
    stdout(&env.ok(&["list"]))
        .lines()
        .map(str::to_owned)
        .collect()
}

#[test]
fn concurrent_sets_do_not_lose_writes() {
    let env = Env::init();
    // Each writer spends two Argon2id derivations (load + save) between its
    // read and its write, so without locking most of these updates would be
    // overwritten by a sibling that read the vault earlier.
    let children: Vec<Child> = (0..WRITERS)
        .map(|i| {
            env.cmd(Some(PASS))
                .args(["set", &format!("KEY_{i}"), &format!("value-{i}")])
                .spawn()
                .unwrap()
        })
        .collect();
    wait_all(children);

    let want: Vec<String> = (0..WRITERS).map(|i| format!("KEY_{i}")).collect();
    assert_eq!(keys(&env), want);
    let out = env.ok(&[
        "run",
        "--",
        "sh",
        "-c",
        r#"printf '%s,' "$KEY_0" "$KEY_3" "$KEY_7""#,
    ]);
    assert_eq!(stdout(&out), "value-0,value-3,value-7,");
}

#[test]
fn concurrent_set_and_unset_are_serialised() {
    let env = Env::init();
    for i in 0..WRITERS {
        env.set(&format!("OLD_{i}"), "x");
    }
    let children: Vec<Child> = (0..WRITERS)
        .flat_map(|i| {
            [
                env.cmd(Some(PASS))
                    .args(["unset", &format!("OLD_{i}")])
                    .spawn()
                    .unwrap(),
                env.cmd(Some(PASS))
                    .args(["set", &format!("NEW_{i}"), "y"])
                    .spawn()
                    .unwrap(),
            ]
        })
        .collect();
    wait_all(children);

    let want: Vec<String> = (0..WRITERS).map(|i| format!("NEW_{i}")).collect();
    assert_eq!(keys(&env), want);
}

#[test]
fn concurrent_init_creates_exactly_one_vault() {
    let env = Env::new();
    let children: Vec<Child> = (0..4)
        .map(|_| {
            env.cmd(Some(PASS))
                .arg("init")
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap()
        })
        .collect();
    let ok = children
        .into_iter()
        .map(|c| c.wait_with_output().unwrap())
        .filter(|o| o.status.success())
        .count();
    assert_eq!(ok, 1, "exactly one concurrent init may succeed");
    assert!(keys(&env).is_empty());
}
