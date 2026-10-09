//! A save that is killed between creating its temporary file and renaming it
//! (SIGKILL, power loss) leaves a file as large as the vault behind, which was
//! never cleaned up. The next writer removes such leftovers: only abandoned
//! (older than a few minutes) regular files that match the generated name
//! exactly, under the vault lock.
#![cfg(unix)]

mod common;

use std::fs;
use std::time::{Duration, SystemTime};

use common::*;

fn touch(path: &std::path::Path, age: Duration) {
    fs::write(path, b"leftover ciphertext").unwrap();
    let f = fs::File::options().write(true).open(path).unwrap();
    f.set_modified(SystemTime::now() - age).unwrap();
}

#[test]
fn the_next_write_removes_an_abandoned_temp_file_and_nothing_else() {
    let env = Env::init();
    env.set("A", "1");
    let dir = env.path().join(".cloak");
    let stale = dir.join(".vault.bin.tmp-d4307e8e739e");
    let fresh = dir.join(".vault.bin.tmp-aaaaaaaaaaaa");
    let foreign = dir.join(".vault.bin.tmp-d4307e8e739e.old");
    let hour = Duration::from_secs(3600);
    touch(&stale, hour);
    touch(&fresh, Duration::from_secs(5));
    touch(&foreign, hour);

    // Reading does not write, so it does not clean.
    env.ok(&["list"]);
    assert!(stale.exists());

    // Any writer does, once it holds the lock.
    env.set("B", "2");
    assert!(!stale.exists(), "the abandoned file must be removed");
    assert!(fresh.exists(), "a recent file may belong to a running save");
    assert!(foreign.exists(), "only the exact generated name is touched");
    assert_eq!(stdout(&env.ok(&["list"])), "A\nB\n");
}

#[test]
fn unset_and_import_clean_up_too() {
    let env = Env::init();
    env.set("A", "1");
    let dir = env.path().join(".cloak");
    let stale = dir.join(".vault.bin.tmp-0123456789ab");
    touch(&stale, Duration::from_secs(3600));
    env.ok(&["unset", "A"]);
    assert!(!stale.exists());

    touch(&stale, Duration::from_secs(3600));
    let file = env.path().join("x.env");
    fs::write(&file, "X=1\n").unwrap();
    let out = env
        .cmd(Some(PASS))
        .arg("import")
        .arg(&file)
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(!stale.exists());
}
