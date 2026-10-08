//! `cloakenv import` reads its `.env` file like the vault is read: regular
//! files only, size capped (16 MiB), contents wiped after use.
#![cfg(unix)]

mod common;

use std::fs;
use std::process::Stdio;
use std::time::{Duration, Instant};

use common::*;

const SECRET: &str = "sk-imp…0777";
const MIB16: u64 = 16 * 1024 * 1024;

// ----------------------------------------------------------------- import

fn imported_env() -> (Env, std::path::PathBuf) {
    let env = Env::init();
    env.set("KEEP", "kept");
    let before = env.path().join("before.bin");
    fs::copy(env.vault(), &before).unwrap();
    (env, before)
}

fn run_import(env: &Env, file: &std::path::Path) -> std::process::Output {
    let started = Instant::now();
    let child = env
        .cmd(Some(PASS))
        .arg("import")
        .arg(file)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(
        started.elapsed() < Duration::from_secs(20),
        "import hung or crawled"
    );
    out
}

#[test]
fn import_reads_ordinary_and_symlinked_files() {
    let env = Env::init();
    let real = env.path().join("real.env");
    fs::write(&real, format!("IMPORTED={SECRET}\n")).unwrap();
    let link = env.path().join("link.env");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let out = run_import(&env, &link);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(!contains(&out.stderr, SECRET) && !contains(&out.stdout, SECRET));
    let out = env.ok(&["run", "--", "sh", "-c", r#"printf %s "$IMPORTED""#]);
    assert_eq!(stdout(&out), SECRET);
}

#[test]
fn import_refuses_non_regular_files_without_reading_them() {
    let (env, before) = imported_env();
    // A directory, an endless device and a FIFO nobody writes to: the last
    // two would exhaust memory or block forever if they were read.
    let fifo = env.path().join("pipe.env");
    assert!(
        std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success(),
        "mkfifo"
    );
    for target in [env.path().to_path_buf(), "/dev/zero".into(), fifo] {
        let out = run_import(&env, &target);
        assert_eq!(out.status.code(), Some(1), "{target:?}");
        let err = stderr(&out);
        assert!(err.contains("is not a regular file"), "{target:?}: {err}");
        assert!(err.contains("refusing to import it"), "{target:?}: {err}");
        assert_eq!(fs::read(env.vault()).unwrap(), fs::read(&before).unwrap());
    }
}

#[test]
fn import_refuses_files_over_16_mib() {
    let (env, before) = imported_env();
    let big = env.path().join("big.env");
    // Sparse: costs no disk or memory, but fstat reports the full size.
    fs::File::create(&big).unwrap().set_len(MIB16 + 1).unwrap();
    let out = run_import(&env, &big);
    assert_eq!(out.status.code(), Some(1));
    let err = stderr(&out);
    assert!(err.contains("is too large (the limit is 16 MiB)"), "{err}");
    assert_eq!(fs::read(env.vault()).unwrap(), fs::read(&before).unwrap());
}

#[test]
fn import_accepts_a_file_of_exactly_16_mib() {
    // The size gate lets it through; the content (all NULs) is then rejected
    // by the parser, by line number only.
    let (env, _) = imported_env();
    let edge = env.path().join("edge.env");
    fs::File::create(&edge).unwrap().set_len(MIB16).unwrap();
    let out = run_import(&env, &edge);
    assert_eq!(out.status.code(), Some(1));
    let err = stderr(&out);
    assert!(err.contains(".env parse error on line 1"), "{err}");
    assert!(!err.contains("too large"), "{err}");
}

#[test]
fn import_rejects_invalid_utf8_without_echoing_it() {
    let (env, before) = imported_env();
    let bad = env.path().join("bad.env");
    let mut bytes = format!("TOKEN={SECRET}").into_bytes();
    bytes.extend_from_slice(&[0xff, 0xfe, b'\n']);
    fs::write(&bad, bytes).unwrap();
    let out = run_import(&env, &bad);
    assert_eq!(out.status.code(), Some(1));
    let err = stderr(&out);
    assert!(err.contains("is not valid UTF-8"), "{err}");
    assert!(!err.contains(SECRET) && !err.contains("TOKEN"), "{err}");
    assert_eq!(fs::read(env.vault()).unwrap(), fs::read(&before).unwrap());
}
