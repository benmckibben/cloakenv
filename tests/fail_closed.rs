//! Fail-closed behaviour: bad passphrases, tampering and corruption must
//! abort with a non-zero exit code *before* the child command is spawned.
#![cfg(unix)]

mod common;

use std::path::Path;

use common::*;

const SECRET: &str = "ghp_tamperproofSecretValue42";

/// Runs a child that would create a marker file if it were ever spawned.
fn run_with_marker(env: &Env, pass: &str) -> (std::process::Output, bool) {
    let marker = env.path().join("child-ran");
    let out = env
        .cmd(Some(pass))
        .args(["run", "--", "sh", "-c", "touch child-ran"])
        .output()
        .unwrap();
    (out, marker.exists())
}

fn assert_refused(env: &Env, pass: &str) -> String {
    let (out, spawned) = run_with_marker(env, pass);
    assert!(!spawned, "child must not be spawned");
    assert_eq!(out.status.code(), Some(125), "stderr: {}", stderr(&out));
    assert!(out.stdout.is_empty());
    assert!(
        !contains(&out.stderr, SECRET),
        "secret leaked in error output"
    );
    assert!(
        !contains(&out.stderr, PASS),
        "passphrase leaked in error output"
    );
    stderr(&out)
}

fn seeded() -> Env {
    let env = Env::init();
    env.set("TOKEN", SECRET);
    // Sanity: the happy path does spawn.
    let (out, spawned) = run_with_marker(&env, PASS);
    assert!(out.status.success() && spawned);
    std::fs::remove_file(env.path().join("child-ran")).unwrap();
    env
}

fn mutate(path: &Path, f: impl FnOnce(&mut Vec<u8>)) {
    let mut bytes = std::fs::read(path).unwrap();
    f(&mut bytes);
    std::fs::write(path, bytes).unwrap();
}

#[test]
fn wrong_passphrase_is_rejected() {
    let env = seeded();
    let err = assert_refused(&env, "not the passphrase");
    assert!(err.contains("wrong passphrase"), "{err}");
}

#[test]
fn wrong_passphrase_does_not_modify_vault_on_set() {
    let env = seeded();
    let before = std::fs::read(env.vault()).unwrap();
    let mut cmd = env.cmd(Some("nope"));
    cmd.args(["set", "OTHER"]);
    let out = Env::output_with_stdin(cmd, "x");
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(std::fs::read(env.vault()).unwrap(), before);
}

#[test]
fn flipped_ciphertext_bit_is_rejected() {
    let env = seeded();
    mutate(&env.vault(), |b| b[70] ^= 0x01);
    assert!(assert_refused(&env, PASS).contains("tampered"));
}

#[test]
fn flipped_tag_bit_is_rejected() {
    let env = seeded();
    mutate(&env.vault(), |b| {
        let last = b.len() - 1;
        b[last] ^= 0x80;
    });
    assert!(assert_refused(&env, PASS).contains("tampered"));
}

#[test]
fn every_header_byte_is_authenticated() {
    let env = seeded();
    let original = std::fs::read(env.vault()).unwrap();
    // Magic, version, ids, reserved, KDF params, salt and nonce.
    for idx in 0..64 {
        let mut bytes = original.clone();
        bytes[idx] ^= 0x01;
        std::fs::write(env.vault(), &bytes).unwrap();
        assert_refused(&env, PASS);
    }
}

#[test]
fn truncated_vault_is_rejected() {
    let env = seeded();
    let original = std::fs::read(env.vault()).unwrap();
    for len in [0, 7, 8, 63, 64, 79, original.len() - 1] {
        std::fs::write(env.vault(), &original[..len]).unwrap();
        assert_refused(&env, PASS);
    }
}

#[test]
fn appended_garbage_is_rejected() {
    let env = seeded();
    mutate(&env.vault(), |b| b.extend_from_slice(b"junk"));
    assert_refused(&env, PASS);
}

#[test]
fn foreign_file_is_rejected() {
    let env = seeded();
    std::fs::write(env.vault(), format!("TOKEN={SECRET}\n")).unwrap();
    let err = assert_refused(&env, PASS);
    assert!(err.contains("not a cloakenv vault"), "{err}");
}

#[test]
fn missing_vault_is_rejected() {
    let env = Env::new();
    let (out, spawned) = run_with_marker(&env, PASS);
    assert!(!spawned);
    assert_eq!(out.status.code(), Some(125));
    assert!(stderr(&out).contains("cloakenv init"));
}

#[test]
fn swapped_vaults_with_different_passphrase_fail() {
    let a = seeded();
    let b = Env::new();
    b.cmd(Some("other pass")).args(["init"]).output().unwrap();
    std::fs::copy(b.vault(), a.vault()).unwrap();
    assert_refused(&a, PASS);
}
