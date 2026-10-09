//! `cloakenv import` and the `.env` files people really have: a byte order
//! mark, Windows line endings, multi-line PEM keys, duplicated names, and
//! values written for tools that expand `$VARIABLES`.
#![cfg(unix)]

mod common;

use std::fs;

use common::*;

fn import_bytes(env: &Env, name: &str, bytes: &[u8]) -> std::process::Output {
    let path = env.path().join(name);
    fs::write(&path, bytes).unwrap();
    env.cmd(Some(PASS))
        .arg("import")
        .arg(&path)
        .output()
        .unwrap()
}

fn value_of(env: &Env, key: &str) -> String {
    let script = format!("printf '%s' \"${key}\"");
    stdout(&env.ok(&["run", "--", "sh", "-c", &script]))
}

#[test]
fn a_utf8_byte_order_mark_on_the_first_line_is_ignored() {
    let env = Env::init();
    let out = import_bytes(&env, "bom.env", b"\xef\xbb\xbfFIRST=1\nSECOND=2\n");
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&env.ok(&["list"])), "FIRST\nSECOND\n");
    assert_eq!(value_of(&env, "FIRST"), "1");
}

#[test]
fn windows_and_old_mac_line_endings_import_cleanly() {
    let env = Env::init();
    let out = import_bytes(
        &env,
        "crlf.env",
        b"A=plain\r\nB=\"quoted\"\r\nC='single'\r\n# comment\r\nD=trailing # note\r\n",
    );
    assert!(out.status.success(), "{}", stderr(&out));
    for (k, v) in [
        ("A", "plain"),
        ("B", "quoted"),
        ("C", "single"),
        ("D", "trailing"),
    ] {
        assert_eq!(value_of(&env, k), v, "{k}");
    }
    // A lone CR is a line break too (as in python-dotenv and the Node dotenv):
    // it must not end up inside a value.
    let out = import_bytes(&env, "cr.env", b"E=one\rF=two\rG=three");
    assert!(out.status.success(), "{}", stderr(&out));
    for (k, v) in [("E", "one"), ("F", "two"), ("G", "three")] {
        assert_eq!(value_of(&env, k), v, "{k}");
    }
}

#[test]
fn a_multi_line_pem_key_in_double_quotes_is_imported_whole() {
    let env = Env::init();
    let pem = "-----BEGIN CERTIFICATE-----\nMIIEvQIBADANBgkq\nhkiG9w0BAQEFAASC\n-----END CERTIFICATE-----";
    let file = format!("PRIVATE_KEY=\"{pem}\"\nAFTER=ok\n");
    let out = import_bytes(&env, "pem.env", file.as_bytes());
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(value_of(&env, "PRIVATE_KEY"), pem);
    assert_eq!(value_of(&env, "AFTER"), "ok");
    // CRLF files give the same key with plain newlines.
    let crlf = file.replace('\n', "\r\n");
    let env2 = Env::init();
    let out = import_bytes(&env2, "pem.env", crlf.as_bytes());
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(value_of(&env2, "PRIVATE_KEY"), pem);
}

#[test]
fn a_duplicate_name_stops_the_import_and_nothing_is_imported() {
    let env = Env::init();
    env.set("KEEP", "kept");
    let before = fs::read(env.vault()).unwrap();
    let out = import_bytes(&env, "dup.env", b"A=first-secret\nB=2\nA=second-secret\n");
    assert_eq!(out.status.code(), Some(1));
    let err = stderr(&out);
    assert!(
        err.contains(".env parse error on line 3") && err.contains("already set on line 1"),
        "{err}"
    );
    assert!(!err.contains("secret"), "{err}");
    assert_eq!(fs::read(env.vault()).unwrap(), before);
}

#[test]
fn dollar_references_are_stored_as_written_and_flagged_by_line() {
    let env = Env::init();
    let out = import_bytes(
        &env,
        "interp.env",
        "HOST=db\nURL=postgres://$HOST/x\nTWO=\"${HOST}:5432\"\nLIT='$HOST'\n".as_bytes(),
    );
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(value_of(&env, "URL"), "postgres://$HOST/x");
    assert_eq!(value_of(&env, "TWO"), "${HOST}:5432");
    assert_eq!(value_of(&env, "LIT"), "$HOST");
    let err = stderr(&out);
    assert!(
        err.contains("warning: the value on line 2, 3 contains") && err.contains("does not expand"),
        "{err}"
    );
    assert!(!err.contains("postgres://"), "{err}");
    // No warning when nothing looks like a reference.
    let out = import_bytes(&env, "plain.env", b"X=1\nY='$LITERAL'\n");
    assert!(!stderr(&out).contains("warning"), "{}", stderr(&out));
}

#[test]
fn empty_values_are_imported_and_named_in_a_warning() {
    let env = Env::init();
    let out = import_bytes(&env, "empty.env", b"A=\nB=1\nC=''\nD=\"\"\n");
    assert!(out.status.success(), "{}", stderr(&out));
    let err = stderr(&out);
    assert!(
        err.contains("warning: A, C, D imported with an empty value"),
        "{err}"
    );
    let out = env.ok(&[
        "run",
        "--",
        "sh",
        "-c",
        "printf %s \"${A+set}${C+set}${D+set}\"",
    ]);
    assert_eq!(stdout(&out), "setsetset");
}

#[test]
fn parse_errors_name_a_line_and_never_any_content() {
    let env = Env::init();
    let before = fs::read(env.vault()).unwrap();
    for (name, body, line) in [
        ("a.env", "OK=1\nsk-live-abc123=oops\n", 2),
        ("b.env", "OK=1\nKEY=\"sk-live-abc123\n", 2),
        ("c.env", "KEY='sk-live-abc123' tail-sk-live\n", 1),
        ("d.env", "OK=\"multi\nline\" sk-live-abc123\n", 1),
    ] {
        let out = import_bytes(&env, name, body.as_bytes());
        assert_eq!(out.status.code(), Some(1), "{name}");
        let err = stderr(&out);
        assert!(
            err.contains(&format!(".env parse error on line {line}")),
            "{name}: {err}"
        );
        assert!(
            !err.contains("sk-live") && !err.contains("abc123"),
            "{name}: {err}"
        );
    }
    assert_eq!(fs::read(env.vault()).unwrap(), before);
}
