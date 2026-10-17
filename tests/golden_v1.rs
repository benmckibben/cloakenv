//! Golden fixtures: vaults written by the PUBLISHED cloakenv 0.1.0 and 0.2.0 binaries (format version 1).
//!
//! These files are never regenerated to make a test pass. If one of these tests fails, the current code can no
//! longer open a vault that a release wrote. See tests/fixtures/v1/README.md for how they were made.

mod common;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use cloakenv::crypto::{CryptoError, TAG_LEN};
use cloakenv::vault::{HEADER_LEN, MAGIC, Vault, VaultError};
use common::{stderr, stdout};

const PASS: &str = "golden-v1-fixture-passphrase";

const FIXTURES: [&str; 6] = [
    "empty",
    "one",
    "many",
    "max_entry",
    "from_0.1.0_one",
    "from_0.1.0_many",
];

fn dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/v1")
}

fn bytes_of(name: &str) -> Vec<u8> {
    std::fs::read(dir().join(format!("{name}.bin")))
        .unwrap_or_else(|e| panic!("fixture {name}: {e}"))
}

/// The contents each fixture was written with. The .env source is read with a plain split at the first '=',
/// not with the crate's own parser, so these tests do not depend on it.
fn expected(name: &str) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    match name {
        "empty" => {}
        "one" | "from_0.1.0_one" => {
            m.insert("GREETING".to_owned(), "hello".to_owned());
        }
        "many" | "from_0.1.0_many" => {
            let text = std::fs::read_to_string(dir().join("many.env")).unwrap();
            for line in text
                .lines()
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
            {
                let (k, v) = line.split_once('=').expect("KEY=value line");
                assert!(
                    m.insert(k.to_owned(), v.to_owned()).is_none(),
                    "duplicate {k} in many.env"
                );
            }
        }
        "max_entry" => {
            let mut v = "0123456789abcdef".repeat(8191);
            v.push_str("01234");
            m.insert("MAX_ENTRY".to_owned(), v);
        }
        other => panic!("unknown fixture {other}"),
    }
    m
}

fn contents(v: &Vault) -> BTreeMap<String, String> {
    v.iter()
        .map(|(k, val)| (k.to_owned(), val.to_owned()))
        .collect()
}

fn u32_at(b: &[u8], i: usize) -> u32 {
    u32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]])
}

#[test]
fn the_many_fixtures_really_hold_forty_one_entries() {
    // Guards the fixture sources themselves: a truncated many.env would make the other tests vacuous.
    assert_eq!(expected("many").len(), 41);
    assert_eq!(expected("many")["LONG_3000"].len(), 3000);
    assert_eq!(
        expected("max_entry")["MAX_ENTRY"].len() + "MAX_ENTRY=".len(),
        131_071
    );
}

#[test]
fn header_bytes_are_the_version_1_layout_and_the_size_is_the_unpadded_length() {
    for name in FIXTURES {
        let b = bytes_of(name);
        assert_eq!(&b[0..8], MAGIC, "{name}");
        assert_eq!(
            &b[8..12],
            &[1, 1, 1, 0],
            "{name}: version, KDF id, AEAD id, reserved"
        );
        assert_eq!(u32_at(&b, 12), 64 * 1024, "{name}: Argon2 memory (KiB)");
        assert_eq!(u32_at(&b, 16), 3, "{name}: Argon2 iterations");
        assert_eq!(u32_at(&b, 20), 1, "{name}: Argon2 lanes");
        // v1 has no padding: the file size is exactly header + payload + tag, which is the length leak v2 removes.
        let payload: usize = 4 + expected(name)
            .iter()
            .map(|(k, v)| 8 + k.len() + v.len())
            .sum::<usize>();
        assert_eq!(b.len(), HEADER_LEN + payload + TAG_LEN, "{name}: file size");
    }
}

#[test]
fn the_library_opens_every_fixture_with_exactly_its_contents() {
    for name in FIXTURES {
        let want = expected(name);
        let from_bytes =
            Vault::open(&bytes_of(name), PASS.as_bytes()).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(contents(&from_bytes), want, "{name} (open)");
        assert_eq!(from_bytes.len(), want.len(), "{name}");
        let from_path = Vault::load(&dir().join(format!("{name}.bin")), PASS.as_bytes()).unwrap();
        assert_eq!(contents(&from_path), want, "{name} (load)");
    }
}

#[test]
fn a_wrong_passphrase_is_refused_with_the_authentication_error() {
    for name in ["one", "from_0.1.0_one"] {
        for wrong in [
            "",
            "golden-v1-fixture-passphrasE",
            "golden-v1-fixture-passphrase ",
        ] {
            match Vault::open(&bytes_of(name), wrong.as_bytes()) {
                Err(VaultError::Crypto(CryptoError::Decrypt)) => {}
                other => panic!("{name} with {wrong:?}: {:?}", other.map(|_| "opened")),
            }
        }
    }
}

#[test]
fn damaged_files_are_refused() {
    let good = bytes_of("one");
    let open = |b: &[u8]| Vault::open(b, PASS.as_bytes()).map(|_| ());

    // Rejected before any key derivation.
    assert!(matches!(open(&good[..7]), Err(VaultError::BadMagic)));
    assert!(matches!(
        open(&good[..HEADER_LEN - 1]),
        Err(VaultError::Malformed)
    ));
    let mut b = good.clone();
    b[8] = 99;
    assert!(matches!(open(&b), Err(VaultError::UnsupportedVersion(99))));
    let mut b = good.clone();
    b[11] = 1;
    assert!(
        matches!(open(&b), Err(VaultError::Malformed)),
        "reserved byte"
    );

    // Rejected by the AEAD: every byte of the header is associated data, the rest is ciphertext and tag.
    let decrypt = |label: &str, b: &[u8]| match open(b) {
        Err(VaultError::Crypto(CryptoError::Decrypt)) => {}
        other => panic!("{label}: {other:?}"),
    };
    let mut b = good.clone();
    b[30] ^= 1;
    decrypt("flipped bit in the salt", &b);
    let mut b = good.clone();
    b[50] ^= 1;
    decrypt("flipped bit in the nonce", &b);
    let mut b = good.clone();
    *b.last_mut().unwrap() ^= 0x80;
    decrypt("flipped bit in the tag", &b);
    decrypt("one byte cut off", &good[..good.len() - 1]);
    let mut b = good.clone();
    b.push(0);
    decrypt("one byte appended", &b);
}

/// Copies a fixture into a fresh private directory, as the CLI expects a vault to be (mode 0600 on Unix).
fn private_copy(name: &str) -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("vault.bin");
    std::fs::copy(dir().join(format!("{name}.bin")), &path).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    (tmp, path)
}

fn cli(vault: &Path, pass: &str) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_cloakenv"));
    cmd.arg("--vault")
        .arg(vault)
        .env_remove("CLOAKENV_PASSPHRASE_FILE")
        .env_remove("CLOAKENV_VAULT")
        .env("CLOAKENV_PASSPHRASE", pass)
        .stdin(std::process::Stdio::null());
    cmd
}

#[test]
fn the_cli_lists_every_fixture_and_leaves_the_file_untouched() {
    for name in FIXTURES {
        let (_tmp, path) = private_copy(name);
        let before = std::fs::read(&path).unwrap();
        let out = cli(&path, PASS).arg("list").output().unwrap();
        assert!(out.status.success(), "{name}: {}", stderr(&out));
        let listed: Vec<String> = stdout(&out).lines().map(str::to_owned).collect();
        let want: Vec<String> = expected(name).into_keys().collect();
        assert_eq!(listed, want, "{name}");
        assert_eq!(
            std::fs::read(&path).unwrap(),
            before,
            "{name}: list must never rewrite a vault"
        );
    }
}

#[test]
fn the_cli_refuses_a_wrong_passphrase_and_spawns_nothing() {
    let (tmp, path) = private_copy("one");
    let marker = tmp.path().join("ran");
    let before = std::fs::read(&path).unwrap();
    let mut cmd = cli(&path, "not the passphrase");
    cmd.args(["run", "--"]);
    #[cfg(unix)]
    cmd.args(["sh", "-c"])
        .arg(format!("touch '{}'", marker.display()));
    #[cfg(not(unix))]
    cmd.args(["cmd", "/C", "exit", "0"]);
    let out = cmd.output().unwrap();
    assert!(!out.status.success());
    assert!(!marker.exists(), "the command must not start");
    assert_eq!(std::fs::read(&path).unwrap(), before);
}

#[cfg(unix)]
#[test]
fn run_injects_the_exact_values_from_every_fixture() {
    let probe = |name: &str, script: &str| -> String {
        let (_tmp, path) = private_copy(name);
        let before = std::fs::read(&path).unwrap();
        let out = cli(&path, PASS)
            .args(["run", "--", "sh", "-c", script])
            .output()
            .unwrap();
        assert!(out.status.success(), "{name}: {}", stderr(&out));
        assert_eq!(
            std::fs::read(&path).unwrap(),
            before,
            "{name}: run must never rewrite a vault"
        );
        stdout(&out)
    };
    for name in ["one", "from_0.1.0_one"] {
        assert_eq!(probe(name, "printf %s \"$GREETING\""), "hello", "{name}");
    }
    let want = expected("many");
    for name in ["many", "from_0.1.0_many"] {
        let got = probe(
            name,
            "printf '%s|%s|%s|%s|%s' \"$ALPHA\" \"$EQUALS_INSIDE\" \"$UNICODE_CJK\" \"$UNICODE_EMOJI\" \"$beta\"",
        );
        let exp = format!(
            "{}|{}|{}|{}|{}",
            want["ALPHA"],
            want["EQUALS_INSIDE"],
            want["UNICODE_CJK"],
            want["UNICODE_EMOJI"],
            want["beta"]
        );
        assert_eq!(got, exp, "{name}");
        assert_eq!(
            probe(name, "printf %s \"$LONG_3000\" | wc -c").trim(),
            "3000",
            "{name}"
        );
    }
    assert_eq!(
        probe("max_entry", "printf %s \"$MAX_ENTRY\" | wc -c").trim(),
        "131061"
    );
    assert_eq!(probe("empty", "printf ok"), "ok");
}
