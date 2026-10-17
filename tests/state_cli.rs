//! End-to-end tests for `cloakenv info` and `cloakenv accept-rollback` on format 2 files (and format 1 for the
//! downgrade case). The vaults are written with the library, since the CLI cannot create format 2 vaults yet; the
//! rollback state is seeded through the library too, and the commands under test are run as the real binary.

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use cloakenv::crypto::KdfParams;
use cloakenv::vault::Vault;
use cloakenv::vault::state::{self, Observed};
use cloakenv::vault::v2;
use common::{stderr, stdout};
use zeroize::Zeroizing;

const PASS: &str = "state cli test passphrase";
const V1_PASS: &str = "golden-v1-fixture-passphrase";
const ID: [u8; 16] = [0x5a; 16];

struct Env {
    _tmp: tempfile::TempDir,
    vault: PathBuf,
    state: PathBuf,
}

fn restrict(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    #[cfg(not(unix))]
    let _ = path;
}

impl Env {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        Env {
            vault: tmp.path().join("vault.bin"),
            state: tmp.path().join("state"),
            _tmp: tmp,
        }
    }

    /// Writes a format 2 vault at generation `generation` (a fresh salt and nonce each time, so two calls with the same
    /// generation are two different copies) and returns what the state check sees of it.
    fn write_v2(&self, generation: u64, entries: &[(&str, &str)]) -> Observed {
        let mut v = Vault::with_params(KdfParams::MIN).unwrap();
        for (k, val) in entries {
            v.set(k, Zeroizing::new((*val).to_owned())).unwrap();
        }
        let bytes = v2::seal(&v, &ID, generation, &[], PASS.as_bytes()).unwrap();
        fs::write(&self.vault, &bytes).unwrap();
        restrict(&self.vault);
        let o = v2::open(&bytes, PASS.as_bytes()).unwrap();
        Observed::V2 {
            id: o.vault_id,
            generation: o.generation,
            tag: o.tag,
        }
    }

    /// Puts the format 1 golden fixture (a vault written by the published 0.2.0) at the vault path.
    fn write_v1(&self) {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/v1/one.bin");
        fs::copy(fixture, &self.vault).unwrap();
        restrict(&self.vault);
    }

    fn seed(&self, obs: &Observed) {
        state::check(&self.state, &self.vault, obs).unwrap();
    }

    fn state_bytes(&self) -> Vec<u8> {
        fs::read(state::state_file(&self.state)).unwrap()
    }

    fn cmd(&self, pass: &str) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_cloakenv"));
        c.arg("--vault")
            .arg(&self.vault)
            .env_remove("CLOAKENV_PASSPHRASE_FILE")
            .env_remove("CLOAKENV_VAULT")
            .env("CLOAKENV_PASSPHRASE", pass)
            .env("CLOAKENV_STATE_DIR", &self.state)
            .stdin(Stdio::null());
        c
    }

    fn run(&self, pass: &str, args: &[&str]) -> Output {
        self.cmd(pass).args(args).output().unwrap()
    }
}

/// The value printed for `label` by `info`.
fn field(out: &str, label: &str) -> String {
    out.lines()
        .find_map(|l| {
            l.strip_prefix(&format!("{label}:"))
                .map(|r| r.trim().to_owned())
        })
        .unwrap_or_else(|| panic!("no {label:?} line in:\n{out}"))
}

#[test]
fn info_describes_a_format_2_vault_without_naming_anything_or_writing_state() {
    let e = Env::new();
    e.write_v2(
        7,
        &[
            ("API_KEY", "super-secret-value"),
            ("DB_URL", "postgres://u:hunter2@h/db"),
        ],
    );
    let before = fs::read(&e.vault).unwrap();
    let out = e.run(PASS, &["info"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let s = stdout(&out);
    assert_eq!(field(&s, "format"), "2");
    assert_eq!(field(&s, "size"), "4208 bytes");
    assert_eq!(field(&s, "entries"), "2");
    assert_eq!(field(&s, "generation"), "7");
    assert_eq!(field(&s, "vault id"), "5a".repeat(16));
    assert_eq!(field(&s, "extensions"), "0");
    assert!(field(&s, "padding").contains("4096"), "{s}");
    assert!(field(&s, "key derivation").contains("Argon2id"), "{s}");
    assert!(
        field(&s, "rollback").starts_with("not seen on this machine"),
        "{s}"
    );
    for secret in ["super-secret-value", "hunter2", "API_KEY", "DB_URL"] {
        assert!(
            !s.contains(secret) && !stderr(&out).contains(secret),
            "info leaked {secret}"
        );
    }
    assert!(
        !e.state.exists(),
        "info must not create the state directory"
    );
    assert_eq!(
        fs::read(&e.vault).unwrap(),
        before,
        "info must not touch the vault"
    );
}

#[test]
fn info_says_what_it_can_and_cannot_know_about_a_format_1_vault() {
    let e = Env::new();
    e.write_v1();
    let out = e.run(V1_PASS, &["info"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let s = stdout(&out);
    assert_eq!(field(&s, "format"), "1");
    assert_eq!(field(&s, "entries"), "1");
    assert!(
        !s.contains("generation:") && !s.contains("vault id:"),
        "format 1 has neither:\n{s}"
    );
    assert!(field(&s, "rollback").starts_with("not protected"), "{s}");
}

#[test]
fn info_with_the_wrong_passphrase_fails_and_prints_nothing_about_the_vault() {
    let e = Env::new();
    e.write_v2(3, &[("K", "v")]);
    let out = e.run("not the passphrase", &["info"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stdout(&out).is_empty(), "{}", stdout(&out));
    assert!(!stderr(&out).is_empty());
    let mut notes = fs::read(&e.vault).unwrap();
    notes[0] ^= 1;
    fs::write(&e.vault, notes).unwrap();
    assert_eq!(
        e.run(PASS, &["info"]).status.code(),
        Some(1),
        "a file that is not a vault"
    );
}

#[test]
fn a_rolled_back_vault_is_reported_and_accepting_it_needs_confirmation() {
    let e = Env::new();
    let newest = e.write_v2(5, &[("K", "v5")]);
    e.seed(&newest);
    e.write_v2(2, &[("K", "v2")]);
    let seeded = e.state_bytes();

    let s = stdout(&e.run(PASS, &["info"]));
    let line = field(&s, "rollback");
    assert!(
        line.starts_with("REFUSED")
            && line.contains("generation 5")
            && line.contains("accept-rollback"),
        "{line}"
    );
    assert_eq!(e.state_bytes(), seeded, "info does not change the state");

    // no terminal and no --yes: nothing happens
    let out = e.run(PASS, &["accept-rollback"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("--yes"), "{}", stderr(&out));
    assert_eq!(e.state_bytes(), seeded);

    let out = e.run(PASS, &["accept-rollback", "--yes"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stderr(&out).contains("accepted"), "{}", stderr(&out));
    assert_ne!(e.state_bytes(), seeded);
    assert_eq!(
        field(&stdout(&e.run(PASS, &["info"])), "rollback"),
        "ok: the version this machine saw last"
    );

    // the next real save is accepted without any ceremony
    let next = e.write_v2(3, &[("K", "v3")]);
    assert!(matches!(
        state::check(&e.state, &e.vault, &next).unwrap().verdict,
        state::Verdict::Advanced { from: 2 }
    ));
}

#[test]
fn a_forked_vault_is_reported_and_can_be_accepted() {
    let e = Env::new();
    let a = e.write_v2(3, &[("K", "from machine A")]);
    e.seed(&a);
    e.write_v2(3, &[("K", "from machine B")]);
    let line = field(&stdout(&e.run(PASS, &["info"])), "rollback");
    assert!(
        line.starts_with("REFUSED") && line.contains("differs"),
        "{line}"
    );
    assert!(e.run(PASS, &["accept-rollback", "--yes"]).status.success());
    assert_eq!(
        field(&stdout(&e.run(PASS, &["info"])), "rollback"),
        "ok: the version this machine saw last"
    );
}

#[test]
fn a_format_1_file_where_a_format_2_vault_was_is_a_downgrade_that_can_be_accepted() {
    let e = Env::new();
    let v2obs = e.write_v2(3, &[("K", "v")]);
    e.seed(&v2obs);
    e.write_v1();
    let line = field(&stdout(&e.run(V1_PASS, &["info"])), "rollback");
    assert!(
        line.starts_with("REFUSED") && line.contains("version 1"),
        "{line}"
    );
    let out = e.run(V1_PASS, &["accept-rollback", "--yes"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(field(&stdout(&e.run(V1_PASS, &["info"])), "rollback").starts_with("not protected"));
}

#[test]
fn accepting_when_nothing_is_refused_does_nothing() {
    let e = Env::new();
    let obs = e.write_v2(5, &[("K", "v")]);
    // never seen
    let out = e.run(PASS, &["accept-rollback", "--yes"]);
    assert!(
        out.status.success() && stderr(&out).contains("nothing to accept"),
        "{}",
        stderr(&out)
    );
    assert!(
        !e.state.exists(),
        "nothing to accept must not create the state either"
    );
    // seen and current
    e.seed(&obs);
    let seeded = e.state_bytes();
    let out = e.run(PASS, &["accept-rollback", "--yes"]);
    assert!(
        out.status.success() && stderr(&out).contains("nothing to accept"),
        "{}",
        stderr(&out)
    );
    assert_eq!(e.state_bytes(), seeded);
}

#[test]
fn without_a_place_for_the_state_info_says_unknown_and_accept_fails_clearly() {
    let e = Env::new();
    let newest = e.write_v2(5, &[("K", "v5")]);
    e.seed(&newest);
    e.write_v2(2, &[("K", "v2")]);
    let bare = |args: &[&str]| {
        let mut c = e.cmd(PASS);
        for var in [
            "CLOAKENV_STATE_DIR",
            "HOME",
            "XDG_STATE_HOME",
            "LOCALAPPDATA",
        ] {
            c.env_remove(var);
        }
        c.args(args).output().unwrap()
    };
    let out = bare(&["info"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        field(&stdout(&out), "rollback").starts_with("unknown"),
        "{}",
        stdout(&out)
    );
    let out = bare(&["accept-rollback", "--yes"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("CLOAKENV_STATE_DIR"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn a_damaged_state_file_is_reported_by_info_and_blocks_accept_without_being_overwritten() {
    let e = Env::new();
    e.write_v2(2, &[("K", "v")]);
    fs::create_dir_all(&e.state).unwrap();
    let file = state::state_file(&e.state);
    fs::write(&file, "this is not a state file\n").unwrap();
    let out = e.run(PASS, &["info"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let line = field(&stdout(&out), "rollback");
    assert!(
        line.starts_with("unknown") && line.contains("damaged"),
        "{line}"
    );
    let out = e.run(PASS, &["accept-rollback", "--yes"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("damaged"), "{}", stderr(&out));
    assert_eq!(
        fs::read_to_string(&file).unwrap(),
        "this is not a state file\n"
    );
}

#[test]
fn the_new_subcommands_are_in_the_help() {
    let out = Command::new(env!("CARGO_BIN_EXE_cloakenv"))
        .arg("--help")
        .output()
        .unwrap();
    let h = stdout(&out);
    assert!(h.contains("accept-rollback") && h.contains("info"), "{h}");
}
