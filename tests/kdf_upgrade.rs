//! KDF settings: weak legacy vaults still open (with a warning), and every
//! `set` / `unset` / `import` re-save raises the settings to at least the
//! defaults, never lowering any.
#![cfg(unix)]

mod common;

use cloakenv::crypto::{self, KdfParams, NONCE_LEN, SALT_LEN};
use cloakenv::vault::{HEADER_LEN, MAGIC, Vault};
use common::*;
use zeroize::Zeroizing;

fn u32_at(b: &[u8], i: usize) -> u32 {
    u32::from_le_bytes(b[i..i + 4].try_into().unwrap())
}

/// KDF parameters recorded in the vault file's header.
fn header_params(env: &Env) -> KdfParams {
    let b = std::fs::read(env.vault()).unwrap();
    KdfParams {
        m_cost_kib: u32_at(&b, 12),
        t_cost: u32_at(&b, 16),
        p_cost: u32_at(&b, 20),
    }
}

/// Writes a vault the way an older version could have: the key-derivation
/// settings are whatever the caller asks for (even below today's minimum).
fn write_vault_with(env: &Env, params: KdfParams, entries: &[(&str, &str)]) {
    let mut payload = (entries.len() as u32).to_le_bytes().to_vec();
    for (k, v) in entries {
        payload.extend_from_slice(&(k.len() as u32).to_le_bytes());
        payload.extend_from_slice(k.as_bytes());
        payload.extend_from_slice(&(v.len() as u32).to_le_bytes());
        payload.extend_from_slice(v.as_bytes());
    }
    let (salt, nonce) = ([5u8; SALT_LEN], [6u8; NONCE_LEN]);
    let mut header = [0u8; HEADER_LEN];
    header[0..8].copy_from_slice(MAGIC);
    header[8..12].copy_from_slice(&[1, 1, 1, 0]);
    header[12..16].copy_from_slice(&params.m_cost_kib.to_le_bytes());
    header[16..20].copy_from_slice(&params.t_cost.to_le_bytes());
    header[20..24].copy_from_slice(&params.p_cost.to_le_bytes());
    header[24..40].copy_from_slice(&salt);
    header[40..64].copy_from_slice(&nonce);
    let key = crypto::derive_key(PASS.as_bytes(), &salt, params).unwrap();
    let ct = crypto::seal(&key, &nonce, &header, &payload).unwrap();
    std::fs::create_dir_all(env.vault().parent().unwrap()).unwrap();
    std::fs::write(env.vault(), [header.as_slice(), &ct].concat()).unwrap();
}

const WEAK: KdfParams = KdfParams::FLOOR; // 8 MiB, t=1: valid before the minimum was raised
const MID: KdfParams = KdfParams {
    m_cost_kib: 32 * 1024,
    t_cost: 2,
    p_cost: 1,
};

#[test]
fn new_vaults_use_the_default_and_do_not_warn() {
    let env = Env::init();
    assert_eq!(header_params(&env), KdfParams::DEFAULT);
    let out = env.ok(&["list"]);
    assert!(!stderr(&out).contains("weaker"), "{}", stderr(&out));
}

#[test]
fn the_default_meets_the_minimum_and_the_minimum_is_owasp() {
    let (min, default) = (KdfParams::MIN, KdfParams::DEFAULT);
    assert!(min.m_cost_kib >= 19 * 1024 && min.t_cost >= 2);
    assert!(default.meets_min());
}

#[test]
fn library_refuses_to_create_a_vault_below_the_minimum() {
    assert!(Vault::with_params(WEAK).is_err());
    assert!(Vault::with_params(KdfParams::MIN).is_ok());
    let mut v = Vault::with_params(KdfParams::MIN).unwrap();
    v.set("A", Zeroizing::new("x".into())).unwrap();
}

#[test]
fn weak_legacy_vault_still_loads_and_warns_on_read() {
    let env = Env::new();
    write_vault_with(&env, WEAK, &[("TOKEN", "dummy-legacy-value")]);

    let out = env.ok(&["list"]);
    assert_eq!(stdout(&out), "TOKEN\n");
    let err = stderr(&out);
    assert!(err.contains("weaker than the recommended minimum"), "{err}");
    assert!(
        err.contains("memory 8192 KiB, iterations 1, lanes 1"),
        "{err}"
    );
    assert!(!contains(&out.stderr, "dummy-legacy-value"));
    // Reading never rewrites the file.
    assert_eq!(header_params(&env), WEAK);

    let out = env.ok(&["run", "--", "sh", "-c", "printf %s \"$TOKEN\""]);
    assert_eq!(stdout(&out), "dummy-legacy-value");
    assert_eq!(header_params(&env), WEAK);
}

#[test]
fn set_upgrades_a_weak_vault_and_keeps_its_contents() {
    let env = Env::new();
    write_vault_with(&env, WEAK, &[("OLD", "dummy-old-value")]);
    let out = env.run_stdin(&["set", "NEW"], "dummy-new-value");
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stderr(&out).contains("upgraded the vault's key-derivation settings"));
    assert!(!contains(&out.stderr, "dummy-"));
    assert_eq!(header_params(&env), KdfParams::DEFAULT);
    assert_eq!(stdout(&env.ok(&["list"])), "NEW\nOLD\n");
    let out = env.ok(&["run", "--", "sh", "-c", "printf %s \"$OLD $NEW\""]);
    assert_eq!(stdout(&out), "dummy-old-value dummy-new-value");
    // Nothing left to warn about once upgraded.
    assert!(!stderr(&env.ok(&["list"])).contains("weaker"));
}

#[test]
fn unset_and_import_upgrade_too() {
    let env = Env::new();
    write_vault_with(&env, WEAK, &[("A", "1"), ("B", "2")]);
    env.ok(&["unset", "A"]);
    assert_eq!(header_params(&env), KdfParams::DEFAULT);
    assert_eq!(stdout(&env.ok(&["list"])), "B\n");

    write_vault_with(&env, WEAK, &[("A", "1")]);
    let dotenv = env.path().join("in.env");
    std::fs::write(&dotenv, "C=3\n").unwrap();
    env.ok(&["import", dotenv.to_str().unwrap()]);
    assert_eq!(header_params(&env), KdfParams::DEFAULT);
    assert_eq!(stdout(&env.ok(&["list"])), "A\nC\n");
}

#[test]
fn a_vault_between_min_and_default_is_upgraded_without_a_warning() {
    let env = Env::new();
    write_vault_with(&env, MID, &[("A", "1")]);
    assert!(!stderr(&env.ok(&["list"])).contains("weaker"));
    assert_eq!(header_params(&env), MID);
    env.run_stdin(&["set", "B"], "2");
    assert_eq!(header_params(&env), KdfParams::DEFAULT);
}

#[test]
fn upgrade_never_lowers_any_parameter() {
    let env = Env::new();
    let strong = KdfParams {
        m_cost_kib: 128 * 1024,
        t_cost: 2,
        p_cost: 2,
    };
    write_vault_with(&env, strong, &[("A", "1")]);
    env.ok(&["unset", "A"]);
    assert_eq!(
        header_params(&env),
        KdfParams {
            m_cost_kib: 128 * 1024,
            t_cost: KdfParams::DEFAULT.t_cost,
            p_cost: 2,
        }
    );
    // A vault already at or above the default in every parameter is untouched
    // by the upgrade (no message).
    write_vault_with(&env, KdfParams::DEFAULT, &[("A", "1")]);
    let out = env.run_stdin(&["set", "B"], "2");
    assert!(!stderr(&out).contains("upgraded"), "{}", stderr(&out));
    assert_eq!(header_params(&env), KdfParams::DEFAULT);
}

#[test]
fn a_vault_below_the_hard_floor_is_rejected() {
    let env = Env::new();
    let below = KdfParams {
        m_cost_kib: 4 * 1024,
        t_cost: 1,
        p_cost: 1,
    };
    // Build a plausible file by patching the header of a real vault.
    env.ok(&["init"]);
    let mut b = std::fs::read(env.vault()).unwrap();
    b[12..16].copy_from_slice(&below.m_cost_kib.to_le_bytes());
    b[16..20].copy_from_slice(&below.t_cost.to_le_bytes());
    std::fs::write(env.vault(), b).unwrap();
    let out = env
        .cmd(Some(PASS))
        .args(["run", "--", "sh", "-c", "touch child-ran"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(125));
    assert!(!env.path().join("child-ran").exists());
    assert!(
        stderr(&out).contains("unsupported key-derivation parameters"),
        "{}",
        stderr(&out)
    );
}

/// The upgrade notice is only true once the new settings are on disk.
#[test]
fn a_failed_unset_does_not_claim_an_upgrade() {
    let env = Env::new();
    write_vault_with(&env, WEAK, &[("A", "1")]);
    let before = std::fs::read(env.vault()).unwrap();
    let out = env.run(&["unset", "NO_SUCH_KEY"]);
    assert_eq!(out.status.code(), Some(1));
    let err = stderr(&out);
    assert!(err.contains("no such key in vault"), "{err}");
    assert!(
        !err.contains("upgraded"),
        "claimed an upgrade it never saved: {err}"
    );
    assert_eq!(
        std::fs::read(env.vault()).unwrap(),
        before,
        "nothing was saved"
    );
    assert_eq!(header_params(&env), WEAK);
}

#[test]
fn a_failed_set_does_not_claim_an_upgrade() {
    let env = Env::new();
    write_vault_with(&env, WEAK, &[("A", "1")]);
    let before = std::fs::read(env.vault()).unwrap();
    // A NUL byte cannot live in an environment: refused after the vault was
    // loaded, before anything is saved.
    let out = env.run_stdin(&["set", "B"], "a\0b");
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(stderr(&out).contains("NUL"), "{}", stderr(&out));
    assert!(!stderr(&out).contains("upgraded"), "{}", stderr(&out));
    assert_eq!(std::fs::read(env.vault()).unwrap(), before);
}

#[test]
fn the_upgrade_notice_follows_the_save_it_describes() {
    let env = Env::new();
    write_vault_with(&env, WEAK, &[("A", "1"), ("B", "2")]);
    let out = env.run(&["unset", "A"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let err = stderr(&out);
    let upgraded = err
        .find("upgraded the vault's key-derivation settings")
        .unwrap();
    let removed = err.find("removed A").unwrap();
    assert!(upgraded < removed, "{err}");
    assert_eq!(header_params(&env), KdfParams::DEFAULT);
}

/// Writers queued on the lock while the first one upgrades a weak
/// vault all see a consistent vault: no update is lost, the file ends up with
/// the upgraded settings, and only the writer that actually upgraded says so.
#[test]
fn queued_writers_and_a_kdf_upgrade_do_not_lose_updates() {
    let env = Env::new();
    write_vault_with(&env, WEAK, &[("OLD", "dummy-old")]);
    let children: Vec<_> = (0..6)
        .map(|i| env.spawn_set(&format!("KEY_{i}"), &format!("dummy-{i}")))
        .collect();
    let mut notices = 0;
    for child in children {
        let out = child.wait_with_output().unwrap();
        assert!(out.status.success(), "{}", stderr(&out));
        notices += stderr(&out)
            .matches("upgraded the vault's key-derivation")
            .count();
    }
    assert_eq!(notices, 1, "exactly one writer performs the upgrade");
    assert_eq!(header_params(&env), KdfParams::DEFAULT);
    let want: Vec<String> = std::iter::once("OLD".to_owned())
        .chain((0..6).map(|i| format!("KEY_{i}")))
        .collect();
    let mut got: Vec<String> = stdout(&env.ok(&["list"]))
        .lines()
        .map(str::to_owned)
        .collect();
    got.sort();
    let mut want = want;
    want.sort();
    assert_eq!(got, want);
}
