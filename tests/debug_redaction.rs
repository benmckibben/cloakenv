//! `Debug` output must never contain a secret (invariant 5: no secret bleed in
//! errors, logs, backtraces or debug traces).
//!
//! `Zeroizing<String>`, `String` and `OsString` all print their contents, so
//! every type that can hold a secret has a hand-written, redacting `Debug`.
//! This test checks those, and pins the list of types that *derive* `Debug`:
//! adding a derive to a type means deciding here that it can never carry one.

use cloakenv::crypto::{self, KdfParams};
use cloakenv::runner::Redactor;
use cloakenv::vault::Vault;
use zeroize::Zeroizing;

const SECRET: &str = "sk-live-DEBUG-REDACTION-0123456789";

#[test]
fn vault_debug_shows_names_but_never_values() {
    let mut vault = Vault::new();
    vault
        .set("API_KEY", Zeroizing::new(SECRET.to_owned()))
        .unwrap();
    for shown in [format!("{vault:?}"), format!("{vault:#?}")] {
        assert!(shown.contains("API_KEY"), "{shown}");
        assert!(
            !shown.contains(SECRET) && !shown.contains("DEBUG-REDACTION"),
            "{shown}"
        );
    }
}

#[test]
fn redactor_debug_never_shows_its_patterns() {
    let r = Redactor::new([SECRET]).unwrap();
    let (a, b) = Redactor::new_pair([SECRET]).unwrap();
    for shown in [format!("{r:?}"), format!("{a:#?}"), format!("{b:?}")] {
        assert!(
            !shown.contains(SECRET) && !shown.contains("DEBUG-REDACTION"),
            "{shown}"
        );
    }
}

#[test]
fn derived_key_debug_is_redacted() {
    let key =
        crypto::derive_key(SECRET.as_bytes(), &[7u8; crypto::SALT_LEN], KdfParams::MIN).unwrap();
    let shown = format!("{key:?}");
    assert!(shown.contains("REDACTED"), "{shown}");
    assert!(!shown.contains(SECRET), "{shown}");
}

#[test]
fn error_types_do_not_carry_values() {
    let mut vault = Vault::new();
    // A rejected value is named by key only.
    let err = vault
        .set("K", Zeroizing::new(format!("{SECRET}\0")))
        .unwrap_err();
    for shown in [format!("{err:?}"), err.to_string()] {
        assert!(!shown.contains(SECRET), "{shown}");
    }
    let err = vault.set(SECRET, Zeroizing::new("v".into())).unwrap_err();
    for shown in [format!("{err:?}"), err.to_string()] {
        assert!(
            !shown.contains(SECRET),
            "swapped key must not be echoed: {shown}"
        );
    }
}

/// The types that derive `Debug`, by source file. None of them holds a secret
/// value: KDF numbers, error enums whose variants carry paths, key names,
/// line numbers or program names (never values), a lock file handle, and the
/// clap `Cli` whose `Cmd` has a hand-written `Debug`.
const DERIVES_DEBUG: &[(&str, &[&str])] = &[
    ("crypto.rs", &["CryptoError", "KdfParams"]),
    // DotenvEntry (dotenv.rs) holds values and deliberately has no Debug.
    ("envcheck.rs", &["Overrun"]), // key names and byte counts
    ("input.rs", &["InputError"]),
    ("main.rs", &["Cli"]),
    ("perms.rs", &["Exposure"]),     // a two-variant tag
    ("prompt.rs", &["PromptError"]), // never carries what was typed
    ("runner.rs", &["RunError"]),
    ("vault.rs", &["VaultError", "VaultLock"]),
];

const SOURCES: &[(&str, &str)] = &[
    ("crypto.rs", include_str!("../src/crypto.rs")),
    ("diag.rs", include_str!("../src/diag.rs")),
    ("dotenv.rs", include_str!("../src/dotenv.rs")),
    ("envcheck.rs", include_str!("../src/envcheck.rs")),
    ("hardening.rs", include_str!("../src/hardening.rs")),
    ("input.rs", include_str!("../src/input.rs")),
    ("lib.rs", include_str!("../src/lib.rs")),
    ("main.rs", include_str!("../src/main.rs")),
    ("passphrase.rs", include_str!("../src/passphrase.rs")),
    ("perms.rs", include_str!("../src/perms.rs")),
    ("prompt.rs", include_str!("../src/prompt.rs")),
    ("runner.rs", include_str!("../src/runner.rs")),
    ("supervise.rs", include_str!("../src/supervise.rs")),
    ("sys.rs", include_str!("../src/sys.rs")),
    ("vault.rs", include_str!("../src/vault.rs")),
];

fn derived_debug_types(source: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut lines = source.lines();
    while let Some(line) = lines.next() {
        let t = line.trim_start();
        if !(t.starts_with("#[derive(") && t.contains("Debug")) {
            continue;
        }
        for next in lines.by_ref() {
            let t = next.trim_start();
            if t.starts_with("#[") || t.starts_with("///") {
                continue;
            }
            let name = t
                .split_whitespace()
                .skip_while(|w| *w != "struct" && *w != "enum")
                .nth(1)
                .expect("a type after derive");
            found.push(name.trim_end_matches(['{', '(', '<', ';']).to_owned());
            break;
        }
    }
    found
}

#[test]
fn the_set_of_types_deriving_debug_is_pinned() {
    for (file, source) in SOURCES {
        let mut want: Vec<&str> = DERIVES_DEBUG
            .iter()
            .find(|(f, _)| f == file)
            .map(|(_, types)| types.to_vec())
            .unwrap_or_default();
        let mut got = derived_debug_types(source);
        want.sort_unstable();
        got.sort_unstable();
        assert_eq!(
            got, want,
            "{file}: the types deriving Debug changed; make sure none can hold a secret, then update DERIVES_DEBUG"
        );
    }
}
