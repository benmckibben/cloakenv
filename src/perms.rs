//! Advisory checks on the permissions of the files cloakenv depends on.
//!
//! These produce *warnings*, never errors, in the spirit of the `ssh` / `gpg`
//! permission complaints: cloakenv never changes the mode of a file or
//! directory it did not create, and it still works with loose permissions
//! (shared deployments, container secret mounts and so on are legitimate).
//! Each warning is one line and names only paths and octal modes; no
//! passphrase or vault content is ever included.
//!
//! The mode checks are Unix-only. The symbolic-link checks apply everywhere.

use std::fs;
use std::path::Path;

use crate::vault::vault_dir;

/// Mask of the permission bits that make a *file* too open: any read or write
/// access for group or others.
#[cfg(unix)]
const FILE_TOO_OPEN: u32 = 0o066;

/// Mask for a *directory*: group or others may create, rename or delete
/// entries in it (so they could swap the vault for one of their own).
#[cfg(unix)]
const DIR_TOO_OPEN: u32 = 0o022;

fn is_symlink(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink())
}

/// Permission bits of `path` (following symlinks, i.e. the object cloakenv
/// would actually read), or `None` if it cannot be inspected.
#[cfg(unix)]
fn mode_of(path: &Path) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path)
        .ok()
        .map(|m| m.permissions().mode() & 0o7777)
}

/// Warnings about the vault at `vault`: its directory and, if
/// `check_file`, the vault file itself.
///
/// `check_file` is false for `init`, which is about to replace the file with
/// a fresh 0600 one.
pub fn vault_warnings(vault: &Path, check_file: bool) -> Vec<String> {
    let mut out = Vec::new();
    let dir = vault_dir(vault);
    let dir = dir.as_path();

    if is_symlink(dir) {
        out.push(format!(
            "vault directory {} is a symbolic link; cloakenv follows it, so make sure its target is private",
            dir.display()
        ));
    }
    #[cfg(unix)]
    if let Some(mode) = mode_of(dir) {
        if mode & DIR_TOO_OPEN != 0 {
            out.push(format!(
                "vault directory {} is group/world-writable (mode {mode:04o}, expected 0700); others could replace the vault",
                dir.display()
            ));
        }
    }

    if check_file {
        if is_symlink(vault) {
            out.push(format!(
                "vault file {} is a symbolic link; reads follow it, but saving replaces the link with a regular file",
                vault.display()
            ));
        }
        #[cfg(unix)]
        if let Some(mode) = mode_of(vault) {
            if mode & FILE_TOO_OPEN != 0 {
                out.push(format!(
                    "vault file {} is group/world-readable or writable (mode {mode:04o}, expected 0600)",
                    vault.display()
                ));
            }
        }
    }
    out
}

/// Warnings about the passphrase file named by `CLOAKENV_PASSPHRASE_FILE`.
///
/// This is a warning rather than an error on purpose: container and
/// orchestrator secret mounts (Docker `/run/secrets`, Kubernetes secret
/// volumes) are commonly mode 0444/0644 and protected by the container
/// boundary instead, and refusing to run there would break working setups.
pub fn passphrase_file_warnings(file: &Path) -> Vec<String> {
    #[allow(unused_mut)]
    let mut out = Vec::new();
    #[cfg(unix)]
    if let Some(mode) = mode_of(file) {
        if mode & FILE_TOO_OPEN != 0 {
            out.push(format!(
                "passphrase file {} is group/world-readable or writable (mode {mode:04o}, expected 0600); anyone who can read it can decrypt the vault",
                file.display()
            ));
        }
    }
    #[cfg(not(unix))]
    let _ = file;
    out
}

/// Prints each warning on stderr as `cloakenv: warning: ...`.
pub fn emit(warnings: &[String]) {
    for w in warnings {
        eprintln!("cloakenv: warning: {w}");
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn chmod(p: &Path, mode: u32) {
        fs::set_permissions(p, fs::Permissions::from_mode(mode)).unwrap();
    }

    fn setup() -> (tempfile::TempDir, std::path::PathBuf) {
        let t = tempfile::tempdir().unwrap();
        let dir = t.path().join(".cloak");
        fs::create_dir(&dir).unwrap();
        chmod(&dir, 0o700);
        let v = dir.join("vault.bin");
        fs::write(&v, b"x").unwrap();
        chmod(&v, 0o600);
        (t, v)
    }

    #[test]
    fn private_vault_has_no_warnings() {
        let (_t, v) = setup();
        assert!(vault_warnings(&v, true).is_empty());
    }

    #[test]
    fn loose_modes_warn() {
        let (_t, v) = setup();
        for mode in [0o640, 0o604, 0o644, 0o660, 0o666, 0o602] {
            chmod(&v, mode);
            let w = vault_warnings(&v, true);
            assert_eq!(w.len(), 1, "mode {mode:o}: {w:?}");
            assert!(w[0].contains(&format!("{mode:04o}")), "{w:?}");
        }
        // Execute bits alone are not a leak.
        chmod(&v, 0o700);
        assert!(vault_warnings(&v, true).is_empty());
        let dir = v.parent().unwrap();
        for mode in [0o770, 0o707, 0o777, 0o720] {
            chmod(dir, mode);
            let w = vault_warnings(&v, false);
            assert_eq!(w.len(), 1, "dir mode {mode:o}: {w:?}");
        }
        // A readable-but-not-writable directory is fine.
        chmod(dir, 0o755);
        assert!(vault_warnings(&v, false).is_empty());
    }

    #[test]
    fn init_ignores_old_file_mode() {
        let (_t, v) = setup();
        chmod(&v, 0o666);
        assert!(vault_warnings(&v, false).is_empty());
    }

    #[test]
    fn symlinks_warn() {
        let (t, v) = setup();
        let real = t.path().join("real.bin");
        fs::rename(&v, &real).unwrap();
        chmod(&real, 0o600);
        symlink(&real, &v).unwrap();
        let w = vault_warnings(&v, true);
        assert_eq!(w.len(), 1, "{w:?}");
        assert!(w[0].contains("symbolic link"));

        let link_dir = t.path().join("link");
        symlink(v.parent().unwrap(), &link_dir).unwrap();
        let w = vault_warnings(&link_dir.join("vault.bin"), true);
        assert!(w.iter().any(|w| w.contains("vault directory")), "{w:?}");
    }

    #[test]
    fn passphrase_file_modes() {
        let t = tempfile::tempdir().unwrap();
        let f = t.path().join("key");
        fs::write(&f, b"dummy").unwrap();
        chmod(&f, 0o600);
        assert!(passphrase_file_warnings(&f).is_empty());
        chmod(&f, 0o400);
        assert!(passphrase_file_warnings(&f).is_empty());
        chmod(&f, 0o666);
        let w = passphrase_file_warnings(&f);
        assert_eq!(w.len(), 1);
        assert!(w[0].contains("passphrase file"));
        // Missing files are reported by the read itself, not here.
        assert!(passphrase_file_warnings(&t.path().join("nope")).is_empty());
    }
}
