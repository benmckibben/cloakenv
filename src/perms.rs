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

/// Sticky bit: in a directory that has it, only the owner of an entry (or of
/// the directory) may rename or delete it, as in `/tmp`.
#[cfg(unix)]
const STICKY: u32 = 0o1000;

/// Who, besides the owner, can write to a vault directory.
#[cfg(unix)]
#[derive(Debug, PartialEq, Eq)]
enum Exposure {
    /// Anyone on the machine, and the directory is not sticky.
    World,
    /// The members of a group that is not a private group of the current user.
    SharedGroup,
}

/// The rule for a vault *directory* (see the README, "Permission warnings"):
///
/// * world-writable and not sticky: always warns, since anyone may replace
///   the vault. (A sticky world-writable directory such as `/tmp` does not
///   let others rename or delete our files, so that bit alone is not reported.)
/// * group-writable: warns unless the directory's group is a private group of
///   the current user (see [`Accounts::is_private_group`]). The Debian and
///   Ubuntu default umask 0002 makes every ordinary project directory 0775 in
///   the user's own one-member group; warning about that on every command
///   would only teach people to ignore the warnings.
#[cfg(unix)]
fn dir_exposure(
    mode: u32,
    gid: u32,
    is_private_group: impl FnOnce(u32) -> bool,
) -> Option<Exposure> {
    if mode & 0o002 != 0 && mode & STICKY == 0 {
        return Some(Exposure::World);
    }
    if mode & 0o020 != 0 && !is_private_group(gid) {
        return Some(Exposure::SharedGroup);
    }
    None
}

/// The account databases, as text, for deciding whether a group is private.
/// Read from `/etc/passwd` and `/etc/group` (no network directory service is
/// consulted: when the answer cannot be found the group counts as shared, so
/// the result errs towards warning). Kept as plain strings so the rule is
/// testable with made-up accounts.
#[cfg(unix)]
pub struct Accounts {
    passwd: String,
    group: String,
    uid: u32,
}

#[cfg(unix)]
impl Accounts {
    /// The databases of this machine, for the current effective user.
    pub fn system() -> Self {
        Accounts {
            passwd: fs::read_to_string("/etc/passwd").unwrap_or_default(),
            group: fs::read_to_string("/etc/group").unwrap_or_default(),
            uid: rustix::process::geteuid().as_raw(),
        }
    }

    /// Made-up accounts, for tests.
    pub fn from_text(uid: u32, passwd: &str, group: &str) -> Self {
        Accounts {
            passwd: passwd.to_owned(),
            group: group.to_owned(),
            uid,
        }
    }

    /// True if `gid` is a private group of the current user, which needs all
    /// of: it is the user's primary group in `passwd`; no other account has it
    /// as its primary group; and `group` has an entry for it named like the
    /// user (the "user private group" convention) whose member list names
    /// nobody else. Anything missing or malformed makes the answer false.
    pub fn is_private_group(&self, gid: u32) -> bool {
        let accounts: Vec<(&str, u32, u32)> = self
            .passwd
            .lines()
            .filter_map(|line| {
                let mut f = line.split(':');
                let name = f.next()?;
                let _password = f.next()?;
                let uid = f.next()?.parse().ok()?;
                let primary = f.next()?.parse().ok()?;
                Some((name, uid, primary))
            })
            .collect();
        let Some(&(user, _, primary)) = accounts.iter().find(|(_, uid, _)| *uid == self.uid) else {
            return false;
        };
        if primary != gid || accounts.iter().any(|&(n, _, g)| g == gid && n != user) {
            return false;
        }
        let entries: Vec<(&str, &str)> = self
            .group
            .lines()
            .filter_map(|line| {
                let mut f = line.split(':');
                let name = f.next()?;
                let _password = f.next()?;
                let entry_gid: u32 = f.next()?.parse().ok()?;
                let members = f.next().unwrap_or("");
                (entry_gid == gid).then_some((name, members))
            })
            .collect();
        !entries.is_empty()
            && entries.iter().all(|&(name, members)| {
                name == user && members.split(',').all(|m| m.is_empty() || m == user)
            })
    }
}

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

/// Owning group of `path` (following symlinks), if it can be inspected.
#[cfg(unix)]
fn gid_of(path: &Path) -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    fs::metadata(path).ok().map(|m| m.gid())
}

/// Warnings about the vault at `vault`: its directory and, if
/// `check_file`, the vault file itself.
///
/// `check_file` is false for `init`, which is about to replace the file with
/// a fresh 0600 one.
pub fn vault_warnings(vault: &Path, check_file: bool) -> Vec<String> {
    #[cfg(unix)]
    {
        // The account files are only read when a group-writable directory
        // makes the question matter.
        let lazy = std::cell::OnceCell::new();
        vault_warnings_with(vault, check_file, &|gid| {
            lazy.get_or_init(Accounts::system).is_private_group(gid)
        })
    }
    #[cfg(not(unix))]
    vault_warnings_with(vault, check_file, &|_| false)
}

/// [`vault_warnings`] with the "is this a private group of mine" question
/// answered by `is_private_group`.
fn vault_warnings_with(
    vault: &Path,
    check_file: bool,
    #[allow(unused_variables)] is_private_group: &dyn Fn(u32) -> bool,
) -> Vec<String> {
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
    if let (Some(mode), Some(gid)) = (mode_of(dir), gid_of(dir)) {
        match dir_exposure(mode, gid, is_private_group) {
            Some(Exposure::World) => out.push(format!(
                "vault directory {} is world-writable (mode {mode:04o}, expected 0700); anyone on this machine could replace the vault",
                dir.display()
            )),
            Some(Exposure::SharedGroup) => out.push(format!(
                "vault directory {} is writable by a group that is not private to you (mode {mode:04o}, expected 0700); the members of that group could replace the vault",
                dir.display()
            )),
            None => {}
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
        crate::elog!("cloakenv: warning: {w}");
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
        for mode in [0o707, 0o777, 0o702, 0o2777] {
            chmod(dir, mode);
            let w = vault_warnings(&v, false);
            assert_eq!(w.len(), 1, "dir mode {mode:o}: {w:?}");
            assert!(w[0].contains("world-writable"), "{w:?}");
        }
        // A readable-but-not-writable directory is fine.
        chmod(dir, 0o755);
        assert!(vault_warnings(&v, false).is_empty());
    }

    const PASSWD: &str = "\
root:x:0:0:root:/root:/bin/bash
ben:x:1000:1000:Ben:/h/ben:/bin/bash
alice:x:1001:100:Alice:/h/alice:/bin/bash
bob:x:1002:100:Bob:/h/bob:/bin/bash
carol:x:1003:1003::/h/carol:/bin/bash
dave:x:1004:1003::/h/dave:/bin/bash
";
    const GROUP: &str = "\
root:x:0:
ben:x:1000:
users:x:100:
carol:x:1003:
docker:x:989:ben,alice
staff:x:50:ben
";

    #[test]
    fn a_world_writable_directory_always_warns_unless_it_is_sticky() {
        let never = |_| false;
        let always = |_| true;
        for mode in [0o777, 0o707, 0o702, 0o2777, 0o772] {
            assert_eq!(
                dir_exposure(mode, 1000, always),
                Some(Exposure::World),
                "{mode:o}"
            );
            assert_eq!(
                dir_exposure(mode, 1000, never),
                Some(Exposure::World),
                "{mode:o}"
            );
        }
        // Sticky (as /tmp): others cannot rename or delete our files.
        assert_eq!(dir_exposure(0o1777, 1000, always), None);
        assert_eq!(dir_exposure(0o1707, 1000, never), None);
        // ...but a sticky directory that is also writable by a shared group.
        assert_eq!(
            dir_exposure(0o1777, 1000, never),
            Some(Exposure::SharedGroup)
        );
        // Not writable by others at all.
        for mode in [0o700, 0o755, 0o750, 0o705, 0o555] {
            assert_eq!(dir_exposure(mode, 1000, never), None, "{mode:o}");
        }
    }

    #[test]
    fn a_group_writable_directory_warns_only_for_a_shared_group() {
        for mode in [0o770, 0o775, 0o720, 0o2775] {
            assert_eq!(dir_exposure(mode, 1000, |_| true), None, "{mode:o}");
            assert_eq!(
                dir_exposure(mode, 1000, |_| false),
                Some(Exposure::SharedGroup),
                "{mode:o}"
            );
        }
        // The group asked about is the directory's own.
        assert_eq!(dir_exposure(0o775, 1234, |gid| gid == 1234), None);
    }

    #[test]
    fn a_private_group_is_the_users_own_group_with_nobody_else_in_it() {
        let ben = Accounts::from_text(1000, PASSWD, GROUP);
        // Debian-style user private group: primary, named like the user, no members.
        assert!(ben.is_private_group(1000));
        // A supplementary group, shared with others.
        assert!(!ben.is_private_group(989));
        assert!(!ben.is_private_group(50));
        // Somebody else's, the shared "users", and one that does not exist.
        assert!(!ben.is_private_group(1001));
        assert!(!ben.is_private_group(100));
        assert!(!ben.is_private_group(4242));
        // alice's primary group is the shared "users" group (gid 100).
        assert!(!Accounts::from_text(1001, PASSWD, GROUP).is_private_group(100));
        // carol's group is named like her, but dave has it as his primary group too.
        assert!(!Accounts::from_text(1003, PASSWD, GROUP).is_private_group(1003));
        // An unknown user, or no account files at all: shared, so warn.
        assert!(!Accounts::from_text(4242, PASSWD, GROUP).is_private_group(1000));
        assert!(!Accounts::from_text(1000, "", "").is_private_group(1000));
    }

    #[test]
    fn a_private_group_with_an_extra_member_or_a_different_name_is_shared() {
        let ben = |group: &str| Accounts::from_text(1000, PASSWD, group).is_private_group(1000);
        assert!(ben("ben:x:1000:\n"));
        assert!(ben("ben:x:1000:ben\n"));
        assert!(!ben("ben:x:1000:ben,mallory\n"));
        assert!(!ben("ben:x:1000:mallory\n"));
        assert!(!ben("friends:x:1000:\n"));
        // Two names for the gid: one of them is not his.
        assert!(!ben("ben:x:1000:\nclub:x:1000:\n"));
        // Garbage lines are ignored, and cannot make a group private.
        assert!(ben("not a line\nben:x:1000:\n\n:::\n"));
        assert!(!ben("garbage\n"));
        // A passwd line that is malformed is skipped.
        let broken = "ben:x:1000\nben:x:oops:1000:::\n";
        assert!(!Accounts::from_text(1000, broken, "ben:x:1000:\n").is_private_group(1000));
    }

    #[test]
    fn the_real_directory_check_uses_the_directory_group() {
        let (_t, v) = setup();
        let dir = v.parent().unwrap();
        let mine = |private: bool| move |_gid: u32| private;
        // 0775 in a private group: quiet. In a shared group: one warning.
        chmod(dir, 0o775);
        assert!(vault_warnings_with(&v, false, &mine(true)).is_empty());
        let w = vault_warnings_with(&v, false, &mine(false));
        assert_eq!(w.len(), 1, "{w:?}");
        assert!(
            w[0].contains("writable by a group that is not private to you"),
            "{w:?}"
        );
        assert!(w[0].contains("0775"), "{w:?}");
        // World-writable warns whatever the group is.
        chmod(dir, 0o777);
        let w = vault_warnings_with(&v, false, &mine(true));
        assert_eq!(w.len(), 1, "{w:?}");
        assert!(w[0].contains("world-writable"), "{w:?}");
        // Sticky and world-writable (as /tmp itself): quiet.
        chmod(dir, 0o1777);
        assert!(vault_warnings_with(&v, false, &mine(true)).is_empty());
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
