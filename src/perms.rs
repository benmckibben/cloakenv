//! Advisory checks on the permissions of the files cloakenv depends on.
//!
//! These produce *warnings*, never errors, in the spirit of the `ssh` / `gpg`
//! permission complaints: cloakenv never changes the mode of a file or
//! directory it did not create, and it still works with loose permissions
//! (shared deployments, container secret mounts and so on are legitimate).
//! Each warning is one line and names only paths and octal modes; no
//! passphrase or vault content is ever included.
//!
//! The mode checks are Unix-only; on Windows the equivalent is a check of the
//! file's ACL (see [`AclEntry`] and [`acl_exposure`]). The symbolic-link checks
//! apply everywhere.

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

/// One entry of a Windows discretionary ACL, reduced to what the exposure rule
/// needs. Read from the file by `winsys::read_dacl` on Windows; plain data here
/// so that the rule is testable on every platform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AclEntry {
    /// The trustee, as a string SID (`S-1-5-32-545`).
    pub sid: String,
    /// The access mask the entry grants or denies.
    pub mask: u32,
    /// True for an "allow" entry, false for a "deny" entry.
    pub allow: bool,
    /// True for an entry that is only inherited by children (a directory's
    /// `(IO)` entries) and does not apply to the object itself.
    pub inherit_only: bool,
}

/// `FILE_WRITE_DATA`/`FILE_ADD_FILE`, `FILE_APPEND_DATA`/`FILE_ADD_SUBDIRECTORY`,
/// `FILE_DELETE_CHILD`, `DELETE`, `WRITE_DAC`, `WRITE_OWNER`, `GENERIC_WRITE` and
/// `GENERIC_ALL`: any of them lets the trustee replace or remove entries in a
/// directory, or change who may.
const WRITE_MASK: u32 = 0x0000_0002
    | 0x0000_0004
    | 0x0000_0040
    | 0x0001_0000
    | 0x0004_0000
    | 0x0008_0000
    | 0x4000_0000
    | 0x1000_0000;

/// The groups that mean "other people on this machine": Everyone, the local
/// Users group and Authenticated Users. Administrators, SYSTEM and the owner
/// are expected to have access and are never reported.
fn broad_group(sid: &str) -> Option<&'static str> {
    match sid {
        "S-1-1-0" => Some("Everyone"),
        "S-1-5-32-545" => Some("BUILTIN\\Users"),
        "S-1-5-11" => Some("Authenticated Users"),
        _ => None,
    }
}

/// Which of Everyone, Users and Authenticated Users the ACL grants access to.
///
/// With `writes_only` (a vault *directory*) only an entry that allows writing is
/// counted, as on Unix where only a writable directory is reported; without it
/// (the vault file, the passphrase file) any access counts, like the Unix check
/// for group/other read or write. Entries that only apply to children are
/// ignored. "Deny" entries are ignored too, which can only make the answer err
/// towards warning, as the rest of this module does. A missing DACL (which
/// Windows treats as "everyone may do anything") is reported by the caller as an
/// Everyone entry. The result has each group once, in the order first seen.
pub fn acl_exposure(entries: &[AclEntry], writes_only: bool) -> Vec<&'static str> {
    let mut out = Vec::new();
    for e in entries {
        if !e.allow || e.inherit_only || e.mask == 0 {
            continue;
        }
        if writes_only && e.mask & WRITE_MASK == 0 {
            continue;
        }
        if let Some(name) = broad_group(&e.sid) {
            if !out.contains(&name) {
                out.push(name);
            }
        }
    }
    out
}

/// The ACL of `path` as seen by the exposure rule, or `None` where ACLs do not
/// exist or the path cannot be inspected.
#[cfg(windows)]
fn acl_of(path: &Path) -> Option<Vec<AclEntry>> {
    crate::winsys::read_dacl(path)
}

/// Joins group names for a warning: `A`, `A and B`, `A, B and C`.
#[cfg(windows)]
fn join_names(names: &[&str]) -> String {
    match names {
        [] => String::new(),
        [one] => (*one).to_owned(),
        [init @ .., last] => format!("{} and {last}", init.join(", ")),
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

    #[cfg(windows)]
    if let Some(acl) = acl_of(dir) {
        let who = acl_exposure(&acl, true);
        if !who.is_empty() {
            out.push(format!(
                "vault directory {} can be written to by {} (Windows ACL); they could replace the vault. A directory cloakenv creates is open only to you, SYSTEM and Administrators",
                dir.display(),
                join_names(&who)
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
        #[cfg(windows)]
        if let Some(acl) = acl_of(vault) {
            let who = acl_exposure(&acl, false);
            if !who.is_empty() {
                out.push(format!(
                    "vault file {} can be read or changed by {} (Windows ACL); expected access for you, SYSTEM and Administrators only",
                    vault.display(),
                    join_names(&who)
                ));
            }
        }
    }
    out
}

/// Warnings about the directory that holds the rollback-protection file and the copies of old vaults. Whoever can
/// change what is in it can edit the record of what this machine has seen, which is the whole of rollback detection,
/// so a directory other people can write to, that belongs to someone else, or that is a symbolic link (to somewhere
/// that may be) is worth saying out loud. Only the directory itself is looked at, not its parents: a home directory
/// that is a link is common and not the point.
pub fn state_dir_warnings(dir: &Path) -> Vec<String> {
    #[cfg(unix)]
    {
        let lazy = std::cell::OnceCell::new();
        state_dir_warnings_with(dir, &|gid| {
            lazy.get_or_init(Accounts::system).is_private_group(gid)
        })
    }
    #[cfg(not(unix))]
    state_dir_warnings_with(dir, &|_| false)
}

fn state_dir_warnings_with(
    dir: &Path,
    #[allow(unused_variables)] is_private_group: &dyn Fn(u32) -> bool,
) -> Vec<String> {
    #[allow(unused_mut)]
    let mut out = Vec::new();
    if is_symlink(dir) {
        out.push(format!(
            "rollback-protection directory {} is a symbolic link; cloakenv follows it, so make sure its target is private (whoever controls it controls rollback detection)",
            dir.display()
        ));
    }
    #[cfg(unix)]
    if let (Some(mode), Some(gid)) = (mode_of(dir), gid_of(dir)) {
        match dir_exposure(mode, gid, is_private_group) {
            Some(Exposure::World) => out.push(format!(
                "rollback-protection directory {} is world-writable (mode {mode:04o}, expected 0700); anyone on this machine could edit the record of which vaults this machine has seen and defeat rollback detection",
                dir.display()
            )),
            Some(Exposure::SharedGroup) => out.push(format!(
                "rollback-protection directory {} is writable by a group that is not private to you (mode {mode:04o}, expected 0700); its members could edit the record of which vaults this machine has seen",
                dir.display()
            )),
            None => {}
        }
        if let Some(owner) = owner_of(dir) {
            if owner != rustix::process::geteuid().as_raw() {
                out.push(format!(
                    "rollback-protection directory {} belongs to another user (uid {owner}); that user can edit the record of which vaults this machine has seen",
                    dir.display()
                ));
            }
        }
    }
    #[cfg(windows)]
    if let Some(acl) = acl_of(dir) {
        let who = acl_exposure(&acl, true);
        if !who.is_empty() {
            out.push(format!(
                "rollback-protection directory {} can be written to by {} (Windows ACL); they could edit the record of which vaults this machine has seen. A directory cloakenv creates is open only to you, SYSTEM and Administrators",
                dir.display(),
                join_names(&who)
            ));
        }
    }
    out
}

/// Owning user of {`path`} (following symlinks), if it can be inspected.
#[cfg(unix)]
fn owner_of(path: &Path) -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    fs::metadata(path).ok().map(|m| m.uid())
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
    #[cfg(windows)]
    if let Some(acl) = acl_of(file) {
        let who = acl_exposure(&acl, false);
        if !who.is_empty() {
            out.push(format!(
                "passphrase file {} can be read or changed by {} (Windows ACL); anyone who can read it can decrypt the vault",
                file.display(),
                join_names(&who)
            ));
        }
    }
    #[cfg(not(any(unix, windows)))]
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

    #[cfg(unix)]
    #[test]
    fn the_state_directory_is_checked_like_the_vault_directory() {
        let t = tempfile::tempdir().unwrap();
        let dir = t.path().join("state");
        std::fs::create_dir(&dir).unwrap();
        chmod(&dir, 0o700);
        assert!(
            state_dir_warnings(&dir).is_empty(),
            "{:?}",
            state_dir_warnings(&dir)
        );
        assert!(
            state_dir_warnings(&t.path().join("missing")).is_empty(),
            "a directory that does not exist has nothing to say"
        );
        chmod(&dir, 0o777);
        let w = state_dir_warnings(&dir);
        assert_eq!(w.len(), 1, "{w:?}");
        assert!(
            w[0].contains("world-writable") && w[0].contains("rollback detection"),
            "{w:?}"
        );
        chmod(&dir, 0o755);
        assert!(
            state_dir_warnings(&dir).is_empty(),
            "readable by others is not writable by others"
        );
        chmod(&dir, 0o700);
        let link = t.path().join("link");
        std::os::unix::fs::symlink(&dir, &link).unwrap();
        let w = state_dir_warnings(&link);
        assert_eq!(w.len(), 1, "{w:?}");
        assert!(w[0].contains("symbolic link"), "{w:?}");
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

#[cfg(test)]
mod acl_tests {
    use super::*;

    fn allow(sid: &str, mask: u32) -> AclEntry {
        AclEntry {
            sid: sid.into(),
            mask,
            allow: true,
            inherit_only: false,
        }
    }

    const USERS: &str = "S-1-5-32-545";
    const AUTH: &str = "S-1-5-11";
    const EVERYONE: &str = "S-1-1-0";
    const SYSTEM: &str = "S-1-5-18";
    const ADMINS: &str = "S-1-5-32-544";
    const ME: &str = "S-1-5-21-1-2-3-1001";
    const READ: u32 = 0x1200A9; // FILE_GENERIC_READ | FILE_GENERIC_EXECUTE
    const MODIFY: u32 = 0x1301BF;
    const FULL: u32 = 0x1F01FF;

    #[test]
    fn an_owner_system_and_admins_acl_is_clean() {
        let acl = [allow(ME, FULL), allow(SYSTEM, FULL), allow(ADMINS, FULL)];
        assert!(acl_exposure(&acl, false).is_empty());
        assert!(acl_exposure(&acl, true).is_empty());
    }

    #[test]
    fn a_file_is_exposed_by_any_access_for_the_broad_groups() {
        assert_eq!(
            acl_exposure(&[allow(USERS, READ)], false),
            ["BUILTIN\\Users"]
        );
        assert_eq!(
            acl_exposure(&[allow(AUTH, MODIFY)], false),
            ["Authenticated Users"]
        );
        assert_eq!(acl_exposure(&[allow(EVERYONE, 1)], false), ["Everyone"]);
    }

    #[test]
    fn a_directory_is_exposed_only_by_write_access() {
        // The default for a folder under C:\dev: Users read, Authenticated Users modify.
        let acl = [allow(USERS, READ), allow(AUTH, MODIFY), allow(ADMINS, FULL)];
        assert_eq!(acl_exposure(&acl, true), ["Authenticated Users"]);
        assert_eq!(
            acl_exposure(&acl, false),
            ["BUILTIN\\Users", "Authenticated Users"]
        );
        assert!(acl_exposure(&[allow(USERS, READ)], true).is_empty());
    }

    #[test]
    fn each_write_bit_counts_for_a_directory() {
        for bit in [
            0x2,
            0x4,
            0x40,
            0x10000,
            0x40000,
            0x80000,
            0x4000_0000,
            0x1000_0000,
        ] {
            assert_eq!(
                acl_exposure(&[allow(USERS, bit)], true),
                ["BUILTIN\\Users"],
                "{bit:#x}"
            );
        }
    }

    #[test]
    fn inherit_only_deny_and_empty_entries_are_ignored() {
        let mut inherit_only = allow(AUTH, MODIFY);
        inherit_only.inherit_only = true;
        let mut deny = allow(USERS, FULL);
        deny.allow = false;
        let acl = [inherit_only, deny, allow(EVERYONE, 0)];
        assert!(acl_exposure(&acl, false).is_empty());
        assert!(acl_exposure(&acl, true).is_empty());
    }

    #[test]
    fn each_group_is_named_once_in_the_order_first_seen() {
        let acl = [
            allow(AUTH, MODIFY),
            allow(USERS, READ),
            allow(AUTH, FULL),
            allow(USERS, FULL),
        ];
        assert_eq!(
            acl_exposure(&acl, false),
            ["Authenticated Users", "BUILTIN\\Users"]
        );
    }

    #[test]
    fn other_accounts_are_not_reported() {
        let acl = [
            allow("S-1-5-21-1-2-3-1002", FULL),
            allow("S-1-5-32-546", FULL),
        ];
        assert!(acl_exposure(&acl, false).is_empty());
    }
}
