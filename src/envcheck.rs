//! Checks on the environment `run` is about to hand to the command, made
//! before anything is started and without ever showing a value.
//!
//! * A vault entry too large for one environment variable, and an
//!   environment that is too large altogether, are reported with the names of
//!   the entries responsible. Otherwise the only symptom is the operating
//!   system's `failed to spawn: Argument list too long`, which names nothing.
//!   The limits are those of Linux (see [`MAX_ENV_ENTRY_LEN`] and
//!   [`kernel_arg_limit`]); other platforms are not checked.

use std::ffi::OsString;

use crate::vault::{MAX_ENV_ENTRY_LEN, Vault, VaultError};
use crate::{PASSPHRASE_ENV, PASSPHRASE_FILE_ENV};

/// The most bytes of argument and environment strings (plus their pointers)
/// the kernel lets a program start with, or `None` where this is not checked.
///
/// Linux allows a quarter of the stack limit (`ulimit -s`, 8 MiB by default,
/// so 2 MiB), at least 128 KiB and at most 6 MiB (`fs/exec.c`,
/// `bprm_stack_limits`). A little less than this is usable in practice (the
/// kernel also keeps a few bytes for itself), so a command can still fail
/// just under the limit; this check never rejects an environment the kernel
/// would accept.
pub fn kernel_arg_limit() -> Option<usize> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        use rustix::process::{Resource, getrlimit};
        const FLOOR: u64 = 128 * 1024;
        const CAP: u64 = 6 * 1024 * 1024;
        let stack = getrlimit(Resource::Stack).current.unwrap_or(u64::MAX);
        let limit = (stack / 4).clamp(FLOOR, CAP);
        usize::try_from(limit).ok()
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        None
    }
}

/// Checks the environment of the command about to be started: every vault
/// entry must fit in one environment string, and all of it together with the
/// inherited environment and `argv` must fit in what the kernel allows. The
/// error names the vault entries to remove, never a value.
pub fn check_run_environment(vault: &Vault, argv: &[OsString]) -> Result<(), VaultError> {
    let Some(limit) = kernel_arg_limit() else {
        return Ok(());
    };
    // Per-variable limit, for vaults written before it was enforced at `set`.
    for (key, value) in vault.iter() {
        let len = key.len() + 1 + value.len();
        if len > MAX_ENV_ENTRY_LEN {
            return Err(VaultError::EntryTooLarge {
                key: key.to_owned(),
                len,
                max: MAX_ENV_ENTRY_LEN,
            });
        }
    }
    let mut entries: Vec<(String, usize)> = vault
        .iter()
        .map(|(k, v)| (k.to_owned(), k.len() + 1 + v.len() + 1))
        .collect();
    // The command's environment is ours, minus the passphrase variables,
    // with the vault's entries on top.
    let mut other = 0usize;
    let mut other_count = 0usize;
    for (k, v) in std::env::vars_os() {
        if k == PASSPHRASE_ENV || k == PASSPHRASE_FILE_ENV {
            continue;
        }
        if k.to_str().is_some_and(|k| vault.get(k).is_some()) {
            continue;
        }
        other += k.len() + v.len() + 2;
        other_count += 1;
    }
    let argv_bytes: usize = argv.iter().map(|a| a.len() + 1).sum();
    let pointers = (argv.len().max(1) + other_count + entries.len()) * std::mem::size_of::<usize>();
    let base = other + argv_bytes + pointers;
    match budget_overrun(&mut entries, base, limit) {
        None => Ok(()),
        Some(over) => Err(VaultError::EnvironmentTooLarge {
            total: over.total,
            limit,
            largest: over.largest,
        }),
    }
}

/// How far over the limit an environment is, and which vault entries are the
/// biggest.
#[derive(Debug, PartialEq, Eq)]
pub struct Overrun {
    pub total: usize,
    pub largest: String,
}

/// Given the vault's entries as `(key, bytes)` and the `base` bytes taken by
/// everything else, returns `None` if the sum fits in `limit` and otherwise the
/// total and a description of the (up to three) largest entries.
pub fn budget_overrun(
    entries: &mut [(String, usize)],
    base: usize,
    limit: usize,
) -> Option<Overrun> {
    let total = base + entries.iter().map(|(_, n)| n).sum::<usize>();
    if total <= limit {
        return None;
    }
    entries.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let largest = entries
        .iter()
        .take(3)
        .map(|(k, n)| format!("{k} ({n} bytes)"))
        .collect::<Vec<_>>()
        .join(", ");
    Some(Overrun { total, largest })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_budget_that_fits_is_not_reported() {
        let mut e = vec![("A".to_owned(), 10), ("B".to_owned(), 20)];
        assert_eq!(budget_overrun(&mut e, 70, 100), None);
        assert!(budget_overrun(&mut e, 71, 100).is_some());
    }

    #[test]
    fn the_largest_entries_are_named_biggest_first() {
        let mut e = vec![
            ("SMALL".to_owned(), 5),
            ("HUGE".to_owned(), 900),
            ("MID".to_owned(), 90),
            ("TIE_B".to_owned(), 50),
            ("TIE_A".to_owned(), 50),
        ];
        let over = budget_overrun(&mut e, 0, 100).unwrap();
        assert_eq!(over.total, 1095);
        assert_eq!(
            over.largest,
            "HUGE (900 bytes), MID (90 bytes), TIE_A (50 bytes)"
        );
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn the_kernel_limit_is_between_128_kib_and_6_mib() {
        let limit = kernel_arg_limit().unwrap();
        assert!((128 * 1024..=6 * 1024 * 1024).contains(&limit), "{limit}");
    }
}
