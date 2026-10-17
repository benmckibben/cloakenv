//! Format-aware reading and writing of vault files: version 1 and version 2 behind one type.
//!
//! [`Vault`] itself is only the entries and the key-derivation settings, and its own `seal`, `open`, `load` and `save`
//! are version 1 only. [`Loaded`] adds what version 2 files carry besides the entries (the vault id, the generation, the
//! tag of the version that was read, the extension records) and writes back the format it read, so a version 1 vault
//! stays version 1 until the owner runs an explicit upgrade (see the design, "Migration and compatibility").
//!
//! This module does not look at the rollback state file; callers compare [`Loaded::observed`] with
//! [`state::check`](super::state::check) after a successful open, and record a save the same way.

use std::path::Path;

use super::state::Observed;
use super::v2::{self, Extension, VAULT_ID_LEN};
use super::{Vault, VaultError, read_vault_file, write_atomic_private};
use crate::crypto::{self, TAG_LEN};

/// What a vault file carries besides its entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Meta {
    /// Format version 1: no id, no generation, no extensions.
    V1,
    /// Format version 2. A generation of 0 means "never saved": the first save writes generation 1.
    V2 {
        id: [u8; VAULT_ID_LEN],
        generation: u64,
        /// The tag of the version that was read or written last (all zero before the first save).
        tag: [u8; TAG_LEN],
        /// Extension records as read, kept so that a save does not drop optional fields a newer release wrote.
        extensions: Vec<Extension>,
    },
}

/// A vault together with the format it was read in.
#[derive(Debug)]
pub struct Loaded {
    pub vault: Vault,
    pub meta: Meta,
}

impl Loaded {
    /// An empty vault that will be written as format 2, with a fresh random vault id.
    pub fn new() -> Result<Self, VaultError> {
        Self::from_vault_v2(Vault::new())
    }

    /// Wraps `vault` to be written as format 2 with a fresh random vault id (the first save writes generation 1).
    /// This is what `upgrade` does with a vault read from a version 1 file.
    pub fn from_vault_v2(vault: Vault) -> Result<Self, VaultError> {
        Ok(Loaded {
            vault,
            meta: Meta::V2 {
                id: crypto::random_bytes()?,
                generation: 0,
                tag: [0; TAG_LEN],
                extensions: Vec::new(),
            },
        })
    }

    /// The format version: 1 or 2.
    pub fn format(&self) -> u8 {
        match self.meta {
            Meta::V1 => 1,
            Meta::V2 { .. } => 2,
        }
    }

    /// What the rollback check compares: nothing for a vault that has never been saved.
    pub fn observed(&self) -> Option<Observed> {
        match &self.meta {
            Meta::V1 => Some(Observed::V1),
            Meta::V2 { generation: 0, .. } => None,
            Meta::V2 {
                id,
                generation,
                tag,
                ..
            } => Some(Observed::V2 {
                id: *id,
                generation: *generation,
                tag: *tag,
            }),
        }
    }

    /// Authenticates and decrypts the complete contents of a vault file of either format.
    pub fn open(bytes: &[u8], passphrase: &[u8]) -> Result<Self, VaultError> {
        match v2::format_version(bytes)? {
            1 => Ok(Loaded {
                vault: Vault::open(bytes, passphrase)?,
                meta: Meta::V1,
            }),
            2 => {
                let o = v2::open(bytes, passphrase)?;
                Ok(Loaded {
                    vault: o.vault,
                    meta: Meta::V2 {
                        id: o.vault_id,
                        generation: o.generation,
                        tag: o.tag,
                        extensions: o.extensions,
                    },
                })
            }
            other => Err(VaultError::UnsupportedVersion(other)),
        }
    }

    /// Reads and decrypts a vault file with the same checks as [`Vault::load`] (one open, a regular file, at most 16 MiB).
    pub fn load(path: &Path, passphrase: &[u8]) -> Result<Self, VaultError> {
        let bytes = read_vault_file(path)?;
        Self::open(&bytes, passphrase)
    }

    /// Encrypts and atomically writes the vault in the format it has: format 1 as before, format 2 with the generation
    /// raised by one and a fresh salt and nonce. Afterwards `self` describes what is now on disk.
    ///
    /// The caller must hold the vault's write lock across load, change and save (the generation it raises is the one it
    /// read). On error nothing changed on disk and `self` is unchanged.
    pub fn save(&mut self, path: &Path, passphrase: &[u8]) -> Result<(), VaultError> {
        match &mut self.meta {
            Meta::V1 => self.vault.save(path, passphrase),
            Meta::V2 {
                id,
                generation,
                tag,
                extensions,
            } => {
                let next = generation.checked_add(1).ok_or(VaultError::Malformed)?;
                let bytes = v2::seal(&self.vault, id, next, extensions, passphrase)?;
                write_atomic_private(path, &bytes)?;
                *generation = next;
                tag.copy_from_slice(&bytes[bytes.len() - TAG_LEN..]);
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{CryptoError, KdfParams};
    use std::fs;
    use zeroize::Zeroizing;

    const PASS: &[u8] = b"file module test passphrase";

    fn entries(l: &Loaded) -> Vec<(String, String)> {
        l.vault
            .iter()
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect()
    }

    fn fresh_with(pairs: &[(&str, &str)]) -> Loaded {
        let mut l = Loaded::from_vault_v2(Vault::with_params(KdfParams::MIN).unwrap()).unwrap();
        for (k, v) in pairs {
            l.vault.set(k, Zeroizing::new((*v).to_owned())).unwrap();
        }
        l
    }

    fn generation_of(l: &Loaded) -> u64 {
        match l.meta {
            Meta::V2 { generation, .. } => generation,
            Meta::V1 => panic!("not format 2"),
        }
    }

    #[test]
    fn a_new_vault_is_format_2_and_unsaved_until_it_is_written() {
        let l = Loaded::new().unwrap();
        assert_eq!(l.format(), 2);
        assert_eq!(generation_of(&l), 0);
        assert!(
            l.observed().is_none(),
            "nothing to compare before the first save"
        );
        let (a, b) = (Loaded::new().unwrap(), Loaded::new().unwrap());
        let (Meta::V2 { id: ia, .. }, Meta::V2 { id: ib, .. }) = (&a.meta, &b.meta) else {
            panic!()
        };
        assert_ne!(ia, ib, "every vault gets its own random id");
        assert_ne!(*ia, [0u8; VAULT_ID_LEN]);
    }

    #[test]
    fn each_save_raises_the_generation_keeps_the_id_and_changes_the_tag() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.bin");
        let mut l = fresh_with(&[("A", "1")]);
        let Meta::V2 { id, .. } = l.meta.clone() else {
            panic!()
        };
        let mut tags = Vec::new();
        for want in 1..=3u64 {
            l.save(&path, PASS).unwrap();
            assert_eq!(generation_of(&l), want);
            let Some(Observed::V2 {
                id: oid,
                generation,
                tag,
            }) = l.observed()
            else {
                panic!("observed")
            };
            assert_eq!((oid, generation), (id, want));
            tags.push(tag);
            // what is on disk is what self says
            let back = Loaded::load(&path, PASS).unwrap();
            assert_eq!(back.meta, l.meta, "generation {want}");
            assert_eq!(entries(&back), entries(&l));
        }
        assert!(
            tags[0] != tags[1] && tags[1] != tags[2],
            "a new salt and nonce every time: {tags:?}"
        );
    }

    #[test]
    fn extensions_a_newer_release_wrote_survive_a_save() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.bin");
        let ext = vec![Extension {
            kind: 0x0042,
            value: vec![9, 8, 7],
        }];
        let mut v = Vault::with_params(KdfParams::MIN).unwrap();
        v.set("K", Zeroizing::new("v".to_owned())).unwrap();
        fs::write(&path, v2::seal(&v, &[3; 16], 4, &ext, PASS).unwrap()).unwrap();
        let mut l = Loaded::load(&path, PASS).unwrap();
        l.save(&path, PASS).unwrap();
        let again = Loaded::load(&path, PASS).unwrap();
        let Meta::V2 {
            generation,
            extensions,
            id,
            ..
        } = again.meta
        else {
            panic!()
        };
        assert_eq!((generation, id), (5, [3; 16]));
        assert_eq!(extensions, ext);
    }

    #[test]
    fn a_format_1_vault_stays_format_1_when_saved() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.bin");
        let mut v = Vault::with_params(KdfParams::MIN).unwrap();
        v.set("K", Zeroizing::new("old".to_owned())).unwrap();
        v.save(&path, PASS).unwrap();
        let mut l = Loaded::load(&path, PASS).unwrap();
        assert_eq!((l.format(), l.observed()), (1, Some(Observed::V1)));
        l.vault.set("K2", Zeroizing::new("new".to_owned())).unwrap();
        l.save(&path, PASS).unwrap();
        assert_eq!(fs::read(&path).unwrap()[8], 1, "still format 1");
        assert_eq!(l.meta, Meta::V1);
        let plain = Vault::load(&path, PASS).unwrap();
        assert_eq!(plain.len(), 2, "the version 1 reader still opens it");
    }

    #[test]
    fn a_format_1_fixture_from_a_released_binary_opens_through_the_format_aware_reader() {
        let bytes = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/v1/one.bin"
        ));
        let l = Loaded::open(bytes, b"golden-v1-fixture-passphrase").unwrap();
        assert_eq!(l.meta, Meta::V1);
        assert_eq!(
            entries(&l),
            vec![("GREETING".to_owned(), "hello".to_owned())]
        );
    }

    #[test]
    fn unknown_versions_and_garbage_are_refused_with_the_right_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.bin");
        let mut l = fresh_with(&[]);
        l.save(&path, PASS).unwrap();
        let good = fs::read(&path).unwrap();
        for version in [0u8, 3, 255] {
            let mut b = good.clone();
            b[8] = version;
            assert!(
                matches!(Loaded::open(&b, PASS), Err(VaultError::UnsupportedVersion(v)) if v == version),
                "version {version}"
            );
        }
        assert!(matches!(
            Loaded::open(b"not a vault at all", PASS),
            Err(VaultError::BadMagic)
        ));
        assert!(matches!(
            Loaded::open(&good[..8], PASS),
            Err(VaultError::Malformed)
        ));
        assert!(matches!(
            Loaded::open(&good, b"wrong"),
            Err(VaultError::Crypto(CryptoError::Decrypt))
        ));
    }

    #[test]
    fn a_failed_save_leaves_the_object_and_the_file_as_they_were() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.bin");
        let mut l = fresh_with(&[("A", "1")]);
        l.save(&path, PASS).unwrap();
        let before = (l.meta.clone(), fs::read(&path).unwrap());
        // a directory in the way: the final rename must fail
        let blocked = dir.path().join("blocked");
        fs::create_dir(&blocked).unwrap();
        assert!(l.save(&blocked, PASS).is_err());
        assert_eq!(
            (l.meta.clone(), fs::read(&path).unwrap()),
            before,
            "nothing changed"
        );
        // the generation counter cannot wrap
        if let Meta::V2 { generation, .. } = &mut l.meta {
            *generation = u64::MAX;
        }
        assert!(matches!(l.save(&path, PASS), Err(VaultError::Malformed)));
        assert_eq!(
            fs::read(&path).unwrap(),
            before.1,
            "the file was not touched"
        );
    }

    #[test]
    fn upgrading_a_vault_keeps_its_entries_and_gets_a_new_identity() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.bin");
        let mut v = Vault::with_params(KdfParams::MIN).unwrap();
        v.set("K", Zeroizing::new("kept".to_owned())).unwrap();
        v.save(&path, PASS).unwrap();
        let old = Loaded::load(&path, PASS).unwrap();
        let mut up = Loaded::from_vault_v2(old.vault).unwrap();
        up.save(&path, PASS).unwrap();
        let back = Loaded::load(&path, PASS).unwrap();
        assert_eq!((back.format(), generation_of(&back)), (2, 1));
        assert_eq!(entries(&back), vec![("K".to_owned(), "kept".to_owned())]);
    }
}
