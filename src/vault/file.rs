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
