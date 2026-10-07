//! Key derivation (Argon2id) and authenticated encryption (XChaCha20-Poly1305).
//!
//! XChaCha20-Poly1305 is used rather than plain ChaCha20-Poly1305 because its
//! 192-bit nonce makes randomly generated nonces safe without any counter
//! state. A fresh salt and nonce are generated on every vault write.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use thiserror::Error;
use zeroize::Zeroizing;

/// Length of the Argon2id salt in bytes.
pub const SALT_LEN: usize = 16;
/// Length of the XChaCha20-Poly1305 nonce in bytes.
pub const NONCE_LEN: usize = 24;
/// Length of the derived symmetric key in bytes.
pub const KEY_LEN: usize = 32;
/// Length of the Poly1305 authentication tag in bytes.
pub const TAG_LEN: usize = 16;

/// Errors produced by the crypto layer. None of them carry key material,
/// passphrases or plaintext.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CryptoError {
    #[error(
        "unsupported key-derivation parameters (memory {m_cost_kib} KiB, iterations {t_cost}, lanes {p_cost})"
    )]
    InvalidKdfParams {
        m_cost_kib: u32,
        t_cost: u32,
        p_cost: u32,
    },
    #[error("key derivation failed")]
    Kdf,
    #[error("encryption failed")]
    Encrypt,
    #[error(
        "decryption failed: wrong passphrase, or the vault is corrupted or has been tampered with"
    )]
    Decrypt,
    #[error("the operating system random number generator is unavailable")]
    Rng,
}

/// Argon2id cost parameters. Stored in the (authenticated) vault header so
/// they can be raised in future versions without breaking old vaults.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory cost in KiB.
    pub m_cost_kib: u32,
    /// Number of passes.
    pub t_cost: u32,
    /// Degree of parallelism.
    pub p_cost: u32,
}

impl KdfParams {
    /// Default parameters for newly created vaults: 64 MiB, 3 passes, 1 lane.
    pub const DEFAULT: Self = Self {
        m_cost_kib: 64 * 1024,
        t_cost: 3,
        p_cost: 1,
    };
    /// Weakest parameters accepted (OWASP-ish floor): 8 MiB, 1 pass, 1 lane.
    pub const MIN: Self = Self {
        m_cost_kib: 8 * 1024,
        t_cost: 1,
        p_cost: 1,
    };
    /// Strongest parameters accepted. Bounds the work an untrusted vault file
    /// can make us do before authentication fails (1 GiB, 32 passes, 16 lanes).
    pub const MAX: Self = Self {
        m_cost_kib: 1024 * 1024,
        t_cost: 32,
        p_cost: 16,
    };

    /// Validates that the parameters fall within [`KdfParams::MIN`] and
    /// [`KdfParams::MAX`].
    pub fn validate(self) -> Result<Self, CryptoError> {
        let in_range = |v: u32, lo: u32, hi: u32| (lo..=hi).contains(&v);
        if in_range(self.m_cost_kib, Self::MIN.m_cost_kib, Self::MAX.m_cost_kib)
            && in_range(self.t_cost, Self::MIN.t_cost, Self::MAX.t_cost)
            && in_range(self.p_cost, Self::MIN.p_cost, Self::MAX.p_cost)
            // Argon2 requires at least 8 KiB of memory per lane.
            && self.m_cost_kib >= 8 * self.p_cost
        {
            Ok(self)
        } else {
            Err(CryptoError::InvalidKdfParams {
                m_cost_kib: self.m_cost_kib,
                t_cost: self.t_cost,
                p_cost: self.p_cost,
            })
        }
    }
}

impl Default for KdfParams {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// A 256-bit symmetric key that is wiped from memory on drop.
pub struct DerivedKey(Zeroizing<[u8; KEY_LEN]>);

impl std::fmt::Debug for DerivedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DerivedKey([REDACTED])")
    }
}

/// Derives a symmetric key from `passphrase` and `salt` using Argon2id v1.3.
pub fn derive_key(
    passphrase: &[u8],
    salt: &[u8; SALT_LEN],
    params: KdfParams,
) -> Result<DerivedKey, CryptoError> {
    let params = params.validate()?;
    let argon_params = Params::new(
        params.m_cost_kib,
        params.t_cost,
        params.p_cost,
        Some(KEY_LEN),
    )
    .map_err(|_| CryptoError::Kdf)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    argon
        .hash_password_into(passphrase, salt, key.as_mut_slice())
        .map_err(|_| CryptoError::Kdf)?;
    Ok(DerivedKey(key))
}

fn cipher(key: &DerivedKey) -> XChaCha20Poly1305 {
    let key: &Key = key.0.as_slice().try_into().expect("key length is fixed");
    XChaCha20Poly1305::new(key)
}

/// Encrypts `plaintext`, authenticating it together with `aad`.
/// Returns `ciphertext || tag`.
pub fn seal(
    key: &DerivedKey,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let nonce: &XNonce = nonce.as_slice().try_into().expect("nonce length is fixed");
    cipher(key)
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Encrypt)
}

/// Verifies and decrypts `ciphertext || tag`. Fails closed on any
/// authentication failure (wrong key, modified ciphertext, modified AAD).
pub fn open(
    key: &DerivedKey,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let nonce: &XNonce = nonce.as_slice().try_into().expect("nonce length is fixed");
    cipher(key)
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| CryptoError::Decrypt)
}

/// Fills an array with bytes from the operating system CSPRNG.
pub fn random_bytes<const N: usize>() -> Result<[u8; N], CryptoError> {
    let mut buf = [0u8; N];
    getrandom::fill(&mut buf).map_err(|_| CryptoError::Rng)?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(pass: &[u8], salt: &[u8; SALT_LEN]) -> DerivedKey {
        derive_key(pass, salt, KdfParams::MIN).unwrap()
    }

    #[test]
    fn roundtrip() {
        let salt = [7u8; SALT_LEN];
        let nonce = [9u8; NONCE_LEN];
        let k = key(b"correct horse", &salt);
        let ct = seal(&k, &nonce, b"hdr", b"top secret").unwrap();
        assert_eq!(ct.len(), b"top secret".len() + TAG_LEN);
        assert!(!ct.windows(10).any(|w| w == b"top secret"));
        let pt = open(&k, &nonce, b"hdr", &ct).unwrap();
        assert_eq!(pt.as_slice(), b"top secret");
    }

    #[test]
    fn wrong_key_or_aad_fails() {
        let salt = [1u8; SALT_LEN];
        let nonce = [2u8; NONCE_LEN];
        let ct = seal(&key(b"a", &salt), &nonce, b"hdr", b"data").unwrap();
        assert_eq!(
            open(&key(b"b", &salt), &nonce, b"hdr", &ct).unwrap_err(),
            CryptoError::Decrypt
        );
        assert_eq!(
            open(&key(b"a", &salt), &nonce, b"hdX", &ct).unwrap_err(),
            CryptoError::Decrypt
        );
    }

    #[test]
    fn kdf_bounds_enforced() {
        let weak = KdfParams {
            m_cost_kib: 1024,
            ..KdfParams::MIN
        };
        assert!(weak.validate().is_err());
        let huge = KdfParams {
            m_cost_kib: u32::MAX,
            ..KdfParams::DEFAULT
        };
        assert!(huge.validate().is_err());
        assert!(KdfParams::DEFAULT.validate().is_ok());
    }

    #[test]
    fn debug_does_not_leak_key() {
        let k = key(b"pw", &[0u8; SALT_LEN]);
        assert_eq!(format!("{k:?}"), "DerivedKey([REDACTED])");
    }
}
