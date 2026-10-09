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
        "unsupported key-derivation parameters (memory {m_cost_kib} KiB, iterations {t_cost}, lanes {p_cost}); \
         this version accepts memory {min_m} to {max_m} KiB, iterations {min_t} to {max_t}, lanes {min_p} to {max_p}",
        min_m = .min.m_cost_kib,
        max_m = KdfParams::MAX.m_cost_kib,
        min_t = .min.t_cost,
        max_t = KdfParams::MAX.t_cost,
        min_p = .min.p_cost,
        max_p = KdfParams::MAX.p_cost,
    )]
    InvalidKdfParams {
        m_cost_kib: u32,
        t_cost: u32,
        p_cost: u32,
        /// The lower bound that applied to this check.
        min: KdfParams,
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
    /// Weakest parameters accepted for a *new* vault, or written by a save:
    /// 19 MiB, 2 passes, 1 lane. This is OWASP's minimum recommended Argon2id
    /// configuration, and [`KdfParams::DEFAULT`] is stronger.
    pub const MIN: Self = Self {
        m_cost_kib: 19 * 1024,
        t_cost: 2,
        p_cost: 1,
    };
    /// Weakest parameters still *readable*: 8 MiB, 1 pass, 1 lane. Earlier
    /// versions accepted these as their minimum, so a vault created through
    /// the library API with such settings must remain openable (otherwise its
    /// owner would be locked out of their secrets). They are never written
    /// back: saving raises every parameter to at least [`KdfParams::MIN`], and
    /// the CLI raises them to [`KdfParams::DEFAULT`] (see
    /// [`KdfParams::at_least`]).
    pub const FLOOR: Self = Self {
        m_cost_kib: 8 * 1024,
        t_cost: 1,
        p_cost: 1,
    };
    /// Strongest parameters accepted (256 MiB, 8 passes, 8 lanes). The KDF
    /// parameters are read from the header *before* the file is authenticated,
    /// so this bounds the memory and CPU an untrusted vault file can make us
    /// spend; it is several times stronger than [`KdfParams::DEFAULT`] in
    /// memory and passes, and costs about a second on a current machine.
    pub const MAX: Self = Self {
        m_cost_kib: 256 * 1024,
        t_cost: 8,
        p_cost: 8,
    };

    /// Validates parameters for *writing* a vault: they must fall within
    /// [`KdfParams::MIN`] and [`KdfParams::MAX`].
    pub fn validate(self) -> Result<Self, CryptoError> {
        self.validate_within(Self::MIN)
    }

    /// Validates parameters for *reading* a vault: like [`KdfParams::validate`]
    /// but the lower bound is the more lenient [`KdfParams::FLOOR`], so
    /// vaults written by earlier versions still open. The upper bound is
    /// always [`KdfParams::MAX`]: this runs on an unauthenticated header.
    pub fn validate_for_open(self) -> Result<Self, CryptoError> {
        self.validate_within(Self::FLOOR)
    }

    fn validate_within(self, min: Self) -> Result<Self, CryptoError> {
        let in_range = |v: u32, lo: u32, hi: u32| (lo..=hi).contains(&v);
        if in_range(self.m_cost_kib, min.m_cost_kib, Self::MAX.m_cost_kib)
            && in_range(self.t_cost, min.t_cost, Self::MAX.t_cost)
            && in_range(self.p_cost, min.p_cost, Self::MAX.p_cost)
            // Argon2 requires at least 8 KiB of memory per lane.
            && self.m_cost_kib >= 8 * self.p_cost
        {
            Ok(self)
        } else {
            Err(CryptoError::InvalidKdfParams {
                m_cost_kib: self.m_cost_kib,
                t_cost: self.t_cost,
                p_cost: self.p_cost,
                min,
            })
        }
    }

    /// The per-parameter maximum of `self` and `other`: every cost is at
    /// least as high as in either input.
    pub fn at_least(self, other: Self) -> Self {
        Self {
            m_cost_kib: self.m_cost_kib.max(other.m_cost_kib),
            t_cost: self.t_cost.max(other.t_cost),
            p_cost: self.p_cost.max(other.p_cost),
        }
    }

    /// Whether every parameter is at least [`KdfParams::MIN`].
    pub fn meets_min(self) -> bool {
        self == self.at_least(Self::MIN)
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
    // Lenient lower bound: this also derives keys for old, weaker vaults that
    // are being opened. Writers enforce [`KdfParams::MIN`] before they get here.
    let params = params.validate_for_open()?;
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
    fn min_is_at_least_owasp_and_default_is_at_least_min() {
        // OWASP's lowest recommended Argon2id setting: 19 MiB, t=2, p=1.
        let (min, default, floor) = (KdfParams::MIN, KdfParams::DEFAULT, KdfParams::FLOOR);
        assert!(min.m_cost_kib >= 19 * 1024 && min.t_cost >= 2 && min.p_cost >= 1);
        assert!(default.meets_min());
        assert_eq!(default.at_least(min), default);
        assert!(!floor.meets_min());
        assert!(floor.validate().is_err(), "weak params are never written");
        assert!(
            floor.validate_for_open().is_ok(),
            "but old vaults still open"
        );
    }

    #[test]
    fn below_floor_is_rejected_even_for_open() {
        for weak in [
            KdfParams {
                m_cost_kib: KdfParams::FLOOR.m_cost_kib - 1,
                ..KdfParams::FLOOR
            },
            KdfParams {
                t_cost: 0,
                ..KdfParams::FLOOR
            },
            KdfParams {
                p_cost: 0,
                ..KdfParams::FLOOR
            },
        ] {
            assert!(weak.validate_for_open().is_err(), "{weak:?}");
            assert!(derive_key(b"pw", &[0u8; SALT_LEN], weak).is_err());
        }
    }

    #[test]
    fn at_least_is_per_parameter() {
        let a = KdfParams {
            m_cost_kib: 100_000,
            t_cost: 1,
            p_cost: 4,
        };
        let up = a.at_least(KdfParams::DEFAULT);
        assert_eq!(up.m_cost_kib, 100_000);
        assert_eq!(up.t_cost, KdfParams::DEFAULT.t_cost);
        assert_eq!(up.p_cost, 4);
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
        // The previous maximum (1 GiB, 32 passes) is now refused...
        let old_max = KdfParams {
            m_cost_kib: 1024 * 1024,
            t_cost: 32,
            p_cost: 16,
        };
        assert!(old_max.validate().is_err());
        // ...exactly at the cap is fine, one step over is not.
        assert_eq!(KdfParams::MAX.validate(), Ok(KdfParams::MAX));
        for over in [
            KdfParams {
                m_cost_kib: KdfParams::MAX.m_cost_kib + 1,
                ..KdfParams::MAX
            },
            KdfParams {
                t_cost: KdfParams::MAX.t_cost + 1,
                ..KdfParams::MAX
            },
            KdfParams {
                p_cost: KdfParams::MAX.p_cost + 1,
                ..KdfParams::MAX
            },
        ] {
            assert!(over.validate().is_err(), "{over:?}");
        }
    }

    #[test]
    fn rejected_params_are_never_derived() {
        // Must fail instantly: no 1 GiB allocation, no 32 passes.
        let started = std::time::Instant::now();
        let err = derive_key(
            b"pw",
            &[0u8; SALT_LEN],
            KdfParams {
                m_cost_kib: 1024 * 1024,
                t_cost: 32,
                p_cost: 1,
            },
        )
        .unwrap_err();
        assert!(matches!(err, CryptoError::InvalidKdfParams { .. }));
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
        let msg = err.to_string();
        assert!(msg.contains("262144") && msg.contains("accepts"), "{msg}");
        assert!(KdfParams::DEFAULT.validate().is_ok());
    }

    #[test]
    fn debug_does_not_leak_key() {
        let k = key(b"pw", &[0u8; SALT_LEN]);
        assert_eq!(format!("{k:?}"), "DerivedKey([REDACTED])");
    }
}
