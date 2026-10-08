//! Rules for the vault passphrase, so that it means the same thing wherever it
//! comes from.
//!
//! The passphrase is exactly the text supplied, byte for byte, with one
//! exception per source:
//!
//! | source                         | what is used                                              |
//! |--------------------------------|-----------------------------------------------------------|
//! | `CLOAKENV_PASSPHRASE`          | the value, exactly as it is                               |
//! | `CLOAKENV_PASSPHRASE_FILE`     | the file's contents minus **one** trailing `\n` or `\r\n` |
//! | interactive prompt             | what was typed, without the Enter key                     |
//!
//! Nothing else is trimmed: leading and inner spaces, a lone trailing `\r` or a
//! second trailing newline are part of the passphrase. The only way two
//! sources can then disagree about the same intended passphrase is a
//! passphrase that ends in a line break (a file "x\n\n" is the passphrase
//! "x\n", which an environment variable set from `$(cat file)` spells "x"). So
//! `init` refuses to create a vault with a passphrase that ends in `\n` or `\r`
//! ([`ends_with_line_break`]), and a failed unlock with one says so. Existing
//! vaults are never affected: every source still yields exactly what it did
//! before.

/// Passphrases shorter than this many characters (not bytes) get a warning at
/// `init`. It is advice, not a rule: nothing is refused for being short.
pub const WEAK_BELOW_CHARS: usize = 12;

/// Whether the passphrase ends with a carriage return or line feed, which not
/// every passphrase source can express (see the module docs).
pub fn ends_with_line_break(passphrase: &str) -> bool {
    passphrase.ends_with(['\n', '\r'])
}

/// Whether the passphrase is shorter than [`WEAK_BELOW_CHARS`] characters.
pub fn is_weak(passphrase: &str) -> bool {
    passphrase.chars().count() < WEAK_BELOW_CHARS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_breaks() {
        for p in ["x\n", "x\r", "x\r\n", "x\n\n", "\n"] {
            assert!(ends_with_line_break(p), "{p:?}");
        }
        for p in ["x", "x\ny", "x ", "\ny", ""] {
            assert!(!ends_with_line_break(p), "{p:?}");
        }
    }

    #[test]
    fn weak_counts_characters_not_bytes() {
        assert!(is_weak(""));
        assert!(is_weak("12345678901"));
        assert!(!is_weak("123456789012"));
        // 11 characters, 22 bytes.
        assert!(is_weak("ééééééééééé"));
        assert!(!is_weak("éééééééééééé"));
    }
}
