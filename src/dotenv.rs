//! The `.env` grammar understood by `cloakenv import`.
//!
//! The README's "Importing a `.env` file" documents exactly this, as a table.
//! In short: one `KEY=value` per statement, optional `export `, `#` comments,
//! unquoted values, `'literal'` values and `"escaped"` values, the two quoted
//! forms may span several lines (PEM keys, JSON), line breaks may be `\n`,
//! `\r\n` or a lone `\r`, a leading byte order mark is ignored, a variable set
//! twice is an error, and nothing is ever expanded (`$VAR` stays as written).
//!
//! Errors carry a line number and a fixed reason, never any of the content: a
//! `.env` file is full of secrets and so is the line that fails to parse.

use std::collections::HashMap;

use zeroize::Zeroizing;

use crate::vault::{VaultError, is_valid_key};

/// One variable read from a `.env` file.
pub struct DotenvEntry {
    pub key: String,
    pub value: Zeroizing<String>,
    /// The line the statement starts on (1-based).
    pub line: usize,
    /// The value contains `$NAME` or `${...}` outside single quotes: another
    /// tool would expand it, cloakenv stores it as written.
    pub looks_interpolated: bool,
}

/// Parses `.env`-style content into `(KEY, value)` pairs. See the module
/// documentation for the grammar.
pub fn parse_dotenv(content: &str) -> Result<Vec<(String, Zeroizing<String>)>, VaultError> {
    Ok(parse_dotenv_entries(content)?
        .into_iter()
        .map(|e| (e.key, e.value))
        .collect())
}

/// Like [`parse_dotenv`] but also reports where each variable came from and
/// whether its value looks like it was meant to be expanded.
pub fn parse_dotenv_entries(content: &str) -> Result<Vec<DotenvEntry>, VaultError> {
    let content = content.strip_prefix('\u{feff}').unwrap_or(content);
    // Every kind of line break becomes `\n` first, like python-dotenv (which
    // reads in text mode) and the Node dotenv package do, so a file with
    // Windows or old Mac line endings parses the same everywhere. (This also
    // applies inside quotes. The `\r` escape is how to store a carriage return.)
    let normalized: Zeroizing<String>;
    let text: &str = if content.contains('\r') {
        let mut buf = Zeroizing::new(String::with_capacity(content.len()));
        let mut chars = content.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '\r' {
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
                buf.push('\n');
            } else {
                buf.push(c);
            }
        }
        normalized = buf;
        &normalized
    } else {
        content
    };

    let mut out: Vec<DotenvEntry> = Vec::new();
    let mut seen: HashMap<String, usize> = HashMap::new();
    let mut rest = text;
    let mut line_no = 1usize;
    while !rest.is_empty() {
        let start = line_no;
        let err = |reason| VaultError::Dotenv {
            line: start,
            reason,
        };
        let eol = rest.find('\n').unwrap_or(rest.len());
        let line = rest[..eol].trim();
        if line.is_empty() || line.starts_with('#') {
            rest = &rest[(eol + 1).min(rest.len())..];
            line_no += 1;
            continue;
        }
        let line = line
            .strip_prefix("export")
            .filter(|after| after.starts_with([' ', '\t']))
            .map(str::trim_start)
            .unwrap_or(line);
        let (key, after_eq) = line
            .split_once('=')
            .ok_or_else(|| err("expected KEY=VALUE"))?;
        let key = key.trim();
        if !is_valid_key(key) {
            return Err(err("invalid variable name"));
        }
        let value_text = after_eq.trim_start();
        // Where the value starts in `rest` (every slice above lies inside it).
        let value_at = value_text.as_ptr() as usize - rest.as_ptr() as usize;

        // The value, whether it is single-quoted, and where just after its
        // closing quote is (`None` for an unquoted value).
        let (value, single_quoted, after_quote) = if value_text.starts_with('\'') {
            let body = &rest[value_at + 1..];
            let close = body
                .find('\'')
                .ok_or_else(|| err("unterminated single quote"))?;
            (
                Zeroizing::new(body[..close].to_owned()),
                true,
                Some(value_at + 1 + close + 1),
            )
        } else if value_text.starts_with('"') {
            let body = &rest[value_at + 1..];
            let close =
                closing_double_quote(body).ok_or_else(|| err("unterminated double quote"))?;
            (
                unescape_double_quoted(&body[..close]),
                false,
                Some(value_at + 1 + close + 1),
            )
        } else {
            // Unquoted: up to the earliest trailing `␣#` or `<tab>#` comment.
            let value = match value_text
                .find(" #")
                .into_iter()
                .chain(value_text.find("\t#"))
                .min()
            {
                Some(i) => &value_text[..i],
                None => value_text,
            };
            (Zeroizing::new(value.trim_end().to_owned()), false, None)
        };

        // The statement ends at the line break after the closing quote, where
        // only a comment may still follow.
        let statement_end = match after_quote {
            None => eol,
            Some(after) => {
                let tail = &rest[after..];
                let tail_eol = tail.find('\n').unwrap_or(tail.len());
                if !trailing_ok(&tail[..tail_eol]) {
                    return Err(err("unexpected characters after closing quote"));
                }
                after + tail_eol
            }
        };
        if value.contains('\0') {
            return Err(err("value contains a NUL byte"));
        }
        if let Some(&first) = seen.get(key) {
            return Err(VaultError::DotenvDuplicate { line: start, first });
        }
        seen.insert(key.to_owned(), start);
        out.push(DotenvEntry {
            key: key.to_owned(),
            looks_interpolated: !single_quoted && looks_interpolated(&value),
            value,
            line: start,
        });
        line_no += rest[..statement_end]
            .bytes()
            .filter(|&b| b == b'\n')
            .count()
            + 1;
        rest = &rest[(statement_end + 1).min(rest.len())..];
    }
    Ok(out)
}

/// Index of the unescaped `"` that closes a double-quoted value whose body
/// starts at `body` (which may run on over many lines).
fn closing_double_quote(body: &str) -> Option<usize> {
    let bytes = body.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 2, // the escaped byte, whatever it is (never a lone quote)
            b'"' => return Some(i),
            _ => i += 1,
        }
    }
    None
}

/// Decodes `\n \r \t \\ \"`; any other backslash sequence is kept as written.
fn unescape_double_quoted(body: &str) -> Zeroizing<String> {
    let mut value = Zeroizing::new(String::with_capacity(body.len()));
    let mut chars = body.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            value.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => value.push('\n'),
            Some('r') => value.push('\r'),
            Some('t') => value.push('\t'),
            Some('\\') => value.push('\\'),
            Some('"') => value.push('"'),
            Some(other) => {
                value.push('\\');
                value.push(other);
            }
            None => value.push('\\'),
        }
    }
    value
}

fn trailing_ok(rest: &str) -> bool {
    let rest = rest.trim();
    rest.is_empty() || rest.starts_with('#')
}

/// `$NAME` or `${...}`: what shells and most `.env` loaders would expand.
fn looks_interpolated(value: &str) -> bool {
    value
        .as_bytes()
        .windows(2)
        .any(|w| w[0] == b'$' && (w[1] == b'{' || w[1] == b'_' || w[1].is_ascii_alphabetic()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(input: &str) -> Vec<(String, String)> {
        parse_dotenv(input)
            .unwrap()
            .into_iter()
            .map(|(k, v)| (k, v.to_string()))
            .collect()
    }

    fn pairs(list: &[(&str, &str)]) -> Vec<(String, String)> {
        list.iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    fn error_of(input: &str) -> VaultError {
        match parse_dotenv(input) {
            Err(e) => e,
            Ok(_) => panic!("{input:?} should not parse"),
        }
    }

    #[test]
    fn dotenv_syntax() {
        let input = concat!(
            "# header\n",
            "\n",
            "PLAIN=value\n",
            "  SPACED = padded value  \n",
            "export EXPORTED=1\n",
            "export\tTABBED=2\n",
            "exporter=not-an-export\n",
            "COMMENTED=abc # note\n",
            "HASH=abc#def\n",
            r"SQ='a \n # b'",
            "\n",
            r#"DQ="tab\tquote\" nl\n" # note"#,
            "\n",
            "EMPTY=\n",
            "EQ=a=b=c\n",
            "CRLF=x\r\n",
        );
        assert_eq!(
            parsed(input),
            pairs(&[
                ("PLAIN", "value"),
                ("SPACED", "padded value"),
                ("EXPORTED", "1"),
                ("TABBED", "2"),
                ("exporter", "not-an-export"),
                ("COMMENTED", "abc"),
                ("HASH", "abc#def"),
                ("SQ", r"a \n # b"),
                ("DQ", "tab\tquote\" nl\n"),
                ("EMPTY", ""),
                ("EQ", "a=b=c"),
                ("CRLF", "x"),
            ])
        );
    }

    #[test]
    fn unquoted_comment_uses_earliest_marker() {
        let cases = [
            ("TAB=val\t# comment\n", "TAB", "val"),
            ("BOTH=val\t#comment #note\n", "BOTH", "val"),
            ("SPACE_FIRST=val #note\t#later\n", "SPACE_FIRST", "val"),
            ("HASH=abc#def\n", "HASH", "abc#def"),
        ];
        for (input, key, value) in cases {
            assert_eq!(parsed(input), pairs(&[(key, value)]), "{input:?}");
        }
    }

    #[test]
    fn a_leading_byte_order_mark_is_ignored() {
        assert_eq!(
            parsed("\u{feff}A=1\nB=2\n"),
            pairs(&[("A", "1"), ("B", "2")])
        );
        // Only at the very start; one elsewhere is part of the text.
        assert_eq!(
            parsed("A=1\nB=\u{feff}x\n"),
            pairs(&[("A", "1"), ("B", "\u{feff}x")])
        );
        assert_eq!(parsed("\u{feff}# comment\nA=1"), pairs(&[("A", "1")]));
    }

    #[test]
    fn crlf_and_lone_cr_are_line_breaks() {
        assert_eq!(
            parsed("A=1\r\nB=\"two\"\r\n# c\r\nC='3'\r\n"),
            pairs(&[("A", "1"), ("B", "two"), ("C", "3")])
        );
        assert_eq!(
            parsed("A=1\rB=2\rC=3"),
            pairs(&[("A", "1"), ("B", "2"), ("C", "3")])
        );
        assert_eq!(parsed("A=1\r\r\nB=2"), pairs(&[("A", "1"), ("B", "2")]));
        // The escape is how a carriage return is stored.
        assert_eq!(parsed("A=\"x\\ry\"\r\n"), pairs(&[("A", "x\ry")]));
        // Inside quotes a line break is a plain \n, whatever the file used.
        assert_eq!(parsed("A=\"x\r\ny\rz\"\n"), pairs(&[("A", "x\ny\nz")]));
    }

    #[test]
    fn multi_line_values_in_either_kind_of_quote() {
        let pem = "KEY=\"-----BEGIN PRIVATE KEY-----\nMIIE\n\nabc=\n-----END PRIVATE KEY-----\"\nNEXT=1\n";
        assert_eq!(
            parsed(pem),
            pairs(&[
                (
                    "KEY",
                    "-----BEGIN PRIVATE KEY-----\nMIIE\n\nabc=\n-----END PRIVATE KEY-----"
                ),
                ("NEXT", "1")
            ])
        );
        assert_eq!(
            parsed("J='{\n  \"a\": \"b\\n\"\n}' # config\nZ=z"),
            pairs(&[("J", "{\n  \"a\": \"b\\n\"\n}"), ("Z", "z")])
        );
        // A KEY=VALUE-looking line and a # inside the quotes are just text.
        assert_eq!(
            parsed("T=\"a\nB=c # not a comment\n\"\n"),
            pairs(&[("T", "a\nB=c # not a comment\n")])
        );
        // An escaped quote does not end it.
        assert_eq!(parsed("Q=\"a\\\"\nb\"\n"), pairs(&[("Q", "a\"\nb")]));
    }

    #[test]
    fn line_numbers_count_the_lines_of_multi_line_values() {
        let input = "A=\"1\n2\n3\"\nB='x\ny'\nC=ok\nnot a pair\n";
        match error_of(input) {
            VaultError::Dotenv { line, .. } => assert_eq!(line, 7),
            e => panic!("{e:?}"),
        }
        // An unterminated quote is reported on the line it opened.
        match error_of("A=1\nB=\"never\nends\nhere\n") {
            VaultError::Dotenv { line, reason } => {
                assert_eq!(line, 2);
                assert_eq!(reason, "unterminated double quote");
            }
            e => panic!("{e:?}"),
        }
        match error_of("A='never\nends\n") {
            VaultError::Dotenv { line, reason } => {
                assert_eq!(line, 1);
                assert_eq!(reason, "unterminated single quote");
            }
            e => panic!("{e:?}"),
        }
    }

    #[test]
    fn text_after_a_closing_quote_is_an_error_even_after_many_lines() {
        for input in ["A=\"x\ny\" trailing\n", "A='x\ny' trailing\n", "A=\"x\"y\n"] {
            match error_of(input) {
                VaultError::Dotenv { reason, .. } => {
                    assert_eq!(
                        reason, "unexpected characters after closing quote",
                        "{input:?}"
                    )
                }
                e => panic!("{e:?}"),
            }
        }
        // A comment after it is fine, and so is the end of the file.
        assert_eq!(parsed("A=\"x\ny\" # fine"), pairs(&[("A", "x\ny")]));
    }

    #[test]
    fn a_variable_set_twice_is_an_error_naming_both_lines_only() {
        let e = error_of("SECRETNAME=1\nB=2\n# x\nexport SECRETNAME=3\n");
        match &e {
            VaultError::DotenvDuplicate { line, first } => assert_eq!((*line, *first), (4, 1)),
            other => panic!("{other:?}"),
        }
        let shown = e.to_string();
        assert!(
            shown.contains("line 4") && shown.contains("line 1"),
            "{shown}"
        );
        assert!(!shown.contains("SECRETNAME"), "{shown}");
        // Not a duplicate: different case, or a name only inside a value.
        assert_eq!(parsed("A=1\na=2\nB=\"A=3\"\n").len(), 3);
    }

    #[test]
    fn variables_are_not_expanded_and_are_flagged() {
        let input =
            "HOST=db\nURL=postgres://$HOST/x\nU2=\"${HOST}\"\nLIT='$HOST'\nPLAIN=a$\nPRICE=5$ 6\n";
        let entries = parse_dotenv_entries(input).unwrap();
        let flags: Vec<(&str, bool, &str)> = entries
            .iter()
            .map(|e| (e.key.as_str(), e.looks_interpolated, e.value.as_str()))
            .collect();
        assert_eq!(
            flags,
            vec![
                ("HOST", false, "db"),
                ("URL", true, "postgres://$HOST/x"),
                ("U2", true, "${HOST}"),
                ("LIT", false, "$HOST"),
                ("PLAIN", false, "a$"),
                ("PRICE", false, "5$ 6"),
            ]
        );
    }

    #[test]
    fn nul_bytes_and_bad_names_are_refused_by_line_only() {
        match error_of("A=1\nB=a\0b\n") {
            VaultError::Dotenv { line, reason } => {
                assert_eq!(line, 2);
                assert_eq!(reason, "value contains a NUL byte");
            }
            e => panic!("{e:?}"),
        }
        match error_of("A=\"multi\nline\0\"\n") {
            VaultError::Dotenv { line, .. } => assert_eq!(line, 1),
            e => panic!("{e:?}"),
        }
    }

    #[test]
    fn dotenv_errors_report_line_only() {
        for (input, line) in [
            ("A=1\nnot a pair\n", 2),
            ("1BAD=x\n", 1),
            ("A=1\nB=\"open\n", 2),
            ("A='open\n", 1),
            ("A='x' trailing\n", 1),
        ] {
            match parse_dotenv(input) {
                Err(VaultError::Dotenv { line: l, .. }) => assert_eq!(l, line, "{input:?}"),
                other => panic!("{input:?}: unexpected {:?}", other.map(|_| ())),
            }
        }
    }
}
