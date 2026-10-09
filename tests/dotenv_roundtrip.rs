//! Property and fuzz tests for the `.env` parser: whatever it is given, it
//! must neither panic nor put any content in an error, and everything cloakenv
//! documents as supported must round-trip. A small fixed-seed generator keeps
//! the runs identical everywhere (no extra dependency, nothing flaky).

use cloakenv::vault::{VaultError, parse_dotenv, parse_dotenv_entries};

/// xorshift64*: deterministic, good enough for test data.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len())]
    }
}

/// Pieces that exercise every corner of the grammar.
const TRICKY: &[&str] = &[
    "A", "KEY", "_", "1", "=", "==", " ", "  ", "\t", "\n", "\r", "\r\n", "#", " #", "\t#", "'",
    "\"", "\\", "\\n", "\\\"", "\\\\", "export ", "export", "$", "${", "}", "{", "é", "🔐",
    "\u{feff}", "\u{0}", "\u{85}", "\u{2028}", "x=y", "\"\"", "''",
];

fn random_text(rng: &mut Rng, pieces: usize) -> String {
    (0..pieces).map(|_| *rng.pick(TRICKY)).collect()
}

fn assert_error_is_content_free(input: &str, e: &VaultError) {
    let shown = e.to_string();
    let allowed = [
        "expected KEY=VALUE",
        "invalid variable name",
        "unterminated single quote",
        "unterminated double quote",
        "unexpected characters after closing quote",
        "value contains a NUL byte",
        "this variable is already set on line",
    ];
    assert!(
        shown.starts_with(".env parse error on line "),
        "{input:?}: {shown}"
    );
    assert!(
        allowed.iter().any(|a| shown.contains(a)),
        "{input:?}: {shown}"
    );
    // A real token of the input never shows up in the message (the message
    // is made of fixed words and numbers only).
    for token in input
        .split(|c: char| !c.is_alphanumeric())
        .filter(|t| t.len() >= 3)
    {
        let common = [
            "line",
            "variable",
            "already",
            "set",
            "remove",
            "one",
            "them",
            "duplicate",
            "never",
            "resolved",
            "silently",
            "parse",
            "error",
            "expected",
            "KEY",
            "VALUE",
            "invalid",
            "name",
            "unterminated",
            "single",
            "quote",
            "double",
            "unexpected",
            "characters",
            "after",
            "closing",
            "value",
            "contains",
            "NUL",
            "byte",
        ];
        if common.contains(&token) {
            continue;
        }
        assert!(!shown.contains(token), "{input:?}: {shown}");
    }
}

#[test]
fn random_input_never_panics_and_errors_never_show_content() {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let mut ok = 0;
    let mut err = 0;
    for i in 0..30_000 {
        let pieces = 1 + rng.below(24);
        let input = random_text(&mut rng, pieces);
        match parse_dotenv_entries(&input) {
            Ok(entries) => {
                ok += 1;
                for e in entries {
                    assert!(!e.value.contains('\u{0}'), "case {i}");
                    assert!(cloakenv::vault::is_valid_key(&e.key), "case {i}");
                }
            }
            Err(e) => {
                err += 1;
                assert_error_is_content_free(&input, &e);
            }
        }
    }
    // The generator must actually reach both outcomes.
    assert!(ok > 500 && err > 500, "ok {ok}, err {err}");
}

#[test]
fn random_bytes_as_lossy_text_never_panic() {
    let mut rng = Rng(0xDEAD_BEEF_CAFE_F00D);
    for _ in 0..5_000 {
        let len = rng.below(200);
        let bytes: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
        let text = String::from_utf8_lossy(&bytes);
        let _ = parse_dotenv(&text);
    }
}

const VALUE_CHARS: &[&str] = &[
    "a", "Z", "0", " ", "\t", "\n", "\r", "#", "=", "'", "\"", "\\", "$", "{", "}", "é", "🔐", "-",
    "/", ":", ".",
];

fn random_value(rng: &mut Rng) -> String {
    let len = rng.below(30);
    (0..len).map(|_| *rng.pick(VALUE_CHARS)).collect()
}

fn escape_double(value: &str) -> String {
    let mut out = String::from("\"");
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Writes a value in a form the README documents as supported, choosing at
/// random among the forms that can represent it.
fn render(rng: &mut Rng, value: &str) -> String {
    let mut forms: Vec<String> = vec![escape_double(value)];
    if !value.contains('\'') && !value.contains('\r') {
        forms.push(format!("'{value}'")); // literal, may span lines
    }
    if !value.contains('\r')
        && !value.contains('\\')
        && !value.contains('"')
        && value.contains('\n')
    {
        forms.push(format!("\"{value}\"")); // raw newlines inside double quotes
    }
    let plain = !value.is_empty()
        && value == value.trim()
        && !value.contains(['\n', '\r'])
        && !value.starts_with(['\'', '"'])
        && !value.contains(" #")
        && !value.contains("\t#");
    if plain {
        forms.push(value.to_owned());
    }
    rng.pick(&forms).clone()
}

#[test]
fn everything_the_documentation_calls_supported_round_trips() {
    let mut rng = Rng(0x0123_4567_89AB_CDEF);
    let line_ends = ["\n", "\r\n", "\r"];
    for case in 0..3_000 {
        let n = 1 + rng.below(6);
        let mut expected: Vec<(String, String)> = Vec::new();
        let mut text = String::new();
        if rng.below(4) == 0 {
            text.push('\u{feff}');
        }
        for i in 0..n {
            let key = format!("K{i}_{}", rng.below(1000));
            let value = random_value(&mut rng);
            let eol = *rng.pick(&line_ends);
            if rng.below(3) == 0 {
                text.push_str("# a comment");
                text.push_str(eol);
            }
            if rng.below(5) == 0 {
                text.push_str("export ");
            }
            text.push_str(&format!("{key}={}", render(&mut rng, &value)));
            if rng.below(4) == 0 {
                text.push_str("  # trailing comment");
            }
            text.push_str(eol);
            // Inside quotes a line break is a plain \n whatever the file used.
            expected.push((key, value));
        }
        let parsed = parse_dotenv(&text).unwrap_or_else(|e| panic!("case {case}: {text:?}: {e}"));
        let got: Vec<(String, String)> = parsed
            .into_iter()
            .map(|(k, v)| (k, v.to_string()))
            .collect();
        // Raw CR and CRLF inside a quoted value were written as \n by the
        // renderer only when escaped; raw ones normalise, so compare after
        // the same normalisation for the (rare) raw-CR single-quote case,
        // which render() excludes. Everything else must match exactly.
        assert_eq!(got, expected, "case {case}: {text:?}");
    }
}
