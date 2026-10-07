//! `--shield` streaming redaction, end to end and at the library level.

mod common;

use cloakenv::runner::{REDACTION, Redactor, redact_all};
use common::*;

const R: &str = "[REDACTED_BY_CLOAKENV]";
const SECRET: &str = "sk-proj-AbCdEf0123456789";

fn redact(secrets: &[&str], input: &str) -> String {
    String::from_utf8(redact_all(secrets, input.as_bytes()).unwrap()).unwrap()
}

/// Feeds `input` through a redactor in fixed-size chunks.
fn redact_chunked(secrets: &[&str], input: &[u8], chunk: usize) -> Vec<u8> {
    let mut r = Redactor::new(secrets).unwrap();
    let mut out = Vec::new();
    for c in input.chunks(chunk) {
        r.push(c, &mut out).unwrap();
    }
    r.finish(&mut out).unwrap();
    out
}

#[test]
fn redaction_marker_is_stable() {
    assert_eq!(REDACTION, R.as_bytes());
}

#[test]
fn basic_replacement() {
    assert_eq!(
        redact(&[SECRET], &format!("key={SECRET}\n")),
        format!("key={R}\n")
    );
    assert_eq!(redact(&[SECRET], "nothing here"), "nothing here");
    assert_eq!(
        redact(&[SECRET, "hunter2"], &format!("{SECRET}{SECRET} hunter2")),
        format!("{R}{R} {R}")
    );
}

#[test]
fn longest_secret_wins_when_prefixes_overlap() {
    assert_eq!(
        redact(&["abc", "abcdef"], "xabcdefx abcx"),
        format!("x{R}x {R}x")
    );
}

#[test]
fn empty_values_are_ignored() {
    assert_eq!(redact(&["", "s3"], "a s3 b"), format!("a {R} b"));
}

#[test]
fn every_chunk_boundary_is_handled() {
    let secrets = [SECRET, "hunter2", "abc", "abcdefgh"];
    let input = format!("pre {SECRET} mid hunter2hunter2 abcdefgh abcdefg ab {SECRET}");
    let expected = redact(&secrets, &input);
    assert_eq!(expected, format!("pre {R} mid {R}{R} {R} {R}defg ab {R}"));
    for chunk in 1..=input.len() {
        let got = redact_chunked(&secrets, input.as_bytes(), chunk);
        assert_eq!(
            String::from_utf8(got).unwrap(),
            expected,
            "chunk size {chunk}"
        );
    }
}

#[test]
fn binary_and_invalid_utf8_pass_through() {
    let mut input = vec![0xff, 0x00, 0xfe];
    input.extend_from_slice(SECRET.as_bytes());
    input.push(0x80);
    let mut expected = vec![0xff, 0x00, 0xfe];
    expected.extend_from_slice(R.as_bytes());
    expected.push(0x80);
    for chunk in [1, 2, 5, 64] {
        assert_eq!(redact_chunked(&[SECRET], &input, chunk), expected);
    }
}

#[test]
fn large_streams_stay_correct() {
    let mut input = Vec::new();
    let mut expected = Vec::new();
    for i in 0..5000 {
        let line = format!("line {i} token={SECRET} ok\n");
        input.extend_from_slice(line.as_bytes());
        expected.extend_from_slice(line.replace(SECRET, R).as_bytes());
    }
    for chunk in [7, 4096, 8192, 65536] {
        assert_eq!(redact_chunked(&[SECRET], &input, chunk), expected);
    }
}

#[cfg(unix)]
mod cli {
    use super::*;

    fn shielded() -> Env {
        let env = Env::init();
        env.set("API_KEY", SECRET);
        env.set("DB_PASS", "hunter2");
        env.set("EMPTY", "");
        env
    }

    #[test]
    fn without_shield_output_is_untouched() {
        let env = shielded();
        let out = env.ok(&["run", "--", "sh", "-c", r#"printf %s "$API_KEY""#]);
        assert_eq!(stdout(&out), SECRET);
    }

    #[test]
    fn shield_redacts_stdout_and_stderr() {
        let env = shielded();
        let out = env.ok(&[
            "run",
            "--shield",
            "--",
            "sh",
            "-c",
            r#"echo "out: $API_KEY / $DB_PASS"; echo "err: $DB_PASS" >&2"#,
        ]);
        assert_eq!(stdout(&out), format!("out: {R} / {R}\n"));
        assert_eq!(stderr(&out), format!("err: {R}\n"));
        assert!(!contains(&out.stdout, SECRET) && !contains(&out.stderr, "hunter2"));
    }

    #[test]
    fn shield_redacts_secrets_split_across_writes() {
        let env = shielded();
        // Emit the secret in separate writes with pauses so it is guaranteed
        // to arrive in different pipe reads.
        let script = format!(
            "printf '{}'; sleep 0.2; printf '{}'; sleep 0.2; printf '{}\\n'",
            &SECRET[..5],
            &SECRET[5..12],
            &SECRET[12..]
        );
        let out = env.ok(&["run", "--shield", "--", "sh", "-c", &script]);
        assert_eq!(stdout(&out), format!("{R}\n"));
    }

    #[test]
    fn shield_redacts_secrets_the_child_reads_from_files() {
        // Redaction is value-based, not env-based: a secret that reaches
        // output by any route is caught.
        let env = shielded();
        std::fs::write(env.path().join("leak.log"), format!("token {SECRET}\n")).unwrap();
        let out = env.ok(&["run", "--shield", "--", "cat", "leak.log"]);
        assert_eq!(stdout(&out), format!("token {R}\n"));
    }

    #[test]
    fn shield_handles_large_output() {
        let env = shielded();
        let out = env.ok(&[
            "run",
            "--shield",
            "--",
            "sh",
            "-c",
            r#"i=0; while [ $i -lt 3000 ]; do echo "$i $API_KEY"; i=$((i+1)); done"#,
        ]);
        let text = stdout(&out);
        assert_eq!(text.lines().count(), 3000);
        assert!(!text.contains(SECRET));
        assert!(text.lines().all(|l| l.ends_with(R)));
    }

    #[test]
    fn shield_still_injects_secrets() {
        let env = shielded();
        let out = env.ok(&[
            "run",
            "--shield",
            "--",
            "sh",
            "-c",
            r#"[ "$API_KEY" = "sk-proj-AbCdEf0123456789" ] && echo injected"#,
        ]);
        assert_eq!(stdout(&out), "injected\n");
    }
}
