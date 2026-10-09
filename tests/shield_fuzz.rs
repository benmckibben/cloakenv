//! The `--shield` redactor against a deliberately naive reference, on random
//! secrets (overlapping, prefix-related, binary), random input and random
//! chunkings: the output must equal the reference's, no secret may ever reach
//! the output, and the redactor must hold back exactly the bytes that could
//! still turn into a secret, and release everything else at once.

use cloakenv::runner::{REDACTION, Redactor};

/// xorshift64*: deterministic, no dependency.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % u64::try_from(n).unwrap()).unwrap()
    }

    fn pick(&mut self, alphabet: &[u8]) -> u8 {
        alphabet[self.below(alphabet.len())]
    }

    fn bytes(&mut self, alphabet: &[u8], len: usize) -> Vec<u8> {
        (0..len).map(|_| self.pick(alphabet)).collect()
    }
}

/// True if `rest` is a *proper* prefix of some secret: more input could still
/// complete it.
fn could_grow(secrets: &[Vec<u8>], rest: &[u8]) -> bool {
    secrets
        .iter()
        .any(|s| s.len() > rest.len() && s.starts_with(rest))
}

/// Leftmost-longest redaction of a whole stream, the slow obvious way. If
/// `complete` is false the stream may continue: the output stops at the first
/// position whose remaining input could still grow into a secret, and the
/// number of bytes held back is returned with it.
fn reference(secrets: &[Vec<u8>], input: &[u8], complete: bool) -> (Vec<u8>, usize) {
    let mut out = Vec::new();
    let mut i = 0;
    while i < input.len() {
        let rest = &input[i..];
        if !complete && could_grow(secrets, rest) {
            return (out, rest.len());
        }
        let longest = secrets
            .iter()
            .filter(|s| rest.starts_with(s))
            .map(Vec::len)
            .max();
        match longest {
            Some(len) => {
                out.extend_from_slice(REDACTION);
                i += len;
            }
            None => {
                out.push(input[i]);
                i += 1;
            }
        }
    }
    (out, 0)
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// Feeds `input` in the given chunk sizes and checks, after every push, the
/// whole contract against the reference.
fn check(secrets: &[Vec<u8>], input: &[u8], chunks: &[usize]) {
    let mut r = Redactor::new(secrets).unwrap();
    let mut out = Vec::new();
    let mut fed = 0;
    for &n in chunks {
        let n = n.min(input.len() - fed);
        r.push(&input[fed..fed + n], &mut out).unwrap();
        fed += n;
        let (expected, held) = reference(secrets, &input[..fed], false);
        assert_eq!(
            (&out, r.held()),
            (&expected, held),
            "secrets {secrets:?}, input {input:?}, after {fed} bytes"
        );
        for s in secrets {
            assert!(!contains(&out, s), "secret reached the output: {secrets:?}");
        }
    }
    r.push(&input[fed..], &mut out).unwrap();
    r.finish(&mut out).unwrap();
    assert_eq!(r.held(), 0);
    let (expected, _) = reference(secrets, input, true);
    assert_eq!(out, expected, "secrets {secrets:?}, input {input:?}");
    for s in secrets {
        assert!(!contains(&out, s), "secret reached the output: {secrets:?}");
    }
}

fn run_fuzz(
    seed: u64,
    rounds: usize,
    secret_alphabet: &[u8],
    input_alphabet: &[u8],
    max_len: usize,
) {
    let mut rng = Rng(seed);
    for _ in 0..rounds {
        let count = 1 + rng.below(4);
        let mut secrets: Vec<Vec<u8>> = Vec::new();
        for _ in 0..count {
            let len = 1 + rng.below(max_len);
            secrets.push(rng.bytes(secret_alphabet, len));
        }
        // Make prefix-related secrets likely.
        if rng.below(2) == 0 {
            let base = secrets[0].clone();
            let cut = 1 + rng.below(base.len());
            secrets.push(base[..cut].to_vec());
        }
        let len = rng.below(120);
        let mut input = rng.bytes(input_alphabet, len);
        // Sprinkle whole secrets and fragments of them.
        for _ in 0..rng.below(5) {
            let s = &secrets[rng.below(secrets.len())];
            let (from, to) = if rng.below(2) == 0 {
                (0, s.len())
            } else {
                (0, 1 + rng.below(s.len()))
            };
            let at = rng.below(input.len() + 1);
            input.splice(at..at, s[from..to].iter().copied());
        }
        let mut chunks = Vec::new();
        let mut total = 0;
        while total < input.len() {
            let span = 1 + rng.below(25);
            let n = 1 + rng.below(span);
            chunks.push(n);
            total += n;
        }
        check(&secrets, &input, &chunks);
    }
}

#[test]
fn text_secrets_with_heavy_overlap_match_the_reference() {
    run_fuzz(1, 4000, b"abc", b"abcx ", 7);
    run_fuzz(2, 4000, b"ab", b"abab", 10);
}

#[test]
fn binary_secrets_and_input_match_the_reference() {
    // Bytes outside the redaction marker's own, so the marker can never
    // complete a secret.
    let bin = [0x00, 0x01, 0x80, 0xfe, 0xff];
    run_fuzz(
        3,
        4000,
        &bin,
        &[0x00, 0x01, 0x80, 0xfe, 0xff, 0x7f, 0x0a],
        8,
    );
    let all: Vec<u8> = (0u8..=255).filter(|b| !REDACTION.contains(b)).collect();
    run_fuzz(4, 2000, &all, &all, 6);
}

#[test]
fn every_chunking_of_a_fixed_stream_gives_the_same_output() {
    let secrets: Vec<Vec<u8>> = ["sk-live-1234", "sk-live", "hunter2", "r2d2", "2fa-token"]
        .iter()
        .map(|s| s.as_bytes().to_vec())
        .collect();
    let input = b"a sk-live-1234 b sk-live c hunter2fa-token d r2d2d2 e sk-liv f sk-live-123 g";
    for chunk in 1..=input.len() {
        let chunks = vec![chunk; input.len() / chunk + 1];
        check(&secrets, input, &chunks);
    }
}

#[test]
fn bytes_that_cannot_start_a_secret_are_released_at_once() {
    let mut r = Redactor::new(["sk-live-abc123"]).unwrap();
    let mut out = Vec::new();
    // A prompt without a newline: nothing in it can begin the secret.
    r.push(b"Enter name: ", &mut out).unwrap();
    assert_eq!(out, b"Enter name: ");
    assert_eq!(r.held(), 0);
    // A line of ordinary output, even one that ends in a letter that does
    // not start the secret.
    r.push(b"listening on port 8080", &mut out).unwrap();
    assert_eq!(out, b"Enter name: listening on port 8080");
    assert_eq!(r.held(), 0);
}

#[test]
fn only_a_trailing_partial_secret_is_held() {
    let mut r = Redactor::new(["sk-live-abc123"]).unwrap();
    let mut out = Vec::new();
    r.push(b"token sk-li", &mut out).unwrap();
    assert_eq!(out, b"token ");
    assert_eq!(r.held(), 5);
    // Not a secret after all: the held bytes follow as soon as that is known.
    r.push(b"ke it", &mut out).unwrap();
    assert_eq!(out, b"token sk-like it");
    assert_eq!(r.held(), 0);
    // ...and a real one is redacted once it is complete.
    r.push(b" sk-live-abc", &mut out).unwrap();
    assert_eq!(r.held(), 11);
    r.push(b"123!", &mut out).unwrap();
    assert_eq!(out, b"token sk-like it [REDACTED_BY_CLOAKENV]!".as_slice());
    assert_eq!(r.held(), 0);
}

#[test]
fn a_held_partial_secret_is_never_released_by_waiting() {
    // There is no timer: only more input or the end of the stream releases
    // held bytes, and at the end a partial secret is written as is (it is
    // not a secret).
    let mut r = Redactor::new(["sk-live-abc123"]).unwrap();
    let mut out = Vec::new();
    r.push(b"sk-live-ab", &mut out).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(50));
    assert!(out.is_empty());
    assert_eq!(r.held(), 10);
    r.finish(&mut out).unwrap();
    assert_eq!(out, b"sk-live-ab");
}

#[test]
fn a_complete_secret_nothing_continues_is_redacted_at_once() {
    let mut r = Redactor::new(["abc"]).unwrap();
    let mut out = Vec::new();
    r.push(b"xabc", &mut out).unwrap();
    assert_eq!(out, b"x[REDACTED_BY_CLOAKENV]");
    assert_eq!(r.held(), 0);
    // But when a longer secret starts with it, it has to wait.
    let mut r = Redactor::new(["abc", "abcdef"]).unwrap();
    let mut out = Vec::new();
    r.push(b"xabc", &mut out).unwrap();
    assert_eq!(out, b"x");
    assert_eq!(r.held(), 3);
    r.push(b"def", &mut out).unwrap();
    assert_eq!(out, b"x[REDACTED_BY_CLOAKENV]");
    // A short secret does not wait because some other secret is long.
    let mut r = Redactor::new(["abc", "wxyzwxyz"]).unwrap();
    let mut out = Vec::new();
    r.push(b"xabc", &mut out).unwrap();
    assert_eq!(out, b"x[REDACTED_BY_CLOAKENV]");
    assert_eq!(r.held(), 0);
}

#[test]
fn nothing_is_held_without_secrets() {
    let none: [&[u8]; 0] = [];
    let mut r = Redactor::new(none).unwrap();
    let mut out = Vec::new();
    r.push(b"anything", &mut out).unwrap();
    assert_eq!(out, b"anything");
    assert_eq!(r.held(), 0);
}

/// A stream that looks like the start of a long self-overlapping secret for
/// its whole length: the exact holdback would be quadratic to work out, so the
/// redactor falls back to holding the whole window. The output is still
/// right and nothing leaks.
#[test]
fn a_stream_that_imitates_a_long_secret_stays_correct() {
    let mut secret = vec![b'x'; 6000];
    secret.push(b'y');
    let secrets = [secret.clone()];
    let mut r = Redactor::new(&secrets).unwrap();
    let mut out = Vec::new();
    let mut input = vec![b'x'; 30_000];
    input.extend_from_slice(&secret);
    input.extend_from_slice(b"end");
    for chunk in input.chunks(997) {
        r.push(chunk, &mut out).unwrap();
        assert!(r.held() < secret.len(), "held {}", r.held());
        assert!(!contains(&out, &secret));
    }
    r.finish(&mut out).unwrap();
    let mut expected = vec![b'x'; 30_000];
    expected.extend_from_slice(REDACTION);
    expected.extend_from_slice(b"end");
    assert_eq!(out, expected);
}

/// Compiling a long value that overlaps itself must not take super-linear
/// time. Before, 16 KiB of `x` took 0.5 s to compile, 64 KiB took 8 s and
/// 200 KB took over 20 s. The bound is generous on purpose (10 s for each of
/// several sizes, against well under a second even in a debug build on a machine
/// with a load average of 28; the dependency is built with optimisations in the
/// dev profile for this): it exists to catch a return of the quadratic build, not
/// to time the machine.
#[test]
fn building_the_filter_for_long_values_is_fast() {
    for len in [16 * 1024, 64 * 1024, 200 * 1024, 1024 * 1024] {
        for fill in *b"xa" {
            let secret = vec![fill; len];
            let start = std::time::Instant::now();
            let mut r = Redactor::new([&secret]).unwrap();
            let build = start.elapsed();
            eprintln!("{len} bytes of {}: build {build:?}", fill as char);
            let mut out = Vec::new();
            let mut input = b"before ".to_vec();
            input.extend_from_slice(&secret);
            input.extend_from_slice(b" after");
            r.push(&input, &mut out).unwrap();
            r.finish(&mut out).unwrap();
            assert_eq!(out, b"before [REDACTED_BY_CLOAKENV] after");
            eprintln!(
                "{len} bytes of {}: build and redact {:?}",
                fill as char,
                start.elapsed()
            );
            assert!(
                start.elapsed() < std::time::Duration::from_secs(10),
                "{len} bytes of {}: build {build:?}, total {:?}",
                fill as char,
                start.elapsed()
            );
        }
    }
}

/// Throughput check, run by hand: `cargo test --release --test shield_fuzz --
/// --ignored --nocapture`. 100 MB of output without a newline, typical
/// (20 secrets of 24 bytes) and worst-ish (output made of the secrets' own
/// first bytes), in 8 KiB chunks like the pumps.
#[test]
#[ignore = "benchmark: run by hand in release mode"]
fn redaction_throughput_on_100_mb_without_a_newline() {
    let mut rng = Rng(9);
    let letters = b"abcdefghijklmnopqrstuvwxyz";
    let secrets: Vec<Vec<u8>> = (0..20).map(|_| rng.bytes(letters, 24)).collect();
    let text = rng.bytes(letters, 100_000_000);
    let mut r = Redactor::new(&secrets).unwrap();
    let mut out = Vec::with_capacity(32 * 1024);
    let start = std::time::Instant::now();
    let mut total = 0usize;
    for chunk in text.chunks(8192) {
        out.clear();
        r.push(chunk, &mut out).unwrap();
        total += out.len();
    }
    r.finish(&mut out).unwrap();
    let took = start.elapsed();
    eprintln!("100 MB in {took:?} ({total} bytes out)");
    assert!(took < std::time::Duration::from_secs(1), "{took:?}");
}
