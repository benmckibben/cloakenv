# cloakenv architecture

## Modules

| module          | responsibility                                                          |
|-----------------|-------------------------------------------------------------------------|
| `src/main.rs`   | clap CLI, passphrase acquisition, exit-code mapping                     |
| `src/crypto.rs` | Argon2id key derivation, XChaCha20-Poly1305 seal/open, OS RNG           |
| `src/vault.rs`  | vault file format, in-memory map, atomic writes (0600 on Unix), `.env` parser |
| `src/perms.rs`  | advisory permission/symlink warnings for the vault and passphrase file (Unix) |
| `src/hardening.rs` | process hardening (`PR_SET_DUMPABLE`, Linux only)                    |
| `src/runner.rs` | child spawning with env injection, `--shield` streaming redactor        |
| `src/lib.rs`    | re-exports the above so integration tests can exercise them directly    |

## Cryptography

* **KDF:** Argon2id v1.3. New vaults use 64 MiB / 3 passes / 1 lane. The
  parameters live in the header; on read they must fall within
  8 MiB–1 GiB, 1–32 passes, 1–16 lanes, which caps the work an untrusted file
  can demand before authentication fails.
* **AEAD:** XChaCha20-Poly1305 with a random 192-bit nonce. A fresh salt *and*
  nonce are generated on every write, so nonce reuse is not a practical concern.
* **Associated data:** the entire 64-byte header (magic, version, algorithm
  ids, KDF parameters, salt, nonce). Flipping any header bit fails decryption.
* Key material, passphrases and decrypted values are held in
  `zeroize::Zeroizing` buffers and wiped on drop. `Debug` impls never print them.

## Vault format (v1)

Little-endian integers.

| offset | size | field                                    |
|-------:|-----:|------------------------------------------|
|      0 |    8 | magic `CLOAKENV`                         |
|      8 |    1 | format version = 1                       |
|      9 |    1 | KDF id = 1 (Argon2id v1.3)               |
|     10 |    1 | AEAD id = 1 (XChaCha20-Poly1305)         |
|     11 |    1 | reserved = 0                             |
|     12 |    4 | Argon2 memory cost (KiB)                 |
|     16 |    4 | Argon2 time cost                         |
|     20 |    4 | Argon2 parallelism                       |
|     24 |   16 | salt                                     |
|     40 |   24 | nonce                                    |
|     64 |    n | ciphertext ‖ 16-byte Poly1305 tag        |

Plaintext payload: `u32 count`, then per entry `u32 key_len, key, u32 value_len,
value` (UTF-8). Variable names are encrypted too — the file reveals only
approximate total size. The decoder rejects duplicate keys, invalid names, NUL
bytes and trailing data.

Writes go to a sibling `.vault.bin.tmp-<random>` created `O_EXCL` (with mode
0600 on Unix), are fsynced, then `rename`d over the target (and, on Unix, the
directory fsynced; the mode and the directory fsync are `cfg(unix)` and do not
happen elsewhere). `rename` replaces a symlinked `vault.bin` rather than
writing through it. Only ciphertext is ever written.

`init` also creates `.cloak/.gitignore` (`*`, `O_EXCL`, never overwritten or
followed through a symlink) when the vault directory is named `.cloak` or was
created by that `init`, so the vault cannot be committed with `git add .`;
failure to write it is a warning, not an error.

Writers (`init`, `set`, `unset`, `import`) hold an exclusive `flock(2)` on a
sibling `.vault.bin.lock` (empty, mode 0600, never deleted) for the whole
load → modify → save cycle, so concurrent updates are serialised instead of
silently overwriting each other. The lock lives on a separate file because the
vault inode is replaced on every save. Readers (`list`, `run`) take no lock;
the atomic rename already guarantees they see a complete vault. Passphrase and
value prompts happen *before* the lock is taken, so an idle prompt never
blocks other writers. `flock` is Unix only; elsewhere the lock is a no-op.

**Permission checks (Unix, advisory).** When a command opens the vault,
`src/perms.rs` warns on stderr if the vault directory is group/world-writable,
the vault file is group/world-readable or writable, either is a symlink, or
the `CLOAKENV_PASSPHRASE_FILE` in use is group/world-readable or writable. The
warnings are printed before decryption and spawning, name only paths and octal
modes, never change exit codes and never chmod anything. A loose passphrase
file is deliberately a warning, not an error: Docker/Kubernetes secret mounts
are routinely 0444/0644 and rely on the container boundary.

## Platform support

Linux and macOS are supported and tested in CI. Windows is unsupported and
untested (not built in CI; integration tests are `cfg(unix)`). Unix-only
pieces: file modes 0600/0700, directory fsync, `flock`, permission warnings,
signal exit codes (`128 + N`; on other platforms any exit status above 255
becomes 1). `PR_SET_DUMPABLE` is Linux only (see invariant 6).

## Invariants and how they are enforced

1. **Zero plaintext on disk.** Decryption happens into memory; secrets reach
   the child only via `Command::envs`. Tests assert the vault contains neither
   values nor names and that no stray files are left behind.
2. **AEAD only.** See above.
3. **Fail closed.** `run` authenticates and decrypts the whole vault *before*
   building the command. Wrong passphrase, tampered ciphertext/tag/header,
   truncation, appended data and foreign files all exit 125 without spawning
   (tests use a marker-file child to prove it was never started).
4. **Streaming redaction.** See below.
5. **No secret bleed in errors or argv.** Error types carry no values. Invalid
   variable names are not echoed (a swapped `set VALUE KEY` would otherwise
   print the secret), and `.env` parse errors report the line number only.
   `set` never takes the value as an argument (where `ps`,
   `/proc/<pid>/cmdline` and shell history would see it): it is read from a
   hidden prompt or stdin, and a stray VALUE argument is refused — without
   repeating it — before anything is written. Command-line parse errors are
   rendered by cloakenv rather than clap, keeping only the error kind, the
   names of missing arguments, "did you mean" hints drawn from our own
   argument names, and the usage line; clap's default messages quote the
   offending token. Tests feed secrets through every common misuse and check
   that no quoted fragment of them comes back.
6. **No same-user introspection (Linux).** Right after argument parsing, and
   before the passphrase is read or anything is decrypted or spawned,
   `cloakenv` calls `prctl(PR_SET_DUMPABLE, 0)` (fatal if it fails). The
   kernel then denies other processes of the same user — including the command
   `run` spawns — access to `/proc/<pid>/environ` (passphrase or passphrase
   file path), `/proc/<pid>/mem`/`ptrace` (decrypted secrets) and
   `/proc/<pid>/fd/*` (which would let a child write straight to cloakenv's
   stdout and bypass `--shield`), and no core dump is written on a crash.
   `execve` resets the flag, so children run normally. Tests run probes from
   inside `cloakenv run` and check they fail. Not covered: root /
   `CAP_SYS_PTRACE`, and **non-Linux platforms**: the call is
   `cfg(linux/android)`-gated and a no-op elsewhere, so on macOS other
   processes of the same user may be able to read cloakenv's environment
   (`CLOAKENV_PASSPHRASE` / the passphrase file path) and cloakenv does not
   disable core dumps. macOS has no `/proc`, so the `/proc/<pid>/fd` shield
   bypass does not exist there, but other macOS equivalents have not been
   assessed. Independently of platform, the child itself receives the plaintext
   in its environment, which same-user processes can read (on Linux the
   child is dumpable again after `execve`).

## `--shield` streaming redaction

stdout and stderr of the child are piped; one thread per stream reads 8 KiB
chunks and feeds them through a `Redactor` (Aho-Corasick, leftmost-longest)
before writing and flushing to the parent's corresponding stream. stdin is
inherited.

**Chunk boundaries:** with `L` = longest secret length, the redactor holds back
the last `L − 1` bytes of its buffer. Any match starting before that window is
fully determined by bytes already seen (including any longer alternative at the
same start), so it is safe to emit or redact; matches that might still be in
flight wait for more input or EOF. Output is therefore byte-for-byte identical
to redacting the whole stream at once, independent of how the OS splits reads —
tests check every chunk size from 1 to the input length.

**Known limitations** (by design for v0.1):

* Only *literal* values are matched. Transformed secrets (base64, hex,
  URL-encoded, JSON-escaped, case-changed, truncated/masked, split across lines
  by the program) are not caught.
* stdout and stderr have independent filters (one per thread): a secret split
  between the two streams is not caught, and the interleaving of stdout versus
  stderr in the output is not guaranteed to match the child's write order.
* If a stream ends while the held-back tail is a proper prefix of a secret
  (child killed, output cut off), that prefix is written in clear at EOF.
* Up to `L − 1` trailing bytes are delayed until more output arrives or the
  stream closes; a prompt without a newline may appear late.
* When two *different* secrets overlap in the output (e.g. `hunter2` and
  `2fa-token` printed as `hunter2fa-token`), leftmost-longest redacts the
  first and the non-overlapping tail of the second remains visible.
* Very short values (1–3 characters, e.g. `1`) redact every occurrence of that
  string: output is mangled and inflated (each 1-byte match becomes
  22 bytes), and seeing `[REDACTED_BY_CLOAKENV]` for a guessed string confirms
  the guess, a practical guessing oracle for such values.
* Empty values are never matched.
* Redaction only applies to the child's stdout/stderr pipes; anything the
  child writes to files, sockets or `/dev/tty` directly is not filtered.
* The pumps run until the pipes close, so a daemonised grandchild that keeps
  stdout open keeps `cloakenv` alive.
* The child process itself obviously has the plaintext secrets; `cloakenv` is
  not a sandbox.
