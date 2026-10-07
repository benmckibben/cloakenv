# AGENTS.md: cloakenv

Read `README.md`, then `docs/ARCHITECTURE.md`. This file contains the core invariants for `cloakenv`.

## Core Invariants (Do Not Break These)

1. **Zero Plaintext Secrets on Disk:**
   Secrets must NEVER be decrypted to temporary files, named pipes, or scratch disks. Decryption happens strictly in-memory into the child process's environment vector (`std::process::Command::envs`).
2. **Authenticated Encryption Only:**
   The encrypted vault format must use modern authenticated encryption (AEAD): e.g. `ChaCha20-Poly1305` or `age` with Argon2id key derivation. Unauthenticated or weak ciphers are strictly forbidden.
3. **Fail-Closed by Default:**
   If the vault is corrupted, MAC verification fails, or passphrase derivation fails, `cloakenv` aborts immediately with a clear error and exit code >0 without spawning the child command.
4. **Streaming Transcript Redaction (`--shield`):**
   When `--shield` is active, stdout and stderr must pass through an in-memory streaming filter (e.g. Aho-Corasick) that replaces any literal occurrences of decrypted secret values with `[REDACTED_BY_CLOAKENV]` before writing to parent stdout/stderr.
5. **No Secret Bleed in Errors or Logs:**
   Never log, echo, or include secret values in errors, backtraces, or debug traces.

## Code Quality & Verification Gates

- Feature branches: `feat/<name>` branched from `origin/main` (or `origin/master`).
- Formatter & Linter: `cargo fmt --check` and `cargo clippy --all-targets -- -D warnings`.
- Test suite: unit tests, integration tests with dummy vaults, and test pass rate verified 3x.
- Commit conventions: conventional commits (`feat:`, `fix:`, `chore:`, `docs:`).
