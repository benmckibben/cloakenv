# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Nothing has been released yet. This section lists everything the first release
will contain. (The crate name is reserved on crates.io by a `0.0.0` placeholder
that has no functionality; it is not a release of this code.)

### Added

- An encrypted local vault (`.cloak/vault.bin`, or `--vault` / `CLOAKENV_VAULT`):
  Argon2id key derivation (64 MiB, 3 passes, 1 lane by default) and
  XChaCha20-Poly1305 authenticated encryption, with the whole header
  authenticated. Names and values are both encrypted.
- Subcommands: `init` (`--force` to start over), `set KEY` (value from a hidden
  prompt or stdin, never from the command line), `unset`, `import FILE` (a
  `.env` file), `list` (names only) and `run [--shield] -- COMMAND`.
- `run` injects the vault into the command's environment; nothing is decrypted
  to disk. `--shield` streams the command's stdout and stderr through an
  in-memory redactor that replaces literal secret values with
  `[REDACTED_BY_CLOAKENV]`, including values split across read boundaries.
- `run` takes its command only after `--` (`cloakenv run [OPTIONS] -- COMMAND
  [ARGS]...`). Everything after the command's name belongs to the command, so a
  `--shield` typed after it can no longer be passed to the command silently (and
  leave its output unredacted); a command without `--`, or an unknown option
  before it, is a usage error (exit 2) and nothing is started.
- Passphrase from `CLOAKENV_PASSPHRASE`, `CLOAKENV_PASSPHRASE_FILE` or a
  terminal prompt. Both variables are removed from the command's environment
  and can't be stored as vault entries.
- Fail closed: a wrong passphrase, a tampered or truncated vault or a foreign
  file stops `run` with exit code 125 before anything is started.
- Linux and macOS support, tested in CI on Ubuntu 24.04 and macOS 15 with stable
  Rust and, on Linux, the MSRV (Rust 1.87). Windows is unsupported.
- CI: rustfmt, clippy, tests, and a `cargo-deny` audit (RustSec advisories,
  licences, bans, sources; also run weekly); Dependabot for Actions and Cargo.
- A build-only release workflow that produces release archives (Linux x86_64 and
  aarch64, static musl; macOS aarch64 and x86_64) and `SHA256SUMS` as
  workflow-run artifacts, after checking the tag against the crate version and
  running the CI checks and a `cargo package` content check. It publishes nothing.
- `SECURITY.md`, `CONTRIBUTING.md` and this changelog.
- A threat model in the README, and `docs/ARCHITECTURE.md` (vault format,
  cryptography, process model, memory hygiene, and a design proposal for
  rollback protection that is not implemented).

### Security

Findings from a security audit of the first version, all fixed before release
(`C` numbers are the audit's finding numbers):

- C1: writers (`init`, `set`, `unset`, `import`) hold an exclusive `flock` for
  their whole load-modify-save cycle, so concurrent `cloakenv set` calls no
  longer lose updates. A filesystem without working locks makes writers refuse
  to run instead of going ahead unprotected.
- C2, C5: on Linux cloakenv marks itself non-dumpable at startup
  (`PR_SET_DUMPABLE`), so other processes of the same user can't read the
  passphrase from `/proc/<pid>/environ`, inspect its memory, or write around
  `--shield` through `/proc/<pid>/fd`, and no core file is written. On every
  Unix it also lowers its own core-file size limit to 0 (covering
  `fs.suid_dumpable=2` and macOS) and hands the original limit back to the
  command.
- C3, C4: no secret is ever read from, or echoed back from, the command line.
  `cloakenv set KEY VALUE` is refused with an error that doesn't repeat the value;
  invalid variable names are not echoed; usage errors are rendered by cloakenv
  rather than clap (which quotes the offending argument) and exit with code 2.
- C6: key-derivation parameters in the (not yet authenticated) vault header are
  capped (256 MiB, 8 passes, 8 lanes), so a hostile file can't force a huge
  allocation or many seconds of CPU.
- C7: the vault is opened once and the open handle is checked; only regular
  files of at most 16 MiB are read (no `/dev/zero`, FIFO, directory or huge file),
  with a hard read cap.
- C8: `run` without `--shield` replaces cloakenv with the command (`execve`), so
  there is no cloakenv process left to probe or orphan, and signals and exit
  status are the command's own. With `--shield` cloakenv forwards `SIGTERM`,
  `SIGHUP`, `SIGINT`, `SIGQUIT`, `SIGUSR1` and `SIGUSR2` to the command, and on
  Linux has the kernel kill the command if cloakenv dies. Output pumps stop
  shortly after the command exits even if a leftover background process holds
  the pipes open.
- C9: `run --shield` warns, naming the keys, about vault values shorter than 6
  bytes, which are redacted so broadly that the marker confirms a guess.
- C11: `init` writes `.cloak/.gitignore` so the vault never shows up in
  `git add .`.
- C12: warnings (not errors) for a vault directory that is group/world-writable,
  a vault or passphrase file that is group/world-readable or writable, and a
  symlinked vault or vault directory.
- C13: decrypted values, the passphrase and the raw child output are kept in
  buffers that are wiped, and no longer in stale copies left by growing reads;
  the vault is dropped as soon as the command has started.
- C14: new vaults are never weaker than OWASP's minimum Argon2id setting
  (19 MiB, 2 passes). Older, weaker vaults still open, with a warning, and are
  upgraded the next time `set`, `unset` or `import` saves them.
- C15: a closed output pipe (`cloakenv list | head -1`) ends quietly instead of
  panicking.
- C16: one set of passphrase rules for all three sources. A source that is set
  but unusable is an error, never a silent fallback; `init` refuses a passphrase
  ending in a line break (which the sources would read differently) and warns
  about one shorter than 12 characters.
- C18: `Debug` output of the parsed command line never shows an argument.
- `import` reads its file with the same care as the vault: regular files only, at
  most 16 MiB, into a buffer that is wiped afterwards.
- C10, C17, C18: the README documents what `--shield` does and doesn't catch,
  platform differences, and an end-to-end threat model, including the known
  rollback limit (anyone who can write the vault's directory can put back an
  older valid vault).

### Fixed

- A missing vault no longer creates a vault directory or lock file when `set`,
  `unset` or `import` fail, and error causes are printed once.
- The key-derivation upgrade notice is only printed after the vault was
  actually saved.

[Unreleased]: https://github.com/benmckibben/cloakenv/commits/main
