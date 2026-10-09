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

- The "vault directory is group/world-writable" warning is no longer printed on
  every command in an ordinary project directory. With the default umask 0002
  (Debian, Ubuntu) such a directory is `0775` in the user's own one-member
  group, which was reported each time `--vault` pointed into it. A
  world-writable directory (not sticky) still always warns; a group-writable
  one warns only when its group is not a private group of the user (the exact
  rule is in the README). The warnings for the vault file and the passphrase
  file are unchanged.
- A vault entry named `PATH`, `LD_*`, `DYLD_*` or `BASH_ENV`, which changes
  which programs and libraries run, is now announced with a one-line warning
  on cloakenv's own stderr (key names only, never values): when it is stored
  with `set` or `import`, and on every `run` before the command starts. It
  used to apply silently (a vault `PATH` changed which `true` ran). Only a
  warning: nothing is blocked and exit codes are unchanged.
- The hidden passphrase prompt no longer leaves the terminal broken. Ctrl-C,
  `kill`, a hangup or Ctrl-Z at the prompt used to leave echo and line editing
  switched off in the user's shell; the terminal is now restored on every way
  out (cloakenv still ends by the signal), and Ctrl-D reports `no passphrase
  entered (end of input at the prompt)` instead of the misleading `no
  passphrase available ... or run on a terminal`. The prompt is now cloakenv's
  own small terminal code (no more `rpassword` on Unix), with tests on a real
  pseudo-terminal.
- `import` reads `.env` files the way people write them. A UTF-8 byte order
  mark is ignored (it used to fail with `invalid variable name`), a lone `\r`
  is a line break instead of ending up inside a value, double-quoted and
  single-quoted values may span several lines (PEM keys, JSON), and a variable
  that appears twice is an error instead of silently keeping the last value.
  `$VAR` and `${VAR}` are stored literally, as before, and now the README
  says so and `import` warns about values that look like references. A `KEY=`
  line is imported as an empty value, with a warning. The README documents the
  exact grammar in a table.
- `cloakenv set` refuses an empty value (empty stdin, a lone line break, or an
  Enter at the prompt) instead of storing it: `false | cloakenv set API_KEY`
  used to replace a good secret with an empty string and exit 0. Use the new
  `cloakenv set --allow-empty KEY` to store an empty value on purpose.
- Every limit on what the vault can hold is now enforced when something is
  stored, before anything is written. Previously two imports could together
  produce a vault larger than the 16 MiB cloakenv will read, after which every
  command failed with `vault file is too large`. `set` and `import` now
  refuse a vault over 16 MiB, and `import` is all or nothing. A variable over
  128 KiB (`KEY=VALUE`, the most Linux can start a command with) is refused by
  `set` and `import` with its key named, instead of failing later as
  `failed to spawn: Argument list too long`; on Linux `run` also reports which
  vault entries make the whole environment too large for the kernel.
- A missing vault no longer creates a vault directory or lock file when `set`,
  `unset` or `import` fail, and error causes are printed once.
- The key-derivation upgrade notice is only printed after the vault was
  actually saved.

[Unreleased]: https://github.com/benmckibben/cloakenv/commits/main
