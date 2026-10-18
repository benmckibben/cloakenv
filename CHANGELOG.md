# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - unreleased

Vault format 2. **Breaking: cloakenv 0.2 and older cannot open a format 2
vault**, and new vaults are format 2. Existing vaults keep working until you
convert them.

### Upgrading (read this first)

- A format 1 vault is **not** changed behind your back. Every command that
  opens one prints a notice that `cloakenv upgrade` is available and
  recommended. Run it when everything that reads the vault (your machines, CI,
  teammates) runs 0.3 or newer: afterwards 0.2 and older refuse the vault with
  "unsupported vault format version 2" and leave it untouched.
- `upgrade` keeps a byte-identical copy of the format 1 file in the **state
  directory** (see below), under `backups/`, and the same passphrase keeps working.
  `init --force` and `passwd` keep their copies there too, no longer next to
  the vault. All three therefore need a state directory (`HOME` or
  `CLOAKENV_STATE_DIR`) and stop with a message if there is none.
- cloakenv refuses to open those kept copies as a downgrade, or (the copy
  `passwd` keeps of a format 2 vault) as a rollback, until you run
  `cloakenv accept-rollback`: they are for recovery.
- A vault shared between machines (a synced folder, a repository) will report
  **forks and rollbacks** when two machines save from the same generation. See
  [Vault format 2](README.md#vault-format-2-rollback-detection-upgrading-and-the-state-directory) in the README.
- `CLOAKENV_NEW_PASSPHRASE_FILE` is a reserved name, like the other two
  passphrase variables: it is removed from the environment of the command `run`
  starts, and `set` and `import` refuse it. A format 1 vault that already holds
  an entry with that name keeps it but `run` no longer injects it.

### Added

- **Vault format 2**: an authenticated header with a **generation** (up by one
  on every save) and a random **vault id**; the plaintext is **padded** (Padmé,
  4 KiB floor, so a small vault is 4,208 bytes) so the file size no longer gives
  the exact total length of your secrets; an extension area for later additions.
  Same passphrase, Argon2id and XChaCha20-Poly1305. No key wrapping.
- **Rollback, fork and downgrade detection.** A per-user record in a **state
  directory** (`CLOAKENV_STATE_DIR`, else `$XDG_STATE_HOME/cloakenv` or
  `~/.local/state/cloakenv`, `~/Library/Application Support/cloakenv`,
  `%LOCALAPPDATA%\cloakenv`) remembers the highest generation of each vault.
  Every command refuses, before anything runs, an **older** copy, a second copy
  of the **same generation** with different contents, and a **format 1 file where
  a format 2 vault was** (`run` exits 125, the others 1; the vault is not
  touched). The first time a machine sees a format 2 vault it says so once.
  Commands that only read repeat a read that looks like a rollback (three reads
  at most) so that a save landing at the same moment is not mistaken for one.
- `cloakenv upgrade`: convert a format 1 vault to format 2, explicitly.
- `cloakenv passwd`: change the passphrase and keep the contents. The new
  passphrase comes from a prompt (twice) or from `CLOAKENV_NEW_PASSPHRASE_FILE`;
  it must differ from the current one. Works on format 1 vaults too.
- `cloakenv info`: format, size, key-derivation settings, number of entries,
  generation and vault id, and the rollback status; never names or values; changes
  nothing.
- `cloakenv accept-rollback [--yes]`: the deliberate way past a refusal
  (never an environment variable). Asks for the passphrase and for confirmation.
- Warnings, on every command, when the state directory is a symlink, writable by
  others or owned by someone else.
- Library: `vault::file::Loaded` (either format), `vault::v2` (the codec),
  `vault::state` (the record), `NEW_PASSPHRASE_FILE_ENV`, and new `VaultError`
  variants (`UnsupportedPadding`, `UnsupportedExtension`, `GenerationOverflow`).
  The format 1 `Vault::seal/open/load/save` are unchanged.
- `fuzz/`: a standalone cargo-fuzz crate (not part of the published package).

### Changed

- `cloakenv init` creates a **format 2** vault. `init --force` keeps its backup
  copy in the state directory instead of next to the vault.
- **Library, breaking:** `vault::backup_vault` now takes the directory to put the
  copy in; `VaultError` has new variants (match it non-exhaustively).
- The short-passphrase warning now points at `cloakenv passwd` instead of saying
  there is no command to change the passphrase.
- The format 2 reader refuses what its writer would not write: key-derivation
  settings below 19 MiB / 2 passes / 1 lane, entries out of key order, the
  reserved passphrase names, and any padding that is not exactly canonical.
- `README.md` and `docs/ARCHITECTURE.md` describe format 2 and the state
  directory; `docs/design/vault-format-v2.md` records why.

### Security

- Closes two limits of 0.2: the exact total length of the secrets being visible
  in the file size (format 2), and a restored older vault being accepted silently
  (format 2 vaults on a machine that has opened them before).
- **Limits that remain, on purpose or by nature:**
  - A **format 1 vault has neither protection**; `upgrade` is the way.
  - Downgrade detection is **best effort**: a format 1 file has no id, so only
    one that this machine upgraded, or one at a path (as typed, or with symbolic
    links resolved) that held a format 2 vault, is recognised. An older format 1
    snapshot that was never upgraded here, under a new path, is not.
  - The record is **not authenticated**: anyone who can write the state directory
    (you, root, code running as you) can edit or delete it, and the next open
    trusts what it finds. A machine that has never opened a vault has nothing to
    compare with. The record holds the **paths** of your vaults in plain text.
  - There is no `export` or `get`, on purpose: rotate a value at its source
    instead of recovering it.

### Known limitations

- **No external security review.** The format 2 code was reviewed once by a
  reviewer other than its author. The two serious findings (a race between
  readers and a writer, and a downgrade bypass) were fixed before this release,
  and most of the rest were fixed or are listed here; that is not the same as an
  outside audit.
- Format 2 was run on Linux, macOS and Windows in CI; it has not been tried by
  hand on Windows or macOS, and how a case-insensitive file system affects the
  path matching of the record on macOS has not been verified.
- The fuzz target that mutates whole files runs few inputs (each one that gets
  past the header costs a key derivation); the targets for the header, the
  decoder and the record file run millions.
- The interoperability check with the published 0.2.0 binary was done by hand
  and is not an automated test.
- `passwd` accepts a new-passphrase file containing a NUL byte or an interior newline,
  which a prompt could not retype.
- The directory entry of a kept backup copy is not synced to disk before the
  command returns (the copy's contents are).
- `set` on a vault path that is a symbolic link replaces the link with a regular file
  (it has always warned about this).

## [0.2.0] - 2026-10-13

Windows support. Nothing else changed.

### Added

- **Windows support (x86_64, MSVC).** Built, linted and tested in CI on every
  change, and tried by hand in PowerShell. A release archive for it
  (`cloakenv-VERSION-x86_64-pc-windows-msvc.zip`, with the C runtime linked in
  statically so no Visual C++ redistributable is needed) is attached to the
  GitHub release and covered by `SHA256SUMS`; it is not code-signed. See the README's platform section for
  the limits. 32-bit and Arm Windows are not supported.
  - The vault lock (`LockFileEx`), so concurrent `cloakenv set` calls no longer
    lose updates, and a save that is moved into place write-through.
  - `run` always stays the parent. The command runs in a job object that kills
    it and everything it started if cloakenv dies, and a command that exits
    normally leaves any background process it started running, as on Unix.
  - Ctrl-C and Ctrl-Break go to the command; cloakenv waits for it and reports
    how it ended. `--shield` waits at most 3 seconds for leftover processes
    that hold the output pipes.
  - The command's exit code is reported as the full 32-bit value (a crash is
    `0xC0000005`); it used to become `1` above 255.
  - A directory, the vault, its lock file and the other files cloakenv creates
    get a protected ACL that gives access to you, SYSTEM and Administrators
    only. Existing files and directories are never changed.
  - Warnings (not errors) when an existing vault file or passphrase file is
    accessible to Everyone, Users or Authenticated Users, or when the vault
    directory is writable by them.
  - `run` refuses, exit 125, a vault with two names that differ only in case
    (environment names are not case-sensitive on Windows), naming both. The
    `PATH` and `BASH_ENV` warning and the reserved passphrase names match in any
    case there.

### Fixed

- Windows: `cloakenv import <directory>` now reports "not a regular file" like
  it does elsewhere, instead of "Access is denied".
- Windows: pressing Ctrl-C at a hidden prompt no longer leaves the console
  without echo and line input for the next program that reads a line.

### Changed

- The README, SECURITY.md, CONTRIBUTING.md and docs/ARCHITECTURE.md describe
  Windows as supported on x86_64, with its known limitations and what has and
  has not been tried.

### Known limitations

What 0.2.0 does not do on Windows, and what nobody has checked. The limitations
listed for 0.1.0 still apply on every platform; the README's platform section
has the detail.

- **Same-user processes are not kept out.** There is no equivalent of the
  non-dumpable flag in use, so another process of your account can read
  cloakenv's own environment and memory (the passphrase variable included) and
  the command's environment. Memory is not locked and may reach the page file
  or a hibernation image; crash dumps are not suppressed.
- **Permissions are ACLs, and cloakenv only warns.** It never changes the ACL of
  a file or directory that already exists.
- **`--shield` filters bytes on the two pipes.** A program that writes UTF-16, or
  writes to the console directly, is not covered.
- **Tried by hand in PowerShell, on one machine, and by CI on Windows Server
  2025.** Not tried: cmd.exe, Windows Terminal, Git Bash and mintty, Ctrl-Break,
  a vault in a OneDrive or Dropbox folder, on a network share or on an exFAT
  drive, a second Windows account, domain accounts, and a command that is itself
  running in another job object.
- **x86_64 only.** 32-bit and Arm Windows are not supported, and the Windows
  binary is not code-signed, so SmartScreen or antivirus software may warn.
- **Unchanged from 0.1.0:** the aarch64 Linux and Intel macOS release binaries
  are smoke-tested, not test-suite-tested, and there has been no external
  security review.

## [0.1.0] - 2026-10-12

The first release.

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
- `--shield` releases output as soon as it is read, holding back only the
  trailing bytes that could still be the beginning of a secret (and never
  releasing those on a timer). A line of output, a prompt without a newline or a
  server's "listening" message appears while the command is still running.
- When `--shield`'s stdout and stderr are the same destination (`> log 2>&1`,
  `2>&1 | tee`), the command's two streams share one pipe, as `2>&1` would give
  it: lines of one stream are never cut in two by the other, the command's own
  order is kept, and a secret split between stdout and stderr is caught.
- `--shield` waits for a non-blocking stdout or stderr instead of cutting the
  output short, reports a failure to write the command's output (a full disk,
  say) as an error with exit status 125 instead of a silent success, and works
  when `SIGCHLD` was inherited as ignored (as a Python `preexec_fn` or some
  launchers leave it).
- `run --help` and the README spell out what `--shield` and the exec mode do
  differently (the command's stdout and stderr are pipes under `--shield`,
  signals, exit status, process tree), what the command inherits, and the exit
  codes, including that a command may itself exit 125, 126 or 127 and that a
  usage error is 2 where every other cloakenv failure under `run` is 125.
- `--shield` builds its matcher in linear time, so a long value that overlaps
  itself (up to the 1 MiB `set` accepts) does not delay the start of the command.
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

Problems found in a security review of the first version, all fixed before
this release:

- writers (`init`, `set`, `unset`, `import`) hold an exclusive `flock` for
  their whole load-modify-save cycle, so concurrent `cloakenv set` calls no
  longer lose updates. A filesystem without working locks makes writers refuse
  to run instead of going ahead unprotected.
- on Linux cloakenv marks itself non-dumpable at startup
  (`PR_SET_DUMPABLE`), so other processes of the same user can't read the
  passphrase from `/proc/<pid>/environ`, inspect its memory, or write around
  `--shield` through `/proc/<pid>/fd`, and no core file is written. On every
  Unix it also lowers its own core-file size limit to 0 (covering
  `fs.suid_dumpable=2` and macOS) and hands the original limit back to the
  command.
- no secret is ever read from, or echoed back from, the command line.
  `cloakenv set KEY VALUE` is refused with an error that doesn't repeat the value;
  invalid variable names are not echoed; usage errors are rendered by cloakenv
  rather than clap (which quotes the offending argument) and exit with code 2.
- key-derivation parameters in the (not yet authenticated) vault header are
  capped (256 MiB, 8 passes, 8 lanes), so a hostile file can't force a huge
  allocation or many seconds of CPU.
- the vault is opened once and the open handle is checked; only regular
  files of at most 16 MiB are read (no `/dev/zero`, FIFO, directory or huge file),
  with a hard read cap.
- `run` without `--shield` replaces cloakenv with the command (`execve`), so
  there is no cloakenv process left to probe or orphan, and signals and exit
  status are the command's own. With `--shield` cloakenv forwards `SIGTERM`,
  `SIGHUP`, `SIGINT`, `SIGQUIT`, `SIGUSR1` and `SIGUSR2` to the command, and on
  Linux has the kernel kill the command if cloakenv dies. Output pumps stop
  shortly after the command exits even if a leftover background process holds
  the pipes open.
- `run --shield` warns, naming the keys, about vault values shorter than 6
  bytes, which are redacted so broadly that the marker confirms a guess.
- `init` writes `.cloak/.gitignore` so the vault never shows up in
  `git add .`.
- warnings (not errors) for a vault directory that is group/world-writable,
  a vault or passphrase file that is group/world-readable or writable, and a
  symlinked vault or vault directory.
- decrypted values, the passphrase and the raw child output are kept in
  buffers that are wiped, and no longer in stale copies left by growing reads;
  the vault is dropped as soon as the command has started.
- new vaults are never weaker than OWASP's minimum Argon2id setting
  (19 MiB, 2 passes). Older, weaker vaults still open, with a warning, and are
  upgraded the next time `set`, `unset` or `import` saves them.
- a closed output pipe (`cloakenv list | head -1`) ends quietly instead of
  panicking.
- one set of passphrase rules for all three sources. A source that is set
  but unusable is an error, never a silent fallback; `init` refuses a passphrase
  ending in a line break (which the sources would read differently) and warns
  about one shorter than 12 characters.
- `Debug` output of the parsed command line never shows an argument.
- `import` reads its file with the same care as the vault: regular files only, at
  most 16 MiB, into a buffer that is wiped afterwards.
- the README documents what `--shield` does and doesn't catch,
  platform differences, and an end-to-end threat model, including the known
  rollback limit (anyone who can write the vault's directory can put back an
  older valid vault).

### Fixed

- The README now states plainly what was only implied: secrets must be UTF-8
  text (binary secrets are unsupported), cloakenv is not an init system (as
  PID 1 of a container it does not reap orphaned processes), the macOS
  limitations, and that the vault's file size reveals the exact total length of
  all secrets and its contents can be rolled back by someone who can write the
  directory. A concrete design for a version 2 vault format (padding, a
  wrapped data key for passphrase change, a rollback counter, an optional
  export command) is written up in docs/ARCHITECTURE.md as a proposal; none of
  it is built.
- `init --force` (the only way to change a vault's passphrase) destroyed the
  old vault without asking or keeping anything. It now asks for confirmation on
  a terminal, needs `--yes` when there is none (so existing scripts that run
  `init --force` must add `--yes`), and saves a backup copy of the old vault
  first, as `vault.bin.bak-YYYYMMDDTHHMMSSZ` (mode 0600).
- An empty `CLOAKENV_VAULT` (or `--vault ""`) gave `one of the values isn't
  valid for an argument`; it is now a plain error saying the vault path is
  empty.
- The `no vault found` error shows the absolute path that was tried and says
  that parent directories are not searched. (They never were, deliberately; the
  README now explains why.)
- `cloakenv --help` and the help of every subcommand now list the exit codes.
- A save that was killed (`kill -9`, power loss) between writing its temporary
  file and renaming it left `.vault.bin.tmp-*` behind forever, as large as the
  vault. The next writing command (`set`, `unset`, `import`, `init`) now removes
  such leftovers under the vault lock, but only regular files that you own, that
  match the generated name exactly and that are older than 5 minutes.
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

### Known limitations

What 0.1.0 does not do, and what nobody has checked. The README's threat model
has the detail; this is the short version.

- **`--shield` is a filter, not a boundary.** It replaces the exact bytes of a
  stored value on the command's stdout and stderr. A transformed value (base64,
  hex, reversed, escaped), a value split across the two streams, a value the
  command writes to a file or sends over the network, and very short values are
  not handled the way you might expect.
- **The command holds your secrets.** After `exec` the kernel makes the
  command's `/proc/<pid>/environ` readable to other processes of your user (and
  root), with or without `--shield`.
- **Not protected:** root and the kernel; code running as you before cloakenv
  starts; the short window before cloakenv marks itself non-dumpable (Linux);
  swap and hibernation images (no `mlock`); a vault replaced by an older valid
  copy (no rollback protection); the vault file's size, which reveals the total
  length of your secrets. macOS has no non-dumpable flag; Windows is unsupported.
- **Tests run natively on x86_64 Linux and Apple-silicon macOS only.** The
  aarch64 Linux and Intel macOS release binaries are smoke-tested, not
  test-suite-tested.
- **No external security review.** The code had an internal review and fixes
  before this release, which is not the same thing.

[Unreleased]: https://github.com/benmckibben/cloakenv/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/benmckibben/cloakenv/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/benmckibben/cloakenv/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/benmckibben/cloakenv/releases/tag/v0.1.0
