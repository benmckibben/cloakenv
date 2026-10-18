# cloakenv architecture

## Modules

| module          | responsibility                                                          |
|-----------------|-------------------------------------------------------------------------|
| `src/main.rs`   | clap CLI, passphrase acquisition, exit-code mapping                     |
| `src/passphrase.rs` | the passphrase rules (what each source yields; line-break and length checks) |
| `src/input.rs`  | reading secret text (stdin value, passphrase file) into one wiped, size-capped buffer |
| `src/crypto.rs` | Argon2id key derivation, XChaCha20-Poly1305 seal/open, OS RNG           |
| `src/envcheck.rs` | pre-flight checks of the environment `run` will build (per-variable and total size, with the offending keys named) |
| `src/dotenv.rs` | the `.env` grammar for `import` (multi-line quotes, BOM, line endings, duplicates; no interpolation) |
| `src/prompt.rs` | the hidden terminal prompt: echo off through a guard that restores the terminal on every exit (return, error, EOF, SIGINT/TERM/HUP/QUIT, SIGTSTP), reading into a wiped buffer |
| `src/vault.rs`  | vault file format 1, the in-memory map, size limits, atomic writes (0600 on Unix), the writer lock, the backup copy |
| `src/vault/v2.rs` | format 2 codec: header, extensions, Padmé padding, the decoder rules |
| `src/vault/file.rs` | `Loaded`: reads and writes either format (the generation, id and tag of a format 2 vault) |
| `src/vault/state.rs` | the per-user rollback record: file format, verdicts, locked check/accept, state directory location |
| `src/perms.rs`  | advisory permission/symlink warnings for the vault, the passphrase file and the state directory (Unix; ACLs on Windows) |
| `src/hardening.rs` | process hardening (`PR_SET_DUMPABLE` on Linux, zero soft core limit on Unix) |
| `src/runner.rs` | env injection: `exec` into the command, or spawn it; `--shield` streaming redactor |
| `src/supervise.rs` | (Unix) `--shield` supervision: signal forwarding, race-free reaping, output pumps |
| `src/sys.rs`    | (Unix) the crate's only `unsafe`: `sigaction` read, `pre_exec` hook (`PDEATHSIG`, core limit) |
| `src/lib.rs`    | re-exports the above so integration tests can exercise them directly    |

## Cryptography

* **KDF:** Argon2id v1.3. New vaults use 64 MiB / 3 passes / 1 lane. A
  vault is only ever *written* with at least 19 MiB / 2 / 1 (OWASP's minimum
  Argon2id setting; `KdfParams::MIN`; `Vault::with_params` refuses less, and
  `seal` clamps up to it). On *read* the lower bound for a format 1 file is the more lenient
  8 MiB / 1 / 1 (`KdfParams::FLOOR`, the old minimum; a format 2 file may not go below
  the writer's minimum), so a weak vault created
  by an earlier version still opens instead of locking its owner out; the CLI
  warns about it and `set`/`unset`/`import`/`passwd`/`upgrade` upgrade every parameter to at
  least the default (`Vault::upgrade_kdf_params`, a per-parameter maximum, so
  a stronger vault is never weakened) when they re-save. The
  parameters live in the header, which is read *before* the file is
  authenticated, so on read they must fall within a fixed range: at most
  256 MiB, 8 passes and 8 lanes. This caps the memory and CPU an untrusted
  vault file can demand (a 1 GiB / 32-pass header used to cost ~18 s and ~1 GiB
  of RAM before failing). Out-of-range headers are rejected before any key
  derivation, like any other malformed vault: exit 125, child not run, and an
  error that names the accepted range. There is deliberately no override
  (flag or environment variable) to raise the cap: new vaults are written with
  64 MiB / 3 / 1, so only a vault created through the library API with
  parameters above the cap is affected.
* **AEAD:** XChaCha20-Poly1305 with a random 192-bit nonce. A fresh salt *and*
  nonce are generated on every write, so nonce reuse is not a practical concern.
* **Associated data:** the entire header. Format 1: 64 bytes (magic, version, algorithm
  ids, KDF parameters, salt, nonce). Format 2: 96 bytes plus the extension area
  (see [Vault format 2](#vault-format-2)). Flipping any header bit fails decryption.
* Key material, passphrases and decrypted values are held in
  `zeroize::Zeroizing` buffers and wiped on drop. `Debug` impls never print them.

## Passphrase rules

One passphrase, three sources (`CLOAKENV_PASSPHRASE`, `CLOAKENV_PASSPHRASE_FILE`,
the prompt; `passwd`'s *new* passphrase comes from the prompt or from
`CLOAKENV_NEW_PASSPHRASE_FILE`, with the same rules), defined in `src/passphrase.rs` and README "Exactly what counts as
the passphrase". Each source yields exactly the text supplied, except that a
file loses **one** trailing `\n` or `\r\n` and the prompt loses the Enter key;
nothing is trimmed. A source that is set but unusable is an error, never a
silent fallback to the next one (a non-UTF-8 `CLOAKENV_PASSPHRASE` used to be
skipped). The only passphrases two sources could disagree on are those ending
in `\n` or `\r`, so `init` refuses them (a vault created with one could be
opened only through the source that made it), while unlocking never rejects
anything: existing vaults keep opening exactly as before, and a failed unlock
with a trailing line break adds a hint. Short passphrases (under 12
characters) get an advisory warning at `init` only, from every source.

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
the total length of all keys and values (84 bytes plus 8 and the lengths of the name and the value for each entry; format 2 pads this away, see [Vault format 2](#vault-format-2)). The decoder rejects duplicate keys, invalid names, NUL
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

Before taking the lock, `set`/`unset`/`import` check that the vault exists, so a
mistyped `--vault` path creates no directory or lock file. The lock file is
opened like every file in Rust, close-on-exec, so no command can inherit it; a
symlink at the lock path is followed (the lock directory has the same trust
level as the vault itself).

`import` reads its `.env` file with the same open-once/`fstat`-the-handle
discipline as the vault: regular files only, at most 16 MiB, into one buffer
sized up front (never reallocated, so no stray copy) that is wiped on drop.

Writers (`init`, `set`, `unset`, `import`, `passwd`, `upgrade`) hold an exclusive `flock(2)` on a
sibling `.vault.bin.lock` (empty, mode 0600, never deleted) for the whole
load → modify → save cycle, so concurrent updates are serialised instead of
silently overwriting each other. The lock lives on a separate file because the
vault inode is replaced on every save. Readers (`list`, `run`, `info`) take no lock;
the atomic rename already guarantees they see a complete vault (their comparison with the rollback record can still race a save: see [Vault format 2](#vault-format-2)). Passphrase and
value prompts happen *before* the lock is taken, so an idle prompt never
blocks other writers. The lock is `flock` on Unix and `LockFileEx` on Windows (byte 0 of the same file, tied to the handle, so it is released if the process dies); on any other platform it is a no-op.

**Reading the vault is bounded.** `Vault::load` opens the path once
(`O_NONBLOCK | O_NOCTTY` on Unix, so opening a FIFO or terminal cannot block
or steal a controlling terminal), runs `fstat` on the *open handle*, and
refuses anything that is not a regular file or is larger than 16 MiB before
reading a byte; the read itself is additionally capped at 16 MiB + 1 byte, so a
file that grows or lies about its size cannot cause unbounded allocation.
Symlinks are followed (and warned about); a symlink to `/dev/zero` is refused
because the check is on what it resolves to.

**Permission checks (Unix, advisory).** When a command opens the vault,
`src/perms.rs` warns on stderr if the vault directory is world-writable (and not sticky) or group-writable by a group that is not private to the user (the rule is in the README, "Permission warnings"),
the vault file is group/world-readable or writable, either is a symlink, or
the `CLOAKENV_PASSPHRASE_FILE` in use is group/world-readable or writable. The
warnings are printed before decryption and spawning, name only paths and octal
modes, never change exit codes and never chmod anything. A loose passphrase
file is deliberately a warning, not an error: Docker/Kubernetes secret mounts
are routinely 0444/0644 and rely on the container boundary.

## Process model of `cloakenv run`

* **No `--shield` (Unix): `exec`.** After the vault is authenticated and
  decrypted, `runner::exec_replace` builds the `Command` (vault entries via
  `envs`, then `env_remove` of both passphrase variables, so a vault entry
  cannot resurrect them), drops the `Vault` and the passphrase (both are
  `Zeroizing`), restores the core-file limit cloakenv lowered for itself and
  calls `CommandExt::exec`. On success the whole address space, including
  std's own non-wipeable copies of the environment that `Command` made, the
  process's original environment block and the stacks of every thread, is
  replaced by the kernel; nothing of cloakenv survives. Only file descriptors
  not marked close-on-exec do, and cloakenv opens none (Rust opens everything
  `O_CLOEXEC`; the write lock is not even held for `run`). `exec` failures
  come back as the same `RunError`s as spawn failures (`ENOENT` → 127,
  `EACCES` → 126, anything else → 125), printed by cloakenv in the same style.
  After a failed exec the environment must not be read again (std has pointed
  `environ` at memory it then frees); the error path only formats and exits.
  Because the kernel resets `PR_SET_DUMPABLE` at exec, the command is
  dumpable and its `/proc/<pid>/environ` (holding the secrets, by design,
  and no passphrase) is readable by same-user processes. That is no change
  from when cloakenv was its parent; the difference is that there is no
  parent whose environment, memory or file descriptors (the `--shield`
  bypass) could be probed, and nothing to orphan, signal or wait for.
* **`--shield` (Unix): supervised child** (`src/supervise.rs`). Handlers for
  `SIGTERM`, `SIGHUP`, `SIGINT`, `SIGQUIT`, `SIGUSR1`, `SIGUSR2` are installed
  (`signal-hook`, iterator mode: the handler only writes to a self-pipe, a
  thread forwards with `kill(2)`) *before* the child is spawned, so an early
  signal is queued rather than lost; signals that were `SIG_IGN` on entry are
  not caught, so the command inherits the ignore. The main thread waits with
  `waitid(WEXITED | WNOWAIT)`, takes the mutex the forwarder holds across
  every `kill`, marks the child gone, and only then reaps it, so a signal can
  never reach a recycled pid. On Linux a `pre_exec` hook sets
  `PR_SET_PDEATHSIG = SIGKILL` (checking `getppid` afterwards to close the
  fork-to-prctl race); the death signal is tied to the *thread* that spawned
  the child, which is the main thread and lives as long as the process. It is
  cleared by `exec` of a set-uid binary and only reaches the direct child.
  The same hook gives the child back the original core-file limit. Exit
  status mapping is unchanged (`128 + N`).
* **One pipe or two.** If cloakenv's own stdout and stderr are the same file,
  pipe, socket or terminal (`fstat` device and inode equal, which also sees
  through `dup`; `fdio::stdout_and_stderr_are_one`), the command gets one pipe
  for both streams (the pipe's write end duplicated onto fd 1 and fd 2, as
  `2>&1` would do) and one pump with one redactor writes to fd 1. Two pumps
  writing unaligned chunks to one destination cut lines of one stream in two
  with lines of the other (a fifth or more of the lines of a busy command were
  garbled when both went to one file), and a secret whose halves went to different streams could not
  be matched. With one pipe the command's own write order is kept, which also
  makes the output reproducible. If the inode is 0 (a platform that does not
  number an object) the answer is "different", the old behaviour. Different
  destinations are untouched: two pipes, two pumps, two redactors.
* **Writing our own output** (`src/fdio.rs`). The pumps write with a loop of
  `write(2)` that tracks how much was written, retries `EINTR`, and on `EAGAIN`
  (our stdout or stderr is non-blocking: the flag is on the open file
  description, shared with whoever else holds it) polls for `POLLOUT` and goes
  on from where it stopped. `std::io::Write::write_all` would fail there and
  could not say how much had been written, so output was cut (1 MB became
  about 64 KB) and the stream treated as closed. `EPIPE` (the reader went away)
  ends that pump quietly, as for `cat`, and the command meets a closed pipe on
  its next write. Any other write error is returned to the supervisor, which
  reports `failed to write the command's output` and exits 125 after the
  command has been reaped. The same writer serves `cloakenv list` and our own
  diagnostics on stderr (for those, waiting is bounded to two seconds).
* **Inherited SIGCHLD.** If `SIGCHLD` is `SIG_IGN` when cloakenv starts (it
  survives `exec`, so a Python `preexec_fn` or an init wrapper can hand it down),
  the kernel reaps children by itself and `waitpid`/`waitid` fail with `ECHILD`.
  Before spawning, `--shield` sets it back to the default for its own process
  (`sys::default_sigchld`); the `pre_exec` hook sets it to `SIG_IGN` again in the
  command (one `signal(2)` call, async-signal-safe), so the command sees what
  it would have seen without cloakenv, in both modes. The exec mode needs
  nothing: it never waits.
* **Output pumps and leftover holders.** The pumps `poll` their pipe with a
  50 ms tick instead of blocking in `read`. After the command has exited
  they end at EOF, or once the pipe has been silent for 250 ms, or 3 seconds
  after the exit (not counting time blocked writing to our own stdout), and
  flush their redactor either way. Leftover processes are not killed.
* `unsafe` is denied crate-wide and allowed in `src/sys.rs` (Unix: two calls
  with no safe wrapper, the `sigaction` read-only query and `pre_exec`) and in
  `src/winsys.rs` (Windows: file locking, write-through replace, private ACLs
  and reading an ACL, the job object, the console control handlers) only, each
  call with a SAFETY comment.
  Each has a SAFETY comment; the `pre_exec` closure only makes raw syscalls.

## Platform support

Linux, macOS and Windows (x86_64) are supported and tested in CI. Unix-only
pieces and their Windows counterparts: file modes 0600/0700 (a protected ACL for
the user, SYSTEM and Administrators, set at creation), the permission warnings
(ACL warnings: any access for Everyone, Users or Authenticated Users to the
vault or passphrase file, write access to the directory), directory fsync
(`MoveFileExW` with `WRITE_THROUGH`), `flock` (`LockFileEx`), `exec` into the
command and signal forwarding (cloakenv stays the parent: the command runs in a
kill-on-close job object, created suspended and resumed once it is in the job,
and cloakenv swallows Ctrl-C and Ctrl-Break while it waits, so the command
decides what to do with them), and exit codes (`128 + N`; on Windows the 32-bit
status is passed through). `PR_SET_DUMPABLE` and `PR_SET_PDEATHSIG` are Linux
only (see invariant 6; Windows has the job object for the second, and nothing
for the first): on macOS `exec` and signal forwarding behave the same, but a
`SIGKILL` of cloakenv under `--shield` leaves
the command running.

## Memory hygiene (best effort)

Plaintext secrets are held in `Zeroizing` buffers and wiped when dropped. Rust
and the standard library offer no way to *guarantee* that no other copy exists
(a growing `Vec` leaves its old allocation behind, freed but not wiped, and
std's own buffers are out of reach), so this section records what is done,
what is not, and why. The numbers come from scanning the anonymous memory and
heap of a running release build through `/proc/<pid>/mem` (from a parent that
is allowed to: root of a user namespace, since cloakenv is non-dumpable) for a
distinctive 212-byte dummy secret, counted before and after the changes
described here:

| situation (cloakenv process scanned)                  | full copies before | full copies after |
|-------------------------------------------------------|-------------------:|------------------:|
| `set`: value read from a slow pipe, waiting for the lock | 1 (plus 0 to 3 stale partial copies from the growing read) | 1 (the live value), no stale copies |
| `run --shield`: command running, output has flowed    | 8 to 16            | 0                 |

* **Value for `set` (stdin).** Read into one buffer allocated once (1 MiB + 2
  bytes: the limit plus room for a final `\r\n`, which is stripped; larger
  input is refused with a non-echoing error), filled in place through a
  duplicate of the stdin descriptor so that std's 8 KiB stdin buffer never
  holds a copy, then *moved* (not copied) into the `String` that goes into the
  vault. Previously `read_to_string` regrew its buffer, leaving unwiped copies
  of the first bytes behind. The interactive prompt (`src/prompt.rs`) reads into one
  preallocated, wiped buffer in the same way (at most 64 KiB), so it leaves no
  stale copies either.
* **Passphrase.** From `CLOAKENV_PASSPHRASE` it is copied into a `Zeroizing`
  string, but the original sits in the process's environment block until the
  process execs or exits, and a safe Rust program cannot unset it. That is
  what the non-dumpable flag is for (and why the README recommends a file or
  the prompt where the same-user window matters). A passphrase file is read like a
  `set` value (one buffer, at most 64 KiB, wiped). Argon2 works in 64 MiB of
  memory that the `argon2` crate does not wipe, but it holds only data derived
  one-way from passphrase and salt, never the passphrase itself (the
  crate does wipe its initial hash and block hashes); an allocation that size
  is returned to the operating system, which zeroes the pages before anyone
  else gets them. Accepted.
* **`run` without `--shield`.** `exec` replaces the address space: nothing of
  cloakenv survives (see "Process model").
* **`run --shield`.** The vault is taken by value and dropped (wiped) right
  after the command has been spawned, together with the `Command` that held a
  copy of every value, instead of being kept for as long as the command runs.
  The two pump read buffers (raw, unredacted child output) and each redactor's
  held-back buffer are `Zeroizing`: buffers are wiped after every chunk, the
  bytes shifted out of the held-back buffer are wiped as they go, and a
  buffer that has to grow is replaced, never reallocated in place. The two
  output streams share **one** Aho-Corasick automaton (a clone is a reference
  count) instead of building one each. The library cannot zeroize an
  automaton, so it is dropped as soon as both pumps are done; but it is built
  with its prefilter turned off, because the prefilter stores the patterns
  verbatim, which made the secret findable by a plain memory search (the
  remaining representation is a state machine, from which a determined
  attacker with memory access could still reconstruct the values: it is not
  encryption, merely not a contiguous copy). The held-back-prefix logic adds
  only a 256-entry table of which bytes can begin a secret, derived from the
  automaton's start state. (Not re-measured with a memory scan after the
  matcher became a DFA-or-NFA pair; both are state machines with no
  contiguous copy of the patterns.) Matching speed is unaffected for typical
  secrets (see "Building the automaton" for numbers).
* **Not fixable here, accepted:** the copies that `std::process::Command` makes
  of the environment (its own map, and the C string array built when
  spawning). They are freed but not wiped, so they can linger in freed heap
  memory until reused. In the `--shield` scan above they did not leave a
  contiguous copy that survived, but nothing guarantees that. Without
  `--shield` they vanish with the exec.
* **Argument vector.** clap's raw arguments hold key names, the command to run
  and, for `set`, a refused VALUE (which is already in the kernel's
  `/proc/<pid>/cmdline` by then): no secret is ever read from argv by design.

## Vault format 2

Implemented in 0.3.0. The reasons behind each choice, and the alternatives that
were weighed, are in [design/vault-format-v2.md](design/vault-format-v2.md); this
section describes what the code does. Format 1 files are still read and written
(a vault stays in the format it was read in until `cloakenv upgrade`); `init`
creates format 2.

### Layout

All integers little-endian. The header is 96 bytes plus an extension area, and the
whole of it (extensions included) is the AEAD's associated data.

| offset | size | field |
|-------:|-----:|-------|
|      0 |    8 | magic `CLOAKENV` |
|      8 |    1 | format version = 2 |
|      9 |    1 | KDF id = 1 (Argon2id v1.3) |
|     10 |    1 | AEAD id = 1 (XChaCha20-Poly1305) |
|     11 |    1 | padding scheme = 1 (Padmé, 4 KiB floor) |
|     12 |    4 | Argon2 memory cost (KiB) |
|     16 |    4 | Argon2 time cost |
|     20 |    4 | Argon2 parallelism |
|     24 |   16 | salt (fresh on every save) |
|     40 |   24 | nonce (fresh on every save) |
|     64 |   16 | vault id (random at creation, never changes) |
|     80 |    8 | generation (1 at creation, +1 on every save; 0 is invalid) |
|     88 |    4 | flags, reserved, must be 0 |
|     92 |    4 | extension area length (at most 4096) |
|     96 |  ext | extension records: `u16 type, u16 length, value` |
| 96+ext |    n | ciphertext ‖ 16-byte Poly1305 tag |

The plaintext is `u32 count`, the entries in key order (`u32 key_len, key, u32
value_len, value`, as in format 1), then zero bytes up to the padded length:
Padmé (round the length up to a multiple of `2^(E-S)` with `E = floor(log2 len)`
and `S = floor(log2 E) + 1`), never below 4096. The overhead above the floor is
below 12% (the tests check at most 6.25% for lengths from 4 KiB to 16 MiB), so the
size shows the length only to within one of a few steps, and a value rotated to a
slightly different length usually leaves the size unchanged; crossing a step is
visible. An empty or small vault is 96 + 4096 + 16 = 4,208 bytes. There is no key
wrapping: the passphrase-derived key encrypts the payload directly, so
`passwd` is two key derivations and one re-encryption, with a fresh salt and nonce.
An unknown extension type with the top bit set (*critical*) is refused; any
other is kept and written back by the next save.

### Decoder rules

Checked from the still-unauthenticated header, before the KDF runs: the magic,
version, algorithm and padding ids, the reserved flags, the extension area (at
most 4096 bytes, every record complete, no type twice, no unknown critical
type), generation not 0, the key-derivation parameters (within the same range as
format 1, and not below 19 MiB / 2 passes / 1 lane, the lowest the writer ever
writes), and a ciphertext of at least the floor plus the tag. The generation, the
vault id and the extensions are **never acted on before the tag verifies**.

After authentication: the format 1 entry rules (valid unique names, no NUL, the
entry size cap), the entries strictly in key order, none of the three reserved
passphrase names, and zero padding of exactly the canonical length. One
plaintext therefore has exactly one valid file, and a file the writer would not
have produced is refused. All header and decode failures are reported alike (the
same "not a usable vault" error), and the 16 MiB limit counts the whole file,
padding included (the size is computed before any key derivation).

### Rollback, fork and downgrade detection

A vault proves nothing about its own freshness, so every open of a format 2
vault, after authentication, is compared with a per-user record
(`src/vault/state.rs`) kept outside every project:

* **Location.** The state directory: `CLOAKENV_STATE_DIR`, else
  `$XDG_STATE_HOME/cloakenv` (absolute only) or `~/.local/state/cloakenv` on
  Unix, `~/Library/Application Support/cloakenv` on macOS, `%LOCALAPPDATA%\cloakenv`
  on Windows; mode 0700 and the file 0600 (a protected ACL on Windows). The
  directory is warned about when it is a symlink, group- or world-writable, or
  owned by someone else.
* **File.** Plain text, strictly parsed, written atomically under an exclusive
  lock on a sibling lock file:

  ```text
  cloakenv-seen 2
  vault <vault id, 32 hex> <generation> <tag, 32 hex> <last path, escaped, or ->
  path <vault id, 32 hex> <path, escaped>
  v1 <tag, 32 hex> <vault id, 32 hex>
  end
  ```

  `vault` lines are the highest generation seen per vault id and the tag of that
  version; `path` lines are the paths a format 2 vault has been opened under (the
  absolute path as given and the path with symlinks resolved); `v1` lines are the
  tags of format 1 files that `upgrade` converted. An unknown line, a duplicate, a
  bad number, a line over 8 KiB, a file over 4 MiB, data after `end` and a missing
  `end` are all errors (every truncation is detected); a newer header version is
  refused. Header `cloakenv-seen 1`, from the first builds, is still read and is
  rewritten in the current form.
* **Verdicts** (a pure function, `State::evaluate`): unknown id is trusted and
  recorded (with a note on stderr); a greater generation is recorded; the same
  generation and tag is accepted; the same generation with another tag is a
  **fork**; a lower generation is a **rollback**; a format 1 file whose tag was
  retired by `upgrade`, or at a path that held a format 2 vault, is a
  **downgrade**. The three refuse, before anything is spawned and without writing
  anything. A path taken over by a different vault id warns and is recorded.
* **Best effort for downgrades.** A format 1 file has no id, so only the two
  lookups above can recognise one. An older snapshot of a format 1 vault that was
  never upgraded here, at a path never seen, is not recognised.
* **Failure handling.** A missing state file is an empty state. If the lock or
  the write is impossible, the check still runs against what can be read (a
  rollback is still refused) and a warning says the record was not updated; if
  there is no state directory at all, one warning and no check. A damaged or
  newer-version file is an error and is never overwritten. `accept` (the
  deliberate override, `cloakenv accept-rollback`) fails loudly instead.
* **Refresh and cap.** At most 1,024 vaults are kept, least recently used first
  dropped (with their paths and retired tags); opening a vault in the older half
  moves it to the end, so a vault in use is not the one forgotten, and nothing is
  rewritten for one in the newer half.
* **Concurrent reads.** `list`, `run` and `info` read the vault without its write
  lock, so a save can land between the read and the comparison and leave the
  reader's copy one generation behind. The writer renames the new file into place
  *before* it records the generation, so a read that looks refusable is repeated
  (three reads at most, `SETTLE_ATTEMPTS` in `main.rs`) before it is believed.
  A copy that is still behind is refused as before; the check is never skipped.
* **Not defended.** The record is not authenticated: whoever can write the state
  directory can edit or delete it, and the next open trusts what it finds. A
  machine that has never opened a vault has nothing to compare with. Each machine
  keeps its own record, so a vault shared through a synced folder or a repository
  reports forks and rollbacks that are real.

### Commands and their failure behaviour

* `init` writes format 2 (generation 1) and records it. `set`, `unset`, `import`
  write the format they read, with the generation raised by one, and record the
  new version only after the rename succeeded (a failed record is a warning: the
  next open sees a newer generation than recorded, which is accepted).
* `upgrade` (under the vault lock): open and check, copy the format 1 file into
  `<state dir>/backups/`, raise weak key-derivation settings, write format 2 with a
  new id and generation 1, then record the new vault and the old file's tag. A
  kill between the copy and the write leaves the vault as it was; between the
  rename and the record, the next open records it.
* `passwd` (under the vault lock): open and check with the current passphrase,
  copy the vault into `backups/`, save under the new passphrase with a fresh salt
  and nonce. A kill leaves the vault openable with the old or the new passphrase.
  The new passphrase must differ from the current one.
* The copies are 0600 in a 0700 directory inside the state directory, never next
  to the vault, and never overwritten (a name collision adds a counter).
  cloakenv refuses to open one (a downgrade, or a rollback for a format 2 vault's
  older generation) until `accept-rollback`.
* `info` and `accept-rollback` read and settle like the other readers; `info` never
  writes anything and never prints a name or a value.

### Threat model and what changed

Format 2 closes the exact-size leak (padding), the silent rollback (record) and
the lack of a passphrase-change command, and leaves a way to add header fields
without a version bump (the extension area). It does not change what an attacker
who can read the vault learns about the passphrase (Argon2id and the cipher are
the same), and it does not protect a format 1 vault at all. It trades a state
directory (plain text, holding vault paths) for the rollback check.

### Decisions

* **No key wrapping.** Re-wrapping a data key without rotating it would let
  someone who cracked an old, weak passphrase read every later version; rotating
  it makes wrapping save nothing, since the cost is the two key derivations.
* **No automatic migration.** Converting a vault silently would lock every older
  cloakenv out of it (a shared volume, a team with mixed versions). `upgrade` is
  explicit and every command on a format 1 vault says it is available.
* **Rollback blocks every command, `run` included**, with the only way past it a
  command, never an environment variable (one set in a profile would switch the
  protection off for good).
* **No `export` or `get`.** Values are rotated at their source, not recovered.
* **Library API.** The format 1 `Vault::seal`, `open`, `load` and `save` are
  unchanged; `vault::file::Loaded` reads and writes either format, `vault::v2`
  is the codec and `vault::state` the record. `VaultError` has new variants.

### How this was tested

* Golden vaults written by the published 0.1.0 and 0.2.0 binaries
  (`tests/fixtures/v1`) must keep opening. The published 0.2.0 binary refuses a
  format 2 vault with "unsupported vault format version 2" and leaves it
  untouched (checked by hand, since it needs that binary).
* A known-answer vector for the format 2 bytes (header spelled out by hand,
  plaintext checked by an independent decryption; the ciphertext and tag are
  pinned from this implementation), rejection tables for the header, the
  extensions and the authenticated plaintext, bit-flip and truncation sweeps, and
  random mutation of valid headers.
* Real processes, not threads, for the race between readers and a writer, the
  downgrade cases (a symlink in place of the vault, a renamed directory) and the
  commands; every one of those fixes was checked by breaking it.
* Fuzz targets (`fuzz/`, not part of the crate): the header parser, the
  authenticated-plaintext decoder, the state-file parser, and mutated whole
  files. The last runs a real key derivation for every input that gets past the
  header, so it executes few inputs and is weak for the `open` path; the plaintext
  target is what covers the decoder.
* An independent review reproduced the format with a separate implementation in
  Python and checked it against this one in both directions, fed it crafted
  headers and authenticated but malformed files (all refused, none panicked),
  and killed `set`, `passwd` and `upgrade` at random points (no refusal and no
  lockout afterwards).
* Tried by hand on one Windows machine (Windows PowerShell 5.1, classic console,
  local NTFS): the commands, rollback refusal and override, upgrading a 0.2.0
  vault, `passwd`, a reader racing a writer, and the downgrade check with a
  directory junction in place of the vault's directory.
* Not verified: a symbolic link to a *file* on Windows (needs Developer Mode or
  an elevated shell; the junction case exercises the same path comparison),
  Windows Terminal, a state directory in a synced or network folder, anything by
  hand on macOS, and how a case-insensitive file system affects path matching
  there.

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
   inside `cloakenv run --shield` and check they fail (without `--shield` there
   is no cloakenv process left to probe). cloakenv also sets its soft
   `RLIMIT_CORE` to 0 (every Unix), covering `fs.suid_dumpable=2` and macOS; the
   original limit is restored for the command. Not covered: root /
   `CAP_SYS_PTRACE`, and **non-Linux platforms**: the call is
   `cfg(linux/android)`-gated and a no-op elsewhere, so on macOS other
   processes of the same user may be able to read cloakenv's environment
   (`CLOAKENV_PASSPHRASE` / the passphrase file path); only the zero soft core
   limit (above) keeps a core file from being written there. macOS has no `/proc`, so the `/proc/<pid>/fd` shield
   bypass does not exist there, but other macOS equivalents have not been
   assessed. Independently of platform, the child itself receives the plaintext
   in its environment, which same-user processes can read (on Linux the
   child is dumpable again after `execve`).

## `--shield` streaming redaction

stdout and stderr of the child are piped; one thread per stream reads 8 KiB
chunks and feeds them through a `Redactor` (Aho-Corasick, leftmost-longest)
before writing to the parent's corresponding stream after every chunk. If the
parent's stdout and stderr are the same destination there is one pipe, one
thread and one redactor for both (see "One pipe or two" above). stdin is
inherited.

**Chunk boundaries:** the redactor holds back exactly the trailing bytes that
could still become the beginning of a match: the longest suffix of its buffer
that is a *proper* prefix of some secret (a secret that nothing longer
continues is complete, so it is redacted at once). Any match starting before
that point is fully determined by bytes already seen (a longer alternative at
the same start would make that start a proper prefix and hold it), so it is
safe to emit or redact; everything else, such as ordinary output or a prompt
without a newline, is released immediately. Held bytes wait for more input or
EOF and are *never* released by a timer: they are the bytes that start a
secret, so releasing them on idle would leak a secret prefix from any slow
writer. Output is therefore byte-for-byte identical to redacting the whole
stream at once, independent of how the OS splits reads. The tests compare the
redactor with a naive leftmost-longest reference on random overlapping,
prefix-related and binary secrets and random chunkings, check after every push
that the held-back length is exactly the reference's, and that no secret ever
appears in the output.

How the held-back suffix is found: a first-byte table (derived from the
automaton's anchored start state, so there is no second copy of the secrets)
skips every position that cannot start a secret; for the others an anchored
walk of the same automaton from that position tells whether the rest of the
buffer is a prefix of some secret (and, for a match state, whether anything
longer continues it). Only the last `L − 1` bytes (`L` = longest secret) are
candidates. The work per push is bounded (about eight steps per candidate
byte plus a constant); a stream built to look like the beginning of a long
self-overlapping secret exceeds it, and the redactor then holds the whole
`L − 1` window, which is always a safe superset (the old behaviour for every
stream).

**Building the automaton:** a DFA is the fastest matcher but its construction
follows failure links for every state and byte class, which is quadratic for a
value that overlaps itself (`x` repeated: 16 KiB took 0.5 s, 32 KiB 2.1 s, 64 KiB
8.7 s, 200 KB more than 20 s; `set` accepts values up to 1 MiB, although Linux
will inject at most 128 KiB per variable). Up to 8 KiB of secret bytes in total
the matcher is therefore still a DFA (worst case, 8 KiB of `x`: about 0.13 s to
build); beyond that it is a contiguous NFA, which builds in linear time (a 1 MiB
value of `x`: a few milliseconds; roughly 12 bytes of automaton per secret byte).
Measured in a release build, through the redactor in the pump's 8 KiB chunks, on
100 MB of output without a newline made of random letters (the hard case: the
text keeps resembling the secrets): 0.18 s with 20 secrets of 24 bytes (DFA),
1.15 s with those plus one random 16 KiB secret (NFA). Typical output, which
rarely resembles a secret, scans at 200 to 540 MB/s on the NFA in a stand-alone
measurement, against 650 to 710 MB/s on the DFA. There is no limit on the secret
bytes: the build cost no longer depends on their structure. (`cargo test
--release --test shield_fuzz -- --ignored --nocapture` repeats the measurement.)

**Known limitations** (by design for v0.1):

* Only *literal* values are matched. Transformed secrets (base64, hex,
  URL-encoded, JSON-escaped, case-changed, truncated/masked, split across lines
  by the program) are not caught.
* stdout and stderr have independent filters (one per thread): a secret split
  between the two streams is not caught, and the interleaving of stdout versus
  stderr in the output is not guaranteed to match the child's write order.
* If a stream ends while the held-back tail is a proper prefix of a secret
  (child killed, output cut off), that prefix is written in clear at EOF.
* A trailing partial secret is delayed until more output arrives or the stream
  closes (and is never released by a timer); nothing else is held back, so a
  prompt without a newline appears at once. An opt-in idle flush was
  considered and not built: the held bytes are by definition a prefix of a
  secret, so flushing them when the writer pauses would reveal the start of
  a secret to anyone watching the output of a slow writer.
* When two *different* secrets overlap in the output (e.g. `hunter2` and
  `2fa-token` printed as `hunter2fa-token`), leftmost-longest redacts the
  first and the non-overlapping tail of the second remains visible.
* Very short values (a few bytes, e.g. `1`) redact every occurrence of that
  string: output is mangled and inflated (each 1-byte match becomes
  22 bytes), and seeing `[REDACTED_BY_CLOAKENV]` for a guessed string confirms
  the guess, a practical guessing oracle for such values.
  `run --shield` warns (stderr of cloakenv itself, before spawning; never via
  the shield stream) naming each key whose non-empty value is under
  `runner::SHORT_VALUE_LEN` = 6 bytes. All vault entries are checked, since
  the shield redacts all of them. Advisory only: no exit-code or redaction
  change.
* Empty values are never matched.
* Redaction only applies to the child's stdout/stderr pipes; anything the
  child writes to files, sockets or `/dev/tty` directly is not filtered.
* A daemonised grandchild that keeps stdout open no longer keeps `cloakenv`
  alive: once the command itself has exited the pumps stop after a short
  quiet period (250 ms) or 3 seconds, whichever comes first, and anything the
  leftover prints afterwards is never shown.
* A Ctrl-C at a terminal reaches the command twice (once from the terminal,
  once forwarded); see "Process model".
* The child process itself obviously has the plaintext secrets; `cloakenv` is
  not a sandbox.
