# cloakenv architecture

## Modules

| module          | responsibility                                                          |
|-----------------|-------------------------------------------------------------------------|
| `src/main.rs`   | clap CLI, passphrase acquisition, exit-code mapping                     |
| `src/passphrase.rs` | the passphrase rules (what each source yields; line-break and length checks) |
| `src/input.rs`  | reading secret text (stdin value, passphrase file) into one wiped, size-capped buffer |
| `src/crypto.rs` | Argon2id key derivation, XChaCha20-Poly1305 seal/open, OS RNG           |
| `src/vault.rs`  | vault file format, in-memory map, atomic writes (0600 on Unix), `.env` parser |
| `src/perms.rs`  | advisory permission/symlink warnings for the vault and passphrase file (Unix) |
| `src/hardening.rs` | process hardening (`PR_SET_DUMPABLE` on Linux, zero soft core limit on Unix) |
| `src/runner.rs` | env injection: `exec` into the command, or spawn it; `--shield` streaming redactor |
| `src/supervise.rs` | (Unix) `--shield` supervision: signal forwarding, race-free reaping, output pumps |
| `src/sys.rs`    | (Unix) the crate's only `unsafe`: `sigaction` read, `pre_exec` hook (`PDEATHSIG`, core limit) |
| `src/lib.rs`    | re-exports the above so integration tests can exercise them directly    |

## Cryptography

* **KDF:** Argon2id v1.3. New vaults use 64 MiB / 3 passes / 1 lane. A
  vault is only ever *written* with at least 19 MiB / 2 / 1 (OWASP's minimum
  Argon2id setting; `KdfParams::MIN`; `Vault::with_params` refuses less, and
  `seal` clamps up to it). On *read* the lower bound is the more lenient
  8 MiB / 1 / 1 (`KdfParams::FLOOR`, the old minimum), so a weak vault created
  by an earlier version still opens instead of locking its owner out; the CLI
  warns about it and `set`/`unset`/`import` upgrade every parameter to at
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
* **Associated data:** the entire 64-byte header (magic, version, algorithm
  ids, KDF parameters, salt, nonce). Flipping any header bit fails decryption.
* Key material, passphrases and decrypted values are held in
  `zeroize::Zeroizing` buffers and wiped on drop. `Debug` impls never print them.

## Passphrase rules

One passphrase, three sources (`CLOAKENV_PASSPHRASE`, `CLOAKENV_PASSPHRASE_FILE`,
the prompt), defined in `src/passphrase.rs` and README "Exactly what counts as
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

Before taking the lock, `set`/`unset`/`import` check that the vault exists, so a
mistyped `--vault` path creates no directory or lock file. The lock file is
opened like every file in Rust, close-on-exec, so no command can inherit it; a
symlink at the lock path is followed (the lock directory has the same trust
level as the vault itself).

`import` reads its `.env` file with the same open-once/`fstat`-the-handle
discipline as the vault: regular files only, at most 16 MiB, into one buffer
sized up front (never reallocated, so no stray copy) that is wiped on drop.

Writers (`init`, `set`, `unset`, `import`) hold an exclusive `flock(2)` on a
sibling `.vault.bin.lock` (empty, mode 0600, never deleted) for the whole
load → modify → save cycle, so concurrent updates are serialised instead of
silently overwriting each other. The lock lives on a separate file because the
vault inode is replaced on every save. Readers (`list`, `run`) take no lock;
the atomic rename already guarantees they see a complete vault. Passphrase and
value prompts happen *before* the lock is taken, so an idle prompt never
blocks other writers. `flock` is Unix only; elsewhere the lock is a no-op.

**Reading the vault is bounded.** `Vault::load` opens the path once
(`O_NONBLOCK | O_NOCTTY` on Unix, so opening a FIFO or terminal cannot block
or steal a controlling terminal), runs `fstat` on the *open handle*, and
refuses anything that is not a regular file or is larger than 16 MiB before
reading a byte; the read itself is additionally capped at 16 MiB + 1 byte, so a
file that grows or lies about its size cannot cause unbounded allocation.
Symlinks are followed (and warned about); a symlink to `/dev/zero` is refused
because the check is on what it resolves to.

**Permission checks (Unix, advisory).** When a command opens the vault,
`src/perms.rs` warns on stderr if the vault directory is group/world-writable,
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
* **Output pumps and leftover holders.** The pumps `poll` their pipe with a
  50 ms tick instead of blocking in `read`. After the command has exited
  they end at EOF, or once the pipe has been silent for 250 ms, or 3 seconds
  after the exit (not counting time blocked writing to our own stdout), and
  flush their redactor either way. Leftover processes are not killed.
* `unsafe` is denied crate-wide and allowed in `src/sys.rs` only, for two
  calls with no safe wrapper (`sigaction` read-only query, `pre_exec`).
  Each has a SAFETY comment; the `pre_exec` closure only makes raw syscalls.

## Platform support

Linux and macOS are supported and tested in CI. Windows is unsupported and
untested (not built in CI; integration tests are `cfg(unix)`). Unix-only
pieces: file modes 0600/0700, directory fsync, `flock`, permission warnings,
`exec` into the command, signal forwarding and exit codes (`128 + N`; on other
platforms any exit status above 255 becomes 1). `PR_SET_DUMPABLE` and
`PR_SET_PDEATHSIG` are Linux only (see invariant 6): on macOS `exec` and signal
forwarding behave the same, but a `SIGKILL` of cloakenv under `--shield` leaves
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
  of the first bytes behind. The interactive prompt uses `rpassword`, whose
  line buffer grows character by character: a few short stale copies of what
  was typed may remain on the heap for the (brief) life of the process.
  Accepted: the interactive path, bounded by the length of one line.
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
  encryption, merely not a contiguous copy). Matching speed is unaffected for
  this workload (about 500 to 600 MB/s in a micro-benchmark either way).
* **Not fixable here, accepted:** the copies that `std::process::Command` makes
  of the environment (its own map, and the C string array built when
  spawning). They are freed but not wiped, so they can linger in freed heap
  memory until reused. In the `--shield` scan above they did not leave a
  contiguous copy that survived, but nothing guarantees that. Without
  `--shield` they vanish with the exec.
* **Argument vector.** clap's raw arguments hold key names, the command to run
  and, for `set`, a refused VALUE (which is already in the kernel's
  `/proc/<pid>/cmdline` by then): no secret is ever read from argv by design.

## Rollback and replacement (limit, with a design proposal)

**What is true today.** Every vault file is authenticated (header as AAD plus
the AEAD tag), so nobody can *forge* or edit one without the passphrase. But a
valid file is not tied to a point in time. Anyone who can write the vault's
directory can put an **older valid vault** back (a copy they took earlier, a
backup, an old git commit): values that were rotated come back as their old
(possibly leaked) versions, removed keys reappear, and nothing complains. The
same goes for swapping in any vault made with the same passphrase. `run` cannot
notice without a record of what it has seen before, and cloakenv keeps no state
outside the vault. This is documented in the README threat model as a limit; the
mitigations that do work today are filesystem permissions (a private vault
directory, which cloakenv warns about), and not storing the vault where an
attacker can write.

**Proposal (not implemented; needs a format version bump).** A monotonic,
authenticated generation counter:

1. *Counter.* A `u64 generation` in the vault, increased by one on every
   save (under the write lock, so concurrent writers cannot repeat a value).
   It must be authenticated: either in the header (which is AAD) or at the start
   of the encrypted payload. The v1 header has no room (byte 11 is reserved and
   must be zero; the payload decoder rejects trailing data), so this is a
   **version 2** format. Old binaries refuse version 2 with the existing
   "unsupported vault format version" error (fail closed, no mis-parse); new
   binaries read version 1 as generation 0 and write version 2, so migration is
   automatic but one-way (a downgrade needs the new binary to export). It is
   deliberately not part of this change for that reason.
2. *High-water mark.* A counter inside the file proves nothing on its own: the
   attacker restores a file with a smaller number and it is perfectly valid. The
   check needs a place the attacker cannot write: a small state file outside the
   vault directory, e.g. `$XDG_STATE_HOME/cloakenv/<hash of the canonical vault
   path>` (0600), holding the highest generation this machine has seen.
   Every command that opens the vault compares: a smaller generation is
   refused with a clear error (fail closed, nothing spawned), unless the user
   explicitly accepts it (`cloakenv accept-rollback`, after restoring a backup on
   purpose); an equal or larger one raises the mark.
3. *Limits that stay.* An attacker who can write the state file too (the same
   user, on the same account) defeats it, so it protects against attackers
   confined to the vault directory or its transport (a shared volume, a sync
   service, a restored backup, a repository), not against code running as you.
   A new machine or a fresh clone has no mark (trust on first use). Losing the
   state file silently re-opens the hole. Two machines syncing one vault would
   trip the check on every hand-over and need the explicit accept.
4. *Cost/benefit.* About 100 lines, one format bump, one new file location, and
   a recovery path to design and test. The benefit exists only for a narrow
   attacker. Recommendation: do not build it before the format is revisited for
   another reason (a passphrase-change command also needs a new header), and
   keep the limit documented.

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
before writing and flushing to the parent's corresponding stream. stdin is
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
will inject at most 128 KiB per variable). Up to 4 KiB of secret bytes in total
the matcher is therefore still a DFA (worst case about 30 ms to build); beyond
that it is a contiguous NFA, which builds in linear time (a 1 MiB value of
`x`: a few milliseconds; roughly 12 bytes of automaton per secret byte) and
scans typical output at 200 to 550 MB/s in a release build against 650 to 710
for the DFA. Measured on the pump's 8 KiB chunks with 100 MB of output without a
newline: 0.14 s (DFA) and 0.19 to 0.59 s (NFA). There is no limit on the secret
bytes: the build cost no longer depends on their structure.

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
