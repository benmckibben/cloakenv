# cloakenv

Lightweight encrypted local secret vault and zero-leak process injection engine.

`cloakenv` replaces plaintext `.env` files with an encrypted vault
(`.cloak/vault.bin`) and injects secrets **directly into a child process's
environment** — nothing is ever decrypted to disk. With `--shield`, the
child's stdout/stderr are streamed through a redactor that replaces any secret
value with `[REDACTED_BY_CLOAKENV]`, so credentials don't end up in AI agent
transcripts, CI logs or terminal scrollback.

## Quick start

```sh
cargo install --path .

cloakenv init                          # prompts for a passphrase
cloakenv set DATABASE_URL              # value read from a hidden prompt
pass show api | cloakenv set API_KEY   # ...or piped on stdin (never as an argument)
cloakenv import .env && rm .env        # migrate an existing .env file
cloakenv list                          # names only, never values

cloakenv run -- npm start              # secrets injected into npm's env
cloakenv run --shield -- ./debug.sh    # ...and redacted from its output
```

## Passphrase sources

In order of precedence:

1. `CLOAKENV_PASSPHRASE` environment variable.
2. `CLOAKENV_PASSPHRASE_FILE` — path to a file holding the passphrase (one
   trailing newline is stripped). Handy for a machine-local key:
   `head -c 32 /dev/urandom | base64 > ~/.config/cloakenv.key && chmod 600 ~/.config/cloakenv.key`.
3. Interactive prompt (only when stdin is a terminal).

Both variables are always stripped from the child's environment, and
`cloakenv set` / `cloakenv import` refuse to store secrets under either name.
On Linux, cloakenv also marks itself non-dumpable at startup
(`prctl(PR_SET_DUMPABLE, 0)`), so neither the commands it runs nor other
processes of your user can read the passphrase out of `/proc/<pid>/environ`,
inspect its memory, or write around `--shield` via `/proc/<pid>/fd`; it never
leaves a core dump. This is **Linux only**; see [Platform support](#platform-support)
for what that means on macOS.

If the passphrase file is readable or writable by group or others, cloakenv
warns (see [Permission warnings](#permission-warnings)) but still uses it.

## Vault location

`.cloak/vault.bin` relative to the current directory by default; override with
`--vault <path>` or `CLOAKENV_VAULT`. On Unix the file is written atomically
with mode `0600`, inside a `0700` directory if cloakenv has to create it (an
existing directory is left as it is). Commands that modify the vault
serialise on an advisory lock file next to it (`.cloak/.vault.bin.lock`), so
concurrent `cloakenv set` calls never lose updates (Unix only; see
[Platform support](#platform-support)).

### Keeping the vault out of git

`cloakenv init` writes `.cloak/.gitignore` containing `*`, so `.cloak/`
(vault, lock file and the ignore file itself) never shows up in `git status`
or `git add .` in *your* project; the repository-level ignore rules of
cloakenv's own source tree don't apply there. An existing `.cloak/.gitignore`
is never overwritten, and if it cannot be written `init` still succeeds and
prints a warning telling you to ignore the directory yourself. For a vault
placed in some other pre-existing directory via `--vault` (the project root,
say) nothing is written, because a `*` there would hide your whole project:
add an ignore rule yourself. `git add -f` can still force the file in; don't.
A committed vault is exposed to offline passphrase guessing by anyone who can
read the repository, forever.

### Permission warnings

On Unix, cloakenv checks permissions each time it opens the vault and prints
one line per problem on its own stderr, before it decrypts or spawns anything
(so it never appears inside the redacted stream of a `--shield` child). These
are warnings only: exit codes do not change and cloakenv never chmods files it
did not create.

| condition | warning |
|-----------|---------|
| vault directory group/world-writable | `cloakenv: warning: vault directory <dir> is group/world-writable (mode 0777, expected 0700); others could replace the vault` |
| vault file group/world-readable or writable | `cloakenv: warning: vault file <file> is group/world-readable or writable (mode 0644, expected 0600)` |
| passphrase file group/world-readable or writable | `cloakenv: warning: passphrase file <file> is group/world-readable or writable (mode 0666, expected 0600); anyone who can read it can decrypt the vault` |
| vault directory is a symlink | `cloakenv: warning: vault directory <dir> is a symbolic link; cloakenv follows it, so make sure its target is private` |
| vault file is a symlink | `cloakenv: warning: vault file <file> is a symbolic link; reads follow it, but saving replaces the link with a regular file` |

A loose passphrase file is a warning rather than an error on purpose:
container secret mounts (Docker, Kubernetes) are commonly mode 0444/0644 and
protected by the container boundary instead. On a normal workstation, fix it
with `chmod 600`.

## Vault file limits

The key-derivation settings are stored in the vault header, which cloakenv has
to read *before* it can authenticate the file. To keep a hostile or corrupted
file from forcing a huge allocation or many seconds of CPU, headers asking for
more than **256 MiB, 8 passes or 8 lanes** are refused up front, exactly like
any other bad vault (exit 125, nothing spawned):

```
cloakenv: error: unsupported key-derivation parameters (memory 1048576 KiB, iterations 32, lanes 1); this version accepts memory 8192 to 262144 KiB, iterations 1 to 8, lanes 1 to 8
```

New vaults use 64 MiB / 3 passes / 1 lane, well inside the limit. There is no
flag or variable to raise it. It only matters if you created a vault through
the library API with stronger-than-default settings above the cap.

### Key-derivation settings are upgraded on save

New vaults use Argon2id with 64 MiB / 3 passes / 1 lane. The library API
refuses to create a vault weaker than OWASP's minimum Argon2id setting
(19 MiB / 2 passes / 1 lane). Vaults written by older versions with weaker
settings (down to 8 MiB / 1 pass) still **open**, so nobody is locked out of
their secrets, but cloakenv warns about them on stderr (exit codes unchanged):

```
cloakenv: warning: vault key-derivation settings (memory 8192 KiB, iterations 1, lanes 1) are weaker than the recommended minimum (memory 19456 KiB, iterations 2, lanes 1); they are upgraded the next time you run `cloakenv set`, `unset` or `import`
```

Every `set`, `unset` and `import` re-saves the vault with each parameter
raised to at least the default (the per-parameter maximum of the vault's own
setting and 64 MiB / 3 / 1; a vault that is already stronger keeps its stronger
parameters), at the cost of one extra key derivation that the save performs
anyway, and says so:

```
cloakenv: upgraded the vault's key-derivation settings from memory 8192 KiB, iterations 1, lanes 1 to memory 65536 KiB, iterations 3, lanes 1
```

A header below 8 MiB / 1 pass / 1 lane is rejected as unsupported.

### Reading the vault

The vault path must also be an ordinary file of at most 16 MiB. cloakenv opens
it once, checks the open handle (not the path) and reads with a hard size cap,
so `--vault /dev/zero`, a FIFO, a directory or a huge file is refused
immediately (exit 125 for `run`, nothing spawned) instead of exhausting memory
or hanging:

```
cloakenv: error: /dev/zero is not a regular file (it is a directory, device, pipe or socket); refusing to read it as a vault
cloakenv: error: vault file is too large (the limit is 16 MiB)
```

A symbolic link to a regular file keeps working (with the warning above).

## Exit codes

| situation                                      | code          |
|------------------------------------------------|---------------|
| `run`: child exited normally                   | child's code  |
| `run`: child killed by signal N                | 128 + N       |
| `run`: vault/passphrase/shield failure         | 125           |
| `run`: command not executable / not found      | 126 / 127     |
| other subcommands: any failure                 | 1             |
| invalid command line (arguments never echoed)  | 2             |
| usage error                                    | 2             |

Exit codes are 0–255 on Unix. A child exit status above 255 (possible on
Windows only, which is unsupported) is reported as `1`.

## What `--shield` does and doesn't do

`--shield` pipes the child's stdout and stderr through an in-memory filter that
replaces every **literal, byte-for-byte** occurrence of a decrypted vault value
with `[REDACTED_BY_CLOAKENV]`, including occurrences that straddle read
boundaries. It is meant to stop *accidents*: `env` or `set -x` dumps, error
messages that echo a connection string, a stack trace that includes a token.
It is **not** a security boundary against a command that wants to leak a
secret: the child process has the plaintext in its environment.

What it does **not** catch:

- **Transformed secrets.** Only the exact value is matched. Base64, hex,
  URL/percent-encoded, JSON- or shell-escaped (`\n`, `\"`), reversed,
  upper/lower-cased, truncated or masked forms (`sk-live-ab…`), and values the
  program wraps or splits across lines are printed in clear.
- **Secrets split across the two streams.** stdout and stderr are filtered
  independently (one filter and one thread each); a secret whose first half goes
  to stdout and second half to stderr matches in neither.
- **Interleaving order.** The two streams are read and written by separate
  threads, so the relative order of stdout and stderr lines in the redacted
  output is **not** guaranteed to match the order the child produced them.
  (Within one stream, order is preserved.)
- **Anything that isn't the stdout/stderr pipe:** files, sockets, `/dev/tty`,
  other inherited file descriptors, or a deliberate `| base64`.
- **Very short secrets (a few bytes).** Every occurrence of the string is
  replaced, so ordinary output is mangled and *inflated* (a 1-byte secret
  becomes 22 bytes per occurrence), and `[REDACTED_BY_CLOAKENV]` appearing for a
  guessed string tells whoever can see the output that the guess is a secret
  value, which is a practical guessing oracle for such short values. Don't keep
  tiny non-secret settings (`DEBUG=1`, `PORT=80`) in the vault. To make
  this visible, `run --shield` prints one warning on cloakenv's own stderr,
  before the child starts (so it is never part of the redacted stream), when
  any non-empty vault value is shorter than 6 bytes. It names the keys, never
  the values, and changes neither exit codes nor redaction:

  ```
  cloakenv: warning: --shield: the values of DEBUG, PORT are shorter than 6 bytes; short values are redacted everywhere they occur (bloating and garbling the output) and the redaction marker confirms a guessed string, so they act as a guessing oracle; keep short, non-secret settings out of the vault
  ```

  Redaction itself is unchanged and still applies to such values.
- **A partial secret at the end of the output.** To match across chunk
  boundaries the filter holds back the last (longest secret − 1) bytes of each
  stream. If the stream ends in the middle of what *would* have been a match
  (the child is killed, or prints only the first part of a token and exits), the
  held-back prefix is flushed as is, in clear.

These are known limitations, documented here rather than fixed in this
release; see [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md#--shield-streaming-redaction).

## Platform support

| platform | status |
|----------|--------|
| Linux | supported; tested in CI (Ubuntu 24.04, stable Rust and the 1.87 MSRV) |
| macOS | supported; tested in CI (macOS 15, stable Rust) |
| Windows | **unsupported and untested**: not built or tested in CI, integration tests are Unix-only |

Several protections described above are implemented with Unix-only APIs
(`cfg(unix)`), and silently do not exist elsewhere:

- file mode `0600` for the vault and lock file, and `0700` for a directory
  cloakenv creates;
- the directory `fsync` after the atomic rename (durability across power loss);
- the advisory `flock` that serialises concurrent writers;
- the permission warnings (symlink warnings do apply);
- `128 + N` exit codes for a child killed by a signal.

On Windows, cloakenv would use default inherited ACLs, would not prevent
concurrent `set` calls from losing updates, and has not been checked at all.

**`PR_SET_DUMPABLE` is Linux only.** The hardening that keeps same-user
processes from reading cloakenv's `/proc/<pid>/environ`, memory and file
descriptors relies on `prctl(PR_SET_DUMPABLE)`, which exists on Linux only; on
macOS and everywhere else it is a no-op. On macOS, cloakenv therefore does
**not** protect `CLOAKENV_PASSPHRASE` (or the `CLOAKENV_PASSPHRASE_FILE` path)
in its own environment from other processes of the same user, nor disable core
dumps. There is no `/proc` on macOS, so the Linux-specific `--shield` bypass
via `/proc/<pid>/fd` doesn't exist there, but equivalent macOS mechanisms have
not been evaluated. Prefer the interactive prompt or a mode-`0600`
`CLOAKENV_PASSPHRASE_FILE` over `CLOAKENV_PASSPHRASE` on shared or untrusted
macOS accounts. Still true on every platform: the commands you run get the
decrypted values in their own environment (readable by other same-user
processes the usual way, e.g. `/proc/<pid>/environ` of the child on Linux),
and cloakenv is not a sandbox.

## Security model

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the vault format,
cryptography and the precise guarantees (and non-guarantees) of `--shield`.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
