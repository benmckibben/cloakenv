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
inspect its memory (`ptrace`, `/proc/<pid>/mem`), or write around `--shield`
via `/proc/<pid>/fd`; it never leaves a core dump. On every Unix (Linux and
macOS) it additionally lowers its own soft core-file size limit to 0, which
also covers systems with `fs.suid_dumpable=2` (where the kernel would
otherwise write a root-readable core for a non-dumpable process) and macOS,
which has no dumpable flag; the command you run gets its original limit back.
The dumpable flag is **Linux only**; see [Platform support](#platform-support)
for what that means on macOS.

These protections last for as long as cloakenv exists. Without `--shield`
that is only until it starts your command, because `cloakenv run` then
*replaces itself* with the command (see [How `run` starts your
command](#how-run-starts-your-command)); the passphrase is gone from memory
and from the process's environment at that moment. The one unprotected window
is the instant between the kernel starting the cloakenv process and its first
instructions setting the flag: a same-user process that polls `/proc` fast
enough could read `CLOAKENV_PASSPHRASE` from a freshly started cloakenv, so
if your threat model includes that, use the interactive prompt or a
`CLOAKENV_PASSPHRASE_FILE` rather than the variable (an exported variable is
also readable in your shell's own environment).

If the passphrase file is readable or writable by group or others, cloakenv
warns (see [Permission warnings](#permission-warnings)) but still uses it.

## Vault location

`.cloak/vault.bin` relative to the current directory by default; override with
`--vault <path>` or `CLOAKENV_VAULT`. On Unix the file is written atomically
with mode `0600`, inside a `0700` directory if cloakenv has to create it (an
existing directory is left as it is). Commands that modify the vault
serialise on an advisory lock file next to it (`.cloak/.vault.bin.lock`), so
concurrent `cloakenv set` calls never lose updates (Unix only; see
[Platform support](#platform-support)). A writer holds the lock for its whole
load-modify-save cycle, which includes two key derivations (a fraction of a
second each at the default settings), so simultaneous writers queue up (the
ones that have to wait say so on stderr); reads (`list`, `run`) never take it
and always see a complete vault. The lock dies with its process, so a killed
writer cannot leave it stuck. On a filesystem where `flock` does not work (an
NFS mount without lock support, say) writers refuse to run with `cannot lock
vault <path>: <OS error>` rather than go ahead unprotected.

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

### Importing a `.env` file

`cloakenv import <file>` reads the file the same careful way: it opens it once
and checks the open handle, refuses anything that is not a regular file (a
directory, `/dev/zero`, a FIFO, a socket) and anything over 16 MiB, and reads
into a single buffer that is wiped afterwards. Symbolic links to regular files
keep working. Invalid UTF-8 is refused without echoing any of it.

```
cloakenv: error: /dev/zero is not a regular file (it is a directory, device, pipe or socket); refusing to import it
cloakenv: error: .env file big.env is too large (the limit is 16 MiB)
```

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

## How `run` starts your command

**Without `--shield` (Unix): cloakenv replaces itself with the command**
(`execve`). After the vault is decrypted, the passphrase and every decrypted
value are wiped from cloakenv's memory, the command's environment is built
(the vault's entries, minus `CLOAKENV_PASSPHRASE` and
`CLOAKENV_PASSPHRASE_FILE`), and the process image is swapped. There is no
cloakenv process left, so:

- the command keeps cloakenv's process id, its parent is whatever started
  cloakenv, and `ps` shows the command, not cloakenv;
- signals (`kill`, Ctrl-C, `docker stop`, a service manager) reach the command
  directly; nothing can be orphaned;
- the exit status is the command's own: a normal exit code, or, if it is killed
  by a signal, the signal death itself (a shell reports it as `128 + N`, a
  program using `waitpid` sees `WIFSIGNALED`, which is not an exit code);
- stdin, stdout, stderr, the controlling terminal, the working directory and
  open descriptors are inherited unchanged (cloakenv opens nothing that survives
  the exec: the vault, passphrase file and lock file are all close-on-exec or
  closed);
- cloakenv's environment block, with the passphrase in it, no longer exists
  anywhere: there is nothing left for another process to read, however it asks.

Nothing about the command's own exposure changes: its environment holds the
vault's secrets by design, and the kernel resets the dumpable flag on `exec`,
so `/proc/<pid>/environ` of your command is readable by other processes of
your user (and by root), exactly as it was when cloakenv was its parent. It
holds no passphrase. If that matters, don't put the secret in an environment
variable the command can't be trusted with. Failures to start the command are
reported by cloakenv before it is gone, with the same exit codes and messages
as always: 127 `command not found`, 126 `permission denied`, 125 anything
else; a failed exec leaves no secret in the message.

**With `--shield` (Unix): cloakenv stays the parent**, because it has to
filter the output. It then

- **forwards `SIGTERM`, `SIGHUP`, `SIGINT`, `SIGQUIT`, `SIGUSR1` and `SIGUSR2`** to
  the command and keeps waiting, so `kill <cloakenv>`, `docker stop` etc. stop
  the command instead of orphaning it, and cloakenv exits with the command's
  status, `128 + N` if the signal killed it (a command that catches the signal
  and exits 0 gives 0). A signal that arrives while the command is starting is
  delivered as soon as it exists, and one that arrives after it exited is
  dropped, never sent to a recycled pid. A signal that was *ignored* when
  cloakenv started (`nohup`, a background job of a non-interactive shell) stays
  ignored for the command too;
- on Linux, has the kernel kill the command (`SIGKILL`, `PR_SET_PDEATHSIG`) if
  cloakenv itself dies, including by `SIGKILL` or the OOM killer, which cannot
  be forwarded. This covers the command's own process only, not processes it
  spawned. On macOS there is no equivalent: if cloakenv is killed with
  `SIGKILL` the command keeps running (its next write to the closed output pipe
  ends it with `SIGPIPE`, if it ever writes);
- delivers a Ctrl-C **twice** to the command at a terminal: the terminal sends
  `SIGINT` to the whole foreground process group (cloakenv and the command), and
  cloakenv forwards its copy as well. Telling the two apart needs the signal's
  sender, which cloakenv has no portable way to see, and dropping the forwarded
  copy would swallow a `kill -INT` aimed at cloakenv alone. Programs that treat
  a second Ctrl-C as "abort now" will abort;
- ends its output pumps shortly after the command exits even if a leftover
  background process still holds the output pipes open (`cmd &`, a daemon):
  it keeps draining until the pipes have been quiet for 250 ms or 3 seconds
  have passed (time spent blocked on its own stdout does not count), flushes
  what it has and exits with the command's status. Leftover processes are not
  killed; they lose their output pipe and get `SIGPIPE` on their next write.
  Before this change a leftover held cloakenv (and so, say, a CI step) up for as
  long as it lived.

Windows is unsupported: there `run` is a plain spawn-and-wait with none of the
above.

## Exit codes

| situation                                      | code          |
|------------------------------------------------|---------------|
| `run`: command exited normally                 | command's code |
| `run --shield`: command killed by signal N     | 128 + N       |
| `run` (no shield): command killed by signal N  | the signal death itself (shells show `128 + N`) |
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
- **Output after the command has exited.** Once the command itself is gone,
  `--shield` stops waiting for background processes that kept the pipes open
  (see [How `run` starts your command](#how-run-starts-your-command)): what
  they print after the grace period is not shown at all, filtered or not.
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
- replacing cloakenv with the command (`exec`) without `--shield`, and signal
  forwarding with it (neither exists on Windows);
- the permission warnings (symlink warnings do apply);
- `128 + N` exit codes for a child killed by a signal.

On Windows, cloakenv would use default inherited ACLs, would not prevent
concurrent `set` calls from losing updates, and has not been checked at all.

**`PR_SET_DUMPABLE` and `PR_SET_PDEATHSIG` are Linux only.** `exec` without
`--shield`, signal forwarding with it and the zero core-file limit work the same
on macOS; killing cloakenv with `SIGKILL` under `--shield` leaves the command
running there (see above).

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
