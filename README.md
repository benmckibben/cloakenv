# cloakenv

Lightweight encrypted local secret vault and zero-leak process injection engine.

`cloakenv` replaces plaintext `.env` files with an encrypted vault
(`.cloak/vault.bin`) and injects secrets **directly into a child process's
environment** — nothing is ever decrypted to disk. With `--shield`, the
child's stdout/stderr are streamed through a redactor that replaces any secret
value with `[REDACTED_BY_CLOAKENV]`, so credentials don't end up in AI agent
transcripts, CI logs or terminal scrollback.

## Install

cloakenv has no release yet: build it from source (Rust 1.87 or newer; Linux or
macOS, see [Platform support](#platform-support)).

```sh
git clone https://github.com/benmckibben/cloakenv
cd cloakenv
cargo install --path . --locked    # installs `cloakenv` into ~/.cargo/bin
# or: cargo build --release --locked   # binary at target/release/cloakenv
```

The name `cloakenv` on crates.io is reserved by a placeholder (version `0.0.0`)
that contains no functionality, so `cargo install cloakenv` does **not** give you
this program. Release archives are built by CI but nothing is published yet; see
[CONTRIBUTING.md](CONTRIBUTING.md#releasing-maintainer).

## Quick start

```sh
cloakenv init                          # prompts for a passphrase
cloakenv set DATABASE_URL              # value read from a hidden prompt
pass show api | cloakenv set API_KEY   # ...or piped on stdin (never as an argument)
cloakenv import .env && rm .env        # migrate an existing .env file
cloakenv list                          # names only, never values

cloakenv run -- npm start              # secrets injected into npm's env
cloakenv run --shield -- ./debug.sh    # ...and redacted from its output
```

What this does and does not protect against is in the [Threat model](#threat-model).

## Commands

| command | what it does |
|---------|--------------|
| `cloakenv init [--force]` | create an empty vault; refuses to overwrite an existing one unless `--force` (which erases its contents) |
| `cloakenv set KEY` | store or replace one value, from a hidden prompt or stdin (never from the command line) |
| `cloakenv unset KEY` | remove one entry (an error if there is no such key) |
| `cloakenv import FILE` | add or replace the entries of a `.env` file, see [Importing a `.env` file](#importing-a-env-file) |
| `cloakenv list` | print the names, one per line, never the values |
| `cloakenv run [--shield] -- COMMAND [ARGS...]` | run a command with the vault in its environment |

The `--` before the command is required, so that everything after the command's
name is the command's: `cloakenv run -- cmd --shield` gives `cmd` an argument
called `--shield`, and `cloakenv run cmd --shield` (no `--`) is a usage error
(exit 2, nothing is started) rather than an unredacted run.

Every command takes `--vault <path>` (or `CLOAKENV_VAULT`), see
[Vault location](#vault-location); `--help` and `--version` work everywhere.
Variable names must match `[A-Za-z_][A-Za-z0-9_]*`; `CLOAKENV_PASSPHRASE` and
`CLOAKENV_PASSPHRASE_FILE` are reserved. Exit codes are in [Exit codes](#exit-codes).

## Values you store

`cloakenv set KEY` reads the value from a hidden prompt, or from stdin when
stdin is not a terminal (never from the command line). From stdin it takes at
most **1 MiB**, with one trailing newline (`\n` or `\r\n`) removed and nothing
else; anything larger, or not valid UTF-8, is refused with an error that does
not repeat any of it, and nothing is stored. (Linux itself will not start a
command whose single environment variable is over 128 KiB, so a value that large
can be stored but not injected.) The input is read into one buffer that is wiped
afterwards; see "Memory hygiene" in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md#memory-hygiene-best-effort).

## Passphrase sources

In order of precedence:

1. `CLOAKENV_PASSPHRASE` environment variable.
2. `CLOAKENV_PASSPHRASE_FILE` — path to a file holding the passphrase (at most
   64 KiB). Handy for a machine-local key:
   `head -c 32 /dev/urandom | base64 > ~/.config/cloakenv.key && chmod 600 ~/.config/cloakenv.key`.
3. Interactive prompt (only when stdin is a terminal).

### Exactly what counts as the passphrase

The passphrase is the text you supply, byte for byte, with one exception per
source:

| source | what is used |
|--------|--------------|
| `CLOAKENV_PASSPHRASE` | the value, exactly as it is |
| `CLOAKENV_PASSPHRASE_FILE` | the file's contents minus **one** trailing `\n` or `\r\n` |
| interactive prompt | what you typed, without the Enter key |

Nothing else is trimmed or normalised: leading and trailing spaces, a lone
trailing `\r` and a *second* trailing newline are all part of the passphrase.
It must be valid UTF-8 and not empty. A source that is set but unusable (a
non-UTF-8 `CLOAKENV_PASSPHRASE`, an unreadable file) is an error; cloakenv never
quietly falls back to the next source.

The one thing two sources cannot agree on is a passphrase that ends in a line
break: a file containing `x` and two newlines is the passphrase `x\n`, whereas
`CLOAKENV_PASSPHRASE="$(cat file)"` is `x`. So **`init` refuses a passphrase that
ends in `\n` or `\r`**, with an error that does not show it, rather than let you
create a vault you could not open the same way later. (`echo x > file` and
`printf %s x > file` are both fine.) Vaults that already exist are not
affected: every source yields exactly what it did before, and if an unlock
fails with a passphrase that ends in a line break cloakenv adds a `hint:` line
saying so, without showing it.

**Short passphrases.** A vault file can be attacked offline: anyone who gets a
copy can try guesses at the cost of one Argon2id run each. At `init`, a
passphrase shorter than **12 characters** (characters, not bytes), from any
source, draws this warning on stderr; nothing is refused, no exit code changes,
and the passphrase is never echoed:

```
cloakenv: warning: the passphrase is shorter than 12 characters; anyone who obtains the vault file can guess it offline, so a short passphrase is easy to crack. Use a longer one (4 or more random words, or 20 or more random characters). There is no command to change the passphrase later: `cloakenv init --force` starts over (and erases the vault's contents)
```

A machine-local key file from `/dev/urandom` (above) never triggers it.

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

The syntax is blank lines, `# comments`, an optional `export ` prefix, `KEY=value`
(an unquoted value ends at the first trailing ` #` comment), `KEY='literal'` and
`KEY="text"` with the escapes `\n \r \t \\ \"`. Multi-line values are not supported. A
line that does not parse stops the import with its line number (never its
content) and nothing is imported; existing entries with the same name are
overwritten.

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
  open descriptors are inherited as they are (cloakenv opens nothing that
  survives the exec: the vault, passphrase file and lock file are all
  close-on-exec or closed). The exceptions are listed in [What the command
  inherits](#what-the-command-inherits-in-both-modes);
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
- resets `SIGCHLD` to its default action for itself if it inherited it as
  *ignored* (a Python `preexec_fn`, some launchers and init wrappers do that).
  Left ignored, the kernel reaps the command the moment it exits and cloakenv
  could not get its exit status (`failed to wait for child process: No child
  processes`, exit 125). The command still sees `SIGCHLD` ignored, as it would without
  `--shield`;
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
  (Without this a leftover would hold cloakenv, and so, say, a CI step, up for
  as long as it lived.)

Windows is unsupported: there `run` is a plain spawn-and-wait with none of the
above.

### What the command inherits, in both modes

Mostly what cloakenv itself had, but not everything:

- **Standard descriptors that were closed.** If descriptor 0, 1 or 2 is closed
  when cloakenv starts (`cloakenv run … <&-`), the Rust runtime reopens it on
  `/dev/null` before cloakenv's own code runs, so the command finds `/dev/null`
  there, not a closed descriptor. (Under `--shield` the command's 1 and 2 are
  cloakenv's output pipes anyway.) "Inherited unchanged" is true for every
  descriptor that was open.
- **`SIGPIPE` is always the default action** for the command, even if cloakenv's
  caller ignored it (`trap '' PIPE`, a Python launcher): the Rust runtime ignores
  `SIGPIPE` in cloakenv itself and resets it for the commands it starts, and the
  caller's setting cannot be recovered. A command that wants `SIGPIPE` ignored
  must do it itself.
- **Ignored signals stay ignored** for `SIGTERM`, `SIGHUP`, `SIGINT`, `SIGQUIT`,
  `SIGUSR1` and `SIGUSR2` (`nohup` style), and `SIGCHLD` keeps whatever the caller
  set, in both modes (see above for how `--shield` copes with an ignored one).
- **The core-file size limit** is the one cloakenv's caller had (cloakenv lowers
  its own to 0, see [Passphrase sources](#passphrase-sources)).
- **The environment** is the vault's entries on top of cloakenv's own
  environment, minus `CLOAKENV_PASSPHRASE` and `CLOAKENV_PASSPHRASE_FILE`. A
  vault entry with the same name as an existing variable replaces it.

### Without `--shield` and with it, side by side

| | no `--shield` (`exec`) | `--shield` |
|---|---|---|
| process | cloakenv *is* the command: same pid, parent is whatever started cloakenv, `ps` shows the command | cloakenv stays the parent; the command is its child (a new pid) |
| signals | go straight to the command; nothing to forward | cloakenv catches `TERM HUP INT QUIT USR1 USR2` and forwards them (Ctrl-C reaches the command twice at a terminal) |
| exit status | the command's own; a signal death is the signal death itself (a shell shows `128+N`) | the command's code, or `128+N` if a signal killed it |
| stdout, stderr | the very descriptors cloakenv got (terminal, file, pipe) | pipes cloakenv reads and filters: `isatty()` is false, so colours, progress bars, pagers, line editing and REPLs behave as if piped, and programs that buffer when not on a terminal (C stdio, Python) deliver output in blocks until they flush |
| stdin | inherited | inherited (a terminal stays a terminal) |
| if cloakenv is killed with `SIGKILL` | there is no cloakenv | the command is killed too on Linux (`PR_SET_PDEATHSIG`); on macOS it keeps running |
| `/proc` (Linux) | the command is dumpable: its `environ` is readable by same-user processes | same for the command; cloakenv itself (non-dumpable) holds the redaction state |
| a leftover background process | keeps the inherited descriptors | cloakenv stops waiting for its output shortly after the command exits (see above) |

## Exit codes

| situation                                      | code          |
|------------------------------------------------|---------------|
| `run`: command exited normally                 | command's code |
| `run --shield`: command killed by signal N     | 128 + N       |
| `run` (no shield): command killed by signal N  | the signal death itself (shells show `128 + N`) |
| `run`: vault/passphrase/shield failure, or the command's output could not be written | 125 |
| `run`: command not executable / not found      | 126 / 127     |
| other subcommands: any failure                 | 1             |
| invalid command line, including `run` (arguments are never echoed) | 2 |
| `list` whose reader closed the pipe early      | 0 (quiet)     |

**Ambiguity.** 125, 126 and 127 are also ordinary exit codes of commands (a
shell script ending in `exit 127`, a wrapper that itself follows the `env`/`docker
run` convention), and the code is passed through unchanged, so a status of 125,
126 or 127 does not by itself say who failed. cloakenv's own failures always
print a line starting with `cloakenv: error:` on stderr first. Under `run`, a
usage error is 2 but every other cloakenv failure is 125 (not 1, which other
subcommands use and which a command may return too). `cloakenv run --help`
prints this table.

Exit codes are 0–255 on Unix. A child exit status above 255 (possible on
Windows only, which is unsupported) is reported as `1`.

**Output that cannot be written.** Under `run --shield`, cloakenv waits for its
stdout and stderr to become writable if they are non-blocking (a parent that made
a pipe non-blocking shares that flag with cloakenv; the output is neither cut
short nor lost). If writing fails for a reason other than the reader having gone
away (a full disk, a closed socket that reports an error) cloakenv says so,
`cloakenv: error: failed to write the command's output: <OS error>`, stops
reading the command's output, and exits 125 even if the command itself
succeeded, rather than report a success with output missing.

**Output closed early.** If whatever reads cloakenv's output goes away
(`cloakenv list | head -1`), cloakenv stops quietly with exit status 0, the way
`cat` ends quietly: no panic, no message. Under `run --shield` it stops reading
the command's output too, so the command gets `SIGPIPE` on its next write and
cloakenv exits with the command's status (`128 + 13` if that is what ended it).
Without `--shield` the command writes to your pipe directly, and is ended by
`SIGPIPE` like any other command. cloakenv's own messages on stderr are
best-effort: a closed stderr never changes an exit status. A genuine write
failure on stdout (a full disk, say) is still an error: `cloakenv: error:
cannot write to stdout: ...`, exit 1.

## What `--shield` does and doesn't do

`--shield` pipes the child's stdout and stderr through an in-memory filter that
replaces every **literal, byte-for-byte** occurrence of a decrypted vault value
with `[REDACTED_BY_CLOAKENV]`, including occurrences that straddle read
boundaries. It is meant to stop *accidents*: `env` or `set -x` dumps, error
messages that echo a connection string, a stack trace that includes a token.
It is **not** a security boundary against a command that wants to leak a
secret: the child process has the plaintext in its environment.

What the command sees under `--shield` (the full comparison with the exec mode
is [above](#without---shield-and-with-it-side-by-side)):

- its **stdout and stderr are pipes, not terminals** (`[ -t 1 ]` is false):
  colours are usually switched off, progress bars, pagers and interactive REPLs
  do not work, and programs that line-buffer only on a terminal (C stdio,
  Python) hold output until a buffer fills unless they flush (`python -u`,
  `stdbuf -oL`). cloakenv itself shows output as soon as it reads it (see the last
  bullet below for what is held back);
- its **stdin is inherited**: still the terminal if cloakenv's is, so
  prompts and `read` work;
- if cloakenv's own stdout and stderr are the same destination, it gets **one
  pipe for both** (what `2>&1` gives it), which also keeps their order.

What it does **not** catch:

- **Transformed secrets.** Only the exact value is matched. Base64, hex,
  URL/percent-encoded, JSON- or shell-escaped (`\n`, `\"`), reversed,
  upper/lower-cased, truncated or masked forms (`sk-live-ab…`), and values the
  program wraps or splits across lines are printed in clear.
- **Secrets split across the two streams.** When your stdout and stderr are
  different files or pipes they are filtered independently (one filter and one
  thread each), and a secret whose first half goes to stdout and second half to
  stderr matches in neither. When they are the same destination (`> log 2>&1`,
  `2>&1 | tee`, both on one terminal) cloakenv gives the command a single pipe
  for both, exactly as `2>&1` would, so such a secret is caught too.
- **Interleaving order.** When stdout and stderr are different destinations
  they are read and written by separate threads, so the relative order of their
  lines in the redacted output is **not** guaranteed to match the order the
  child produced them. (Within one stream, order is preserved.) When they are
  the same destination the child's own order is kept, and a line of one stream
  is never cut in two by the other.
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
  boundaries the filter holds back the trailing bytes of each stream that could
  still turn out to be the beginning of a secret, and only those: the longest
  suffix of the output so far that is a prefix of some secret (`sk-li` for a
  `sk-live-…` token). A line, a prompt without a newline (`Enter name: `) or a
  server's `listening on …` message is shown at once. Held bytes wait for more
  output or for the end of the stream, and are never released by a timer: they
  are exactly the bytes that begin a secret, so a slow writer would otherwise
  leak its first half. If the stream ends in the middle of what *would* have
  been a match (the child is killed, or prints only the first part of a token
  and exits), the held-back prefix is flushed as is, in clear; it is not the
  secret.

These are known limitations, documented here rather than fixed in this
version; see [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md#--shield-streaming-redaction).

## Platform support

| platform | status |
|----------|--------|
| Linux | supported; tested in CI (Ubuntu 24.04, stable Rust and the 1.87 MSRV) |
| macOS | supported; tested in CI (macOS 15, stable Rust) |
| Windows | **unsupported and untested**: not built or tested in CI, integration tests are Unix-only |

The release workflow ([CONTRIBUTING.md](CONTRIBUTING.md#releasing-maintainer))
builds static musl binaries for Linux (x86_64 and aarch64) and binaries for
macOS (Apple silicon and Intel). The test suite runs natively on x86_64 Linux
(glibc, and musl in the release workflow) and on Apple-silicon macOS; the
aarch64 Linux and Intel macOS builds are smoke-tested (under QEMU and Rosetta)
but their tests are not run.

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
on macOS. The hardening that keeps same-user processes from reading cloakenv's
`/proc/<pid>/environ`, memory and file descriptors relies on
`prctl(PR_SET_DUMPABLE)`; on macOS and everywhere else it is a no-op. On macOS,
cloakenv therefore does **not** protect `CLOAKENV_PASSPHRASE` (or the
`CLOAKENV_PASSPHRASE_FILE` path) in its own environment from other processes
of the same user (core dumps are still prevented by the zero core-file limit).
There is no `/proc` on macOS, so the Linux-specific `--shield` bypass via
`/proc/<pid>/fd` doesn't exist there, but equivalent macOS mechanisms have not
been evaluated. Killing cloakenv with `SIGKILL` under `--shield` leaves the
command running there (see above). Prefer the interactive prompt or a
mode-`0600` `CLOAKENV_PASSPHRASE_FILE` over `CLOAKENV_PASSPHRASE` on shared or
untrusted macOS accounts. Still true on every platform: the commands you run
get the decrypted values in their own environment (readable by other same-user
processes the usual way, e.g. `/proc/<pid>/environ` of the command on Linux),
and cloakenv is not a sandbox.

## Threat model

cloakenv is a small tool with a narrow job: keep secrets out of plaintext files
and out of transcripts and logs, on a machine you otherwise trust. This section
says, in one place, what it does and does not defend against; the details are in
the sections it links to and in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

**What it protects**

| threat | outcome |
|--------|---------|
| Someone gets a copy of the vault file (stolen laptop, backup, a mistaken `git add -f`) | They can only guess the passphrase offline, one Argon2id run (64 MiB, 3 passes) per guess; names and values are both encrypted, only the approximate total size shows. **The passphrase is the whole defence**, hence the warning at `init` for one under 12 characters ([Short passphrases](#exactly-what-counts-as-the-passphrase)). `init` also keeps `.cloak/` out of `git add .`. |
| Tampering with the vault file | Any change, truncation or foreign file fails authentication; `run` exits 125 and starts nothing ([Vault file limits](#vault-file-limits)). |
| Plaintext `.env` files, secrets in argv and shell history | `set` never takes a value on the command line (it refuses one and says so); nothing is decrypted to disk ([Values you store](#values-you-store)). Importing does not undo the past: the `.env` you import from stays on disk (and in any backup or git history) until you remove it, and deleting a file does not securely erase it. |
| Secrets showing up in agent transcripts, CI logs, terminal scrollback | `run --shield` replaces exact occurrences of values in the command's stdout and stderr, for accidents only ([What `--shield` does and doesn't do](#what---shield-does-and-doesnt-do)). |
| Other local users | The vault is written `0600` in a `0700` directory; loose permissions and symlinks are warned about ([Permission warnings](#permission-warnings)). |
| Other processes of your user reading cloakenv itself (Linux) | While cloakenv exists it is non-dumpable: no `/proc/<pid>/environ`, `/proc/<pid>/mem`, ptrace or `/proc/<pid>/fd` access, no core dump. Without `--shield` cloakenv replaces itself with the command, so afterwards there is no cloakenv process to read ([Passphrase sources](#passphrase-sources), [How `run` starts your command](#how-run-starts-your-command)). |

**What it does not protect, by design or because it cannot**

- **The command you run.** It gets the secrets in its environment and can do
  anything with them. After `exec` the kernel resets the dumpable flag, so
  **other processes of your user (and root) can read the command's
  `/proc/<pid>/environ`**, with or without `--shield` (it holds no passphrase).
  cloakenv is not a sandbox.
- **Root, the kernel, the hypervisor** (`CAP_SYS_PTRACE` bypasses everything
  above), and **any code running as you before cloakenv starts.**
- **The passphrase window.** Between the kernel starting cloakenv and its first
  instruction setting the non-dumpable flag, a same-user process polling `/proc`
  could read `CLOAKENV_PASSPHRASE` from a freshly started cloakenv; and an
  exported variable is visible in your shell's own environment. Use the prompt or
  a `0600` passphrase file where that matters.
- **Platforms.** On macOS there is no dumpable flag, so cloakenv's own environment
  and memory are not protected from same-user processes; Windows is unsupported
  ([Platform support](#platform-support)).
- **A shield is a filter, not a boundary.** Transformed secrets (base64, hex,
  escaped, masked, split) pass through; so do secrets split across stdout and
  stderr, and anything not on those two pipes; and values shorter than 6 bytes
  are redacted so broadly that the marker confirms a guess (a warning names the
  keys). Output after the command exits, and a partial secret at the very end of
  a stream, are also not covered.
- **Rollback.** Everything in the vault is authenticated, but a valid file is
  not tied to a point in time. **Anyone who can write the vault's directory can
  put an older valid vault back** (a backup, an old commit, a copy they took
  earlier): rotated secrets revert to their old values and deleted ones return,
  and nothing notices, because `run` has no record of what it saw before. They
  still cannot read or forge one; they can also just delete it. Keep the
  directory private (cloakenv warns when it is not) and do not keep the vault
  where others can write. A generation counter with a high-water mark kept
  outside the directory could catch this for attackers confined to the
  directory; it needs a new file format and is written up as a proposal, not
  built ([Rollback and replacement](docs/ARCHITECTURE.md#rollback-and-replacement-limit-with-a-design-proposal)).
- **Memory and swap.** Decrypted values are held in buffers that are wiped when
  dropped, and `exec` without `--shield` leaves nothing behind, but this is best
  effort: cloakenv does not lock memory (`mlock`), so the OS may write pages
  holding secrets to swap or a hibernation image, and the copies that the
  standard library's `Command` makes of the environment cannot be wiped
  ([Memory hygiene](docs/ARCHITECTURE.md#memory-hygiene-best-effort) lists what
  is and is not covered, with measurements). Use an encrypted swap if that is in
  your threat model.
- **Weak passphrases.** See above: cloakenv warns, it does not refuse.
- **Metadata.** File size (roughly how much you store), modification time and
  the existence of a vault are visible to anyone who can list the directory.

## More detail

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the vault format,
cryptography, memory hygiene and the precise guarantees (and non-guarantees) of
`--shield`.

## Security, contributing, changes

To report a vulnerability, see [SECURITY.md](SECURITY.md). To build, test or
contribute, see [CONTRIBUTING.md](CONTRIBUTING.md). What changed is in
[CHANGELOG.md](CHANGELOG.md).

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
