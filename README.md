# cloakenv

Lightweight encrypted local secret vault and process injection engine with output redaction.

`cloakenv` replaces plaintext `.env` files with an encrypted vault
(`.cloak/vault.bin`) and injects secrets **directly into a child process's
environment** — nothing is ever decrypted to disk. With `--shield`, the
child's stdout/stderr are streamed through a redactor that replaces any secret
value with `[REDACTED_BY_CLOAKENV]`, so credentials don't end up in AI agent
transcripts, CI logs or terminal scrollback.

## Install

Rust 1.87 or newer; Linux, macOS or Windows on x86_64 (see [Platform support](#platform-support)).

```sh
cargo install --locked cloakenv       # installs `cloakenv` into ~/.cargo/bin
```

or from a checkout:

```sh
git clone https://github.com/benmckibben/cloakenv
cd cloakenv
cargo install --path . --locked
# or: cargo build --release --locked   # binary at target/release/cloakenv
```

Each GitHub release also carries static Linux (x86_64, aarch64) and macOS
(aarch64, x86_64) archives with a `SHA256SUMS` file.

## Quick start

```sh
cloakenv init                          # prompts for a passphrase
cloakenv set DATABASE_URL              # value read from a hidden prompt
pass show api | cloakenv set API_KEY   # ...or piped on stdin (never as an argument)
                                       # (an empty value is refused, see below)
cloakenv import .env && rm .env        # migrate an existing .env file
cloakenv list                          # names only, never values

cloakenv run -- npm start              # secrets injected into npm's env
cloakenv run --shield -- ./debug.sh    # ...and redacted from its output
```

What this does and does not protect against is in the [Threat model](#threat-model).

## Commands

| command | what it does |
|---------|--------------|
| `cloakenv init [--force [--yes]]` | create an empty vault; refuses to overwrite an existing one unless `--force`, which asks for confirmation (or `--yes`) and first saves a backup copy in the state directory, see [Replacing a vault, changing the passphrase](#replacing-a-vault-changing-the-passphrase) |
| `cloakenv set [--allow-empty] KEY` | store or replace one value, from a hidden prompt or stdin (never from the command line); empty input is refused unless `--allow-empty` |
| `cloakenv unset KEY` | remove one entry (an error if there is no such key) |
| `cloakenv import FILE` | add or replace the entries of a `.env` file, see [Importing a `.env` file](#importing-a-env-file) |
| `cloakenv list` | print the names, one per line, never the values |
| `cloakenv upgrade` | convert a format 1 vault to format 2, keeping a copy of the old file, see [Vault format 2](#vault-format-2-rollback-detection-upgrading-and-the-state-directory) |
| `cloakenv passwd` | change the vault's passphrase, keeping its contents |
| `cloakenv info` | show the vault's format, key-derivation settings, generation and rollback status; never names or values |
| `cloakenv accept-rollback [--yes]` | accept an older, diverged or downgraded copy of a format 2 vault as the new normal, see [Rollback, fork and downgrade detection](#rollback-fork-and-downgrade-detection) |
| `cloakenv run [--shield] -- COMMAND [ARGS...]` | run a command with the vault in its environment |

The `--` before the command is required, so that everything after the command's
name is the command's: `cloakenv run -- cmd --shield` gives `cmd` an argument
called `--shield`, and `cloakenv run cmd --shield` (no `--`) is a usage error
(exit 2, nothing is started) rather than an unredacted run.

Every command takes `--vault <path>` (or `CLOAKENV_VAULT`), see
[Vault location](#vault-location); `--help` and `--version` work everywhere.
Variable names must match `[A-Za-z_][A-Za-z0-9_]*`; `CLOAKENV_PASSPHRASE`,
`CLOAKENV_PASSPHRASE_FILE` and `CLOAKENV_NEW_PASSPHRASE_FILE` are reserved. Exit codes are in [Exit codes](#exit-codes).

## Values you store

`cloakenv set KEY` reads the value from a hidden prompt, or from stdin when
stdin is not a terminal (never from the command line). From stdin it takes at
most **1 MiB**, with one trailing newline (`\n` or `\r\n`) removed and nothing
else; anything larger, or not valid UTF-8, is refused with an error that does
not repeat any of it, and nothing is stored. The input is read into one buffer that is wiped
afterwards; see "Memory hygiene" in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md#memory-hygiene-best-effort).

**Empty values are refused.** If the value is empty (after the one trailing
line break is removed), `cloakenv set` exits with status 1 and stores
nothing, and the existing value, if any, stays as it was. The usual cause is the
command feeding stdin having failed: `false | cloakenv set API_KEY`, or a
`pass show` that could not decrypt, used to replace the good secret with an
empty string and exit 0. The same goes for pressing Enter at the hidden prompt.
To store an empty value on purpose (a variable that must exist but be empty),
say so: `cloakenv set --allow-empty KEY`. In a shell pipeline also use
`set -o pipefail` so the failure of the producer is not lost. (`import` is
different: a `KEY=` line in a `.env` file is an explicit empty value, and is
imported, with a warning that names the keys; see
[Importing a `.env` file](#importing-a-env-file).)

### Size limits, checked when you store, not when you next open the vault

Everything cloakenv can read back has a limit, and every limit is enforced
**before anything is written** (`set` and `import`), so a vault can
never be saved in a state it cannot be opened from again. The errors name the
key or the limit and never repeat a value:

| limit | value | what happens beyond it |
|-------|-------|------------------------|
| one variable, `KEY=VALUE` together | 131,071 bytes (128 KiB minus one) | `set` and `import` refuse it, naming the key: `cloakenv: error: BIG: the variable would be 131072 bytes as KEY=VALUE, over the limit of 131071 bytes for one environment variable`. Linux refuses to start a command with a single environment string over 128 KiB (`E2BIG`); the same limit applies on every platform so a vault stays usable wherever it is copied. This also bounds the length of a key. |
| the vault file (for format 2, the whole padded file) | 16 MiB (16,777,216 bytes) | any write that would produce a larger file is refused with `the vault would be N bytes, over the 16 MiB limit ...; nothing was written`. `import` is all or nothing: the merged result is checked first, and if one entry is too large or the total is, nothing is imported and the vault is untouched. |
| the `.env` file for `import` | 16 MiB | refused up front, see [Importing a `.env` file](#importing-a-env-file) |
| a value on stdin to `set` | 1 MiB (plus one line ending) | refused while reading; this is only the read limit, the per-variable limit above is stricter |
| the environment of the command (Linux) | a quarter of the stack limit (`ulimit -s`; 2 MiB by default), at most 6 MiB, at least 128 KiB | `run` fails with exit 125 before starting anything and names the largest vault entries: `the environment for the command would be N bytes, over the M bytes this system lets a program start with ... Largest vault entries: A (n bytes), B (n bytes)`. The total counts the inherited environment, the command's arguments and the pointers the kernel adds. |

The entry count has no limit of its own; it is bounded by the 16 MiB file size.
The total-environment check only runs on Linux, where the exact kernel rule is
known; on macOS the operating system's own error (`Argument list too long`)
is all you get. **Windows has no such limit in practice:** in a measurement on
the CI runner, 640 variables of 100,000 characters each (64 MB, far more than a
vault holds) reached a child intact, as did a single 1,000,000-character
variable. (The 32,767-character limit you may have read about applies to
setting a variable in the running process, not to a new process's environment.)
On Windows `run` instead refuses a vault in which two names differ only in case
(for example `Token` and `TOKEN`): environment names are not case-sensitive
there, so one would silently replace the other. It exits 125 and names both
keys; unset or rename one. A vault written before these checks existed can already hold an
entry over the per-variable limit: it still opens, `list` and `unset` work, and
`run` on Linux names the key.

## Secrets are text

Names must match `[A-Za-z_][A-Za-z0-9_]*` and values must be **valid UTF-8 text
without a NUL byte**, because they live in environment variables and are
replaced in output as text. A binary secret (a key file, a keystore) is not
supported: `set` and `import` refuse input that is not UTF-8 or contains a NUL,
without echoing it. Store such a secret encoded (for example base64) and decode
it in the command that uses it.

## Passphrase sources

In order of precedence:

1. `CLOAKENV_PASSPHRASE` environment variable.
2. `CLOAKENV_PASSPHRASE_FILE` — path to a file holding the passphrase (at most
   64 KiB). Handy for a machine-local key:
   `head -c 32 /dev/urandom | base64 > ~/.config/cloakenv.key && chmod 600 ~/.config/cloakenv.key`.
3. Interactive prompt (only when stdin is a terminal).

### The interactive prompt

On a terminal the passphrase (and the value for `set`) is typed at a hidden
prompt: echo is switched off, nothing you type is shown, and line editing and
Ctrl-C keep working. The terminal is put back **on every way out**: a normal
return, an error, Ctrl-D, a wrong passphrase, and Ctrl-C, `kill` (`SIGINT`,
`SIGTERM`, `SIGHUP`, `SIGQUIT`), which still end cloakenv *by that signal*
(a shell reports 130 for Ctrl-C) but no longer leave your shell without echo.
Ctrl-Z stops cloakenv with the terminal restored, and hides input again when
you `fg` it. Only `SIGKILL` cannot be handled; `reset` fixes a terminal after
one. A signal that was ignored when cloakenv started (`nohup`) stays ignored.

Ctrl-D at the prompt (nothing typed) reports `no passphrase entered (end of
input at the prompt)` and exits 1. If there is no terminal and neither
`CLOAKENV_PASSPHRASE` nor `CLOAKENV_PASSPHRASE_FILE` is set, the error says
so instead.

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
cloakenv: warning: the passphrase is shorter than 12 characters; anyone who obtains the vault file can guess it offline, so a short passphrase is easy to crack. Use a longer one (4 or more random words, or 20 or more random characters). To change the passphrase later, run `cloakenv passwd`
```

A machine-local key file from `/dev/urandom` (above) never triggers it.

**The new passphrase for `passwd`.** `cloakenv passwd` takes the current
passphrase from the sources above and the new one from a hidden prompt (typed
twice, only on a terminal) or from the file named by
`CLOAKENV_NEW_PASSPHRASE_FILE` (at most 64 KiB, one trailing newline removed,
the same rules as above). There is no environment variable that holds the new
passphrase itself. The new passphrase gets the same checks as at `init` (not
empty, not ending in a line break, the short-passphrase warning), and must differ
from the current one.

All three variables (`CLOAKENV_PASSPHRASE`, `CLOAKENV_PASSPHRASE_FILE` and
`CLOAKENV_NEW_PASSPHRASE_FILE`) are always stripped from the child's
environment, and `cloakenv set` / `cloakenv import` refuse to store secrets under
any of those names (a format 2 vault cannot even hold them).
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

**Only that path is used.** The vault is looked for at exactly one place, the
path given (`.cloak/vault.bin` in the current directory by default). cloakenv
does **not** search parent directories the way git does, on purpose: a parent
directory that someone else can write to could hold a vault that injects
variables of their choosing (a `PATH`, say) into every command you run from
below it. When there is no vault the error gives the absolute path that was
tried: `no vault found at /abs/path/.cloak/vault.bin (only this path is tried; parent directories are not searched)`.
An empty `CLOAKENV_VAULT` (or `--vault ""`) is an error that says so, rather
than a silent fallback to the default.

`.cloak/vault.bin` relative to the current directory by default; override with
`--vault <path>` or `CLOAKENV_VAULT`. On Unix the file is written atomically
with mode `0600`, inside a `0700` directory if cloakenv has to create it (an
existing directory is left as it is). On Windows the files and a directory
cloakenv creates get a protected ACL (nothing inherited) that gives access to
you, SYSTEM and Administrators only, set when the file is created, and a save
replaces the vault with a write-through move. Commands that modify the vault
serialise on an advisory lock file next to it (`.cloak/.vault.bin.lock`), so
concurrent `cloakenv set` calls never lose updates (`flock` on Unix,
`LockFileEx` on Windows; see [Platform support](#platform-support)). A writer holds the lock for its whole
load-modify-save cycle, which includes two key derivations (a fraction of a
second each at the default settings), so simultaneous writers queue up (the
ones that have to wait say so on stderr); reads (`list`, `run`, `info`) never take
it and always see a complete vault (they may update the rollback record, see
[Vault format 2](#vault-format-2-rollback-detection-upgrading-and-the-state-directory)). The lock dies with its process, so a killed
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

### Replacing a vault, changing the passphrase

To change the passphrase **and keep the contents**, use `cloakenv passwd` (see
[Changing the passphrase](#changing-the-passphrase)). To start over with a new,
**empty** vault under a new passphrase, use `cloakenv init --force`. Because that
destroys the old contents, it is guarded:

* On a terminal it asks `Type 'yes' to continue:` and does nothing for any other
  answer. With no terminal (scripts, CI) it refuses unless you add `--yes`
  (`init --force --yes`).
* Before replacing anything, it saves the old file in the **state directory**
  (see [The state directory](#the-state-directory)), as
  `backups/vault.bin.bak-YYYYMMDDTHHMMSSZ` (UTC; mode 0600; byte for byte the old
  ciphertext, so it needs the **old** passphrase) and tells you where. It needs a
  state directory (`HOME` or `CLOAKENV_STATE_DIR`); with none it stops before
  replacing anything. To keep your secrets, `set` them again or `import` them,
  then delete the backup. cloakenv never overwrites or removes a backup; delete
  them when you no longer need the old passphrase, because a backup is a vault
  encrypted with a passphrase you chose to retire. The backups are not in the
  vault's directory, so there is no old copy lying next to the vault for anyone
  who can write that directory.
* The new vault is format 2 and is recorded as the latest for that path.

### Permission warnings

On Unix, cloakenv checks permissions each time it opens the vault and prints
one line per problem on its own stderr, before it decrypts or spawns anything
(so it never appears inside the redacted stream of a `--shield` child). These
are warnings only: exit codes do not change and cloakenv never chmods files it
did not create. The four state-directory rows are printed once the vault has
been opened and compared with the rollback record, not before (they use the same
group rule as the vault directory).

| condition | warning |
|-----------|---------|
| vault directory world-writable (and not sticky) | `cloakenv: warning: vault directory <dir> is world-writable (mode 0777, expected 0700); anyone on this machine could replace the vault` |
| vault directory group-writable, group not private to you | `cloakenv: warning: vault directory <dir> is writable by a group that is not private to you (mode 0770, expected 0700); the members of that group could replace the vault` |
| vault file group/world-readable or writable | `cloakenv: warning: vault file <file> is group/world-readable or writable (mode 0644, expected 0600)` |
| passphrase file group/world-readable or writable | `cloakenv: warning: passphrase file <file> is group/world-readable or writable (mode 0666, expected 0600); anyone who can read it can decrypt the vault` |
| vault directory is a symlink | `cloakenv: warning: vault directory <dir> is a symbolic link; cloakenv follows it, so make sure its target is private` |
| vault file is a symlink | `cloakenv: warning: vault file <file> is a symbolic link; reads follow it, but saving replaces the link with a regular file` |
| state directory is a symlink | `cloakenv: warning: rollback-protection directory <dir> is a symbolic link; cloakenv follows it, so make sure its target is private (whoever controls it controls rollback detection)` |
| state directory world-writable | `cloakenv: warning: rollback-protection directory <dir> is world-writable (mode 0777, expected 0700); anyone on this machine could edit the record of which vaults this machine has seen and defeat rollback detection` |
| state directory group-writable, group not private to you | `cloakenv: warning: rollback-protection directory <dir> is writable by a group that is not private to you (mode 0770, expected 0700); its members could edit the record of which vaults this machine has seen` |
| state directory owned by another user | `cloakenv: warning: rollback-protection directory <dir> belongs to another user (uid 1001); that user can edit the record of which vaults this machine has seen` |

**The exact rule for the vault directory.** A directory that others can write
to lets them replace the vault with one of their own, but an ordinary project
directory is group-writable (`0775`) on Debian and Ubuntu, where the default
umask is `0002` and every user has a private one-member group, and a warning
on every command there would only teach people to ignore warnings. So:

1. World-writable (`o+w`) and **not** sticky: always a warning. (A sticky
   world-writable directory such as `/tmp` does not let others rename or
   delete your files, so that alone is not reported.)
2. Group-writable (`g+w`): a warning **unless** the directory's group is a
   *private group of yours*, meaning all of: it is your primary group in
   `/etc/passwd`; no other account has it as a primary group; and `/etc/group`
   has an entry for it with your user name whose member list names nobody
   else (the "user private group" convention). Any group that is shared, or
   that cannot be found in those two files (a network directory service is not
   consulted), counts as shared and warns.
3. Otherwise nothing. The mode of the vault *file* (`0600`) and of the
   passphrase file are still checked strictly, as in the table, whatever the
   group.

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

### Format 2 files

A format 2 file is refused up front, before any key derivation, for the same
kind of reasons as above: an unknown version, algorithm, padding scheme or
reserved flag, an extension record it cannot read (or a *critical* one it does
not know), a generation of 0, or too short a ciphertext. The format 2 reader is
as strict as its writer, so after authentication it also refuses
key-derivation settings below 19 MiB / 2 passes / 1 lane (the writer never goes
below them: `upgrade` raises a weaker format 1 vault's settings first and says
so), entries that are not in key order, a name that is not a valid variable name,
the three reserved names, and any padding that is not exactly the canonical
length of zero bytes. All of these look the same to you: the file is refused as
an unusable vault. The size limit above counts the **padded** file, so a vault
can hold slightly less than 16 MiB of entries (padding adds at most 12% above the
4 KiB floor, and about 6% at most in practice).

### Leftover temporary files

Every save writes the new vault to a temporary file next to it
(`.vault.bin.tmp-<12 hex digits>`, mode 0600, ciphertext only) and renames it into
place, so the vault is never half-written. If cloakenv is killed (`kill -9`,
power loss, the out-of-memory killer) between those two steps, the temporary
file stays behind, as large as the vault. The next command that **writes** (`set`,
`unset`, `import`, `init`, `passwd`, `upgrade`) removes such leftovers once it holds the vault lock, but
only files that are: regular files (not links or directories), named exactly as
a save names them for this vault, owned by you, and not modified for 5 minutes
(a running save finishes in seconds). Read-only commands do not clean up.
Nothing else in the directory is ever deleted.

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

`cloakenv import FILE` reads a `.env` file with the grammar below and adds or
replaces those entries in the vault. This is cloakenv's own small grammar,
close to what python-dotenv and the Node `dotenv` package accept, **not** a
shell: nothing is executed and **nothing is expanded**.

| form | supported | notes |
|------|-----------|-------|
| blank lines, `# comment` lines | yes | ignored |
| `KEY=value` | yes | the value is trimmed; an unquoted value ends at the first `␣#` or tab-`#` (a trailing comment); a `#` with no whitespace before it is part of the value |
| `export KEY=value` | yes | the `export` prefix (followed by a space or tab) is ignored |
| spaces around `=`, indentation | yes | `KEY = value` is `KEY=value` |
| `KEY='literal'` | yes | everything up to the next `'` is taken as is: no escapes, no way to include a `'` |
| `KEY="text"` | yes | escapes `\n`, `\r`, `\t`, `\\` and `\"`; any other backslash sequence (`\$`, `\x`) stays as written |
| **multi-line** `"..."` and `'...'` values | yes | a quoted value may span lines (PEM keys, JSON); an error is reported on the line where the quote opened |
| text after a closing quote | only a `# comment` | anything else is an error |
| `KEY=` (empty value) | yes | stored as an empty value, and `import` prints a warning naming the keys. This differs from `cloakenv set` on purpose: a `KEY=` line is an explicit, visible statement, while empty stdin is usually a failed command |
| UTF-8 byte order mark at the start of the file | ignored | Windows editors add one |
| line breaks | `\n`, `\r\n` and a lone `\r` | all are line breaks, including inside quotes (python-dotenv and Node `dotenv` do the same), so a CRLF file never leaves a `\r` in a value. To store a real carriage return use the `\r` escape in double quotes |
| the same variable twice | **error** | the import stops (nothing is imported) and names both line numbers: duplicates are resolved differently by different tools, and silently taking the last (or first) value is how a wrong secret gets in. Remove one of them |
| `$VAR`, `${VAR}` (interpolation) | **not supported** | stored **literally**, e.g. `postgres://$HOST/db` really is that string. The import prints a warning with the line numbers of values (outside single quotes) that look like references. Expand them first (`envsubst`) or write the final value |
| `KEY` with no `=`, `KEY: value`, `\` line continuations | no | an error (or, for a continuation, part of the value) |
| backticks as quotes, command substitution `$(...)` | no | not special: part of the literal value |
| invalid names (not `[A-Za-z_][A-Za-z0-9_]*`), a NUL byte in a value, `CLOAKENV_PASSPHRASE` and `CLOAKENV_PASSPHRASE_FILE` | error | |

A line that does not parse stops the import with its **line number and a fixed
reason, never its content or the name** (a misplaced secret may be in either),
and nothing is imported; entries already in the vault with the same name are
overwritten. All values must be valid UTF-8 text (see
[Secrets are text](#secrets-are-text)).

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

(cloakenv itself never writes a file that large: see [Size limits](#size-limits-checked-when-you-store-not-when-you-next-open-the-vault).)

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

**On Windows** there is no `exec`, so `run` always stays the parent, with or
without `--shield`, and there are no signals. Instead:

- The command runs inside a **job object** that kills it and everything it
  started if cloakenv dies in any way (killed, crashed, console window closed).
  The command is created suspended and put in the job before it runs, so
  nothing it starts can escape. When the command exits normally the job is
  released, so a background process it left behind keeps running, as on Unix.
  If a job cannot be created or joined, cloakenv prints a warning and runs the
  command without one.
- **Ctrl-C and Ctrl-Break** go to the command, which gets them from the console
  itself; cloakenv stays alive, waits for the command and reports how it ended.
  Closing the console window, logging off and shutting down end cloakenv and,
  through the job object, the command.
- With `--shield`, after the command exits cloakenv waits at most 3 seconds for
  leftover processes that still hold the output pipes, then stops.

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

### Variables that change what runs

Most variables only change what the command *knows*. A few change what it
*executes*, for the command and for everything it starts:

| variable | effect |
|----------|--------|
| `PATH` | which `true`, `python`, `git` ... is found and run |
| `LD_*` (`LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_AUDIT` ...) | the dynamic loader loads code of the vault's choosing into every program |
| `DYLD_*` (macOS equivalents) | the same on macOS (the system strips them for protected programs) |
| `BASH_ENV` | a file every non-interactive bash runs first |

A vault entry with one of these names is applied like any other (an entry
overrides the inherited variable, as always), but cloakenv announces it with
one line on its **own** stderr, naming the keys and never the values:

```
cloakenv: warning: the vault sets PATH, LD_PRELOAD, which change what programs and libraries run (see the README); check it is meant, and remove it with `cloakenv unset KEY` if not
```

The line is printed when the entry is stored (`set`, `import`) and on every
`run`, before the command starts, and never goes through the `--shield`
stream. It is only a warning: nothing is blocked and exit codes do not change.
The list is deliberately short. `PYTHONPATH`, `NODE_OPTIONS`, `RUBYOPT` and the
like affect one language runtime and are common, legitimate project settings,
so they are not flagged; anything that makes you want to set them is for you
to review. Treat a vault you did not create as you would a script you did not
write.

### cloakenv is not an init system

cloakenv starts your command and waits for **that one process**. It does not
adopt orphaned grandchildren (it is not a "subreaper") and does not reap
anything but its direct child. If cloakenv is **PID 1 of a container** (the
usual case of `docker run image cloakenv run --shield -- ...`), a process your
command leaves behind, or a grandchild that outlives its parent, is re-parented
to cloakenv and stays a zombie until the container stops, and signals other
than the ones forwarded to the child are not handled the way an init would.
Run a real init as PID 1 and cloakenv under it (`docker run --init`, `tini`,
`dumb-init`, or Kubernetes `shareProcessNamespace` with a pause container).

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

Exit codes are 0–255 on Unix. On Windows exit codes are 32 bits wide and are
reported unchanged (a crash is `0xC0000005`, Ctrl-C is `0xC000013A`; PowerShell
shows them as signed numbers, e.g. `-1073741819`). There is no `128 + N`
mapping on Windows, because there are no signals.

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

## Vault format 2: rollback detection, upgrading and the state directory

`cloakenv init` now creates a **format 2** vault.
Compared with format 1 it has an authenticated header with a **generation** that
goes up on every save and a random **vault id**; it is **padded** so its size
does not reveal the exact total length of the contents (a small vault is 4,208
bytes); and it can be checked against a record kept outside the vault's
directory so that an older copy being put back is noticed. The passphrase, the
key derivation (Argon2id) and the cipher (XChaCha20-Poly1305) are the same.
A format 1 vault keeps working exactly as before until you run
`cloakenv upgrade`.

### Rollback, fork and downgrade detection

The first time a command opens a
format 2 vault it records the vault's id and generation. Every later open
compares, after the passphrase has verified the file and before anything runs:

| what is in hand | result |
|-----------------|--------|
| a vault this machine has not seen | trusted, recorded, with one note on stderr |
| a newer generation | accepted and recorded (a save, here or elsewhere) |
| the generation and contents last seen | accepted |
| an **older** generation | **refused** (rollback) |
| the **same generation, different contents** | **refused** (fork: two copies were saved from the same version) |
| a **format 1 file** where a format 2 vault used to be | **refused** (downgrade) |

A refusal prints the reason and what to do, changes nothing, starts nothing
(`run` exits 125, every other command exits 1), and is never overridden by an
environment variable. If you really did restore an older copy on purpose, run
`cloakenv accept-rollback`: it asks for the passphrase, says what it will
replace, asks for confirmation on a terminal (`--yes` when there is none) and
then treats the copy in hand as the latest. Anything saved only in the newer or
the other copy is not in it.

Commands that only read (`list`, `run`, `info`) do not take the vault's write
lock, so a save by another command can land between their read and their
comparison. A read that looks like a rollback is therefore repeated, up to three
reads in all, before it is believed; a copy that is still behind is refused.
`cloakenv info` shows the format, size, key-derivation settings, the number of
entries (never names or values), the generation and vault id of a format 2
vault, and what the record says (`REFUSED: ...` with the reason, if the vault would be
refused), without changing anything; it exits 0 either way, since reporting is its
job. It needs the passphrase, because a header means nothing until it has been
authenticated.

### The state directory

The record is a small text file, `seen`, in the user's
state directory (with an empty lock file, `.seen.lock`, and the kept copies of old
vaults in `backups/` beside it):

| platform | state directory |
|----------|-----------------|
| Linux and other Unix | `$XDG_STATE_HOME/cloakenv` if that is an absolute path, else `~/.local/state/cloakenv` |
| macOS | `~/Library/Application Support/cloakenv` |
| Windows | `%LOCALAPPDATA%\cloakenv` |

`CLOAKENV_STATE_DIR` names another directory (used as given). cloakenv creates
it private (0700, the file 0600; a protected ACL on Windows) and warns, on
every command, if it is a symbolic link, writable by others or owned by someone
else. If no state directory can be found (no `HOME`) or it cannot be written,
a command on a format 2 vault says so once and carries on without the check,
except that a rollback it can still see is still refused. A damaged file is an
error that names it; if you did not edit it, delete it to start over (the next
vault found is then trusted once). The record holds the **paths** of your vaults
in plain text, ids, generations and AEAD tags; no secret. It is kept for the
1,024 most recently used vaults, and opening a vault counts as use.

### Upgrading a format 1 vault

Every command that opens a format 1 vault prints
this on stderr, after the passphrase has been accepted, never through
`--shield`'s streams and without changing any exit code:

```text
cloakenv: this vault uses format 1. Format 2 detects a rolled-back vault and hides its exact size;
cloakenv: run 'cloakenv upgrade' to convert it (recommended; cloakenv 0.2 and older cannot open format 2).
```

`cloakenv upgrade` asks for the passphrase, keeps a byte-identical copy of the
format 1 file in the state directory (`backups/vault.bin.bak-YYYYMMDDTHHMMSSZ`,
mode 0600), writes the format 2 vault (generation 1, a new vault id, the same
passphrase) and remembers the old file's identity. **It is never done
automatically and cannot be undone by cloakenv 0.2 or older, which refuse a
format 2 vault** ("unsupported vault format version 2") without touching it.
The kept copy is for recovery only: cloakenv refuses to open it as a downgrade,
and the copy that `passwd` keeps of a format 2 vault is an older generation of the
same vault, so it is refused as a rollback; to use one on purpose, restore it
and run `accept-rollback`.
Delete it when you no longer need it; it is encrypted with the passphrase the
vault had then.

### Changing the passphrase

`cloakenv passwd` asks for the current passphrase
(the usual sources) and takes the new one from a prompt (twice) or from the file
named by `CLOAKENV_NEW_PASSPHRASE_FILE`, never from the environment itself. It
re-encrypts the contents with a fresh salt and nonce, keeps a copy of the vault
as it was in the state directory (still encrypted with the **old** passphrase:
delete it once the new one works), and refuses a new passphrase equal to the
current one, an empty one, or a wrong current one, before changing anything. It
works on format 1 vaults too and leaves them format 1.

### Shared vaults and forks

Each machine keeps its own record. If a vault file
is shared between machines or people (a synced folder, a repository), two of
them saving from the same generation produce two different files of that
generation; the first machine to meet both reports a fork, and one that last
saw a newer generation reports a rollback. That is the check working, not a bug,
and cloakenv cannot merge: `accept-rollback` picks the copy in hand. Prefer one
machine that writes the vault, or keep a vault per machine, rather than a folder
that creates conflicted copies.

### Downgrade detection is best effort

A format 1 file has no vault id, so
cloakenv recognises one by (a) the paths a format 2 vault has been opened under
(both the absolute path as typed and the path with symbolic links resolved, so a
link put in place of the vault is still caught) and (b) the identity of the
format 1 file that **this machine upgraded**, wherever it turns up (a renamed
directory, another name). An older format 1 snapshot that was never upgraded
here, under a path never seen, has nothing to be recognised by.

### What the record does not defend against

It is a file in your account's
state directory, so anyone or anything that can write it (you, root, code running
as you) can lower or delete it. The design assumes an attacker who can write the
vault's directory, or the place it is shipped through, but not the state
directory. It is not signed or encrypted, because any key for that would have to
be readable by the same code that could edit the file.

## Platform support

| platform | status |
|----------|--------|
| Linux | supported; tested in CI (Ubuntu 24.04, stable Rust and the 1.87 MSRV) |
| macOS | supported; tested in CI (macOS 15, stable Rust) |
| Windows | supported on **x86_64 (MSVC)** only; built, linted and tested in CI (Windows Server 2025) and tried by hand on one Windows machine (0.2.0's Windows support, and again for 0.3.0's vault format 2). See the limitations below. 32-bit and Arm Windows are not supported |

The release workflow ([CONTRIBUTING.md](CONTRIBUTING.md#releasing-maintainer))
builds static musl binaries for Linux (x86_64 and aarch64) and binaries for
macOS (Apple silicon and Intel), and a zip with a `cloakenv.exe` (C runtime
linked in) for x86_64 Windows. The test suite runs natively on x86_64 Linux
(glibc, and musl in the release workflow), on Apple-silicon macOS and on
x86_64 Windows; the aarch64 Linux and Intel macOS builds are smoke-tested (under
QEMU and Rosetta) but their tests are not run.

Several protections described above are implemented with Unix-only APIs
(`cfg(unix)`) and have a different Windows counterpart:

| Unix | Windows |
|------|---------|
| file mode `0600` for the vault and lock file, `0700` for a directory cloakenv creates | a protected ACL (no inheritance) for you, SYSTEM and Administrators, set when the file or directory is created |
| the permission warnings (modes) | warnings when an existing vault file or passphrase file gives *any* access to Everyone, Users or Authenticated Users, or the vault directory gives them *write* access; warnings only, nothing is changed. Symlink warnings apply everywhere |
| directory `fsync` after the atomic rename | the rename is done with `MoveFileExW` `WRITE_THROUGH` |
| advisory `flock` | `LockFileEx` on the same lock file |
| replacing cloakenv with the command (`exec`) without `--shield`; signal forwarding | cloakenv stays the parent; job object and console Ctrl-C/Ctrl-Break handling (see [`run`](#what-the-command-inherits-in-both-modes) above) |
| `PR_SET_PDEATHSIG` (Linux) | the job object (also covers the command's descendants) |
| `128 + N` exit codes for a child killed by a signal | the 32-bit exit code, unchanged |

**Windows limitations in one place:**

- **Same-user processes are not kept out.** There is no `PR_SET_DUMPABLE`
  equivalent in use, so another process of your account can read cloakenv's own
  environment and memory (`CLOAKENV_PASSPHRASE` included) and the command's
  environment, as on macOS. Prefer the prompt or a passphrase file readable
  only by you. Memory is not locked, so it may reach the page file or a
  hibernation image. No crash-dump suppression is implemented.
- **Permissions are ACLs, and cloakenv only warns.** It never changes the ACL of
  a file or directory that already exists, so a vault in a folder others can
  write to warns until you fix the folder (for example `icacls <dir> /inheritance:r`
  and then grant yourself access). A save replaces the vault file with a private
  one, but not the directory.
- **`--shield` filters bytes on the two pipes.** A program that writes UTF-16,
  or writes to the console directly instead of to standard output or standard
  error, is not covered. The other shield limits above apply too.
- **Environment limits** are checked before `run`: see the limits table.
- **Tried by hand** in PowerShell only (prompts, Ctrl-C, closing the window,
  killing cloakenv, ACLs). **Not tried:** cmd.exe, Windows Terminal, Git Bash and
  mintty (which has no real console), Ctrl-Break, a vault in a OneDrive or
  Dropbox folder, on a network share or on an exFAT drive, a second Windows
  account, domain accounts, and a program that is itself running in another job
  object.
- **Vault format 2 on Windows (0.3.0), tried by hand** in Windows PowerShell 5.1
  in the classic console (not Windows Terminal), on one 64-bit machine, not
  elevated, with the vault and the state directory on local NTFS: `init`, `info`,
  `set`, `list`, `run`; a rolled-back copy refused and then accepted with
  `accept-rollback`; upgrading a vault made by the published 0.2.0 build, the old
  file refused as a downgrade, and 0.2.0 refusing the upgraded vault; `passwd` with a
  new passphrase from a file with Windows line endings and from the prompt; a
  second window reading while the first saves, with no spurious refusal; and the
  downgrade check with a **directory junction** in place of the vault's
  directory (both for the file that was upgraded and for a different, never
  upgraded format 1 file). **Not tried:** a symbolic link to a *file* (creating
  one needs Developer Mode or an elevated shell), Windows Terminal, the state
  directory in a synced or network folder, and macOS by hand.
- **Release binaries are not signed**; SmartScreen or antivirus software may
  warn about them.

**macOS limitations in one place:** no `PR_SET_DUMPABLE`, so same-user processes
can read cloakenv's own environment and memory (the passphrase variable
included); no `PR_SET_PDEATHSIG`, so `SIGKILL` on cloakenv under `--shield` leaves the
command running; the total-environment-size check before `run` and the
per-process hardening are Linux only; the pseudo-terminal tests of the
prompt's terminal restoration are the least portable part of the test suite;
the Ctrl-Z/`fg` behaviour of the prompt is tested on Linux only. The rollback record keys a vault by its absolute path and its canonical path; how a case-insensitive file system affects the second has not been verified. The details
follow.

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
| Someone gets a copy of the vault file (stolen laptop, backup, a mistaken `git add -f`) | They can only guess the passphrase offline, one Argon2id run (64 MiB, 3 passes) per guess; names and values are both encrypted; a format 2 vault's size shows only its rough magnitude (padded, 4 KiB at least), a format 1 vault's size gives the exact total length ([Vault format 2](#vault-format-2-rollback-detection-upgrading-and-the-state-directory)). **The passphrase is the whole defence**, hence the warning at `init` for one under 12 characters ([Short passphrases](#exactly-what-counts-as-the-passphrase)). `init` also keeps `.cloak/` out of `git add .`. |
| Tampering with the vault file | Any change, truncation or foreign file fails authentication; `run` exits 125 and starts nothing ([Vault file limits](#vault-file-limits)). |
| Someone who can write the vault's directory puts an **older valid copy** back (a backup, an old commit), or a second copy saved from the same version, or the old format 1 file | A format 2 vault is compared with a record kept outside the directory and **refused**, before anything is decrypted into a command: `run` exits 125 and starts nothing, the other commands exit 1, and the vault is not touched ([Vault format 2](#vault-format-2-rollback-detection-upgrading-and-the-state-directory)). Not for a format 1 vault, which cannot be told from a restored backup; downgrade detection is best effort, and the record itself is not protected from code running as you. |
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
  and memory are not protected from same-user processes, and nor are they on
  Windows ([Platform support](#platform-support)).
- **A shield is a filter, not a boundary.** Transformed secrets (base64, hex,
  escaped, masked, split) pass through; so do secrets split across stdout and
  stderr, and anything not on those two pipes; and values shorter than 6 bytes
  are redacted so broadly that the marker confirms a guess (a warning names the
  keys). Output after the command exits, and a partial secret at the very end of
  a stream, are also not covered.
- **Rollback, with limits.** A format 2 vault is protected against an older
  copy being put back, against two diverged copies and against the old format 1
  file coming back, by a record that lives **outside the vault's directory**
  (the state directory). That protection has edges: it is **best effort for
  downgrades** (a format 1 file has no id, so only a file that was upgraded on
  this machine, or a path a format 2 vault was opened under, is recognised; an
  older format 1 snapshot under a new path is not); **the record is not itself
  protected** (anyone who can write the state directory, which includes you,
  root and any code running as you, can edit or delete it, and the next open
  trusts what it finds, with a one-line note); a machine that has **never**
  opened the vault has nothing to compare with; and a **format 1 vault has no
  protection at all** (`cloakenv upgrade` converts it). A vault in a synced
  folder or a repository shared between machines will report forks and
  rollbacks that are real, because each machine keeps its own record
  ([Shared vaults](#shared-vaults-and-forks)).
- **Getting a value back.** There is deliberately no `export` and no `get`: a
  value goes in with `set` or `import` and comes out only as an environment
  variable of a command that `run` starts. If you need a value you cannot see,
  rotate it at the service that issued it and `set` the new one. If you forget
  the passphrase the contents are gone; there is no recovery key.
- **Memory and swap.** Decrypted values are held in buffers that are wiped when
  dropped, and `exec` without `--shield` leaves nothing behind, but this is best
  effort: cloakenv does not lock memory (`mlock`), so the OS may write pages
  holding secrets to swap or a hibernation image, and the copies that the
  standard library's `Command` makes of the environment cannot be wiped
  ([Memory hygiene](docs/ARCHITECTURE.md#memory-hygiene-best-effort) lists what
  is and is not covered, with measurements). Use an encrypted swap if that is in
  your threat model.
- **Weak passphrases.** See above: cloakenv warns, it does not refuse.
- **Metadata.** Names and values are encrypted, and a format 2 vault is
  padded (Padmé, with a 4 KiB floor), so its size shows only its rough
  magnitude, and a value rotated to a slightly different length usually leaves
  the size unchanged. Crossing a size step is still visible, and so are the
  modification time and the existence of a vault to anyone who can list the
  directory. **A format 1 vault is not padded**: its size is 84 bytes plus, for
  each entry, 8 bytes and the length of the name and of the value, so the exact
  total length of your secrets is visible to anyone who can see the file.
- **The state directory holds paths.** The record of which vaults this machine
  has seen includes the path each was last opened at, in plain text, in a
  directory only you should be able to read (mode 0700, file 0600). It holds no
  secret, no key and no name or value, but it does say where your vaults are.

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
