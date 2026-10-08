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
cloakenv set DATABASE_URL              # value read from a hidden prompt / stdin
cloakenv set API_KEY sk-live-...       # or inline (lands in shell history!)
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
On Linux, cloakenv also marks itself non-dumpable at startup, so neither the
commands it runs nor other processes of your user can read the passphrase out
of `/proc/<pid>/environ`, inspect its memory, or write around `--shield` via
`/proc/<pid>/fd`; it never leaves a core dump.

## Vault location

`.cloak/vault.bin` relative to the current directory by default; override with
`--vault <path>` or `CLOAKENV_VAULT`. The file is written atomically with mode
`0600` inside a `0700` directory. `.cloak/` is git-ignored. Commands that
modify the vault serialise on an advisory lock file next to it
(`.cloak/.vault.bin.lock`), so concurrent `cloakenv set` calls never lose
updates.

## Exit codes

| situation                                      | code          |
|------------------------------------------------|---------------|
| `run`: child exited normally                   | child's code  |
| `run`: child killed by signal N                | 128 + N       |
| `run`: vault/passphrase/shield failure         | 125           |
| `run`: command not executable / not found      | 126 / 127     |
| other subcommands: any failure                 | 1             |
| usage error                                    | 2             |

## Security model

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the vault format,
cryptography and the precise guarantees (and non-guarantees) of `--shield`.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
