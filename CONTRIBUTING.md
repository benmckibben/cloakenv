# Contributing

Thanks for looking at cloakenv. Bug reports and pull requests are welcome. For a
security problem, please follow [SECURITY.md](SECURITY.md) instead of opening a
public issue.

Please read the [README](README.md) (especially its threat model) and
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) before changing behaviour: this is a
security tool, and most of the code exists to keep a handful of promises.

## Building and testing

cloakenv supports Linux, macOS and Windows (x86_64) and needs Rust **1.87 or
newer** (the MSRV, set as `rust-version` in `Cargo.toml`). Windows-only code is
in `src/winsys.rs` and must be checked on the Windows CI job (a Linux machine
can only type-check it with `cargo check --target x86_64-pc-windows-msvc`).

```bash
cargo build --locked
cargo test --locked                                  # integration tests run the real binary
cargo fmt --all --check
cargo clippy --all-targets --locked -- -D warnings
cargo deny --all-features check                      # needs cargo-deny
cargo package --locked --list                        # what the crate would contain
```

To test the MSRV: `cargo +1.87 test --locked` (use a separate `CARGO_TARGET_DIR` so
it doesn't rebuild your normal target directory). The tests must pass reliably:
run them a few times when you touch anything involving processes, signals, locks
or timing.

The tests use dummy vaults in temporary directories and a dummy passphrase; none of
them needs a real secret, network access or special privileges (they do use `sh`,
`git` and `mkfifo`, which any Linux or macOS machine has). Please keep it that way.

## Invariants

These hold for every change. A pull request that weakens one needs a very good
reason, stated up front.

1. **No plaintext secrets on disk.** Secrets are never written to temporary files,
   named pipes or scratch space. They are decrypted in memory and handed to the
   command through its environment (`std::process::Command::envs`, or `exec` into the
   command), nothing else.
2. **Authenticated encryption only.** The vault uses an AEAD (XChaCha20-Poly1305)
   with a key derived by Argon2id, and the header is authenticated. No
   unauthenticated or weak cipher, no home-made construction.
3. **Fail closed.** If the vault is corrupt, authentication fails or the key can't be
   derived, cloakenv stops with a clear error and a non-zero exit status
   **without starting the command**. Never fall back to "run it anyway".
4. **Redaction (`--shield`).** With `--shield`, the command's stdout and stderr go
   through an in-memory streaming filter that replaces literal secret values with
   `[REDACTED_BY_CLOAKENV]` before anything is written. It is a filter for accidents,
   not a security boundary, and the README says what it doesn't catch.
5. **No secret in errors, logs or argv.** Never print, log or put in an error,
   panic message, backtrace or `Debug` output a secret value, a passphrase, or an
   argument that might be one. Never accept a secret on the command line. Don't
   derive `Debug` for a type that holds a secret, or for a struct with a field whose
   `Debug` would print one.

Also: `unsafe` is denied crate-wide and allowed only in `src/sys.rs`, each use with a
SAFETY comment; new ones need a strong case. Wipe secret buffers (`zeroize`) and
avoid extra copies.

## What CI checks

Every pull request must pass (see [`.github/workflows/ci.yml`](.github/workflows/ci.yml)):

- `rustfmt` and `clippy` with warnings as errors;
- the test suite on Ubuntu 24.04 (stable and the MSRV) and macOS 15 (stable);
- `cargo-deny` against `deny.toml` (RustSec advisories, licences, bans, sources).

Keep `Cargo.lock` committed and use `--locked`. New dependencies need to pass
`cargo deny`; licences outside the allow-list in `deny.toml` need a reason.
Third-party GitHub Actions are pinned to a full commit SHA with the tag in a
trailing comment; Dependabot proposes updates.

## Pull requests

- Branch from `main` and keep a pull request to one topic.
- Use [Conventional Commits](https://www.conventionalcommits.org/) for commit
  messages and PR titles (`fix: ...`, `feat: ...`, `docs: ...`, `ci: ...`).
- Add or update tests for behaviour changes, and update the README when you change
  what the tool does or doesn't protect. Every claim there should match what the
  binary actually does.
- Add a line under `## [Unreleased]` in [CHANGELOG.md](CHANGELOG.md) for
  user-visible changes.
- Say explicitly in the description if a change affects what is protected or what
  leaks.

## Releasing (maintainer)

The release workflow (`.github/workflows/release.yml`) runs on a `v*` tag (or
manually), checks that the tag matches `Cargo.toml`, that the commit is on `main`
and that the changelog has a section for the version, runs the CI checks, runs
`cargo package` as a packaging check, builds static Linux (x86_64, aarch64) and
macOS (aarch64, x86_64) binaries, smoke-tests them, and writes `SHA256SUMS`. For a
real tag it then creates a **draft** GitHub release with those files and the
changelog section as the notes. A manual run has no tag, so it stops after
uploading the archives as artifacts. The token is read-only except in the one job
that creates the draft; it uses no secrets and publishes nothing: you publish the
draft and run `cargo publish` by hand:

1. Bump `version` in `Cargo.toml` and `Cargo.lock`; in `CHANGELOG.md`, the section
   for the version must exist as `## [X.Y.Z] - YYYY-MM-DD` (the release workflow
   checks for the heading): move the `Unreleased` entries under a new heading and
   update the two link lines at the bottom. 0.1.0 did this already.
2. Merge that to `main` once CI is green.
3. Tag the merge commit `vX.Y.Z` and push the tag. Wait for the "Release build" run
   to go green; its last job, "draft GitHub release", creates the draft (it fails,
   and creates nothing, if a release for the tag already exists).
4. Check the draft on the Releases page: the notes are the changelog section for
   the version, and the archives and `SHA256SUMS` are attached. Download them,
   verify (`sha256sum --check SHA256SUMS`), and try an archive. The same files are
   also the `release-assets-X.Y.Z` artifact of the run.
5. Publish the draft, and run `cargo publish` from the same commit.
