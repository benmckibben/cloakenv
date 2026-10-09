# Security policy

## Supported versions

cloakenv is pre-1.0 and hasn't had a release yet. Security fixes go into the
default branch and, once releases exist, into the latest release only.

| Version | Supported |
|---|---|
| latest release (once there is one) | yes |
| `main` | yes |
| anything older | no |

## Reporting a vulnerability

**Please don't open a public issue or pull request for a security problem, and
please don't put a real secret or a real vault in a report.**

Report it privately with GitHub's private vulnerability reporting: open the
repository's **Security** tab, choose **Report a vulnerability**, and fill in the
form. Only the maintainer and you can see the report.

If that button isn't available, open an issue that says only that you have a
security report (no details) and ask for a private way to send it.

A useful report has: what you ran (the cloakenv command line and, for `run`, the
command inside), what you expected, what happened instead, the cloakenv version
or commit, and the operating system. A proof of concept that fits in a few lines,
using dummy secrets, is ideal.

cloakenv is a small project maintained on a best-effort basis: there is no
guaranteed response time or fix time. Reports are read, and fixed as time and
severity allow. Reporters are credited in the changelog unless they'd rather not
be.

## Threat model, in short

cloakenv keeps secrets out of plaintext files, shell history, process
arguments, terminal scrollback, CI logs and AI-agent transcripts, on a machine
you otherwise trust. The vault is encrypted at rest (Argon2id and
XChaCha20-Poly1305), nothing is ever decrypted to disk, and secrets reach the
command only through its environment. The README's
[Threat model](README.md#threat-model) section has the full list; in short:

**What it protects**

- **A copy of the vault file** (stolen laptop, backup, a mistaken `git add -f`):
  an attacker can only guess the passphrase offline, one Argon2id run per guess.
  *The passphrase is the whole defence*, so use a long one; cloakenv warns about
  short ones but doesn't refuse them.
- **Tampering**: any change to the file, truncation, or a foreign file fails
  authentication; `run` starts nothing (exit 125).
- **Secrets in arguments, plaintext `.env` files and history**: `set` never takes
  a value on the command line.
- **Accidental leaks in the command's output**: `run --shield` redacts exact
  occurrences of vault values from the command's stdout and stderr.
- **Other local users and (on Linux) other processes of your user probing
  cloakenv itself**: restrictive file modes, warnings about loose ones, and a
  non-dumpable process.

**What it does not protect**

- **The command you run.** It gets the secrets in its environment and can do
  anything with them; other processes of your user (and root) can read its
  `/proc/<pid>/environ`. `--shield` is a filter for accidents, not a boundary
  against a command that wants to leak a value (base64, hex, split, masked, or
  written anywhere but stdout/stderr all pass through). cloakenv is not a sandbox.
- **Root, the kernel, the hypervisor, and any code already running as you before
  cloakenv starts.**
- **A weak passphrase**, or one kept in an environment variable on a shared
  machine (use the prompt or a `0600` passphrase file).
- **macOS**: there is no non-dumpable flag, so cloakenv's own environment and
  memory aren't protected from same-user processes there. Windows is unsupported.
- **Rollback**: anyone who can write the vault's directory can put back an older
  valid vault (rotated secrets revert); they can't read or forge one.
- **Memory and swap**: wiping is best effort and memory isn't locked, so pages
  may reach swap or a hibernation image.
- **Metadata**: the vault's approximate size, modification time and existence.

### In scope

Behaviour that contradicts the documented guarantees, for example:

- a way to make cloakenv write a secret, or the passphrase, to disk, argv, an
  error message, a log or a debug trace;
- a vault that opens, or a command that starts, after tampering or with a wrong
  passphrase (fail-closed bypass);
- `--shield` letting a literal vault value through on stdout or stderr outside
  the limits the README lists;
- the passphrase reaching the command's environment, or being readable by other
  processes of your user on Linux despite the non-dumpable flag;
- memory-safety, parsing or resource-exhaustion bugs triggered by a hostile
  vault file, `.env` file or command line (for example a header that forces a huge
  allocation);
- weaknesses in the vault format or cryptography.

### Out of scope

- Anything that needs a hostile command, root, or code already running as you to
  attack the host by other means.
- Limits already documented in the README's threat model and
  [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md), such as the ones listed
  above, an offline attack on a short passphrase, or a deliberately transformed
  secret getting past `--shield`.
- Vulnerabilities in dependencies that don't affect cloakenv (CI runs
  `cargo deny` against the RustSec advisory database, weekly).
