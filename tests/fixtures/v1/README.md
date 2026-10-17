# Golden vault fixtures (format version 1)

Vaults written by the **published** cloakenv 0.1.0 and 0.2.0 binaries (installed from crates.io, not built from this
checkout), kept so that every later change to the vault code has to keep opening what real releases wrote.

The passphrase is `golden-v1-fixture-passphrase`. It is public on purpose: the vaults hold dummy data only.

| file | written by | contents |
|---|---|---|
| `empty.bin` | 0.2.0 `init` | no entries |
| `one.bin` | 0.2.0 `init` + `set` | `GREETING=hello` |
| `many.bin` | 0.2.0 `import many.env` | 41 entries: unicode, `=` inside values, a 3000-byte value, a long key name |
| `max_entry.bin` | 0.2.0 `set` | one entry of 131,071 bytes (key + `=` + value), the largest the format accepts |
| `from_0.1.0_one.bin` | 0.1.0 | `GREETING=hello` |
| `from_0.1.0_many.bin` | 0.1.0 | the same 41 entries as `many.bin` |

`tests/golden_v1.rs` opens every one of them through the library and through the CLI, checks the header bytes and
the exact contents, and checks that a wrong passphrase, a flipped bit and a truncated file are refused.

**What is not here, and why:** a vault written with key-derivation settings below the current minimum (8 MiB, 1 pass).
No published release ever wrote one (0.1.0 already had the 19 MiB minimum); only pre-release builds did, so there is
nothing real to capture. `tests/kdf_upgrade.rs` covers reading and upgrading such a file.

**Regenerating:** `generate.sh` (needs cargo and network access). The output is not reproducible byte for byte
(random salt and nonce on every save), which is why the files are committed. `SHA256SUMS` records the committed
files. Never regenerate to make a failing test pass: a failure means the current code can no longer open a released vault.
