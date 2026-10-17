# Vault format v2: design

**Status:** design for review. Nothing here is implemented. When it is accepted, this document replaces the
"Proposed: vault format v2" section of ARCHITECTURE.md, which it builds on and in three places corrects.

## Goals

One format change that fixes the four limits of v1 together:

1. **Rollback:** a valid but older vault put back in place is accepted silently.
2. **Length:** the file size reveals the exact total length of all keys and values.
3. **Passphrase change:** the only way is `init --force`, which empties the vault.
4. **Forward compatibility:** v1 has one reserved byte and no way to add anything without another version bump.

Non-goals: multiple passphrases or recipients, OS keychain unlock, hiding that a vault exists or roughly how big
it is, protection against code running as the same user (it can read the passphrase as it is typed).

## Summary of decisions

| # | decision | differs from the ARCHITECTURE.md proposal? |
|---|---|---|
| D1 | **No key wrapping.** The passphrase-derived key encrypts the payload, as in v1. | **yes** (see "Why no wrapped data key") |
| D2 | `passwd` = decrypt with the old passphrase, encrypt with the new one, fresh salt and nonce. No separate `rekey`. | **yes** (follows from D1) |
| D3 | A random 16-byte **vault id** in the header, fixed at `init` and kept forever. The anti-rollback state is keyed by it, not by a hash of the path. | **yes** (new) |
| D4 | Generation counter in the header; per-user state file holds, per vault id, the highest generation seen **and the tag of that version**. Same generation with a different tag = forked history, also refused. | extends it |
| D5 | Padding with **Padmé** (at most 12% overhead, leaks O(log log n) bits) above a **4 KiB floor**, padding = zero bytes inside the AEAD. | resolves an open question |
| D6 | **No automatic migration.** New binaries read v1 and v2 and write back the version they read; `init` creates v2; `cloakenv upgrade` converts explicitly. | **yes** |
| D7 | Rollback refusal is fail-closed for every command, including `run` and `list`; the way past it is a command, `cloakenv accept-rollback`, never an environment variable. | resolves an open question |
| D8 | `export` is **out of scope** for v2 (it needs no format change); decided separately. | narrows scope |
| D9 | A TLV **extension area** in the header so later additions need no version bump. | new |

## Why no wrapped data key (D1, D2)

The proposal wraps a random data key (DEK) under the passphrase key so that `passwd` only re-wraps 32 bytes. Two
problems:

- **Re-wrapping without rotating the DEK is unsafe.** Someone who copied the vault while the old passphrase was weak
  can crack it at leisure, unwrap the DEK, and then decrypt **every future version** of the vault, although they never
  learn the new passphrase. So `passwd` must rotate the DEK anyway, which is what the proposal's `rekey` did.
- **Once the DEK rotates, wrapping saves nothing.** The cost of a passphrase change is two Argon2id runs (old and new),
  roughly 0.3 to 1 s. Re-encrypting a payload of at most 16 MiB with XChaCha20-Poly1305 is a few milliseconds.

Without wrapping: one key, one AEAD, a smaller header, fewer ways to get the construction wrong, and no
"rekey vs passwd" choice for the user to understand. The cost of being wrong: if a later feature needs a DEK
(OS-keychain unlock, a second recipient), it bumps the version again. The version byte and the extension area (D9) make
that a clean change.

## On-disk layout (version 2)

All integers little-endian. Header length is variable: `96 + ext_len` bytes. **The whole header is the AEAD's
associated data**, so every field (including the generation, the vault id and the extensions) is authenticated.

| offset | size | field |
|---:|---:|---|
| 0 | 8 | magic `CLOAKENV` |
| 8 | 1 | format version = 2 |
| 9 | 1 | KDF id: 1 = Argon2id v1.3 |
| 10 | 1 | AEAD id: 1 = XChaCha20-Poly1305 |
| 11 | 1 | padding scheme: 1 = Padmé with a 4 KiB floor |
| 12 | 4 | Argon2 memory (KiB) |
| 16 | 4 | Argon2 iterations |
| 20 | 4 | Argon2 lanes |
| 24 | 16 | salt (fresh on every save) |
| 40 | 24 | nonce (fresh on every save) |
| 64 | 16 | vault id (random at `init` / `upgrade`, never changes) |
| 80 | 8 | generation (u64; 1 at creation, +1 on every save) |
| 88 | 4 | flags (u32): all bits reserved, must be 0 |
| 92 | 4 | ext_len (u32): length of the extension area, at most 4096 |
| 96 | ext_len | extensions: TLV records `u16 type, u16 len, value` |
| 96 + ext_len | n | ciphertext ‖ 16-byte Poly1305 tag |

**Plaintext payload:** `u32 count`, then `count` entries `u32 key_len, key, u32 value_len, value` (as v1), then zero
bytes up to the padded length.

**Decoder rules** (all checked before anything is used):
- Unknown version, KDF, AEAD or padding id: refused with the existing "unsupported" errors.
- Flags non-zero, `ext_len` over 4096 or running past the file, a malformed TLV (length past the area, duplicate type): Malformed.
- Unknown extension type: **refused if the type's top bit is set** ("critical"), ignored otherwise. Version 2 defines
  no extensions; the rule exists so that later releases can add optional fields without breaking 0.3 readers.
- KDF parameters validated against the open-time bounds (as v1) **before** running Argon2, since they are not yet authenticated.
- After decryption: the v1 entry rules (no duplicates, valid names, no NUL, entry size cap), then **every padding byte
  must be zero** and the plaintext length must equal `padme(unpadded length)` exactly. Anything else is Malformed.
  A canonical length means one plaintext has exactly one valid padded form.
- Generation, vault id and the extensions are **never acted on before the tag verifies.**

## Padding (D5)

`padded = max(4096, padme(unpadded))` where, for L >= 2: `E = floor(log2 L)`, `S = floor(log2 E) + 1`, `z = E - S`,
then L rounded up to a multiple of `2^z`. (Padmé, from Nikitin et al., "Reducing Metadata Leakage from Encrypted Files
and Communication with PURBs", PETS 2019.)

- **What it hides:** small changes. A vault with 20 secrets that rotates one to a different length keeps its size in
  most cases, and the size only says which of about 2^S buckets the length is in.
- **What it costs:** a small vault is 4,096 + 112 bytes instead of about 100. Above the floor the overhead is bounded
  by 12% in general and measured at most 6.2% for payloads from 4 KiB to 4 MiB (versus up to 100% for the power-of-two
  buckets the proposal suggested). Examples: 5,000 → 5,120; 20,000 → 20,480; 100,000 → 100,352 bytes.
- **What it does not hide:** that a vault exists, its order of magnitude, its modification time, and the jump when it
  crosses a bucket boundary.
- `MAX_VAULT_LEN` (16 MiB) applies to the **padded** file; `sealed_len()` and `check_size()` change accordingly, so the
  usable capacity drops by up to 12%. `set` and `import` already check the size before writing; the error gives both numbers.

## Rollback and fork detection (D3, D4, D7)

### State file

One file per user, outside every project:

| platform | location |
|---|---|
| Linux and other Unix | `$XDG_STATE_HOME/cloakenv/seen`, default `~/.local/state/cloakenv/seen` |
| macOS | `~/Library/Application Support/cloakenv/seen` |
| Windows | `%LOCALAPPDATA%\cloakenv\seen` |

Overridable with `CLOAKENV_STATE_DIR` (for tests and unusual setups). Directory 0700 and file 0600 on Unix, owner-only ACL on
Windows (reusing the existing helpers). Paths are computed by hand from these variables: no new dependency.

Content: one line per vault, `<vault id hex> <highest generation> <tag hex of that version> <last canonical path>`,
plus one line per path that has held a v2 vault (the downgrade guard below). Plain text, so a user can read and fix it.
It holds no secret: vault ids, counters, AEAD tags and paths. Every update is a read-modify-write **under an exclusive
lock on a sibling lock file** (the existing VaultLock code), written by temp file and rename, so two concurrent `run`s
cannot lower each other's mark.

### Check, after every successful decryption

Let the vault say `(id, gen, tag)` and the state say `(gen*, tag*)` for that id:

| case | result |
|---|---|
| id unknown | trust on first use: record it, continue |
| gen > gen* | record it, continue (normal: another process or machine saved) |
| gen = gen*, tag = tag* | continue |
| gen = gen*, tag differs | **refuse: forked history** (two copies were both saved from the same version, e.g. two machines with a synced folder) |
| gen < gen* | **refuse: rollback** ("this vault is generation 7; this machine has seen generation 9 of it, last at PATH") |
| v1 file at a path recorded as having held v2 | **refuse: downgrade** (v1 has no generation, so an old v1 copy would otherwise bypass everything) |
| a different id at a path recorded with another id | **warn**, record the new path (moving a vault, or `init --force`, is normal; substitution by another vault of yours is possible, hence the warning) |

A refusal happens **before anything is spawned or printed**, and exits with the existing failure code. The vault file is
never modified by the check.

**Getting past a refusal, on purpose:** `cloakenv accept-rollback` (asks for the passphrase, decrypts, shows the
generation it will accept and the one it replaces, asks for confirmation or `--yes`, then lowers the mark for that id).
A command, not an environment variable: a variable set once in a shell profile or CI config would switch the protection
off for good, and nobody would notice. For a forked history the same command chooses the copy in hand; it does not merge.

**State file missing or unwritable** (a fresh machine, a read-only home in a container): one warning on stderr, then
continue without the check. Failing closed here would break every container that mounts a vault read-only, which is a
common way to use the tool, and the threat model already says the protection needs a place the attacker cannot write.
**Corrupt state file** (unparsable): refuse with a message naming the file, since silently ignoring it would reopen the
hole. A one-line fix is in the message.

### What this does and does not protect (for the README threat model)

- **Protects:** an attacker who can write the vault's directory or its transport (a shared volume, a sync service, a
  backup, a repository) and puts an older valid vault back, or a v1 copy from before the upgrade, or a copy that was
  modified on another machine in parallel.
- **Does not protect:** code running as you (it can edit the state file); a machine that has never opened the vault
  (trust on first use); a deleted state file (the next open re-trusts whatever it finds, with no warning on a fresh
  file); two machines legitimately sharing a vault through a sync folder, which will see "forked" or "rollback" on
  hand-overs and need `accept-rollback`. That last cost is real; the README already discourages synced folders.

## Commands

- `cloakenv init`: creates a v2 vault, generation 1, fresh vault id; records it in the state file.
- `cloakenv passwd` (new): prompts for the current passphrase, then the new one twice (or reads them from
  `CLOAKENV_PASSPHRASE_FILE` / `CLOAKENV_NEW_PASSPHRASE_FILE`, files only, for scripts). Holds the write lock, decrypts,
  writes a backup copy (the existing `.bak-<UTC>` mechanism), saves with the new passphrase, a fresh salt and nonce, and
  generation + 1. A wrong current passphrase exits non-zero without touching anything. The output says that the backup is
  still encrypted with the **old** passphrase and should be deleted once the new one is confirmed to work. Works on a v1 vault
  too (writes v1 back, see D6).
- `cloakenv upgrade` (new): v1 → v2 under the write lock, backup first, new vault id, generation 1, records the
  id and marks the path as v2. Refuses on a v2 vault ("already version 2"). Prints that cloakenv 0.2 and older cannot
  open the result.
- `cloakenv accept-rollback [--yes]` (new): as above.
- `cloakenv info` (new, small): prints the version, KDF parameters, generation, vault id, file size and what the state file
  says about it. Needs the passphrase (the header is unauthenticated until then; showing unverified numbers would invite
  trusting them).
- `set`, `unset`, `import`: unchanged behaviour; on v2 they increase the generation and update the state file **after**
  the rename succeeds. The existing automatic raise of weak KDF parameters on save stays.
- `run`, `list`: still never write the vault; they do write the state file (raising the mark).

## Migration and compatibility (D6)

The proposal migrated automatically on the next write. I recommend against it: a vault on a shared machine, a
volume mounted into containers, or a team with mixed versions, would be silently converted by whoever ran `set` first
with 0.3, after which every 0.2 binary fails with "unsupported vault format version 2". The user then has to discover
that the cause was an upgrade they never asked for.

Instead:
- 0.3 **reads** v1 and v2. It **writes back the version it read**; on a v1 save it prints one line:
  "this vault uses format 1, which cannot detect rollback or hide its size; run `cloakenv upgrade` to convert it
  (cloakenv 0.2 and older cannot open version 2)".
- `init` creates v2. A team that needs 0.2 compatibility for a new vault can create it with an 0.2 binary; I would not
  add a `--format 1` flag, which would keep the old format alive.
- 0.2 and older refuse v2 with the error they already have. (This needs a test against the published 0.2.0 binary,
  not just a reading of the code.)
- A downgrade is possible by restoring the `.bak` copy that `upgrade` keeps; the downgrade guard will then refuse it
  until `accept-rollback`, which is the correct behaviour.
- Library API (`cloakenv::vault` is public): `Vault::seal/open/load/save` change shape (they need the
  generation, id and state). Pre-1.0, so a breaking change in 0.3.0, listed in the CHANGELOG.

## Cryptographic notes

- Same primitives as v1: Argon2id v1.3, XChaCha20-Poly1305, 16-byte salt, 24-byte random nonce, fresh salt and nonce on
  every save. No new dependency.
- One key per save, derived from the passphrase and a fresh salt: nonce reuse under a key cannot happen across saves,
  and the 192-bit random nonce makes it negligible anyway.
- XChaCha20-Poly1305 is not key-committing. With one key, derived from one passphrase, there is no
  partitioning-oracle setting to exploit (that needs many candidate keys tried against one ciphertext by a server).
  Noted so that it is reconsidered if multiple recipients are ever added.
- The generation is authenticated (it is in the AAD) but its **meaning** comes only from the state file. A stand-alone
  vault proves nothing about freshness, and the docs must not suggest otherwise.
- The AEAD tag stored in the state file is public information (it is in the vault file); it identifies a version, it
  is not a secret.

## Test plan

Before any format code changes:
- **Golden v1 fixtures:** vaults written by the published 0.2.0 binary (empty, one entry, many entries, maximum entry
  size, weak legacy KDF parameters), checked in under tests/fixtures with their passphrases. There are none today; every
  later step has to keep opening them.

For v2:
- **Known-answer vectors:** fixed passphrase, salt, nonce, vault id and generation, so the exact bytes are asserted
  and a second implementation could be checked against them.
- **Decoder rejection table:** one test per rule above (each field, each bound, non-zero padding, non-canonical padded
  length, critical unknown extension, truncation at every offset, one flipped bit at every offset of a small vault).
- **Property tests:** encode/decode round trip, Padmé monotonic and at most 12% above the floor, and a value rotated to a different length within one bucket leaves the file size unchanged.
- **Rollback matrix,** each as an end-to-end CLI test: older copy, forked copy, v1 copy after upgrade, moved vault, missing
  state file, read-only state directory, corrupt state file, accept-rollback, two concurrent `run`s racing on the mark.
- **Interop:** the 0.2.0 binary on a v2 vault (refuses with the version error, exit code 1, file untouched); 0.3 on every
  golden v1 fixture; `upgrade` of each fixture and back through the backup.
- **passwd:** wrong old passphrase leaves the file byte-identical; old passphrase fails and new one opens afterwards;
  backup exists and opens with the old one; interrupted save (killed between write and rename) leaves the old vault valid.
- **Platforms:** the state-file paths and permissions on Linux, macOS and Windows CI.
- A **fuzz target** for the v2 decoder (cargo-fuzz, run locally and as a short CI smoke job).

## Implementation plan (one PR each, in order)

1. **Golden v1 fixtures** and their tests. No behaviour change.
2. **v2 codec in the library:** header, extensions, Padmé, the decoder rules, vectors, fuzz target. Not reachable from the CLI yet.
3. **State file and the check:** locations, locking, the table above, `accept-rollback`, `info`.
4. **Commands:** `init` writes v2, `upgrade`, `passwd`, the v1 hint on save.
5. **Docs and release:** README threat model and file-format sections, ARCHITECTURE.md (replace the proposal with the
   implemented design), CHANGELOG with a migration section, then a 0.3.0 release on Ben's go-ahead.

Rough size: 1,500 to 2,500 lines including tests; PRs 2 and 3 carry the risk and want the most review. I would also like
an **independent review of PR 2 and 3** by someone other than their author before release.

## Decisions for Ben

1. **D1: drop key wrapping?** I recommend yes (reasons above). The alternative is wrapping now in case keychain unlock comes later.
2. **D6: no automatic migration?** I recommend explicit `upgrade`.
3. **D7: fail closed on rollback for `run` too,** with a warning-only fallback when the state file cannot be written. The alternative is warning only, everywhere.
4. **Padding floor:** 4 KiB (my default) or 1 KiB (smaller files, more leakage for tiny vaults).
5. **`export`:** decide separately, or not at all.
6. **Release:** 0.3.0, breaking (library API and the new default format).
