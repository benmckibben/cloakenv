#!/usr/bin/env bash
# Smoke-test a release archive: extract it and run the real binary through an
# init / set / list / run round trip in a throwaway directory.
#
#   smoke-test.sh ARCHIVE VERSION [RUNNER...]
#
# RUNNER is an optional command prefix for binaries that can't run natively
# (e.g. `qemu-aarch64`, or `arch -x86_64` for Rosetta). Everything here is
# dummy data: a made-up passphrase and a made-up "secret", in a temp directory
# that is deleted afterwards. Nothing leaves the machine.
#
# Written for bash 3.2 (macOS) as well as bash 5.

# The commands run through ce are meant to be expanded by the inner sh, not here.
# shellcheck disable=SC2016
set -euo pipefail

if [ "$#" -lt 2 ]; then
  echo "usage: $0 ARCHIVE VERSION [RUNNER...]" >&2
  exit 2
fi
archive=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
version=$2
shift 2
runner=("$@")

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

tar -xzf "$archive" -C "$work"
bin=$(find "$work" -type f -name cloakenv -perm -u+x | head -n 1)
[ -n "$bin" ] || { echo "::error::no cloakenv binary in $archive"; exit 1; }

ce() {
  if [ "${#runner[@]}" -gt 0 ]; then
    "${runner[@]}" "$bin" "$@"
  else
    "$bin" "$@"
  fi
}

fail() {
  echo "::error::smoke test failed: $*"
  exit 1
}

# What the archive contains besides the binary.
dir=$(dirname "$bin")
for f in README.md LICENSE-MIT LICENSE-APACHE; do
  [ -f "$dir/$f" ] || fail "$f is missing from the archive"
done

got=$(ce --version)
echo "$got"
[ "$got" = "cloakenv $version" ] || fail "expected 'cloakenv $version', got '$got'"

# A throwaway project directory. The passphrase is a dummy used only here.
proj="$work/project"
mkdir "$proj"
cd "$proj"
export CLOAKENV_PASSPHRASE='smoke-test passphrase, not a real one'
unset CLOAKENV_PASSPHRASE_FILE CLOAKENV_VAULT
secret='sk-smoke-0123456789abcdef-NOT-A-REAL-SECRET'

ce init
[ -f .cloak/vault.bin ] || fail "init did not create .cloak/vault.bin"
[ "$(cat .cloak/.gitignore)" = "*" ] || fail "init did not write .cloak/.gitignore"

printf '%s\n' "$secret" | ce set SMOKE_SECRET

# The vault is encrypted: neither the value nor the name is in the file.
if grep -aqF -e "$secret" -e SMOKE_SECRET .cloak/vault.bin; then
  fail "the vault file contains the secret or its name in clear"
fi

# list shows names, never values.
listed=$(ce list)
[ "$listed" = "SMOKE_SECRET" ] || fail "list printed '$listed'"

# run injects the value into the command's environment (exec mode).
injected=$(ce run -- sh -c 'printf %s "$SMOKE_SECRET"')
[ "$injected" = "$secret" ] || fail "the secret was not injected"

# The passphrase never reaches the command.
leaked=$(ce run -- sh -c 'printf %s "${CLOAKENV_PASSPHRASE-unset}"')
[ "$leaked" = "unset" ] || fail "CLOAKENV_PASSPHRASE reached the command"

# --shield redacts the value from stdout and from stderr. The two streams are
# filtered by separate threads (their relative order is not guaranteed), so
# capture them separately.
ce run --shield -- sh -c 'echo "out:$SMOKE_SECRET"; echo "err:$SMOKE_SECRET" >&2' >shield.out 2>shield.err
cat shield.out shield.err
if grep -qF -e "$secret" shield.out shield.err; then fail "--shield let the secret through"; fi
[ "$(cat shield.out)" = "out:[REDACTED_BY_CLOAKENV]" ] || fail "--shield did not redact stdout"
[ "$(cat shield.err)" = "err:[REDACTED_BY_CLOAKENV]" ] || fail "--shield did not redact stderr"

# Exit codes pass through, with and without --shield.
rc=0
ce run -- sh -c 'exit 7' || rc=$?
[ "$rc" -eq 7 ] || fail "run: expected exit code 7, got $rc"
rc=0
ce run --shield -- sh -c 'exit 7' || rc=$?
[ "$rc" -eq 7 ] || fail "run --shield: expected exit code 7, got $rc"

# Fail closed: a wrong passphrase starts nothing and exits 125.
rc=0
CLOAKENV_PASSPHRASE='the wrong passphrase' ce run -- touch ran-anyway 2>/dev/null || rc=$?
[ "$rc" -eq 125 ] || fail "wrong passphrase: expected exit code 125, got $rc"
[ ! -e ran-anyway ] || fail "the command ran despite a wrong passphrase"

echo "smoke test passed"
