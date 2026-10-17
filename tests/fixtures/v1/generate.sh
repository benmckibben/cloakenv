#!/usr/bin/env bash
# Regenerates the golden vault fixtures from the PUBLISHED cloakenv releases (crates.io), not from this checkout.
#
#   tests/fixtures/v1/generate.sh
#
# It installs cloakenv 0.1.0 and 0.2.0 from crates.io into a scratch directory, then uses each binary's own
# init/set/import to write the vaults. The fixtures are not reproducible byte for byte (every save picks a random
# salt and nonce), so they are checked in; regenerate only when a new fixture is needed, never to "fix" a failing
# test: a failing golden test means the current code can no longer open a vault that a release wrote.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK="${GOLDEN_WORK:-$(mktemp -d)}"
PASS="golden-v1-fixture-passphrase"     # public, on purpose: the vaults hold dummy data only
export CLOAKENV_PASSPHRASE="$PASS"
unset CLOAKENV_PASSPHRASE_FILE CLOAKENV_VAULT

for v in 0.1.0 0.2.0; do
  if [ ! -x "$WORK/$v/bin/cloakenv" ]; then
    cargo install cloakenv --version "$v" --locked --root "$WORK/$v" >&2
  fi
done

make() {   # make <version> <fixture name> <kind>
  local v="$1" name="$2" kind="$3" bin="$WORK/$1/bin/cloakenv" out="$HERE/$2.bin"
  rm -f "$out"
  export CLOAKENV_VAULT="$out"
  "$bin" init >&2
  case "$kind" in
    empty) ;;
    one) printf 'hello' | "$bin" set GREETING >&2 ;;
    many) "$bin" import "$HERE/many.env" >&2 ;;
    max) # MAX_ENTRY (9) + '=' (1) + 131061 value bytes = 131071 = the largest entry the format accepts
      awk 'BEGIN{for(i=0;i<8191;i++)printf "0123456789abcdef"; printf "01234"}' | "$bin" set MAX_ENTRY >&2 ;;
  esac
  chmod 0644 "$out"       # git does not keep modes; the tests set 0600 on their own copy
  echo "$name: $("$bin" --version) -> $(wc -c < "$out") bytes" >&2
}

make 0.2.0 empty empty
make 0.2.0 one one
make 0.2.0 many many
make 0.2.0 max_entry max
make 0.1.0 from_0.1.0_one one
make 0.1.0 from_0.1.0_many many

# the CLI leaves an empty writer-lock file next to every vault it writes
rm -f "$HERE"/.*.bin.lock
( cd "$HERE" && sha256sum ./*.bin ./many.env > SHA256SUMS )
echo "wrote $(ls "$HERE"/*.bin | wc -l) fixtures; scratch dir $WORK" >&2
