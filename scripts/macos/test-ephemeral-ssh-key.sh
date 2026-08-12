#!/bin/sh
set -eu

if [ "$(uname -s)" != "Darwin" ]; then
    echo "test-ephemeral-ssh-key.sh requires macOS" >&2
    exit 2
fi

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
guardctl=${1:-"$repo_dir/target/debug/guardctl"}
if [ ! -x "$guardctl" ]; then
    echo "guardctl executable is unavailable: $guardctl" >&2
    exit 2
fi
command -v ssh-keygen >/dev/null 2>&1 || {
    echo "ssh-keygen is unavailable" >&2
    exit 2
}

fixture_root=$(mktemp -d "${TMPDIR:-/tmp}/guard-phase08-ssh.XXXXXX")
fixture_root=$(CDPATH= cd -- "$fixture_root" && pwd -P)
cleanup() {
    rm -rf -- "$fixture_root"
}
trap cleanup EXIT HUP INT TERM

ssh-keygen -q -t ed25519 -N '' -C guard-phase08-ephemeral \
    -f "$fixture_root/id_ed25519"
printf '%s\n' 'synthetic reserved metadata' >"$fixture_root/known_hosts"
printf '%s\n' 'synthetic config metadata' >"$fixture_root/config"

suggestions=$("$guardctl" ssh suggest --dir "$fixture_root")
printf '%s\n' "$suggestions" | grep -Fq "$fixture_root/id_ed25519"
if printf '%s\n' "$suggestions" | grep -Eq 'id_ed25519\.pub|known_hosts|/config$'; then
    echo "FAIL: public or reserved SSH metadata was suggested" >&2
    exit 1
fi

echo "PASS: a real ephemeral Ed25519 key was suggested by metadata only; .pub and reserved names were excluded"
