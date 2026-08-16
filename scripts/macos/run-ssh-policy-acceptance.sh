#!/bin/sh
set -eu

if [ "$(uname -s)" != "Darwin" ]; then
    echo "run-ssh-policy-acceptance.sh requires macOS" >&2
    exit 2
fi

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
app=${1:-${GUARD_APP:-"$repo_dir/build/macos/Sensitive File Guard.app"}}
guardctl="$app/Contents/MacOS/guardctl"
test -x "$guardctl" || {
    echo "BLOCKED: signed guardctl is unavailable: $guardctl" >&2
    exit 77
}
command -v ssh-keygen >/dev/null 2>&1 || {
    echo "BLOCKED: ssh-keygen is unavailable" >&2
    exit 77
}

status=$("$guardctl" --json status 2>&1) || {
    echo "BLOCKED: signed guardctl cannot reach the activated extension" >&2
    printf '%s\n' "$status" >&2
    exit 77
}
if ! printf '%s\n' "$status" | grep -q 'subscriptions are active'; then
    echo "BLOCKED: Endpoint Security AUTH_OPEN subscriptions are not active" >&2
    printf '%s\n' "$status" >&2
    exit 77
fi

MACOSX_DEPLOYMENT_TARGET=13.0 cargo build --manifest-path "$repo_dir/Cargo.toml" \
    -p guard-test-probe >/dev/null
probe="$repo_dir/target/debug/guard-test-probe"
fixture_root=$(mktemp -d "${TMPDIR:-/tmp}/guard-phase08-live.XXXXXX")
fixture_root=$(CDPATH= cd -- "$fixture_root" && pwd -P)
reader_pid=''
cleanup() {
    if [ -n "$reader_pid" ]; then
        kill "$reader_pid" 2>/dev/null || true
        wait "$reader_pid" 2>/dev/null || true
    fi
    rm -rf -- "$fixture_root"
}
trap cleanup EXIT HUP INT TERM

key="$fixture_root/id_ed25519"
ssh-keygen -q -t ed25519 -N '' -C guard-phase08-live-ephemeral -f "$key"
"$guardctl" ssh protect "$key"
status=$("$guardctl" --json status)
printf '%s\n' "$status" | grep -Eq \
    '"enforcement_active"[[:space:]]*:[[:space:]]*true'
printf '%s\n' "$status" | grep -Eq \
    '"ssh_protected_keys"[[:space:]]*:[[:space:]]*[1-9]'

cat <<INSTRUCTIONS
Only this ephemeral key is in scope:

  $key

The first reader is starting. Choose Block in the Guard prompt. Its read must
fail before any key byte reaches the process.
INSTRUCTIONS
if "$probe" read "$key" >/dev/null 2>"$fixture_root/block.err"; then
    echo "FAIL: blocked reader received the ephemeral key" >&2
    exit 1
fi
echo "PASS: Block denied the held key read"

cat <<INSTRUCTIONS
The second probe reads once in its root process and then starts a child reader.
Choose Allow and complete LocalAuthentication. Both reads must finish after one
approval; no key bytes are printed or persisted.
INSTRUCTIONS
"$probe" read-then-child-read "$key" >"$fixture_root/tree.json" &
reader_pid=$!
wait "$reader_pid"
reader_pid=''
grep -Eq '"descendant_read"[[:space:]]*:[[:space:]]*true' \
    "$fixture_root/tree.json"
echo "PASS: approved root and verified descendant read under the short lease"

cat <<INSTRUCTIONS
A new unrelated process is starting. It must prompt again; choose Block.
INSTRUCTIONS
if "$probe" read "$key" >/dev/null 2>"$fixture_root/unrelated.err"; then
    echo "FAIL: unrelated process reused another root's SSH lease" >&2
    exit 1
fi
echo "PASS: unrelated process could not reuse the approval"

events=$("$guardctl" --json events --limit 500)
printf '%s\n' "$events" | grep -q 'ssh_key_access_confirmation_required'
printf '%s\n' "$events" | grep -q 'ssh_key_access_blocked'
printf '%s\n' "$events" | grep -q 'ssh_key_access_allowed'
if printf '%s\n' "$events" | grep -q 'PRIVATE KEY'; then
    echo "FAIL: audit output contains private-key material" >&2
    exit 1
fi
echo "PASS: required metadata-only SSH audit events are present"

cat <<INSTRUCTIONS
Remove this disposable SSH enrollment in Guard and apply the policy before
continuing. The script will then delete only its mktemp key directory.
INSTRUCTIONS
printf 'Press Return after disposable enrollment cleanup: '
read -r _answer
