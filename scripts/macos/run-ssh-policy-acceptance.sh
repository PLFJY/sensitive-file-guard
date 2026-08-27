#!/bin/sh
set -eu

if [ "$(uname -s)" != "Darwin" ]; then
    echo "run-ssh-policy-acceptance.sh requires macOS" >&2
    exit 2
fi

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
case "${1:-}" in
    --help|-h)
        cat <<'USAGE'
Usage:
  scripts/macos/run-ssh-policy-acceptance.sh [GUARD_APP]

This fixture-only test creates one fresh, disposable SSH key and asks for two
decisions in order: first Block, then Allow. It waits for Return before each
reader starts. During this one test only, post-Block prompt suppression is
disabled in memory and is restored on exit (or automatically after 3 minutes).
USAGE
        exit 0
        ;;
esac

if [ "$#" -gt 1 ]; then
    echo "Usage: $0 [GUARD_APP]" >&2
    exit 2
fi

app=${1:-${GUARD_APP:-"/Applications/Sensitive File Guard.app"}}
if [ ! -d "$app" ] && [ -d "$repo_dir/build/macos/Sensitive File Guard.app" ]; then
    app="$repo_dir/build/macos/Sensitive File Guard.app"
fi
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
if ! printf '%s\n' "$status" | grep -Eq \
    '"enforcement_active"[[:space:]]*:[[:space:]]*true' \
    || ! printf '%s\n' "$status" | grep -Eq \
    '"target_path_inversion_active"[[:space:]]*:[[:space:]]*true'; then
    echo "BLOCKED: Endpoint Security enforcement or target-path inversion is unavailable" >&2
    printf '%s\n' "$status" >&2
    exit 77
fi

MACOSX_DEPLOYMENT_TARGET=13.0 cargo build --manifest-path "$repo_dir/Cargo.toml" \
    -p guard-test-probe >/dev/null
probe="$repo_dir/target/debug/guard-test-probe"
fixture_root=$(mktemp -d "${TMPDIR:-/tmp}/guard-phase08-live.XXXXXX")
fixture_root=$(CDPATH= cd -- "$fixture_root" && pwd -P)
reader_pid=''
enrollment_removed=0
test_override_active=0
restore_test_override() {
    if [ "$test_override_active" -eq 1 ]; then
        if "$guardctl" acceptance block-suppression --disable-for-secs 0 >/dev/null 2>&1; then
            test_override_active=0
        else
            echo "WARNING: test prompt override could not be restored; it expires automatically within 3 minutes." >&2
        fi
    fi
}
cleanup() {
    if [ -n "$reader_pid" ]; then
        kill "$reader_pid" 2>/dev/null || true
        wait "$reader_pid" 2>/dev/null || true
    fi
    if [ "$enrollment_removed" -eq 1 ]; then
        rm -rf -- "$fixture_root"
    else
        echo "Fixture enrollment may still be active. Remove $key in Guard before deleting $fixture_root." >&2
    fi
    restore_test_override
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
Only this freshly generated, disposable key is in scope:

  $key

No real SSH key, browser data, or secret is read.

This test has exactly two phases:
  1. Block one reader: it must not receive key bytes.
  2. Allow a new reader: it and its child must finish under one short lease.

The test-only suppression override starts only after you press Return below.
It never grants access, is not saved to configuration, and expires within
3 minutes even if this terminal is interrupted.
INSTRUCTIONS

printf 'Press Return to enable the fixture-only override and begin: '
read -r _answer
"$guardctl" acceptance block-suppression --disable-for-secs 180 >/dev/null
test_override_active=1

cat <<INSTRUCTIONS

Phase 1 of 2 — Block
Choose Block in the Guard prompt that appears now. The terminal will wait for
that result; it does not advance on a timer.
INSTRUCTIONS
if "$probe" read "$key" >/dev/null 2>"$fixture_root/block.err"; then
    echo "FAIL: Block allowed the disposable key to be read" >&2
    exit 1
fi
echo "PASS: Phase 1 Block denied the disposable key before it was read"

cat <<INSTRUCTIONS

Phase 2 of 2 — Allow
Press Return only when you are ready. Then choose Allow in the new Guard prompt
and complete macOS authentication. The root reader and its child should finish
from that one approval; the child does not need another prompt.
INSTRUCTIONS
printf 'Press Return to start Phase 2: '
read -r _answer
"$probe" read-then-child-read "$key" >"$fixture_root/tree.json" &
reader_pid=$!
wait "$reader_pid"
reader_pid=''
grep -Eq '"descendant_read"[[:space:]]*:[[:space:]]*true' \
    "$fixture_root/tree.json"
echo "PASS: Phase 2 Allow approved the root and its child under one short lease"

events=$("$guardctl" --json events --limit 500)
require_audit_event() {
    case "$events" in
        *"$1"*) ;;
        *)
            echo "FAIL: expected SSH audit event is missing: $1" >&2
            exit 1
            ;;
    esac
}
require_audit_event 'ssh_key_access_confirmation_required'
require_audit_event 'ssh_key_access_blocked'
require_audit_event 'ssh_key_access_allowed'
if case "$events" in *'PRIVATE KEY'*) true ;; *) false ;; esac; then
    echo "FAIL: audit output contains private-key material" >&2
    exit 1
fi
echo "PASS: the required metadata-only SSH audit events are present"
restore_test_override
echo "PASS: normal post-Block prompt suppression has been restored"

cat <<INSTRUCTIONS
Cleanup (one item): in Guard's Protection screen, find this exact disposable
key under SSH private keys, click its trash button, then click Apply
configuration and complete macOS authentication. Once it is gone from the
list, return here. The script will then remove its temporary directory.
INSTRUCTIONS
printf 'Press Return after the disposable enrollment has been removed: '
read -r _answer
enrollment_removed=1
