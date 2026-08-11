#!/bin/sh
set -eu

if [ "$(uname -s)" != "Darwin" ]; then
    echo "run-es-poc.sh requires macOS" >&2
    exit 2
fi

: "${APP_BUNDLE_ID:?approved APP_BUNDLE_ID is required}"
: "${SYSTEM_EXTENSION_BUNDLE_ID:?approved SYSTEM_EXTENSION_BUNDLE_ID is required}"
: "${DEVELOPMENT_TEAM:?DEVELOPMENT_TEAM is required}"
: "${SIGNING_IDENTITY:?SIGNING_IDENTITY is required}"
: "${HOST_PROVISIONING_PROFILE:?HOST_PROVISIONING_PROFILE is required}"
: "${EXTENSION_PROVISIONING_PROFILE:?EXTENSION_PROVISIONING_PROFILE is required}"

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH= cd -- "$script_dir/../.." && pwd)
fixture_dir=$(mktemp -d "${TMPDIR:-/tmp}/guard-es-poc.XXXXXX")
fixture="$fixture_dir/protected-synthetic.txt"
deny_output="$fixture_dir/deny-output.txt"
canary="SDF_CANARY_MAC_ES_PHASE03"
activated=0

cleanup() {
    if [ "$activated" -eq 1 ]; then
        echo "PoC cleanup: requesting explicit system-extension deactivation" >&2
        "$repo_dir/build/macos/Guard.app/Contents/MacOS/Guard" \
            --deactivate-system-extension || true
    fi
    rm -rf -- "$fixture_dir"
}
trap cleanup EXIT HUP INT TERM

printf '%s\n' "$canary" >"$fixture"
cd "$repo_dir"
cargo build -p guard-test-probe
probe=$(cd target/debug && pwd)/guard-test-probe

GUARD_ES_POC=1 \
GUARD_ES_POC_FILE="$fixture" \
GUARD_ES_POC_ALLOW_EXE="$probe" \
scripts/macos/build-dev-app.sh
scripts/macos/inspect-signing.sh

host="$repo_dir/build/macos/Guard.app/Contents/MacOS/Guard"
"$host" --activate-system-extension
activated=1

attempt=0
while [ "$attempt" -lt 120 ]; do
    lifecycle=$("$host" --system-extension-status 2>&1) || {
        echo "$lifecycle" >&2
        exit 1
    }
    echo "$lifecycle"
    case "$lifecycle" in
        *state=Active*) break ;;
        *state=Failed*) exit 1 ;;
    esac
    attempt=$((attempt + 1))
    sleep 1
done
if [ "$attempt" -eq 120 ]; then
    echo "BLOCKED: system extension did not become active within 120 seconds" >&2
    exit 1
fi

if /usr/bin/cat "$fixture" >"$deny_output" 2>&1; then
    echo "FAIL: non-enrolled /usr/bin/cat read the protected synthetic fixture" >&2
    exit 1
fi
if /usr/bin/grep -F "$canary" "$deny_output" >/dev/null 2>&1; then
    echo "FAIL: deny probe returned protected bytes before failing" >&2
    exit 1
fi
echo "PASS: deny probe received no protected bytes"

allow_output=$($probe read "$fixture")
if [ "$allow_output" != "$canary" ]; then
    echo "FAIL: enrolled synthetic probe did not receive the expected canary" >&2
    exit 1
fi
echo "PASS: explicitly enrolled synthetic probe read the fixture"
