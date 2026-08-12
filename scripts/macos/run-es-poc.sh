#!/bin/sh
set -eu

if [ "$(uname -s)" != "Darwin" ]; then
    echo "run-es-poc.sh requires macOS" >&2
    exit 2
fi

self_use=${SELF_USE_SIP_OFF:-0}
case "$self_use" in 0|1) ;; *) echo "SELF_USE_SIP_OFF must be 0 or 1" >&2; exit 2 ;; esac
if [ "$self_use" = 1 ]; then
    : "${SELF_USE_SIGNING_IDENTITY:?SELF_USE_SIGNING_IDENTITY is required for SELF_USE_SIP_OFF=1}"
else
    : "${APP_BUNDLE_ID:?approved APP_BUNDLE_ID is required}"
    : "${SYSTEM_EXTENSION_BUNDLE_ID:?approved SYSTEM_EXTENSION_BUNDLE_ID is required}"
    : "${DEVELOPMENT_TEAM:?DEVELOPMENT_TEAM is required}"
    : "${SIGNING_IDENTITY:?SIGNING_IDENTITY is required}"
    : "${HOST_PROVISIONING_PROFILE:?HOST_PROVISIONING_PROFILE is required}"
    : "${EXTENSION_PROVISIONING_PROFILE:?EXTENSION_PROVISIONING_PROFILE is required}"
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH= cd -- "$script_dir/../.." && pwd)
fixture_dir=$(mktemp -d "${TMPDIR:-/tmp}/guard-es-poc.XXXXXX")
fixture="$fixture_dir/protected-synthetic.txt"
deny_output="$fixture_dir/deny-output.txt"
canary="SDF_CANARY_MAC_ES_PHASE03"
activated=0
app_root=${MACOS_ES_POC_ROOT:-"$repo_dir/build/macos-es-poc"}
app="$app_root/Guard.app"

cleanup() {
    if [ "$activated" -eq 1 ]; then
        echo "PoC cleanup: requesting explicit system-extension deactivation" >&2
        "$app/Contents/MacOS/Guard" \
            --deactivate-system-extension || true
    fi
    rm -rf -- "$fixture_dir"
}
trap cleanup EXIT HUP INT TERM

printf '%s\n' "$canary" >"$fixture"
cd "$repo_dir"
cargo build -p guard-test-probe
probe=$(cd target/debug && pwd)/guard-test-probe

if [ "$self_use" = 1 ]; then
    GUARD_ES_POC=1 GUARD_ES_POC_FILE="$fixture" GUARD_ES_POC_ALLOW_EXE="$probe" \
        SELF_USE_SIP_OFF=1 SELF_USE_SIGNING_IDENTITY="$SELF_USE_SIGNING_IDENTITY" \
        MACOS_RELEASE_ROOT="$app_root" CODESIGN_TIMESTAMP=none \
        scripts/macos/build-release-app.sh
    scripts/macos/self-use-preflight.sh "$app"
else
    GUARD_ES_POC=1 \
GUARD_ES_POC_FILE="$fixture" \
GUARD_ES_POC_ALLOW_EXE="$probe" \
scripts/macos/build-dev-app.sh
    app="$repo_dir/build/macos/Guard.app"
    scripts/macos/inspect-signing.sh "$app"
fi

host="$app/Contents/MacOS/Guard"
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
