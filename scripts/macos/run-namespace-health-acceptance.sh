#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
app=${GUARD_APP:-$repo_dir/build/macos/Sensitive File Guard.app}
guardctl="$app/Contents/MacOS/guardctl"
chrome='/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'

for required in "$guardctl" "$chrome"; do
    if [ ! -x "$required" ]; then
        echo "BLOCKED: required executable is unavailable: $required" >&2
        exit 77
    fi
done

status=$($guardctl --json status 2>&1) || {
    echo "BLOCKED: signed guardctl cannot reach the activated extension" >&2
    printf '%s\n' "$status" >&2
    exit 77
}
printf '%s\n' "$status" | grep -Eq \
    '"backend_state"[[:space:]]*:[[:space:]]*"(ACTIVE|DEGRADED)"'

test_root=$(mktemp -d "${TMPDIR:-/tmp}/guard-phase09-live.XXXXXX")
chrome_pid=''
cleanup() {
    if [ -n "$chrome_pid" ]; then
        kill "$chrome_pid" 2>/dev/null || true
        wait "$chrome_pid" 2>/dev/null || true
    fi
    rm -rf "$test_root"
}
trap cleanup EXIT INT TERM

profile="$test_root/Chrome"
run_chrome() {
    "$chrome" --headless --disable-gpu --disable-background-networking \
        --no-first-run --no-default-browser-check --user-data-dir="$profile" \
        --dump-dom 'data:text/html,<title>guard-phase09-live</title>' \
        >"$test_root/chrome-dom.txt" 2>"$test_root/chrome.err" &
    chrome_pid=$!
    attempt=0
    while [ "$attempt" -lt 100 ]; do
        grep -q 'guard-phase09-live' "$test_root/chrome-dom.txt" 2>/dev/null && break
        kill -0 "$chrome_pid" 2>/dev/null || break
        attempt=$((attempt + 1))
        sleep 0.1
    done
    grep -q 'guard-phase09-live' "$test_root/chrome-dom.txt"
    kill "$chrome_pid" 2>/dev/null || true
    wait "$chrome_pid" 2>/dev/null || true
    chrome_pid=''
}

run_chrome
cookies="$profile/Default/Network/Cookies"
if [ ! -f "$cookies" ]; then
    echo "BLOCKED: disposable Chrome did not create its synthetic Cookies database" >&2
    exit 77
fi
preexisting_alias="$test_root/preexisting-cookie-alias"
ln "$cookies" "$preexisting_alias"

cat <<INSTRUCTIONS
Enroll exactly this disposable Chrome profile in Guard and enable Protection:

  profile root: $profile
  executable:   $chrome

Do not select a normal user profile. Press Return after status is ACTIVE.
INSTRUCTIONS
read -r _answer

status=$($guardctl --json status)
printf '%s\n' "$status" | grep -Eq \
    '"enforcement_active"[[:space:]]*:[[:space:]]*true'
printf '%s\n' "$status" | grep -q '"mac_health"'

MACOSX_DEPLOYMENT_TARGET=13.0 cargo build --manifest-path "$repo_dir/Cargo.toml" \
    -p guard-test-probe >/dev/null
probe="$repo_dir/target/debug/guard-test-probe"

if "$probe" read "$preexisting_alias" >/dev/null 2>"$test_root/hardlink.err"; then
    echo "FAIL: pre-existing hardlink alias bypassed protection" >&2
    exit 1
fi

symlink_alias="$test_root/symlink-cookie-alias"
ln -s "$cookies" "$symlink_alias"
if "$probe" read "$symlink_alias" >/dev/null 2>"$test_root/symlink.err"; then
    echo "FAIL: symlink target identity bypassed protection" >&2
    exit 1
fi

if ln "$cookies" "$test_root/new-cookie-alias" 2>"$test_root/link.err"; then
    echo "FAIL: unknown process linked a protected file outside its namespace" >&2
    exit 1
fi
if mv "$cookies" "$test_root/renamed-out-cookie" 2>"$test_root/rename.err"; then
    echo "FAIL: unknown process renamed a protected file out of its namespace" >&2
    exit 1
fi
if mv "$profile/Default" "$test_root/renamed-profile" 2>"$test_root/parent-rename.err"; then
    echo "FAIL: unknown process renamed a protected parent directory" >&2
    exit 1
fi

# A real enrolled browser must retain normal atomic profile-update behavior.
run_chrome
status=$($guardctl --json status)
printf '%s\n' "$status" | grep -q '"namespace_denied"'
echo "PASS: hardlink, rename-out, parent rename, symlink, and browser regression checks completed"

cat <<INSTRUCTIONS
Remove or disable the disposable enrollment in Guard, then press Return. Only
the mktemp tree printed above will be deleted by this script.
INSTRUCTIONS
read -r _answer
