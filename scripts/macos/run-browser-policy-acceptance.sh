#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
app=${GUARD_APP:-$repo_dir/build/macos/Guard.app}
guardctl="$app/Contents/MacOS/guardctl"
chrome='/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
firefox='/Applications/Firefox.app/Contents/MacOS/firefox'

for required in "$guardctl" "$chrome" "$firefox"; do
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
printf '%s\n' "$status" | grep -q '"read_only_guaranteed":true'

test_root=$(mktemp -d "${TMPDIR:-/tmp}/guard-phase07-live.XXXXXX")
chrome_pid=''
cleanup() {
    if [ -n "$chrome_pid" ]; then
        kill "$chrome_pid" 2>/dev/null || true
        wait "$chrome_pid" 2>/dev/null || true
    fi
    rm -rf "$test_root"
}
trap cleanup EXIT INT TERM

test_home="$test_root/home"
chrome_profile="$test_home/Library/Application Support/Google/Chrome"
firefox_profile="$test_home/Library/Application Support/Firefox/Profiles/phase07.default"
mkdir -p "$chrome_profile" "$firefox_profile"

"$chrome" --headless --disable-gpu --disable-background-networking \
    --no-first-run --no-default-browser-check \
    --user-data-dir="$chrome_profile" \
    --dump-dom 'data:text/html,<title>guard-phase07-live</title>' \
    >"$test_root/chrome-dom.txt" 2>"$test_root/chrome.err" &
chrome_pid=$!
attempt=0
while [ "$attempt" -lt 100 ]; do
    grep -q 'guard-phase07-live' "$test_root/chrome-dom.txt" 2>/dev/null && break
    kill -0 "$chrome_pid" 2>/dev/null || break
    attempt=$((attempt + 1))
    sleep 0.1
done
grep -q 'guard-phase07-live' "$test_root/chrome-dom.txt"
kill "$chrome_pid" 2>/dev/null || true
wait "$chrome_pid" 2>/dev/null || true
chrome_pid=''

HOME="$test_home" "$firefox" --headless --no-remote --offline \
    --profile "$firefox_profile" \
    --screenshot "$test_root/firefox.png" \
    'data:text/html,<title>guard-phase07-live</title>' \
    >"$test_root/firefox.out" 2>"$test_root/firefox.err"

cat <<INSTRUCTIONS
Disposable profiles are ready. They are the only browser data allowed in this test:

  Chrome profile root:  $chrome_profile
  Chrome executable:    $chrome
  Firefox profile root: $firefox_profile
  Firefox executable:   $firefox

In Guard, enroll exactly these two custom profiles, enable Protection policy,
and confirm that status becomes ACTIVE. Do not select a normal user profile.
INSTRUCTIONS
printf 'Press Return after the disposable policy is active: '
read -r _answer

status=$($guardctl --json status)
printf '%s\n' "$status" | grep -q '"enforcement_active":true'
printf '%s\n' "$status" | grep -q '"read_only_guaranteed":true'

MACOSX_DEPLOYMENT_TARGET=13.0 cargo build --manifest-path "$repo_dir/Cargo.toml" \
    -p guard-test-probe >/dev/null
probe="$repo_dir/target/debug/guard-test-probe"
if "$probe" read "$chrome_profile/Default/Login Data" \
    >"$test_root/probe-chrome.out" 2>"$test_root/probe-chrome.err"; then
    echo 'FAIL: unknown probe opened disposable Chrome protected data' >&2
    exit 1
fi
if "$probe" read "$firefox_profile/key4.db" \
    >"$test_root/probe-firefox.out" 2>"$test_root/probe-firefox.err"; then
    echo 'FAIL: unknown probe opened disposable Firefox protected data' >&2
    exit 1
fi
echo 'PASS: unknown same-user probe was denied for both disposable profiles'

cat <<INSTRUCTIONS
The next command opens Firefox's migration wizard against the disposable HOME.
Select the disposable Chrome profile. First choose Block in Guard and close the
wizard. The command will then run a second time; select the same source and
choose Allow after LocalAuthentication. No normal profile is in this HOME.
INSTRUCTIONS
HOME="$test_home" "$firefox" --no-remote --offline --profile "$firefox_profile" --migration
printf 'Press Return after the Block result is visible: '
read -r _answer
HOME="$test_home" "$firefox" --no-remote --offline --profile "$firefox_profile" --migration
printf 'Press Return after the Allow result and import completion are visible: '
read -r _answer

events=$($guardctl --json events --limit 500)
printf '%s\n' "$events" | grep -q 'browser_migration_confirmation_required'
printf '%s\n' "$events" | grep -q 'browser_migration_blocked'
printf '%s\n' "$events" | grep -q 'browser_migration_allowed'
printf '%s\n' "$events" | grep -q 'read_only_guaranteed=true'
echo 'PASS: real disposable migration produced required, blocked, and FREAD-only allowed audit events'

cat <<INSTRUCTIONS
Remove or disable the two disposable enrollments in Guard before continuing.
The script will then delete only its mktemp directory.
INSTRUCTIONS
printf 'Press Return after disposable enrollment cleanup: '
read -r _answer
