#!/bin/sh
set -eu

chrome='/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
firefox='/Applications/Firefox.app/Contents/MacOS/firefox'
for browser_executable in "$chrome" "$firefox"; do
    if [ ! -x "$browser_executable" ]; then
        echo "BLOCKED: required browser is not installed: $browser_executable" >&2
        exit 77
    fi
done

test_root=$(mktemp -d "${TMPDIR:-/tmp}/guard-phase07-browsers.XXXXXX")
chrome_pid=''
cleanup() {
    if [ -n "$chrome_pid" ]; then
        kill "$chrome_pid" 2>/dev/null || true
        wait "$chrome_pid" 2>/dev/null || true
    fi
    rm -rf "$test_root"
}
trap cleanup EXIT INT TERM

chrome_profile="$test_root/chrome"
firefox_profile="$test_root/firefox"
mkdir -p "$chrome_profile" "$firefox_profile"

"$chrome" \
    --headless \
    --disable-gpu \
    --disable-background-networking \
    --no-first-run \
    --no-default-browser-check \
    --user-data-dir="$chrome_profile" \
    --dump-dom 'data:text/html,<title>guard-phase07</title><p>synthetic</p>' \
    >"$test_root/chrome-dom.txt" 2>"$test_root/chrome.err" &
chrome_pid=$!
attempt=0
while [ "$attempt" -lt 100 ]; do
    if grep -q 'guard-phase07' "$test_root/chrome-dom.txt" 2>/dev/null; then
        break
    fi
    if ! kill -0 "$chrome_pid" 2>/dev/null; then
        wait "$chrome_pid"
        chrome_pid=''
        echo 'FAIL: Chrome exited before rendering the synthetic local page' >&2
        exit 1
    fi
    attempt=$((attempt + 1))
    sleep 0.1
done
grep -q 'guard-phase07' "$test_root/chrome-dom.txt"
kill "$chrome_pid" 2>/dev/null || true
wait "$chrome_pid" 2>/dev/null || true
chrome_pid=''
test -f "$chrome_profile/Local State"
test -f "$chrome_profile/Default/Login Data"
test -d "$chrome_profile/Default/Session Storage"
echo 'PASS: Chrome used only its disposable profile and wrote credential resources plus website storage'

"$firefox" \
    --headless \
    --no-remote \
    --offline \
    --profile "$firefox_profile" \
    --screenshot "$test_root/firefox.png" \
    'data:text/html,<title>guard-phase07</title><p>synthetic</p>' \
    >"$test_root/firefox.out" 2>"$test_root/firefox.err"
test -s "$test_root/firefox.png"
test -f "$firefox_profile/cookies.sqlite"
test -f "$firefox_profile/key4.db"
test -d "$firefox_profile/storage"
echo 'PASS: Firefox used only its disposable profile and wrote credential resources plus website storage'

chrome_identity=$(codesign -dv --verbose=4 "$chrome" 2>&1)
firefox_identity=$(codesign -dv --verbose=4 "$firefox" 2>&1)
printf '%s\n' "$chrome_identity" | grep -q 'Identifier=com.google.Chrome'
printf '%s\n' "$chrome_identity" | grep -q 'TeamIdentifier=EQHXZ8M8AV'
printf '%s\n' "$firefox_identity" | grep -q 'Identifier=org.mozilla.firefox'
printf '%s\n' "$firefox_identity" | grep -q 'TeamIdentifier=43AQ936H96'
echo 'PASS: installed Chrome and Firefox exact signing identities match enrollment definitions'
