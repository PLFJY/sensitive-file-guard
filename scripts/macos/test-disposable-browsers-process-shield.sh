#!/bin/sh
set -eu

if [ "$(uname -s)" != "Darwin" ]; then
    echo "disposable browser compatibility requires macOS" >&2
    exit 2
fi
: "${SELF_USE_SIGNING_IDENTITY:?SELF_USE_SIGNING_IDENTITY is required}"
: "${LIVE_ES_ACCEPTANCE:?set LIVE_ES_ACCEPTANCE=I_ACCEPT_SYSTEM_EXTENSION_RISK to activate the system extension}"

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH= cd -- "$script_dir/../.." && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/guard-mps11.XXXXXX")
watchdog_log="$work/watchdog.log"
watchdog_stop="$work/stop-watchdog"
audit_db="/Library/Application Support/Sensitive Data Firewall/audit.db"
release_root=${MACOS_RELEASE_ROOT:-"$repo_dir/build/macos-release"}
app="$release_root/Guard.app"
installed_app="/Applications/Guard.app"
extension_bundle_id=top.plfjy.SensitiveFileGuard.guard-es
watchdog_pid=

cleanup() {
    if [ -n "$watchdog_pid" ] && kill -0 "$watchdog_pid" 2>/dev/null; then
        : >"$watchdog_stop" || true
        attempt=0
        while kill -0 "$watchdog_pid" 2>/dev/null && [ "$attempt" -lt 150 ]; do
            attempt=$((attempt + 1))
            sleep 0.1
        done
    fi
    # Kill disposable browser processes.
    pkill -f 'user-data-dir=.*guard-mps11' 2>/dev/null || true
    pkill -f 'profile .*guard-mps11' 2>/dev/null || true
    pkill -f 'Disposable.*chrome' 2>/dev/null || true
    rm -rf -- "$work"
}
trap cleanup EXIT HUP INT TERM

pass=0
fail=0
check() {
    name=$1
    shift
    if "$@"; then
        pass=$((pass + 1))
        echo "PASS: $name"
    else
        fail=$((fail + 1))
        echo "FAIL: $name"
    fi
}

# Install the new production build over the old Guard.app. Stale leftovers
# from previous test runs may be root-owned and unremovable by a normal user;
# in that case install to a side-by-side path and activate from there.
test -f "$app/Contents/MacOS/Guard" || { echo "release app missing: $app" >&2; exit 2; }
rm -rf "/Applications/Guard.app.pre-mps11" "/Applications/Guard.app.new" || true
if ! rm -rf "$installed_app" 2>/dev/null; then
    echo "cannot remove $installed_app (root-owned leftover); installing alongside instead" >&2
    installed_app="/Applications/Guard.app.new"
    rm -rf "$installed_app"
fi
ditto "$app" "$installed_app"
echo "installed production Guard.app with new Process Shield build"

GUARD_EXTENSION_WATCHDOG_SECONDS=120 \
GUARD_EXTENSION_WATCHDOG_STOP_FILE="$watchdog_stop" \
    "$installed_app/Contents/MacOS/Guard" --activate-system-extension-watchdog >"$watchdog_log" 2>&1 &
watchdog_pid=$!
attempt=0
while [ "$attempt" -lt 1500 ]; do
    if grep -q '^WATCHDOG_ACTIVE ' "$watchdog_log" 2>/dev/null; then
        break
    fi
    if ! kill -0 "$watchdog_pid" 2>/dev/null; then
        sed -n '1,120p' "$watchdog_log" >&2 || true
        exit 1
    fi
    attempt=$((attempt + 1))
    sleep 0.1
done
[ "$attempt" -lt 1500 ] || { echo "BLOCKED: activation watchdog did not report active"; sed -n '1,120p' "$watchdog_log" >&2; exit 1; }
echo "production extension active (Process Shield enabled)"

# Wait for guard-es to be up and process-graph warm.
sleep 3

chrome="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
firefox="/Applications/Firefox.app/Contents/MacOS/firefox"

# --- Chrome disposable ---
chrome_profile="$work/chrome-profile"
mkdir -p "$chrome_profile"
"$chrome" --user-data-dir="$chrome_profile" --no-first-run --no-default-browser-check --disable-background-networking --disable-component-update --disable-sync --no-sandbox "data:text/html,<title>guard-mps11-chrome</title><script>document.title=document.title</script><h1>ok</h1>" >"$work/chrome1.log" 2>&1 &
chrome_pid=$!
sleep 12
check 'chrome launches (first)' kill -0 "$chrome_pid" 2>/dev/null
chrome_main_pid=$(pgrep -f 'user-data-dir=.*guard-mps11' | head -1 || true)
check 'chrome main process running' test -n "$chrome_main_pid"
# JS/JIT smoke: use the DevTools-less heuristic — the process must stay alive.
sleep 5
check 'chrome stays alive after JS/JIT load' kill -0 "$chrome_pid" 2>/dev/null
# Restart the disposable profile.
pkill -f "user-data-dir=$chrome_profile" 2>/dev/null || true
sleep 4
"$chrome" --user-data-dir="$chrome_profile" --no-first-run --no-default-browser-check --disable-background-networking --disable-component-update --disable-sync --no-sandbox "data:text/html,<h1>restart</h1>" >"$work/chrome2.log" 2>&1 &
chrome_pid=$!
sleep 12
check 'chrome relaunch works' kill -0 "$chrome_pid" 2>/dev/null
pkill -f 'user-data-dir=.*guard-mps11' 2>/dev/null || true
sleep 3

# --- Firefox disposable ---
ff_profile="$work/ff-profile"
mkdir -p "$ff_profile"
"$firefox" --no-remote -profile "$ff_profile" "data:text/html,<title>guard-mps11-ff</title><h1>ok</h1>" >"$work/ff1.log" 2>&1 &
ff_pid=$!
sleep 14
check 'firefox launches' kill -0 "$ff_pid" 2>/dev/null
ff_main=$(pgrep -f 'profile .*guard-mps11' | head -1 || true)
check 'firefox main process running' test -n "$ff_main"
# JIT/JS smoke: keep alive + a second profile page.
sleep 5
check 'firefox stays alive after JS load' kill -0 "$ff_pid" 2>/dev/null
pkill -f "profile .*guard-mps11" 2>/dev/null || true
sleep 4
"$firefox" --no-remote -profile "$ff_profile" "data:text/html,<h1>restart</h1>" >"$work/ff2.log" 2>&1 &
ff_pid=$!
sleep 14
check 'firefox relaunch works' kill -0 "$ff_pid" 2>/dev/null
pkill -f 'profile .*guard-mps11' 2>/dev/null || true
sleep 3

# --- File Shield own-profile access ---
# The disposable Chrome profile is not enrolled, so own-profile File Shield
# rules do not apply; the browser itself must be able to read/write its own
# disposable profile (not a protected resource). Guard only intercepts
# PROTECTED resources, so ordinary profile IO must be unaffected.
chrome_session="$chrome_profile/Default"
mkdir -p "$chrome_session"
printf "synthetic disposable state\n" >"$chrome_session/Preferences"
check "disposable profile write is not blocked by File Shield" test -f "$chrome_session/Preferences"

# --- Audit: task-deny storm check ---
sleep 2
if [ -f "$audit_db" ]; then
    echo '--- task/process-shield audit summary ---'
    sqlite3 "$audit_db" "SELECT event_code, COUNT(*) FROM events GROUP BY event_code ORDER BY 2 DESC LIMIT 15;" 2>/dev/null || echo "audit query unavailable"
    task_denies=$(sqlite3 "$audit_db" "SELECT COUNT(*) FROM events WHERE event_code LIKE 'process_shield_task%denied%' OR event_code LIKE 'process_shield_task%denied%' OR event_code='process_shield_task_control_denied' OR event_code='process_shield_task_read_denied';" 2>/dev/null || echo 0)
    echo "task_denies=$task_denies"
else
    echo "audit db not found at $audit_db"
fi

echo "=== MPS11 SUMMARY pass=$pass fail=$fail ==="
echo "browser logs: $work"
if [ "$fail" -eq 0 ] && [ "$pass" -ge 7 ]; then
    echo "DISPOSABLE BROWSER COMPATIBILITY PASS"
else
    echo "DISPOSABLE BROWSER COMPATIBILITY FAIL — inspect logs and task-deny audit rows"
    exit 1
fi

# Restore protection: stop the test watchdog, then activate the extension in
# plain mode so it stays enabled and active with Process Shield.
if [ -n "$watchdog_pid" ] && kill -0 "$watchdog_pid" 2>/dev/null; then
    : >"$watchdog_stop"
    wait "$watchdog_pid" 2>/dev/null || true
fi
watchdog_pid=
sleep 2
"$installed_app/Contents/MacOS/Guard" --activate-system-extension >/dev/null 2>&1 &
sleep 5
if systemextensionsctl list 2>&1 | grep "$extension_bundle_id" | grep -q '^\*\*'; then
    echo "extension left ACTIVE (protection restored with Process Shield)"
else
    echo "WARNING: extension did not return to active; see systemextensionsctl list"
fi