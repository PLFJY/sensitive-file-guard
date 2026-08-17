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
app="$release_root/Sensitive File Guard.app"
installed_app="/Applications/Sensitive File Guard.app"
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

# Install the new production build over the old Sensitive File Guard.app. Stale leftovers
# from previous test runs may be root-owned and unremovable by a normal user;
# in that case install to a side-by-side path and activate from there.
test -f "$app/Contents/MacOS/Guard" || { echo "release app missing: $app" >&2; exit 2; }
rm -rf "/Applications/Sensitive File Guard.app.pre-mps11" "/Applications/Sensitive File Guard.app.new" || true
if ! rm -rf "$installed_app" 2>/dev/null; then
    echo "cannot remove $installed_app (root-owned leftover); installing alongside instead" >&2
    installed_app="/Applications/Sensitive File Guard.app.new"
    rm -rf "$installed_app"
fi
ditto "$app" "$installed_app"
echo "installed production Sensitive File Guard.app with new Process Shield build"

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

# --- Chrome disposable (normal sandbox FIRST; --no-sandbox only as a
# labeled diagnostic fallback if the automation sandbox is blocked) ---
chrome_profile="$work/chrome-profile"
mkdir -p "$chrome_profile"
chrome_flags="--user-data-dir=$chrome_profile --no-first-run --no-default-browser-check --disable-background-networking --disable-component-update --disable-sync"
sandbox_ok=1
"$chrome" $chrome_flags "data:text/html,<title>guard-mps11-chrome</title><script>document.title=document.title</script><h1>ok</h1>" >"$work/chrome1.log" 2>&1 &
chrome_pid=$!
sleep 12
if kill -0 "$chrome_pid" 2>/dev/null; then
    check 'chrome launches (first, normal sandbox)' true
else
    echo "CHROME_SANDBOX_BLOCKER: normal-sandbox launch failed; see $work/chrome1.log" >&2
    sandbox_ok=0
    "$chrome" $chrome_flags --no-sandbox "data:text/html,<title>guard-mps11-chrome-diagnostic</title><h1>ok</h1>" >"$work/chrome1-nosandbox.log" 2>&1 &
    chrome_pid=$!
    sleep 12
    check 'chrome launches (diagnostic --no-sandbox fallback only)' kill -0 "$chrome_pid" 2>/dev/null
fi
chrome_main_pid=$(pgrep -f 'user-data-dir=.*guard-mps11' | head -1 || true)
check 'chrome main process running' test -n "$chrome_main_pid"
# JS/JIT smoke: use the DevTools-less heuristic — the process must stay alive.
sleep 5
check 'chrome stays alive after JS/JIT load' kill -0 "$chrome_pid" 2>/dev/null
# Restart the disposable profile (same sandbox mode as the first launch).
pkill -f "user-data-dir=$chrome_profile" 2>/dev/null || true
sleep 4
if [ "$sandbox_ok" -eq 1 ]; then
    "$chrome" $chrome_flags "data:text/html,<h1>restart</h1>" >"$work/chrome2.log" 2>&1 &
else
    "$chrome" $chrome_flags --no-sandbox "data:text/html,<h1>restart</h1>" >"$work/chrome2.log" 2>&1 &
fi
chrome_pid=$!
sleep 12
check 'chrome relaunch works' kill -0 "$chrome_pid" 2>/dev/null
chrome_main_pid=$(pgrep -f 'user-data-dir=.*guard-mps11' | head -1 || true)
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
# --- MPS Hardening 2: protected disposable-profile integration ---
# Enroll the DISPOSABLE Chrome profile as a protected browser profile and
# verify the full allow/deny chain without touching any real browser data.
# The disposable profile root is the ONLY enrollment in scope for this test.
chrome_session="$chrome_profile/Default"
mkdir -p "$chrome_session/Network"
# Synthetic protected fixtures (never real browser data).
printf "%s\n" "MPS11_DISPOSABLE_COOKIE_FIXTURE_$$" >"$chrome_session/Network/Cookies"
printf "%s\n" "MPS11_DISPOSABLE_PREFERENCES_$$" >"$chrome_session/Preferences"

cat <<INSTRUCTIONS
A new disposable browser profile is ready at:

  $chrome_profile

In the Sensitive File Guard GUI, enroll EXACTLY this disposable profile as a
protected Chrome browser profile (custom profile enrollment). Do NOT select
or modify any real browser profile. Confirm status shows the disposable
profile protected and Process Shield Active/Reduced.
INSTRUCTIONS
printf "Press Return after the disposable profile is enrolled: "
read -r _answer

# Verify enrollment took effect: at least one enrolled browser exe.
status=$("$installed_app/Contents/MacOS/guardctl" --json status 2>/dev/null || true)
if printf "%s\n" "$status" | grep -Eq '"browser_exes"[[:space:]]*:[[:space:]]*[1-9]'; then
    check "disposable browser profile enrolled (browser_exes >= 1)" true
else
    echo "browser_exes not visible in status; enrollment may be incomplete" >&2
    check "disposable browser profile enrolled (browser_exes >= 1)" false
fi

# 1. The REAL signed browser reading its OWN protected disposable profile
#    must be ALLOWED (browser stays alive and can page-load with File Shield
#    protecting its profile).
"$chrome" $chrome_flags "data:text/html,<title>guard-mps11-protected</title><h1>protected</h1>" >"$work/chrome-protected.log" 2>&1 &
chrome_protected_pid=$!
sleep 12
check "chrome own protected disposable profile: page load with File Shield active" kill -0 "$chrome_protected_pid" 2>/dev/null
sleep 3
check "chrome stays alive after own-profile protected page load" kill -0 "$chrome_protected_pid" 2>/dev/null
chrome_main_pid=$(pgrep -f 'user-data-dir=.*guard-mps11' | head -1 || true)

# 2. Untrusted same-user probe -> protected disposable Cookies -> DENY.
MACOSX_DEPLOYMENT_TARGET=13.0 cargo build --manifest-path "$repo_dir/Cargo.toml"     -p guard-test-probe >/dev/null 2>&1 || true
probe="$repo_dir/target/debug/guard-test-probe"
if [ -x "$probe" ]; then
    set +e
    "$probe" read "$chrome_session/Network/Cookies" >"$work/probe-cookies.out" 2>"$work/probe-cookies.err"
    probe_cookie_exit=$?
    set -e
    if [ "$probe_cookie_exit" -ne 0 ]; then
        check "untrusted probe DENIED protected disposable Cookies" true
    else
        echo "probe read cookies exit=$probe_cookie_exit (expected non-zero = denied)" >&2
        check "untrusted probe DENIED protected disposable Cookies" false
    fi
    set +e
    "$probe" read "$chrome_session/Preferences" >"$work/probe-prefs.out" 2>"$work/probe-prefs.err"
    probe_prefs_exit=$?
    set -e
    if [ "$probe_prefs_exit" -ne 0 ]; then
        check "untrusted probe DENIED protected disposable Preferences" true
    else
        echo "probe read preferences exit=$probe_prefs_exit (expected non-zero = denied)" >&2
        check "untrusted probe DENIED protected disposable Preferences" false
    fi
else
    echo "BLOCKED: guard-test-probe unavailable; protected-file deny checks skipped" >&2
fi

# 3. Untrusted same-user probe -> real browser task control -> DENY.
if [ -x "$probe" ] && [ -n "$chrome_main_pid" ]; then
    set +e
    "$probe" probe-task "$chrome_main_pid" control
    probe_task_exit=$?
    set -e
    if [ "$probe_task_exit" -eq 4 ]; then
        check "untrusted probe DENIED real browser task control" true
    else
        echo "probe_task exit=$probe_task_exit (expected 4 = denied)" >&2
        check "untrusted probe DENIED real browser task control" false
    fi
else
    echo "BLOCKED: probe or chrome main unavailable; task-deny recheck skipped" >&2
fi

pkill -f "user-data-dir=.*guard-mps11" 2>/dev/null || true
sleep 3

# --- Audit (real assertion): the untrusted probe denials above must have
# produced protected-resource deny rows, and a task-deny row must be present
# from the real-browser task probe. These are real conditions, not stubs.
sleep 2
guardctl="$installed_app/Contents/MacOS/guardctl"
events=$("$guardctl" --json events --limit 1000 2>/dev/null || true)
if printf "%s\n" "$events" | grep -qE '"event_code"[[:space:]]*:[[:space:]]*"(browser_access_denied|browser_protected_resource|system_process_access_suppressed)"'; then
    check "audit row for protected-resource probe deny present" true
else
    echo "no protected-resource deny row found in events:" >&2
    printf "%s\n" "$events" | grep -E '"event_code"' | head -8 >&2 || true
    check "audit row for protected-resource probe deny present" false
fi
if printf "%s\n" "$events" | grep -qE '"event_code"[[:space:]]*:[[:space:]]*"process_shield_task_(control|read)_denied"'; then
    check "audit row for real-browser task-port deny present" true
else
    echo "no process_shield task-deny row found in events:" >&2
    printf "%s\n" "$events" | grep -E '"event_code"' | head -8 >&2 || true
    check "audit row for real-browser task-port deny present" false
fi
if printf "%s\n" "$events" | grep -qE 'MPS11_DISPOSABLE_(COOKIE|PREFERENCES)_FIXTURE'; then
    check "audit contains NO protected disposable fixture contents" false
else
    check "audit contains NO protected disposable fixture contents" true
fi

echo "=== MPS11 SUMMARY pass=$pass fail=$fail ==="
echo "browser logs: $work"
if [ "$fail" -eq 0 ] && [ "$pass" -ge 12 ]; then
    echo "DISPOSABLE BROWSER + PROTECTED-PROFILE INTEGRATION PASS"
else
    echo "MPS11 FAIL — inspect logs, task-deny rows and protected-profile deny rows"
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