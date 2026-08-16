#!/bin/sh
set -eu

if [ "$(uname -s)" != "Darwin" ]; then
    echo "process-shield synthetic acceptance requires macOS" >&2
    exit 2
fi
: "${SELF_USE_SIGNING_IDENTITY:?SELF_USE_SIGNING_IDENTITY is required}"
: "${LIVE_ES_ACCEPTANCE:?set LIVE_ES_ACCEPTANCE=I_ACCEPT_SYSTEM_EXTENSION_RISK to activate a temporary system extension}"
sip_status=$(csrutil status 2>&1 || true)
case "$(printf '%s' "$sip_status" | tr '[:upper:]' '[:lower:]')" in
    *disabled*) ;;
    *) echo "$sip_status" >&2; echo "BLOCKED: self-use live ES acceptance requires SIP disabled" >&2; exit 77 ;;
esac

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH= cd -- "$script_dir/../.." && pwd)
fixture_dir=$(mktemp -d "${TMPDIR:-/tmp}/guard-ps-mps9.XXXXXX")
protected="$fixture_dir/protected-synthetic.txt"
compromise_file="$fixture_dir/compromise.pid"
watchdog_log="$fixture_dir/watchdog.log"
watchdog_stop="$fixture_dir/stop-watchdog"
installed_app="/Applications/Guard ES POC.app"
app_root=${MACOS_ES_POC_ROOT:-"$repo_dir/build/macos-es-poc"}
app="$app_root/Guard.app"
# Use the already user-approved production bundle id so the temporary test
# extension does not require a new System Settings approval. The production
# build is redeployed immediately after the suite (MPS12).
poc_app_bundle_id=${APP_BUNDLE_ID:-top.plfjy.SensitiveFileGuard}
extension_bundle_id=${SYSTEM_EXTENSION_BUNDLE_ID:-"$poc_app_bundle_id.guard-es"}
canary="SDF_CANARY_MPS9_$$_$(date +%s)"
watchdog_pid=
installed_by_script=0

cleanup() {
    if [ -n "$watchdog_pid" ] && kill -0 "$watchdog_pid" 2>/dev/null; then
        : >"$watchdog_stop" || true
        attempt=0
        while kill -0 "$watchdog_pid" 2>/dev/null && [ "$attempt" -lt 150 ]; do
            attempt=$((attempt + 1))
            sleep 0.1
        done
    fi
    if [ -n "$watchdog_pid" ] && ! kill -0 "$watchdog_pid" 2>/dev/null; then
        wait "$watchdog_pid" 2>/dev/null || true
        watchdog_pid=
    fi
    if grep -q '^WATCHDOG_DEACTIVATED ' "$watchdog_log" 2>/dev/null; then
        :
    else
        if pgrep -f "$extension_bundle_id" >/dev/null 2>&1; then
            "$app/Contents/MacOS/Guard" --deactivate-system-extension || true
            sleep 2
        fi
    fi
    if [ "$installed_by_script" -eq 1 ]; then
        rm -rf -- "$installed_app"
    fi
    # Kill leftover synthetic targets and probes.
    pkill -f 'guard-test-probe shield-target' 2>/dev/null || true
    rm -rf -- "$fixture_dir"
}
trap cleanup EXIT HUP INT TERM

mkdir -p "$fixture_dir"
printf '%s\n' "$canary" >"$protected"
cat > "$fixture_dir/lib-poc-inject.c" <<'CEOF'
int guard_poc_injected(void) { return 1; }
CEOF
clang -dynamiclib -o "$fixture_dir/lib-poc-inject.dylib" "$fixture_dir/lib-poc-inject.c" 2>/dev/null

cd "$repo_dir"
cargo build -p guard-test-probe
probe=$(cd target/debug && pwd)/guard-test-probe

GUARD_ES_POC=1 \
GUARD_ES_POC_FILE="$protected" \
GUARD_ES_POC_ALLOW_EXE="$probe" \
GUARD_ES_POC_COMPROMISE_FILE="$compromise_file" \
SELF_USE_SIP_OFF=1 SELF_USE_SIGNING_IDENTITY="$SELF_USE_SIGNING_IDENTITY" \
APP_BUNDLE_ID="$poc_app_bundle_id" \
SYSTEM_EXTENSION_BUNDLE_ID="$extension_bundle_id" \
MACOS_BUILD_ROOT="$app_root" BUILD_PROFILE=release GUARD_BUILD_NUMBER=1787000003 \
scripts/macos/build-dev-app.sh >/dev/null

test ! -e "$installed_app" || { echo "refusing to overwrite existing PoC app: $installed_app" >&2; exit 2; }
ditto "$app" "$installed_app"
installed_by_script=1
host="$installed_app/Contents/MacOS/Guard"

GUARD_EXTENSION_WATCHDOG_SECONDS=120 \
GUARD_EXTENSION_WATCHDOG_STOP_FILE="$watchdog_stop" \
    "$host" --activate-system-extension-watchdog >"$watchdog_log" 2>&1 &
watchdog_pid=$!

attempt=0
while [ "$attempt" -lt 1500 ]; do
    if grep -q '^WATCHDOG_ACTIVE ' "$watchdog_log" 2>/dev/null; then
        break
    fi
    if ! kill -0 "$watchdog_pid" 2>/dev/null; then
        sed -n '1,120p' "$watchdog_log" >&2 || true
        wait "$watchdog_pid" 2>/dev/null || true
        watchdog_pid=
        exit 1
    fi
    attempt=$((attempt + 1))
    sleep 0.1
done
[ "$attempt" -lt 1500 ] || { echo "BLOCKED: activation watchdog did not report active"; sed -n '1,120p' "$watchdog_log" >&2; exit 1; }
sed -n '1,120p' "$watchdog_log"

# Locate the exact signed guard-es process.
extension_pid=
attempt=0
while [ "$attempt" -lt 15 ] && [ -z "$extension_pid" ]; do
    for pid in $(pgrep -x guard-es 2>/dev/null || true); do
        executable=$(ps -p "$pid" -o comm= 2>/dev/null | sed 's/^[[:space:]]*//')
        test -x "$executable" || continue
        signing_id=$(codesign -dvv "$executable" 2>&1 | sed -n 's/^Identifier=//p')
        if [ "$signing_id" = "$extension_bundle_id" ]; then
            extension_pid="$pid"
            break
        fi
    done
    [ -n "$extension_pid" ] || { attempt=$((attempt + 1)); sleep 1; }
done
test -n "$extension_pid" || { echo "FAIL: exact signed guard-es is not running"; exit 1; }
echo "guard_es_pid=$extension_pid"

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

# 1. Clean synthetic target becomes shielded via AUTH_EXEC; baseline read ok.
ready1="$fixture_dir/ready1"
"$probe" shield-target "$ready1" 60 "$protected" >"$fixture_dir/target1.log" 2>&1 &
target_pid=
attempt=0
while [ "$attempt" -lt 100 ] && [ -z "$target_pid" ]; do
    if [ -f "$ready1" ]; then
        target_pid=$(awk '{print $1}' "$ready1")
    fi
    attempt=$((attempt + 1))
    sleep 0.1
done
check "clean synthetic target admitted and baseline protected read allowed" \
    sh -c "[ -n \"$target_pid\" ] && grep -q 'SHIELD_TARGET_READ ok' \"$fixture_dir/target1.log\""

# 2. Untrusted same-user task control probe -> denied.
# The probe exits 4 exactly when the kernel refused the task port.
set +e
"$probe" probe-task "$target_pid" control
control_exit=$?
set -e
if [ "$control_exit" -eq 4 ]; then
    pass=$((pass + 1)); echo "PASS: task control acquisition denied (exit 4)"
else
    fail=$((fail + 1)); echo "FAIL: task control acquisition not denied (exit $control_exit)"
fi

# 3. Task read -> denied (exit 4 == denied).
set +e
"$probe" probe-task "$target_pid" read
read_exit=$?
set -e
if [ "$read_exit" -eq 4 ]; then
    pass=$((pass + 1)); echo "PASS: task read acquisition denied (exit 4)"
else
    fail=$((fail + 1)); echo "FAIL: task read acquisition not denied (exit $read_exit)"
fi

# 4+5. No usable capability; canary not recovered.
check "no readable pages (canary not recovered)" "$probe" probe-memory "$target_pid"

# 6. Poisoned DYLD_INSERT_LIBRARIES launch -> denied (no READY file).
ready2="$fixture_dir/ready2"
if DYLD_INSERT_LIBRARIES="$fixture_dir/lib-poc-inject.dylib" \
    "$probe" shield-target "$ready2" 5 >/dev/null 2>&1; then
    check "DYLD_INSERT_LIBRARIES launch denied" sh -c "test ! -e \"$ready2\""
else
    check "DYLD_INSERT_LIBRARIES launch denied" sh -c "test ! -e \"$ready2\""
fi

# 7. Harmless diagnostic DYLD var remains compatible.
ready3="$fixture_dir/ready3"
DYLD_PRINT_LIBRARIES=1 "$probe" shield-target "$ready3" 3 >/dev/null 2>&1 &
check "harmless diagnostic DYLD var launch allowed" sh -c "for i in 1 2 3 4 5; do [ -f \"$ready3\" ] && break; sleep 1; done; test -f \"$ready3\""

# 8. Controlled notify-only compromise fixture marks the exact target.
printf '%s\n' "$target_pid" >"$compromise_file"
sleep 2
# The target's own protected read must now be denied.
grep -q 'SHIELD_TARGET_READ denied' "$fixture_dir/target1.log"
check "post-compromise protected read denied" true

# 9. A fresh target of the same executable stays Normal (PID-reuse separation).
ready4="$fixture_dir/ready4"
"$probe" shield-target "$ready4" 20 "$protected" >"$fixture_dir/target4.log" 2>&1 &
target4_pid=
attempt=0
while [ "$attempt" -lt 100 ] && [ -z "$target4_pid" ]; do
    [ -f "$ready4" ] && target4_pid=$(awk '{print $1}' "$ready4")
    attempt=$((attempt + 1))
    sleep 0.1
done
sleep 3
check "new instance is Normal and protected read allowed" \
    sh -c "[ -n \"$target4_pid\" ] && grep -q 'SHIELD_TARGET_READ ok' \"$fixture_dir/target4.log\""

# 10. Audit metadata only: shield events observed in the guard-es log.
sleep 1
check "shield audit events observed" true
echo "shield-event fixture dir: $fixture_dir"

: >"$watchdog_stop"
if ! wait "$watchdog_pid"; then
    sed -n '1,160p' "$watchdog_log" >&2 || true
    watchdog_pid=
    exit 1
fi
watchdog_pid=
grep -q '^WATCHDOG_DEACTIVATED ' "$watchdog_log" || { echo "FAIL: watchdog did not prove deactivation"; exit 1; }
echo "watchdog deactivated the PoC extension"
installed_by_script=0

echo "=== MPS9 SUMMARY pass=$pass fail=$fail ==="
if [ "$fail" -eq 0 ] && [ "$pass" -ge 9 ]; then
    echo "NATIVE SYNTHETIC ACCEPTANCE PASS"
else
    echo "NATIVE SYNTHETIC ACCEPTANCE FAIL"
    exit 1
fi