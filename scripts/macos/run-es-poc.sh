#!/bin/sh
set -eu

if [ "$(uname -s)" != "Darwin" ]; then
    echo "run-es-poc.sh requires macOS" >&2
    exit 2
fi

self_use=${SELF_USE_SIP_OFF:-0}
build_only=${ES_POC_BUILD_ONLY:-0}
cat_probe=${CAT_PROBE:-/bin/cat}
test -x "$cat_probe" || {
    echo "required deny probe executable is missing or not executable: $cat_probe" >&2
    exit 2
}
case "$self_use" in 0|1) ;; *) echo "SELF_USE_SIP_OFF must be 0 or 1" >&2; exit 2 ;; esac
case "$build_only" in 0|1) ;; *) echo "ES_POC_BUILD_ONLY must be 0 or 1" >&2; exit 2 ;; esac
if [ "$self_use" = 1 ]; then
    : "${SELF_USE_SIGNING_IDENTITY:?SELF_USE_SIGNING_IDENTITY is required for SELF_USE_SIP_OFF=1}"
    if [ "$build_only" = 0 ] && [ "${LIVE_ES_ACCEPTANCE:-}" != I_ACCEPT_SYSTEM_EXTENSION_RISK ]; then
        echo "refusing live Endpoint Security activation without LIVE_ES_ACCEPTANCE=I_ACCEPT_SYSTEM_EXTENSION_RISK" >&2
        exit 2
    fi
    if [ "$build_only" = 0 ]; then
        sip_status=$(csrutil status 2>&1 || true)
        case "$(printf '%s' "$sip_status" | tr '[:upper:]' '[:lower:]')" in
            *disabled*) ;;
            *)
                echo "$sip_status" >&2
                echo "BLOCKED: self-use live ES acceptance requires SIP disabled" >&2
                exit 77
                ;;
        esac
    fi
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
watchdog_pid=
installed_by_script=0
app_root=${MACOS_ES_POC_ROOT:-"$repo_dir/build/macos-es-poc"}
app="$app_root/Sensitive File Guard.app"
installed_app=${MACOS_ES_POC_INSTALLED_APP:-"/Applications/Sensitive File Guard PoC.app"}
poc_app_bundle_id=${APP_BUNDLE_ID:-top.plfjy.SensitiveFileGuard.poc}
extension_bundle_id=${SYSTEM_EXTENSION_BUNDLE_ID:-"$poc_app_bundle_id.guard-es"}
watchdog_log="$fixture_dir/watchdog.log"
watchdog_stop="$fixture_dir/stop-watchdog"

extension_is_active() {
    extension_state=$(systemextensionsctl list 2>&1) || return 0
    printf '%s\n' "$extension_state" | awk -v id="$extension_bundle_id" '
        index($0, id) > 0 && $1 == "*" && $2 == "*" { active = 1 }
        END { exit active ? 0 : 1 }
    '
}

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
        activated=0
    fi
    if [ "$activated" -eq 1 ]; then
        echo "PoC cleanup: watchdog did not prove deactivation; requesting explicit fallback deactivation" >&2
        "$app/Contents/MacOS/Guard" \
            --deactivate-system-extension || true
        attempt=0
        while extension_is_active && [ "$attempt" -lt 300 ]; do
            attempt=$((attempt + 1))
            sleep 0.1
        done
        if ! extension_is_active; then
            activated=0
        fi
    fi
    if [ "$activated" -eq 1 ]; then
        echo "RECOVERY REQUIRED: retaining $installed_app and diagnostics at $fixture_dir" >&2
        echo "Run: '$app/Contents/MacOS/Guard' --deactivate-system-extension" >&2
        return
    fi
    if [ -n "$watchdog_pid" ]; then
        kill "$watchdog_pid" 2>/dev/null || true
        wait "$watchdog_pid" 2>/dev/null || true
        watchdog_pid=
    fi
    if [ "$installed_by_script" -eq 1 ]; then
        rm -rf -- "$installed_app"
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
        SELF_USE_SIGNING_KEYCHAIN="${SELF_USE_SIGNING_KEYCHAIN:-}" \
        APP_BUNDLE_ID="$poc_app_bundle_id" \
        SYSTEM_EXTENSION_BUNDLE_ID="$extension_bundle_id" \
        MACOS_BUILD_ROOT="$app_root" BUILD_PROFILE=release GUARD_BUILD_NUMBER=2 \
        scripts/macos/build-dev-app.sh
    scripts/macos/inspect-signing.sh "$app"
    if [ "$build_only" = 1 ]; then
        echo "PASS: isolated Endpoint Security PoC bundle built and inspected without installation or activation"
        exit 0
    fi
    test ! -e "$installed_app" || {
        echo "refusing to overwrite existing PoC app: $installed_app" >&2
        exit 2
    }
    ditto "$app" "$installed_app"
    installed_by_script=1
    app="$installed_app"
else
    GUARD_ES_POC=1 \
GUARD_ES_POC_FILE="$fixture" \
GUARD_ES_POC_ALLOW_EXE="$probe" \
scripts/macos/build-dev-app.sh
    app="$repo_dir/build/macos/Sensitive File Guard.app"
    scripts/macos/inspect-signing.sh "$app"
    if [ "$build_only" = 1 ]; then
        echo "PASS: Endpoint Security PoC bundle built and inspected without activation"
        exit 0
    fi
fi

host="$app/Contents/MacOS/Guard"
GUARD_EXTENSION_WATCHDOG_SECONDS=90 \
GUARD_EXTENSION_WATCHDOG_STOP_FILE="$watchdog_stop" \
    "$host" --activate-system-extension-watchdog >"$watchdog_log" 2>&1 &
watchdog_pid=$!
activated=1

attempt=0
while [ "$attempt" -lt 1200 ]; do
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
if [ "$attempt" -eq 1200 ]; then
    echo "BLOCKED: activation watchdog did not report active within 120 seconds" >&2
    sed -n '1,120p' "$watchdog_log" >&2 || true
    exit 1
fi
sed -n '1,120p' "$watchdog_log"

system_extension_evidence=$(systemextensionsctl list 2>&1)
printf '%s\n' "$system_extension_evidence" | grep -F "$extension_bundle_id" || {
    echo "FAIL: systemextensionsctl does not list $extension_bundle_id" >&2
    exit 1
}
printf '%s\n' "$system_extension_evidence" | awk -v id="$extension_bundle_id" '
    index($0, id) > 0 && $1 == "*" && $2 == "*" { active = 1 }
    END { exit active ? 0 : 1 }
' || {
    echo "FAIL: lifecycle delegate completed but systemextensionsctl does not show the exact extension enabled and active" >&2
    exit 1
}

extension_process=
attempt=0
while [ "$attempt" -lt 10 ] && [ -z "$extension_process" ]; do
    for pid in $(pgrep -x guard-es 2>/dev/null || true); do
        executable=$(ps -p "$pid" -o comm= 2>/dev/null | sed 's/^[[:space:]]*//')
        test -x "$executable" || continue
        signing_id=$(codesign -dvv "$executable" 2>&1 | sed -n 's/^Identifier=//p')
        if [ "$signing_id" = "$extension_bundle_id" ]; then
            extension_process="$pid:$executable"
            break
        fi
    done
    if [ -z "$extension_process" ]; then
        attempt=$((attempt + 1))
        sleep 1
    fi
done
test -n "$extension_process" || {
    echo "FAIL: the exact signed guard-es process is not running; do not touch the fixture" >&2
    exit 1
}
echo "guard_es_process=$extension_process"

if "$cat_probe" "$fixture" >"$deny_output" 2>&1; then
    echo "FAIL: non-enrolled $cat_probe read the protected synthetic fixture" >&2
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

: >"$watchdog_stop"
if ! wait "$watchdog_pid"; then
    sed -n '1,160p' "$watchdog_log" >&2 || true
    watchdog_pid=
    exit 1
fi
watchdog_pid=
grep -q '^WATCHDOG_DEACTIVATED ' "$watchdog_log" || {
    echo "FAIL: activation watchdog exited without proving deactivation" >&2
    sed -n '1,160p' "$watchdog_log" >&2 || true
    exit 1
}
activated=0
tail -n 5 "$watchdog_log"

if extension_is_active; then
    echo "FAIL: PoC extension remains enabled and active after watchdog deactivation" >&2
    exit 1
fi
echo "PASS: PoC watchdog deactivated the system extension"
