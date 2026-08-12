#!/bin/sh
set -eu

if [ "$(uname -s)" != "Darwin" ]; then
    echo "test-xpc-auth.sh requires macOS" >&2
    exit 2
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH= cd -- "$script_dir/../.." && pwd)
app_bundle=${1:-"$repo_dir/build/macos/Guard.app"}
case "$app_bundle" in
    /*) ;;
    *) app_bundle=$(CDPATH= cd -- "$(dirname -- "$app_bundle")" && pwd)/$(basename -- "$app_bundle") ;;
esac
extension_bundle=$(find "$app_bundle/Contents/Library/SystemExtensions" \
    -maxdepth 1 -type d -name '*.systemextension' -print | head -n 1)
test -n "$extension_bundle" || {
    echo "Endpoint Security extension is missing from $app_bundle" >&2
    exit 2
}

guardctl="$app_bundle/Contents/MacOS/guardctl"
guard_notify="$app_bundle/Contents/MacOS/guard-notify"
guard_ui="$app_bundle/Contents/MacOS/Guard"
guard_es="$extension_bundle/Contents/MacOS/guard-es"
service_name=$(plutil -extract NSEndpointSecurityMachServiceName raw \
    "$extension_bundle/Contents/Info.plist")
team_id=$(codesign -dvv "$extension_bundle" 2>&1 | sed -n 's/^TeamIdentifier=//p')
if [ -z "$team_id" ] || [ "$team_id" = "not set" ]; then
    echo "test-xpc-auth.sh requires a Team-signed development bundle" >&2
    exit 2
fi

guard_xpc_test_root=$(mktemp -d "${TMPDIR:-/tmp}/guard-xpc-phase05.XXXXXX")
domain="gui/$(id -u)"
label="io.github.plfjy.SensitiveFileGuard.phase05.$PPID"
plist="$guard_xpc_test_root/$label.plist"
probe="$guard_xpc_test_root/wrong-signed-probe"
test_server="$guard_xpc_test_root/guard-es-xpc-test-server"
test_app="$guard_xpc_test_root/Guard-xpc-test.app"
test_ui="$test_app/Contents/MacOS/Guard"
bootstrapped=0
notify_pid=
pending_ui_pid=
cleanup() {
    if [ -n "$pending_ui_pid" ] && kill -0 "$pending_ui_pid" 2>/dev/null; then
        kill "$pending_ui_pid" 2>/dev/null || true
        wait "$pending_ui_pid" 2>/dev/null || true
    fi
    if [ -n "$notify_pid" ] && kill -0 "$notify_pid" 2>/dev/null; then
        kill "$notify_pid" 2>/dev/null || true
        wait "$notify_pid" 2>/dev/null || true
    fi
    if [ "$bootstrapped" -eq 1 ]; then
        launchctl bootout "$domain" "$plist" >/dev/null 2>&1 || true
    fi
    rm -rf -- "$guard_xpc_test_root"
}
trap cleanup EXIT HUP INT TERM

# A restricted-entitlement system-extension executable is intentionally killed
# when launched outside its approved container. Re-sign a temporary byte-for-
# byte copy without entitlements for transport-only testing; the production
# app/extension bundle remains untouched and live ES is not claimed here.
signing_authority=$(codesign -dvv "$extension_bundle" 2>&1 \
    | sed -n 's/^Authority=//p' | head -n 1)
extension_identifier=$(plutil -extract CFBundleIdentifier raw \
    "$extension_bundle/Contents/Info.plist")
app_identifier=$(plutil -extract CFBundleIdentifier raw \
    "$app_bundle/Contents/Info.plist")
test -n "$signing_authority" || {
    echo "could not determine the development signing authority" >&2
    exit 2
}
cp "$guard_es" "$test_server"
codesign --force --sign "$signing_authority" \
    --identifier "$extension_identifier" "$test_server" >/dev/null
guard_es=$test_server
mkdir -p "$test_app/Contents/MacOS" "$test_app/Contents/Library/LaunchAgents"
cp "$app_bundle/Contents/Info.plist" "$test_app/Contents/Info.plist"
cp "$app_bundle/Contents/Library/LaunchAgents/$app_identifier.guard-notify.plist" \
    "$test_app/Contents/Library/LaunchAgents/$app_identifier.guard-notify.plist"
if [ -d "$app_bundle/Contents/Frameworks" ]; then
    cp -R "$app_bundle/Contents/Frameworks" "$test_app/Contents/Frameworks"
fi
if [ -d "$app_bundle/Contents/Resources" ]; then
    cp -R "$app_bundle/Contents/Resources" "$test_app/Contents/Resources"
fi
cp "$guard_ui" "$test_ui"
cp "$guard_notify" "$test_app/Contents/MacOS/guard-notify"
codesign --force --sign "$signing_authority" \
    --identifier "$app_identifier.guard-notify" \
    "$test_app/Contents/MacOS/guard-notify" >/dev/null
codesign --force --sign "$signing_authority" \
    --identifier "$app_identifier" "$test_app" >/dev/null
guard_ui=$test_ui

plutil -create xml1 "$plist"
plutil -insert Label -string "$label" "$plist"
plutil -insert ProgramArguments -json "[\"$guard_es\"]" "$plist"
plutil -insert MachServices -json "{\"$service_name\":true}" "$plist"
plutil -insert RunAtLoad -bool true "$plist"
plutil -insert StandardErrorPath -string "$guard_xpc_test_root/guard-es.error" "$plist"

launchctl bootstrap "$domain" "$plist"
bootstrapped=1

attempt=0
until "$guardctl" --json status >"$guard_xpc_test_root/status.json" \
    2>"$guard_xpc_test_root/status.error"; do
    attempt=$((attempt + 1))
    if [ "$attempt" -ge 5 ]; then
        echo "valid signed guardctl could not query the temporary XPC service" >&2
        sed -n '1,40p' "$guard_xpc_test_root/status.error" >&2
        sed -n '1,80p' "$guard_xpc_test_root/guard-es.error" >&2 || true
        launchctl print "$domain/$label" >&2 || true
        exit 1
    fi
    sleep 0.1
done
python3 -m json.tool "$guard_xpc_test_root/status.json" >/dev/null
"$guard_ui" --xpc-status >"$guard_xpc_test_root/ui-status.json"
python3 -m json.tool "$guard_xpc_test_root/ui-status.json" >/dev/null
"$guard_ui" --pending-helper-status \
    >"$guard_xpc_test_root/pending-helper-status.txt"
rg -q 'NotRegistered|Enabled|RequiresApproval|NotFound' \
    "$guard_xpc_test_root/pending-helper-status.txt"
"$guard_ui" --pending-only >"$guard_xpc_test_root/pending-ui.out" \
    2>"$guard_xpc_test_root/pending-ui.error" &
pending_ui_pid=$!
pending_attempt=0
while kill -0 "$pending_ui_pid" 2>/dev/null; do
    pending_attempt=$((pending_attempt + 1))
    if [ "$pending_attempt" -ge 30 ]; then
        echo "pending-only GTK client did not exit after a successful empty snapshot" >&2
        exit 1
    fi
    sleep 0.1
done
wait "$pending_ui_pid"
pending_ui_pid=
echo "PASS: pending-only GTK client exited after the successful empty snapshot"
"$guard_notify" --once

"$guard_notify" --poll-ms 500 >"$guard_xpc_test_root/notify.out" \
    2>"$guard_xpc_test_root/notify.error" &
notify_pid=$!
sleep 5
notify_cpu_time=$(ps -o time= -p "$notify_pid" | tr -d ' ')
notify_cpu_percent=$(ps -o %cpu= -p "$notify_pid" | tr -d ' ')
kill "$notify_pid"
wait "$notify_pid" 2>/dev/null || true
notify_pid=
echo "MEASURE: guard-notify 500ms polling for 5s cpu_time=$notify_cpu_time sampled_cpu_percent=$notify_cpu_percent"

xcrun clang -fobjc-arc -fmodules -Wall -Wextra -Werror \
    -framework Foundation \
    "$repo_dir/native/macos/xpc_wrong_signed_probe.m" \
    -o "$probe"
codesign --force --sign - --identifier "$label.wrong-signed" "$probe" >/dev/null
"$probe" "$service_name"
codesign --force --sign "$signing_authority" \
    --identifier "$label.same-team-unlisted" "$probe" >/dev/null
"$probe" "$service_name"

echo "PASS: signed Guard UI/CLI/pending helper reached XPC; ad-hoc and same-Team unlisted same-UID SSH self-approval attempts did not"
