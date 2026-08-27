#!/bin/sh
set -eu

if [ "$(uname -s)" != Darwin ]; then
    echo "preflight-final-acceptance.sh requires macOS" >&2
    exit 2
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH= cd -- "$script_dir/../.." && pwd)
app=${1:-"$repo_dir/build/macos-release/Sensitive File Guard.app"}
signing_mode=${VERIFY_SIGNING_MODE:-release}
guard="$app/Contents/MacOS/SensitiveFileGuard"

acceptance_root=$(mktemp -d "${TMPDIR:-/tmp}/guard-final-acceptance.XXXXXX")
cleanup() { rm -rf -- "$acceptance_root"; }
trap cleanup EXIT HUP INT TERM
mkdir -p "$acceptance_root/home" "$acceptance_root/browser-fixtures" \
    "$acceptance_root/ssh-fixtures" "$acceptance_root/output"
echo "disposable_acceptance_root=$acceptance_root"
echo "No normal browser profile or ~/.ssh path is an acceptance target."

VERIFY_SIGNING_MODE="$signing_mode" "$script_dir/verify-bundle.sh" "$app"

blocked=0
sip_status=$(csrutil status 2>&1 || true)
printf '%s\n' "$sip_status" | tee "$acceptance_root/output/sip.txt"
case "$signing_mode" in
    self-use)
        if ! printf '%s\n' "$sip_status" | grep -q \
            'System Integrity Protection status: disabled'; then
            echo "BLOCKED: self-use acceptance requires SIP disabled" >&2
            blocked=1
        fi
        ;;
    release)
        if ! printf '%s\n' "$sip_status" | grep -q \
            'System Integrity Protection status: enabled'; then
            echo "BLOCKED: formal release acceptance requires SIP enabled" >&2
            blocked=1
        fi
        ;;
    local)
        echo "BLOCKED: entitlement-free local packaging cannot enforce" >&2
        blocked=1
        ;;
esac

if [ "$blocked" -ne 0 ]; then
    echo "FINAL_SECURITY_ACCEPTANCE_PREFLIGHT=BLOCKED" >&2
    exit 77
fi

HOME="$acceptance_root/home" "$guard" --packaging-smoke

lifecycle=$("$guard" --system-extension-status 2>&1) || true
printf '%s\n' "$lifecycle"
if ! printf '%s\n' "$lifecycle" | grep -q 'state=Active'; then
    echo "BLOCKED: the selected system extension is not active" >&2
    blocked=1
fi

health=$("$guard" --xpc-status 2>&1) || true
printf '%s\n' "$health"
if ! printf '%s\n' "$health" | grep -Eq \
    '"backend_state"[[:space:]]*:[[:space:]]*"(ACTIVE|DEGRADED)"'; then
    echo "BLOCKED: authenticated Endpoint Security XPC health is unavailable" >&2
    blocked=1
fi
if ! printf '%s\n' "$health" | grep -Eq \
    '"enforcement_active"[[:space:]]*:[[:space:]]*true'; then
    echo "BLOCKED: enforcement is not active" >&2
    blocked=1
fi
if printf '%s\n' "$health" | grep -q 'REQUIRES_FULL_DISK_ACCESS'; then
    echo "BLOCKED: Full Disk Access is required" >&2
    blocked=1
fi

helper=$("$guard" --pending-helper-status 2>&1) || true
printf '%s\n' "pending_helper=$helper"
helper_dir="$app/Contents/Library/LaunchAgents"
helper_plist=$(find "$helper_dir" -maxdepth 1 -type f -name '*.plist' -print -quit 2>/dev/null || true)
helper_label=$(plutil -extract Label raw "$helper_plist" 2>/dev/null || true)
if [ "$helper" != Enabled ] || [ -z "$helper_label" ] \
    || ! launchctl print "gui/$(id -u)/$helper_label" >/dev/null 2>&1; then
    echo "BLOCKED: pending-confirmation helper is not loaded; closed-GUI approvals would time out" >&2
    blocked=1
fi

if [ "$blocked" -ne 0 ]; then
    echo "FINAL_SECURITY_ACCEPTANCE_PREFLIGHT=BLOCKED" >&2
    exit 77
fi

cat <<EOF
FINAL_SECURITY_ACCEPTANCE_PREFLIGHT=PASS
Run the fixture-only gates next:
  $script_dir/run-target-selection-acceptance.sh
  $script_dir/run-ssh-policy-acceptance.sh '$app'

The older browser-policy and namespace-health scripts require manual policy
replacement and are not final acceptance gates. The target-selection command
stages and restores an isolated policy automatically.
EOF
