#!/bin/sh
set -eu

if [ "$(uname -s)" != Darwin ]; then
    echo "preflight-final-acceptance.sh requires macOS" >&2
    exit 2
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH= cd -- "$script_dir/../.." && pwd)
app=${1:-"$repo_dir/build/macos-release/Guard.app"}
signing_mode=${VERIFY_SIGNING_MODE:-release}
guard="$app/Contents/MacOS/Guard"

acceptance_root=$(mktemp -d "${TMPDIR:-/tmp}/guard-final-acceptance.XXXXXX")
cleanup() { rm -rf -- "$acceptance_root"; }
trap cleanup EXIT HUP INT TERM
mkdir -p "$acceptance_root/home" "$acceptance_root/browser-fixtures" \
    "$acceptance_root/ssh-fixtures" "$acceptance_root/output"
echo "disposable_acceptance_root=$acceptance_root"
echo "No normal browser profile or ~/.ssh path is an acceptance target."

VERIFY_SIGNING_MODE="$signing_mode" "$script_dir/verify-bundle.sh" "$app"
HOME="$acceptance_root/home" "$guard" --packaging-smoke

blocked=0
if ! csrutil status | tee "$acceptance_root/output/sip.txt" | \
    grep -q 'System Integrity Protection status: enabled'; then
    echo "BLOCKED: SIP must be enabled for final security acceptance" >&2
    blocked=1
fi

if [ "$signing_mode" != release ]; then
    echo "BLOCKED: local-only signing is not a release acceptance identity" >&2
    blocked=1
fi

lifecycle=$($guard --system-extension-status 2>&1) || true
printf '%s\n' "$lifecycle"
if ! printf '%s\n' "$lifecycle" | grep -q 'state=Active'; then
    echo "BLOCKED: the provisioned system extension is not active" >&2
    blocked=1
fi

health=$($guard --xpc-status 2>&1) || true
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

helper=$($guard --pending-helper-status 2>&1) || true
printf '%s\n' "pending_helper=$helper"
if [ "$helper" != Enabled ]; then
    echo "BLOCKED: the pending helper is not enabled" >&2
    blocked=1
fi

if [ "$blocked" -ne 0 ]; then
    echo "FINAL_SECURITY_ACCEPTANCE_PREFLIGHT=BLOCKED" >&2
    exit 77
fi

cat <<EOF
FINAL_SECURITY_ACCEPTANCE_PREFLIGHT=PASS
Run the interactive fixture-only gates next:
  GUARD_APP='$app' $script_dir/run-browser-policy-acceptance.sh
  $script_dir/run-ssh-policy-acceptance.sh '$app'
  GUARD_APP='$app' $script_dir/run-namespace-health-acceptance.sh
EOF
