#!/bin/sh
set -eu

if [ "$(uname -s)" != "Darwin" ]; then
    echo "self-use-preflight.sh requires macOS" >&2
    exit 2
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH= cd -- "$script_dir/../.." && pwd)
app=${1:-"$repo_dir/build/macos-release/Sensitive File Guard.app"}

VERIFY_SIGNING_MODE=self-use "$script_dir/verify-bundle.sh" "$app"

sip=$(/usr/bin/csrutil status 2>&1 || true)
printf '%s\n' "$sip"
case "$sip" in
    *disabled*) echo 'PASS: SIP is disabled for the self-use Endpoint Security path' ;;
    *)
        echo 'BLOCKED: Self-use Endpoint Security mode requires SIP disabled.' >&2
        echo 'Disable SIP manually from macOS Recovery, reboot, then rerun.' >&2
        exit 77
        ;;
esac

echo 'System Extension developer mode has no read-only status subcommand on this macOS release.'
echo 'Required setup command (run once, then rerun this preflight): sudo systemextensionsctl developer on'
echo 'Current system-extension evidence:'
/usr/bin/systemextensionsctl list || true

echo 'SELF_USE_PREFLIGHT=PASS (developer-mode command must have been run manually)'
