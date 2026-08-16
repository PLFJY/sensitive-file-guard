#!/bin/sh
set -u

if [ "$(uname -s)" != "Darwin" ]; then
    echo "diagnose.sh requires macOS" >&2
    exit 2
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH= cd -- "$script_dir/../.." && pwd)
app=${1:-"$repo_dir/build/macos-release/Sensitive File Guard.app"}
guard="$app/Contents/MacOS/Guard"
guardctl="$app/Contents/MacOS/guardctl"

echo "Guard macOS diagnostics (metadata only)"
echo "app=$app"
if [ ! -x "$guard" ]; then
    echo "backend_state=EXTENSION_NOT_INSTALLED diagnostic=Sensitive File Guard.app is unavailable"
    exit 1
fi

"$script_dir/verify-bundle.sh" "$app" || echo "bundle_verification=FAILED"
"$guard" --system-extension-status || echo "system_extension_status=UNAVAILABLE"
"$guard" --pending-helper-status || echo "pending_helper_status=UNAVAILABLE"
"$guard" --xpc-status || echo "endpoint_security_xpc=UNAVAILABLE"
"$guardctl" --version || echo "guardctl_version=UNAVAILABLE"

for metadata_path in \
    '/Library/Application Support/Sensitive Data Firewall/config.json' \
    '/Library/Application Support/Sensitive Data Firewall/audit.db'; do
    if [ -e "$metadata_path" ]; then
        stat -f 'metadata path=%N owner=%u group=%g mode=%Sp size=%z' "$metadata_path"
    else
        echo "metadata path=$metadata_path state=absent"
    fi
done

echo "Diagnostics never open browser profiles, SSH keys, config contents, or audit rows."
