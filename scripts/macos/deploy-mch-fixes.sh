#!/bin/sh
# Deploy the locally built fix bundle (0.1.1) to /Applications and request
# extension activation. Durable artifact for the MCH hardening round:
#   - config.rs: policy_enabled serde default -> true (File Shield must not
#     silently turn off when the config file omits the field).
#   - process_shield.rs: NOTIFY_GET_TASK_READ is DETECTED telemetry only
#     (GET_TASK_READ_NOTIFY_STRONG_SIGNAL_UNVALIDATED).
# The script installs the bundle and requests activation; the user approves
# the extension version replacement in System Settings. It never modifies TCC
# or the protected-file policy, and it does not read protected contents.
set -eu

if [ "$(uname -s)" != "Darwin" ]; then
    echo "this deploy is macOS-only" >&2
    exit 2
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH= cd -- "$script_dir/../.." && pwd)
src="$repo_dir/build/macos/Sensitive File Guard.app"
expected_version=0.1.1

test -d "$src" || { echo "built bundle not found: $src (run build-dev-app.sh first)" >&2; exit 2; }
version=$(plutil -extract CFBundleShortVersionString raw "$src/Contents/Info.plist")
test "$version" = "$expected_version" || {
    echo "expected version $expected_version, found $version" >&2
    exit 2
}
codesign --verify --deep --strict "$src" || { echo "signature verification failed" >&2; exit 2; }
echo "bundle verified: $expected_version"

for dest in "/Applications/Sensitive File Guard MCH.app" "/Applications/Sensitive File Guard.app"; do
    if [ -e "$dest" ]; then
        echo "replacing $dest"
        if ! rm -rf -- "$dest" 2>/dev/null; then
            echo "need sudo to replace $dest" >&2
            sudo rm -rf -- "$dest"
        fi
    fi
    if ! ditto "$src" "$dest" 2>/dev/null; then
        echo "need sudo to install $dest" >&2
        sudo ditto "$src" "$dest"
    fi
    codesign --verify --deep --strict "$dest" || { echo "installed bundle failed verification: $dest" >&2; exit 2; }
    echo "installed: $dest"
done

# A watchdog process deactivates the extension when it exits (by design). Kill
# any leftover watchdog before the plain activation.
pkill -f -- '--activate-system-extension-watchdog' >/dev/null 2>&1 || true
sleep 1

echo "requesting extension activation (approve the version replacement in System Settings)"
"/Applications/Sensitive File Guard MCH.app/Contents/MacOS/Guard" --activate-system-extension     || echo "activation request returned non-zero; the user may need to approve it in System Settings" >&2

echo "deployed; verify with:"
echo "  '/Applications/Sensitive File Guard MCH.app/Contents/MacOS/guardctl' --json status"
