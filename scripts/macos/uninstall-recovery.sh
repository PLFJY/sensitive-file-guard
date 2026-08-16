#!/bin/sh
set -eu

if [ "$(uname -s)" != "Darwin" ]; then
    echo "uninstall-recovery.sh requires macOS" >&2
    exit 2
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH= cd -- "$script_dir/../.." && pwd)
app=${GUARD_APP:-"$repo_dir/build/macos-release/Sensitive File Guard.app"}
remove_data=0
remove_app=0
dry_run=0
confirmed=0
for argument in "$@"; do
    case "$argument" in
        --remove-product-data) remove_data=1 ;;
        --remove-app) remove_app=1 ;;
        --dry-run) dry_run=1 ;;
        --confirm) confirmed=1 ;;
        --preserve-data) remove_data=0 ;;
        *.app) app=$argument ;;
        *)
            echo "usage: $0 [Sensitive File Guard.app] [--preserve-data|--remove-product-data] [--remove-app] [--dry-run] --confirm" >&2
            exit 2
            ;;
    esac
done
case "$app" in
    /|*.app/..|*.app/../*) echo "unsafe app path: $app" >&2; exit 2 ;;
esac
test "$confirmed" = 1 || {
    echo "refusing recovery mutation without --confirm; use --dry-run --confirm to inspect" >&2
    exit 2
}

guard="$app/Contents/MacOS/Guard"
echo "1. Protection must be disabled in Guard before deactivation."
if [ "$dry_run" = 0 ] && [ -x "$guard" ]; then
    status=$($guard --xpc-status 2>/dev/null || true)
    if printf '%s\n' "$status" | grep -q '"enforcement_active": true'; then
        echo "refusing uninstall while protection policy is active; disable it in Guard first" >&2
        exit 2
    fi
fi

echo "2. Unregister pending helper: $guard --unregister-pending-helper"
echo "3. Request extension deactivation: $guard --deactivate-system-extension"
if [ "$dry_run" = 0 ] && [ -x "$guard" ]; then
    "$guard" --unregister-pending-helper || true
    "$guard" --deactivate-system-extension || true
fi

data_dir='/Library/Application Support/Sensitive Data Firewall'
if [ "$remove_data" = 1 ]; then
    echo "4. Remove only product config/audit files from: $data_dir"
    if [ "$dry_run" = 0 ]; then
        sudo rm -f -- "$data_dir/config.json" "$data_dir/audit.db" \
            "$data_dir/audit.db-shm" "$data_dir/audit.db-wal"
        sudo rmdir "$data_dir" 2>/dev/null || true
    fi
else
    echo "4. Preserve config and audit data in: $data_dir"
fi

if [ "$remove_app" = 1 ]; then
    trash=${HOME:?HOME is required}/.Trash
    destination="$trash/Guard-$(date +%Y%m%d-%H%M%S).app"
    echo "5. Move app to recoverable Trash path: $destination"
    if [ "$dry_run" = 0 ]; then
        mkdir -p "$trash"
        mv "$app" "$destination"
    fi
else
    echo "5. Application retained at: $app"
fi
echo "Browser profiles and SSH keys are never deletion targets."
