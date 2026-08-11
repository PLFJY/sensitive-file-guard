#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
failed=0

if rg -n 'NetworkExtension|NEFilter|systemextensionsctl' \
    "$repo_dir/crates/platform-macos" "$repo_dir/apps/guard-es" \
    "$repo_dir/native/macos" "$repo_dir/scripts/macos" "$repo_dir/packaging/macos"; then
    echo "macOS boundary violation: Network Extension or undocumented lifecycle CLI found" >&2
    failed=1
fi
if rg -n 'platform-macos[[:space:]]*=' "$repo_dir/apps/guard-ui/Cargo.toml" | head -n 1 >/dev/null; then
    if ! rg -n -B 2 '\[target.*target_os = "macos".*dependencies\]' "$repo_dir/apps/guard-ui/Cargo.toml" >/dev/null; then
        echo "macOS boundary violation: guard-ui Apple dependency is not target-specific" >&2
        failed=1
    fi
fi
if ! rg -q 'CARGO_CFG_TARGET_OS.*macos' "$repo_dir/crates/platform-macos/build.rs"; then
    echo "macOS boundary violation: native bridge build lacks target guard" >&2
    failed=1
fi
if [ "$failed" -ne 0 ]; then
    exit 1
fi
echo "PASS: macOS target boundaries are clean"
