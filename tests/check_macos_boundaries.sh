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
if rg -n 'ES_EVENT_TYPE_(AUTH|NOTIFY)_[A-Z_]+' \
    "$repo_dir/native/macos/endpoint_security_bridge.c" \
    | rg -v 'ES_EVENT_TYPE_(AUTH_OPEN|NOTIFY_FORK|NOTIFY_EXEC|NOTIFY_EXIT)'; then
    echo "macOS boundary violation: unsupported Endpoint Security event subscription" >&2
    failed=1
fi
if rg -n 'es_respond_auth_result|es_copy_message|es_free_message' \
    "$repo_dir/native/macos/endpoint_security_bridge.c"; then
    echo "macOS boundary violation: wrong or deprecated Endpoint Security response/lifetime API" >&2
    failed=1
fi
if rg -n 'O_RDONLY|O_RDWR|O_WRONLY' \
    "$repo_dir/native/macos/endpoint_security_bridge.c"; then
    echo "macOS boundary violation: AUTH_OPEN must use kernel FFLAGS, not open(2) O_* flags" >&2
    failed=1
fi
if ! rg -U -q 'es_respond_flags_result\([^;]*false' \
    "$repo_dir/native/macos/endpoint_security_bridge.c"; then
    echo "macOS boundary violation: AUTH_OPEN response must hardcode cache=false" >&2
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
