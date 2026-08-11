#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
portable_crates="guard-core guard-browser guard-ssh guard-ipc guard-audit guard-platform guard-client"
failed=0

for crate in $portable_crates; do
    manifest="$repo_dir/crates/$crate/Cargo.toml"
    if grep -Eq '(^|[[:space:]])platform-linux[[:space:]]*=' "$manifest"; then
        echo "boundary violation: $crate depends directly on platform-linux" >&2
        failed=1
    fi
    source_dir="$repo_dir/crates/$crate/src"
    if rg -n 'platform_linux|platform-linux|^[[:space:]]*(use|pub use|mod)[^;]*(fanotify|ssh_behavior|systemd|polkit|bpf)' "$source_dir"; then
        echo "boundary violation: Linux implementation import found in $crate" >&2
        failed=1
    fi
done

if rg -n 'platform_linux|platform-linux' "$repo_dir/apps/guard-ui/src"; then
    echo "boundary violation: guard-ui imports platform-linux" >&2
    failed=1
fi

if [ "$failed" -ne 0 ]; then
    exit 1
fi
echo "PASS: portable platform boundaries are clean"
