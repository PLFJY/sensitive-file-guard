#!/bin/sh
set -eu

if [ "$(uname -s)" != "Darwin" ]; then
    echo "self-use-safety-gate.sh requires macOS" >&2
    exit 2
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH= cd -- "$script_dir/../.." && pwd)

cd "$repo_dir"
cargo test \
    -p guard-es \
    -p guardctl \
    -p guard-notify \
    -p guard-test-probe \
    -p guard-ui \
    -p platform-macos \
    --all-features
cargo clippy \
    -p guard-es \
    -p guardctl \
    -p guard-notify \
    -p guard-test-probe \
    -p guard-ui \
    -p platform-macos \
    --all-targets \
    --all-features \
    -- \
    -D warnings

echo "PASS: macOS self-use safety gate mac-auth-scope-v1"
