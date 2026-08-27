#!/bin/sh
set -eu

# Fixture-only live acceptance. It requires an already approved extension, but
# the signed guardctl stages and restores the disposable profile automatically;
# it never touches a normal browser profile, real cookies, or SSH keys.
repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
if [ -n "${GUARD_APP:-}" ]; then
    app=$GUARD_APP
elif [ -x '/Applications/Sensitive File Guard.app/Contents/MacOS/guardctl' ]; then
    app='/Applications/Sensitive File Guard.app'
elif [ -x "$repo_dir/build/macos-release/Sensitive File Guard.app/Contents/MacOS/guardctl" ]; then
    app="$repo_dir/build/macos-release/Sensitive File Guard.app"
else
    app="$repo_dir/build/macos/Sensitive File Guard.app"
fi
guardctl="$app/Contents/MacOS/guardctl"
probe="$repo_dir/target/debug/guard-test-probe"

for required in "$guardctl"; do
    test -x "$required" || { echo "BLOCKED: missing $required" >&2; exit 77; }
done
cargo build --manifest-path "$repo_dir/Cargo.toml" -p guard-test-probe >/dev/null

root=$(mktemp -d "${TMPDIR:-/tmp}/sensitive-file-guard-target-selection.XXXXXX")
cleanup() { rm -rf -- "$root"; }
trap cleanup EXIT INT TERM
profile="$root/Chrome"
cookies="$profile/Default/Network/Cookies"
mkdir -p "$(dirname -- "$cookies")"
printf '%s\n' 'synthetic fixture only; not a browser secret' >"$cookies"
printf '%s\n' '{}' >"$profile/Default/Preferences"

cat <<EOF
Running a fixture-only target-selection acceptance test. The signed guardctl
will preserve the current policy, temporarily add only this disposable profile,
and restore the original policy after every result:

  profile root: $profile
  executable: /Applications/Google Chrome.app/Contents/MacOS/Google Chrome

macOS will request local authentication to stage the fixture, verify hardlink
rejection, and restore the original policy. No browser or SSH secret is read.
EOF
"$guardctl" acceptance target-selection \
    --profile-root "$profile" \
    --browser-executable '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome' \
    --probe "$probe"
