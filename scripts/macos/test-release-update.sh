#!/bin/sh
set -eu

if [ "$(uname -s)" != "Darwin" ]; then
    echo "test-release-update.sh requires macOS" >&2
    exit 2
fi

: "${SIGNING_IDENTITY:?SIGNING_IDENTITY is required}"
: "${DEVELOPMENT_TEAM:?DEVELOPMENT_TEAM is required}"
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
test_root=$(mktemp -d "${TMPDIR:-/tmp}/guard-release-update.XXXXXX")
cleanup() { rm -rf -- "$test_root"; }
trap cleanup EXIT INT TERM

release_root="$test_root/release"
state="$test_root/persistent-state"
home="$test_root/home"
profile="$test_root/synthetic-browser-profile"
mkdir -p "$state" "$home" "$profile"
printf '%s\n' '{"synthetic":"config-canary"}' >"$state/config.json"
printf '%s\n' 'synthetic audit canary' >"$state/audit.db"
printf '%s\n' 'synthetic browser canary' >"$profile/Cookies"
before_config=$(cksum "$state/config.json")
before_audit=$(cksum "$state/audit.db")
before_profile=$(cksum "$profile/Cookies")

build() {
    version=$1
    number=$2
    MACOS_RELEASE_ROOT="$release_root" LOCAL_SIGNING_ONLY=1 \
        CODESIGN_TIMESTAMP=none GUARD_VERSION="$version" \
        GUARD_BUILD_NUMBER="$number" "$script_dir/build-release-app.sh"
}

build 0.1.0 1
app="$release_root/Guard.app"
test "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' \
    "$app/Contents/Info.plist")" = 0.1.0
HOME="$home" "$app/Contents/MacOS/Guard" --packaging-smoke

build 0.1.1 2
test "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' \
    "$app/Contents/Info.plist")" = 0.1.1
HOME="$home" "$app/Contents/MacOS/Guard" --packaging-smoke
test "$(cksum "$state/config.json")" = "$before_config"
test "$(cksum "$state/audit.db")" = "$before_audit"
test "$(cksum "$profile/Cookies")" = "$before_profile"

GUARD_APP="$app" HOME="$home" "$script_dir/uninstall-recovery.sh" \
    --dry-run --preserve-data --remove-app --confirm >"$test_root/uninstall.txt"
grep -q 'Preserve config and audit' "$test_root/uninstall.txt"
grep -q 'Browser profiles and SSH keys are never deletion targets' "$test_root/uninstall.txt"
test "$(cksum "$profile/Cookies")" = "$before_profile"
echo "PASS: local signed update, restart, persistence, and dry-run recovery"
