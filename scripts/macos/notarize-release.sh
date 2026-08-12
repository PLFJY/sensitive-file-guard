#!/bin/sh
set -eu

if [ "$(uname -s)" != "Darwin" ]; then
    echo "notarize-release.sh requires macOS" >&2
    exit 2
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH= cd -- "$script_dir/../.." && pwd)
app=${1:-"$repo_dir/build/macos-release/Guard.app"}
profile=${NOTARY_KEYCHAIN_PROFILE:?NOTARY_KEYCHAIN_PROFILE is required}
version=${GUARD_VERSION:-0.1.0}
architecture=${EXPECTED_ARCH:-$(uname -m)}
archive=${NOTARIZED_ARCHIVE:-"$(dirname "$app")/Guard-$version-$architecture.zip"}

test -d "$app" || { echo "release app not found: $app" >&2; exit 2; }
"$script_dir/verify-bundle.sh" "$app"

work=$(mktemp -d "${TMPDIR:-/tmp}/guard-notarize.XXXXXX")
cleanup() { rm -rf -- "$work"; }
trap cleanup EXIT INT TERM
submission="$work/Guard-notarization.zip"
ditto -c -k --keepParent "$app" "$submission"

# Credentials are resolved only by notarytool from the named Keychain profile.
# The profile contents are never printed, copied, or stored in this repository.
xcrun notarytool submit "$submission" --keychain-profile "$profile" --wait
xcrun stapler staple "$app"
xcrun stapler validate "$app"
spctl --assess --type execute --verbose=4 "$app"
VERIFY_GATEKEEPER=1 "$script_dir/verify-bundle.sh" "$app"

rm -f -- "$archive"
ditto -c -k --keepParent "$app" "$archive"
echo "notarized and stapled archive: $archive"
