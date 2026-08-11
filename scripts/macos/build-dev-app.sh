#!/bin/sh
set -eu

if [ "$(uname -s)" != "Darwin" ]; then
    echo "build-dev-app.sh requires macOS and the active Xcode SDK" >&2
    exit 2
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH= cd -- "$script_dir/../.." && pwd)
build_root=${MACOS_BUILD_ROOT:-"$repo_dir/build/macos"}
app_bundle="$build_root/Guard.app"
app_bundle_id=${APP_BUNDLE_ID:-io.github.plfjy.SensitiveFileGuard}
extension_bundle_id=${SYSTEM_EXTENSION_BUNDLE_ID:-"$app_bundle_id.guard-es"}
version=${GUARD_VERSION:-0.1.0}
build_number=${GUARD_BUILD_NUMBER:-1}
build_profile=${BUILD_PROFILE:-debug}
signing_identity=${SIGNING_IDENTITY:--}

validate_bundle_id() {
    case "$1" in
        *[!A-Za-z0-9.-]*|*..*|.*|*.)
            echo "invalid bundle identifier: $1" >&2
            exit 2
            ;;
    esac
}
validate_bundle_id "$app_bundle_id"
validate_bundle_id "$extension_bundle_id"
case "$version:$build_number" in
    *[!0-9.:+-]*)
        echo "GUARD_VERSION/GUARD_BUILD_NUMBER contain unsupported characters" >&2
        exit 2
        ;;
esac
case "$build_profile" in
    debug) cargo_profile=debug; cargo_flags= ;;
    release) cargo_profile=release; cargo_flags=--release ;;
    *) echo "BUILD_PROFILE must be debug or release" >&2; exit 2 ;;
esac
case "$build_root" in
    /|"$repo_dir") echo "refusing unsafe MACOS_BUILD_ROOT: $build_root" >&2; exit 2 ;;
esac

for command_name in cargo pkg-config plutil codesign; do
    command -v "$command_name" >/dev/null 2>&1 || {
        echo "missing required command: $command_name" >&2
        exit 2
    }
done
pkg-config --exists 'gtk4 >= 4.14' 'libadwaita-1 >= 1.4' || {
    echo "GTK4 >= 4.14 and libadwaita >= 1.4 development packages are required" >&2
    exit 2
}
xcrun --sdk macosx --show-sdk-path >/dev/null

cd "$repo_dir"
GUARD_SYSTEM_EXTENSION_BUNDLE_ID="$extension_bundle_id" \
    cargo build -p guard-ui -p guard-es $cargo_flags

if [ -e "$app_bundle" ]; then
    rm -rf -- "$app_bundle"
fi
extension_bundle="$app_bundle/Contents/Library/SystemExtensions/$extension_bundle_id.systemextension"
mkdir -p "$app_bundle/Contents/MacOS" "$extension_bundle/Contents/MacOS"
cp "target/$cargo_profile/guard-ui" "$app_bundle/Contents/MacOS/Guard"
cp "target/$cargo_profile/guard-es" "$extension_bundle/Contents/MacOS/guard-es"

render_plist() {
    input=$1
    output=$2
    sed \
        -e "s|@APP_BUNDLE_ID@|$app_bundle_id|g" \
        -e "s|@EXTENSION_BUNDLE_ID@|$extension_bundle_id|g" \
        -e "s|@VERSION@|$version|g" \
        -e "s|@BUILD_NUMBER@|$build_number|g" \
        "$input" >"$output"
    plutil -lint "$output" >/dev/null
}

render_plist packaging/macos/Guard.Info.plist.in "$app_bundle/Contents/Info.plist"
render_plist packaging/macos/GuardES.Info.plist.in "$extension_bundle/Contents/Info.plist"

if [ "${SKIP_SIGNING:-0}" != "1" ]; then
    codesign --force --sign "$signing_identity" \
        --entitlements packaging/macos/GuardES.entitlements \
        "$extension_bundle"
    codesign --force --sign "$signing_identity" \
        --entitlements packaging/macos/Guard.entitlements \
        "$app_bundle"
    codesign --verify --deep --strict "$app_bundle"

    signed_team=$(codesign -dvv "$app_bundle" 2>&1 | sed -n 's/^TeamIdentifier=//p')
    if [ "$signed_team" = "not set" ]; then
        signed_team=
    fi
    if [ -n "${DEVELOPMENT_TEAM:-}" ] && [ "$signed_team" != "$DEVELOPMENT_TEAM" ]; then
        echo "signed TeamIdentifier '$signed_team' does not match DEVELOPMENT_TEAM '$DEVELOPMENT_TEAM'" >&2
        exit 2
    fi
fi

echo "assembled development bundle: $app_bundle"
echo "app bundle id: $app_bundle_id"
echo "system extension bundle id: $extension_bundle_id"
echo "signing identity: $signing_identity"
if [ "${SKIP_SIGNING:-0}" = "1" ]; then
    echo "signing skipped"
elif [ -n "$signed_team" ]; then
    echo "signed TeamIdentifier: $signed_team"
else
    echo "signed TeamIdentifier: not set (ad-hoc bundles cannot activate for release acceptance)"
fi
