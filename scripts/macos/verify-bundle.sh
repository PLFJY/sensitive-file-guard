#!/bin/sh
set -eu

if [ "$(uname -s)" != "Darwin" ]; then
    echo "verify-bundle.sh requires macOS" >&2
    exit 2
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH= cd -- "$script_dir/../.." && pwd)
app=${1:-"$repo_dir/build/macos-release/Sensitive File Guard.app"}
expected_arch=${EXPECTED_ARCH:-$(uname -m)}
signing_mode=${VERIFY_SIGNING_MODE:-release}

case "$signing_mode" in
    release|local|self-use) ;;
    *) echo "VERIFY_SIGNING_MODE must be release, local, or self-use" >&2; exit 2 ;;
esac

for required in \
    "$app/Contents/MacOS/SensitiveFileGuard" \
    "$app/Contents/MacOS/guardctl" \
    "$app/Contents/MacOS/guard-notify" \
    "$app/Contents/Frameworks" \
    "$app/Contents/Resources/guard-release-runtime" \
    "$app/Contents/Resources/SensitiveFileGuard.icns" \
    "$app/Contents/Resources/gdk-pixbuf/loaders.cache.in" \
    "$app/Contents/Resources/share/glib-2.0/schemas/gschemas.compiled" \
    "$app/Contents/Resources/THIRD_PARTY_NOTICES.md"; do
    test -e "$required" || { echo "missing release artifact: $required" >&2; exit 2; }
done

extension=$(find "$app/Contents/Library/SystemExtensions" -maxdepth 1 \
    -type d -name '*.systemextension' -print | head -n 1)
test -n "$extension" || { echo "system extension is missing" >&2; exit 2; }
agent=$(find "$app/Contents/Library/LaunchAgents" -maxdepth 1 -type f \
    -name '*.plist' -print | head -n 1)
test -n "$agent" || { echo "embedded LaunchAgent is missing" >&2; exit 2; }

plutil -lint "$app/Contents/Info.plist" "$extension/Contents/Info.plist" "$agent" >/dev/null
test "$(plutil -extract CFBundleIconFile raw "$app/Contents/Info.plist")" = SensitiveFileGuard.icns
file "$app/Contents/Resources/SensitiveFileGuard.icns" | grep -q 'Mac OS X icon'
codesign --verify --strict --verbose=2 "$extension"
codesign --verify --strict --verbose=2 "$app/Contents/MacOS/guardctl"
codesign --verify --strict --verbose=2 "$app/Contents/MacOS/guard-notify"
codesign --verify --deep --strict --verbose=2 "$app"

# Notifications must originate in the signed Guard process. A stale helper
# that still embeds the historical osascript/Script Editor bridge is not a
# valid release artifact, even if the rest of its code signature is valid.
if strings "$app/Contents/MacOS/SensitiveFileGuard" "$app/Contents/MacOS/guard-notify" \
    | grep -Eiq '/usr/bin/osascript|display notification|Script Editor'; then
    echo "legacy Script Editor notification path remains in Sensitive File Guard.app" >&2
    exit 2
fi

work=$(mktemp -d "${TMPDIR:-/tmp}/guard-verify-bundle.XXXXXX")
cleanup() { rm -rf -- "$work"; }
trap cleanup EXIT INT TERM
codesign -d --entitlements :- "$app" >"$work/host.entitlements" 2>/dev/null
codesign -d --entitlements :- "$extension" >"$work/extension.entitlements" 2>/dev/null
if [ "$signing_mode" = release ]; then
    test -f "$app/Contents/embedded.provisionprofile"
    test -f "$extension/Contents/embedded.provisionprofile"
    grep -q 'com.apple.developer.system-extension.install' "$work/host.entitlements"
    ! grep -q 'com.apple.developer.endpoint-security.client' "$work/host.entitlements"
    grep -q 'com.apple.developer.endpoint-security.client' "$work/extension.entitlements"
    ! grep -q 'com.apple.developer.system-extension.install' "$work/extension.entitlements"
elif [ "$signing_mode" = self-use ]; then
    test ! -f "$app/Contents/embedded.provisionprofile"
    test ! -f "$extension/Contents/embedded.provisionprofile"
    grep -q 'com.apple.developer.system-extension.install' "$work/host.entitlements"
    ! grep -q 'com.apple.developer.endpoint-security.client' "$work/host.entitlements"
    grep -q 'com.apple.developer.endpoint-security.client' "$work/extension.entitlements"
    ! grep -q 'com.apple.developer.system-extension.install' "$work/extension.entitlements"
    test -f "$app/Contents/Resources/SELF_USE_SIP_OFF.txt"
    grep -q 'SELF-USE / SIP-OFF' "$app/Contents/Resources/SELF_USE_SIP_OFF.txt"
    grep -qx 'SAFETY_GATE=mac-auth-scope-v1' \
        "$app/Contents/Resources/SELF_USE_SIP_OFF.txt"
else
    ! grep -q 'com.apple.developer.system-extension.install' "$work/host.entitlements"
    ! grep -q 'com.apple.developer.endpoint-security.client' "$work/host.entitlements"
    ! grep -q 'com.apple.developer.endpoint-security.client' "$work/extension.entitlements"
    ! grep -q 'com.apple.developer.system-extension.install' "$work/extension.entitlements"
fi
for helper in "$app/Contents/MacOS/guardctl" "$app/Contents/MacOS/guard-notify"; do
    codesign -d --entitlements :- "$helper" >"$work/helper.entitlements" 2>/dev/null || true
    ! grep -q 'com.apple.developer.endpoint-security.client' "$work/helper.entitlements"
    ! grep -q 'com.apple.developer.system-extension.install' "$work/helper.entitlements"
done

for code in "$app" "$extension" "$app/Contents/MacOS/guardctl" \
    "$app/Contents/MacOS/guard-notify"; do
    codesign -dvv "$code" 2>&1 | grep -q 'runtime'
done

find "$app/Contents/Frameworks" "$app/Contents/Resources/gdk-pixbuf/loaders" \
    -type f -print | while IFS= read -r target; do
    file "$target" | grep -q 'Mach-O' || continue
    codesign --verify --strict "$target"
    lipo -archs "$target" | tr ' ' '\n' | grep -qx "$expected_arch" || {
        echo "required architecture $expected_arch missing from $target" >&2
        exit 2
    }
    if otool -L "$target" | grep -E '/opt/homebrew|/usr/local|/Cellar/'; then
        echo "external package-manager dependency remains in $target" >&2
        exit 2
    fi
done

for executable in "$app/Contents/MacOS/SensitiveFileGuard" "$app/Contents/MacOS/guardctl" \
    "$app/Contents/MacOS/guard-notify" "$extension/Contents/MacOS/guard-es"; do
    lipo -archs "$executable" | tr ' ' '\n' | grep -qx "$expected_arch" || {
        echo "required architecture $expected_arch missing from $executable" >&2
        exit 2
    }
    if otool -L "$executable" | grep -E '/opt/homebrew|/usr/local|/Cellar/'; then
        echo "external package-manager dependency remains in $executable" >&2
        exit 2
    fi
done

grep -q '@GUARD_APP@/Contents/Resources/gdk-pixbuf/loaders' \
    "$app/Contents/Resources/gdk-pixbuf/loaders.cache.in"
! grep -E '/opt/homebrew|/usr/local|/Cellar/' \
    "$app/Contents/Resources/gdk-pixbuf/loaders.cache.in"

if [ "${VERIFY_GATEKEEPER:-0}" = 1 ]; then
    spctl --assess --type execute --verbose=4 "$app"
fi
echo "PASS: self-contained $signing_mode-signed Sensitive File Guard.app verified for $expected_arch"
