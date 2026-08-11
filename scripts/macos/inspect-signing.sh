#!/bin/sh
set -eu

if [ "$(uname -s)" != "Darwin" ]; then
    echo "inspect-signing.sh requires macOS" >&2
    exit 2
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH= cd -- "$script_dir/../.." && pwd)
app_bundle=${1:-"$repo_dir/build/macos/Guard.app"}

if [ ! -d "$app_bundle/Contents/Library/SystemExtensions" ]; then
    echo "not a Guard development app bundle: $app_bundle" >&2
    exit 2
fi
extension_bundle=$(find "$app_bundle/Contents/Library/SystemExtensions" -maxdepth 1 -type d -name '*.systemextension' -print | head -n 1)
if [ -z "$extension_bundle" ]; then
    echo "system extension bundle not found" >&2
    exit 2
fi

plutil -lint "$app_bundle/Contents/Info.plist"
plutil -lint "$extension_bundle/Contents/Info.plist"
codesign --verify --deep --strict --verbose=2 "$app_bundle"
codesign -d --verbose=4 "$app_bundle" 2>&1
codesign -d --entitlements :- "$app_bundle" 2>/dev/null
codesign -d --verbose=4 "$extension_bundle" 2>&1
codesign -d --entitlements :- "$extension_bundle" 2>/dev/null
otool -L "$app_bundle/Contents/MacOS/Guard"
otool -L "$extension_bundle/Contents/MacOS/guard-es"
