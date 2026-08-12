#!/bin/sh
set -eu

if [ "$(uname -s)" != "Darwin" ]; then
    echo "build-release-app.sh requires macOS" >&2
    exit 2
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH= cd -- "$script_dir/../.." && pwd)
build_root=${MACOS_RELEASE_ROOT:-"$repo_dir/build/macos-release"}
app="$build_root/Guard.app"
version=${GUARD_VERSION:-0.1.0}
architecture=$(uname -m)
local_only=${LOCAL_SIGNING_ONLY:-0}
self_use=${SELF_USE_SIP_OFF:-0}

case "$local_only" in 0|1) ;; *) echo "LOCAL_SIGNING_ONLY must be 0 or 1" >&2; exit 2 ;; esac
case "$self_use" in 0|1) ;; *) echo "SELF_USE_SIP_OFF must be 0 or 1" >&2; exit 2 ;; esac
if [ "$local_only" = 1 ] && [ "$self_use" = 1 ]; then
    echo "LOCAL_SIGNING_ONLY and SELF_USE_SIP_OFF are mutually exclusive" >&2
    exit 2
fi
if [ "$self_use" = 1 ]; then
    identity=${SELF_USE_SIGNING_IDENTITY:?SELF_USE_SIGNING_IDENTITY is required for SELF_USE_SIP_OFF=1}
    signing_keychain=${SELF_USE_SIGNING_KEYCHAIN:-}
    if [ -n "$signing_keychain" ]; then
        keychain_password=$(security find-generic-password -a "$signing_keychain" \
            -s top.plfjy.SensitiveFileGuard.self-use-keychain -w 2>/dev/null || \
            security find-generic-password -a "$USER" \
                -s top.plfjy.SensitiveFileGuard.self-use-keychain -w 2>/dev/null) || {
            echo "cannot unlock SELF_USE_SIGNING_KEYCHAIN: local keychain password is unavailable" >&2
            exit 2
        }
        security unlock-keychain -p "$keychain_password" "$signing_keychain"
        unset keychain_password
    fi
    identity=$("$script_dir/resolve-self-use-signing-identity.sh" \
        "$identity" "$signing_keychain")
    signing_mode=self-use
elif [ "$local_only" = 1 ]; then
    identity=${SIGNING_IDENTITY:?SIGNING_IDENTITY is required}
    signing_mode=local
else
    identity=${SIGNING_IDENTITY:?SIGNING_IDENTITY is required}
    team=${DEVELOPMENT_TEAM:?DEVELOPMENT_TEAM is required}
    signing_mode=release
fi

if [ "$signing_mode" = self-use ]; then
    "$script_dir/self-use-safety-gate.sh"
fi
case "$build_root" in /|"$repo_dir") echo "unsafe MACOS_RELEASE_ROOT: $build_root" >&2; exit 2 ;; esac
if [ "$signing_mode" = release ]; then
    : "${HOST_PROVISIONING_PROFILE:?HOST_PROVISIONING_PROFILE is required}"
    : "${EXTENSION_PROVISIONING_PROFILE:?EXTENSION_PROVISIONING_PROFILE is required}"
    test -f "$HOST_PROVISIONING_PROFILE" || {
        echo "host provisioning profile not found: $HOST_PROVISIONING_PROFILE" >&2
        exit 2
    }
    test -f "$EXTENSION_PROVISIONING_PROFILE" || {
        echo "extension provisioning profile not found: $EXTENSION_PROVISIONING_PROFILE" >&2
        exit 2
    }
fi

for command_name in codesign ditto file; do
    command -v "$command_name" >/dev/null 2>&1 || {
        echo "missing required command: $command_name" >&2
        exit 2
    }
done

SELF_USE_SIP_OFF=0 MACOS_BUILD_ROOT="$build_root" BUILD_PROFILE=release SKIP_SIGNING=1 \
    "$script_dir/build-dev-app.sh"
"$script_dir/bundle-gtk-runtime.sh" "$app"

if [ "$signing_mode" = self-use ]; then
    printf '%s\n%s\n' \
        'SELF-USE / SIP-OFF: local entitlement-bearing build; not notarized or distributable' \
        'SAFETY_GATE=mac-auth-scope-v1' \
        >"$app/Contents/Resources/SELF_USE_SIP_OFF.txt"
fi

extension=$(find "$app/Contents/Library/SystemExtensions" -maxdepth 1 \
    -type d -name '*.systemextension' -print | head -n 1)
test -n "$extension" || { echo "system extension is missing" >&2; exit 2; }

if [ "$signing_mode" = release ]; then
    cp "$HOST_PROVISIONING_PROFILE" "$app/Contents/embedded.provisionprofile"
    cp "$EXTENSION_PROVISIONING_PROFILE" \
        "$extension/Contents/embedded.provisionprofile"
fi

timestamp_flag=--timestamp
if [ "${CODESIGN_TIMESTAMP:-secure}" = none ]; then
    timestamp_flag=
fi

sign_code() {
    if [ -n "${signing_keychain:-}" ]; then
        codesign --force --sign "$identity" --keychain "$signing_keychain" \
            --options runtime $timestamp_flag "$@"
    else
        codesign --force --sign "$identity" --options runtime $timestamp_flag "$@"
    fi
}

sign_runtime_file() {
    sign_code "$1"
}

# Explicit inside-out signing. Only Mach-O loader/runtime files are included;
# resources and license text are sealed by the outer app signature.
find "$app/Contents/Frameworks" "$app/Contents/Resources/gdk-pixbuf/loaders" \
    -type f -print | sort | while IFS= read -r target; do
    if file "$target" | grep -q 'Mach-O'; then
        sign_runtime_file "$target"
    fi
done

app_id=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$app/Contents/Info.plist")
sign_code --identifier "$app_id.guardctl" "$app/Contents/MacOS/guardctl"
sign_code --identifier "$app_id.guard-notify" "$app/Contents/MacOS/guard-notify"
if [ "$signing_mode" = local ]; then
    # Restricted system-extension and Endpoint Security entitlements require
    # matching provisioning profiles. Omitting them makes this explicitly
    # local-only artifact executable for runtime/upgrade smoke tests.
    sign_code "$extension"
    sign_code "$app"
    verify_signing_mode=local
else
    sign_code --entitlements "$repo_dir/packaging/macos/GuardES.entitlements" "$extension"
    sign_code --entitlements "$repo_dir/packaging/macos/Guard.entitlements" "$app"
    verify_signing_mode=$signing_mode
fi

VERIFY_SIGNING_MODE="$verify_signing_mode" "$script_dir/verify-bundle.sh" "$app"
if [ "$signing_mode" = release ]; then
    signed_team=$(codesign -dvv "$app" 2>&1 | sed -n 's/^TeamIdentifier=//p')
    test "$signed_team" = "$team" || {
        echo "signed TeamIdentifier '$signed_team' does not match '$team'" >&2
        exit 2
    }
fi

archive="$build_root/Guard-$version-$architecture.zip"
rm -f -- "$archive"
ditto -c -k --keepParent "$app" "$archive"
echo "release bundle: $app"
echo "release archive: $archive"
echo "tested architecture claim: $architecture only"
if [ "$signing_mode" = local ]; then
    echo "LOCAL SIGNING ONLY: provisioning, activation, notarization, and distribution remain BLOCKED"
elif [ "$signing_mode" = self-use ]; then
    echo "SELF-USE SIP-OFF: entitlement-bearing local build created; run scripts/macos/self-use-preflight.sh before activation"
fi
