#!/bin/sh
set -eu

if [ "$(uname -s)" != "Darwin" ]; then
    echo "build-dev-app.sh requires macOS and the active Xcode SDK" >&2
    exit 2
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH= cd -- "$script_dir/../.." && pwd)
build_root=${MACOS_BUILD_ROOT:-"$repo_dir/build/macos"}
app_bundle="$build_root/Sensitive File Guard.app"
app_bundle_id=${APP_BUNDLE_ID:-top.plfjy.SensitiveFileGuard}
extension_bundle_id=${SYSTEM_EXTENSION_BUNDLE_ID:-"$app_bundle_id.guard-es"}
guard_xpc_service_name=${GUARD_XPC_SERVICE_NAME:-"$extension_bundle_id.control"}
notify_label="$app_bundle_id.guard-notify"
user_agent_plist_name="$notify_label.plist"
version=${GUARD_VERSION:-0.1.0}
build_number=${GUARD_BUILD_NUMBER:-1}
build_profile=${BUILD_PROFILE:-debug}
self_use_identity=${SFG_SELF_USE_SIGNING_IDENTITY:-'Sensitive File Guard Local Development'}
self_use_keychain=${SFG_SELF_USE_SIGNING_KEYCHAIN:-"$HOME/Library/Keychains/SensitiveFileGuardSelfUse.keychain-db"}
signing_identity=${SIGNING_IDENTITY:--}
self_use=${SELF_USE_SIP_OFF:-0}

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
validate_bundle_id "$guard_xpc_service_name"
case "$self_use" in 0|1) ;; *) echo "SELF_USE_SIP_OFF must be 0 or 1" >&2; exit 2 ;; esac
if [ "$self_use" = 1 ]; then
    signing_identity=$self_use_identity
    test "$signing_identity" != - || {
        echo "SELF_USE_SIP_OFF requires a local certificate; ad-hoc signing is not valid for authenticated XPC" >&2
        exit 2
    }
    test "${SKIP_SIGNING:-0}" != 1 || {
        echo "SELF_USE_SIP_OFF cannot be combined with SKIP_SIGNING=1" >&2
        exit 2
    }
    if ! "$script_dir/resolve-self-use-signing-identity.sh" \
        "$signing_identity" "$self_use_keychain" >/dev/null 2>&1; then
        SFG_SELF_USE_SIGNING_IDENTITY="$signing_identity" \
        SFG_SELF_USE_SIGNING_KEYCHAIN="$self_use_keychain" \
            "$script_dir/create-self-use-signing-identity.sh"
    fi
    keychain_password=$(security find-generic-password -a "$self_use_keychain" \
        -s top.plfjy.SensitiveFileGuard.self-use-keychain -w 2>/dev/null || \
        security find-generic-password -a "$USER" \
            -s top.plfjy.SensitiveFileGuard.self-use-keychain -w 2>/dev/null) || {
        echo "cannot unlock self-use signing keychain: $self_use_keychain" >&2
        exit 2
    }
    security unlock-keychain -p "$keychain_password" "$self_use_keychain"
    unset keychain_password
    signing_identity=$("$script_dir/resolve-self-use-signing-identity.sh" \
        "$signing_identity" "$self_use_keychain")
    "$script_dir/self-use-safety-gate.sh"
fi
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
case "${GUARD_ES_POC:-0}" in
    0) feature_flags= ;;
    1)
        : "${GUARD_ES_POC_FILE:?GUARD_ES_POC_FILE is required when GUARD_ES_POC=1}"
        : "${GUARD_ES_POC_ALLOW_EXE:?GUARD_ES_POC_ALLOW_EXE is required when GUARD_ES_POC=1}"
        feature_flags="--features guard-es/es-poc"
        ;;
    *) echo "GUARD_ES_POC must be 0 or 1" >&2; exit 2 ;;
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
GUARD_APP_BUNDLE_ID="$app_bundle_id" \
GUARD_SYSTEM_EXTENSION_BUNDLE_ID="$extension_bundle_id" \
GUARD_XPC_SERVICE_NAME="$guard_xpc_service_name" \
GUARD_USER_AGENT_PLIST_NAME="$user_agent_plist_name" \
    cargo build -p guard-ui -p guard-es -p guardctl -p guard-notify $cargo_flags $feature_flags

if [ -e "$app_bundle" ]; then
    rm -rf -- "$app_bundle"
fi
extension_bundle="$app_bundle/Contents/Library/SystemExtensions/$extension_bundle_id.systemextension"
mkdir -p "$app_bundle/Contents/MacOS" "$extension_bundle/Contents/MacOS"
mkdir -p "$app_bundle/Contents/Library/LaunchAgents"
cp "target/$cargo_profile/guard-ui" "$app_bundle/Contents/MacOS/SensitiveFileGuard"
cp "target/$cargo_profile/guardctl" "$app_bundle/Contents/MacOS/guardctl"
cp "target/$cargo_profile/guard-notify" "$app_bundle/Contents/MacOS/guard-notify"
cp "target/$cargo_profile/guard-es" "$extension_bundle/Contents/MacOS/guard-es"

render_plist() {
    input=$1
    output=$2
    sed \
        -e "s|@APP_BUNDLE_ID@|$app_bundle_id|g" \
        -e "s|@EXTENSION_BUNDLE_ID@|$extension_bundle_id|g" \
        -e "s|@XPC_SERVICE_NAME@|$guard_xpc_service_name|g" \
        -e "s|@NOTIFY_LABEL@|$notify_label|g" \
        -e "s|@VERSION@|$version|g" \
        -e "s|@BUILD_NUMBER@|$build_number|g" \
        "$input" >"$output"
    plutil -lint "$output" >/dev/null
}

render_plist packaging/macos/Guard.Info.plist.in "$app_bundle/Contents/Info.plist"
render_plist packaging/macos/GuardES.Info.plist.in "$extension_bundle/Contents/Info.plist"
render_plist packaging/macos/GuardNotify.LaunchAgent.plist.in \
    "$app_bundle/Contents/Library/LaunchAgents/$user_agent_plist_name"
mkdir -p "$app_bundle/Contents/Resources"
"$script_dir/build-app-icon.sh" \
    "$repo_dir/data/io.github.plfjy.SensitiveFileGuard.svg" \
    "$app_bundle/Contents/Resources/SensitiveFileGuard.icns"

if [ -n "${HOST_PROVISIONING_PROFILE:-}" ] || [ -n "${EXTENSION_PROVISIONING_PROFILE:-}" ]; then
    : "${HOST_PROVISIONING_PROFILE:?both host and extension provisioning profiles are required}"
    : "${EXTENSION_PROVISIONING_PROFILE:?both host and extension provisioning profiles are required}"
    test -f "$HOST_PROVISIONING_PROFILE" || {
        echo "host provisioning profile not found: $HOST_PROVISIONING_PROFILE" >&2
        exit 2
    }
    test -f "$EXTENSION_PROVISIONING_PROFILE" || {
        echo "extension provisioning profile not found: $EXTENSION_PROVISIONING_PROFILE" >&2
        exit 2
    }
    cp "$HOST_PROVISIONING_PROFILE" "$app_bundle/Contents/embedded.provisionprofile"
    cp "$EXTENSION_PROVISIONING_PROFILE" "$extension_bundle/Contents/embedded.provisionprofile"
fi

if [ "$self_use" = 1 ]; then
    printf '%s\n%s\n' \
        'SELF-USE / SIP-OFF development bundle; not notarized or distributable' \
        'SAFETY_GATE=mac-auth-scope-v1' \
        >"$app_bundle/Contents/Resources/SELF_USE_SIP_OFF.txt"
fi

if [ "${SKIP_SIGNING:-0}" != "1" ]; then
    sign_code() {
        if [ -n "$self_use_keychain" ]; then
            codesign --force --sign "$signing_identity" --keychain "$self_use_keychain" "$@"
        else
            codesign --force --sign "$signing_identity" "$@"
        fi
    }
    sign_code \
        --identifier "$app_bundle_id.guardctl" \
        "$app_bundle/Contents/MacOS/guardctl"
    sign_code \
        --identifier "$app_bundle_id.guard-notify" \
        "$app_bundle/Contents/MacOS/guard-notify"
    sign_code \
        --entitlements packaging/macos/GuardES.entitlements \
        "$extension_bundle"
    sign_code \
        --entitlements packaging/macos/Guard.entitlements \
        "$app_bundle"
    codesign --verify --deep --strict "$app_bundle"

    signed_team=$(codesign -dvv "$app_bundle" 2>&1 | sed -n 's/^TeamIdentifier=//p')
    if [ "$signed_team" = "not set" ]; then
        signed_team=
    fi
    if [ "$self_use" = 0 ] && [ -n "${DEVELOPMENT_TEAM:-}" ] \
        && [ "$signed_team" != "$DEVELOPMENT_TEAM" ]; then
        echo "signed TeamIdentifier '$signed_team' does not match DEVELOPMENT_TEAM '$DEVELOPMENT_TEAM'" >&2
        exit 2
    fi
fi

echo "assembled development bundle: $app_bundle"
echo "app bundle id: $app_bundle_id"
echo "system extension bundle id: $extension_bundle_id"
echo "Endpoint Security Mach service: $guard_xpc_service_name"
echo "pending helper LaunchAgent: $user_agent_plist_name"
echo "signing identity: $signing_identity"
if [ "${SKIP_SIGNING:-0}" = "1" ]; then
    echo "signing skipped"
elif [ -n "$signed_team" ]; then
    echo "signed TeamIdentifier: $signed_team"
elif [ "$self_use" = 1 ]; then
    echo "signed local certificate identity: TeamIdentifier intentionally not set"
else
    echo "signed TeamIdentifier: not set (ad-hoc bundles cannot activate for release acceptance)"
fi
