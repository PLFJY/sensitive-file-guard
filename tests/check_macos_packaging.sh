#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
scripts="$repo_dir/scripts/macos"
failed=0

for name in bundle-gtk-runtime.sh build-release-app.sh verify-bundle.sh \
    notarize-release.sh diagnose.sh uninstall-recovery.sh \
    test-release-update.sh preflight-final-acceptance.sh \
    create-self-use-signing-identity.sh build-deploy-self-use.sh; do
    if [ ! -x "$scripts/$name" ]; then
        echo "macOS packaging violation: missing executable script $name" >&2
        failed=1
    fi
done
if rg -n 'find-generic-password' \
    "$scripts/build-release-app.sh" "$scripts/build-dev-app.sh"; then
    echo "macOS packaging violation: build scripts bypass centralized keychain recovery" >&2
    failed=1
fi
if ! rg -Uq '(?s)find-generic-password.{0,200}"\$login_keychain"' \
    "$scripts/create-self-use-signing-identity.sh" || \
   ! rg -Uq '(?s)add-generic-password.{0,200}"\$login_keychain"' \
    "$scripts/create-self-use-signing-identity.sh"; then
    echo "macOS packaging violation: self-use password is not managed through the login keychain" >&2
    failed=1
fi
delete_count=$(rg -c 'security delete-keychain' \
    "$scripts/create-self-use-signing-identity.sh" || true)
if [ "$delete_count" -ne 1 ] || \
   ! rg -q 'newly created, otherwise unrecoverable keychain' \
    "$scripts/create-self-use-signing-identity.sh"; then
    echo "macOS packaging violation: existing signing keychain may be silently deleted" >&2
    failed=1
fi
if ! rg -q 'ensure_keychain_in_user_search_list' \
    "$scripts/create-self-use-signing-identity.sh" || \
   rg -Uq '(?s)list-keychains.{0,80}-s[[:space:]\\]*"\$keychain"[[:space:]\\]*"\$HOME/Library/Keychains/login' \
    "$scripts/create-self-use-signing-identity.sh"; then
    echo "macOS packaging violation: self-use keychain search-list update is absent or destructive" >&2
    failed=1
fi

if rg -n 'codesign[^\n]*--deep' "$scripts/build-release-app.sh"; then
    echo "macOS packaging violation: release signing must be explicitly inside-out" >&2
    failed=1
fi
if ! rg -q 'Contents/embedded\.provisionprofile' "$scripts/build-release-app.sh" || \
   ! rg -q 'extension/Contents/embedded\.provisionprofile' "$scripts/build-release-app.sh"; then
    echo "macOS packaging violation: release provisioning profiles are not embedded" >&2
    failed=1
fi
if ! rg -q 'Guard\.entitlements' "$scripts/build-release-app.sh" || \
   ! rg -q 'GuardES\.entitlements' "$scripts/build-release-app.sh"; then
    echo "macOS packaging violation: scoped release entitlements are not signed" >&2
    failed=1
fi
if ! rg -q 'LOCAL_SIGNING_ONLY' "$scripts/build-release-app.sh" || \
   ! rg -q 'verify_signing_mode=local' "$scripts/build-release-app.sh"; then
    echo "macOS packaging violation: local-only test artifacts are not distinguished" >&2
    failed=1
fi
if ! rg -q 'notarytool submit.*--keychain-profile.*--wait' \
    "$scripts/notarize-release.sh" || \
   ! rg -q 'stapler staple' "$scripts/notarize-release.sh" || \
   ! rg -q 'spctl --assess' "$scripts/notarize-release.sh"; then
    echo "macOS packaging violation: notarize/staple/Gatekeeper pipeline is incomplete" >&2
    failed=1
fi
if rg -n 'csrutil[[:space:]]+disable|spctl[[:space:]]+--master-disable|tccutil[[:space:]]+reset|docker' \
    "$scripts/bundle-gtk-runtime.sh" "$scripts/build-release-app.sh" \
    "$scripts/notarize-release.sh" "$scripts/diagnose.sh" \
    "$scripts/uninstall-recovery.sh" "$scripts/test-release-update.sh" \
    "$scripts/preflight-final-acceptance.sh"; then
    echo "macOS packaging violation: security relaxation or Docker command found" >&2
    failed=1
fi
if ! rg -q 'config\.json.*audit\.db' "$scripts/uninstall-recovery.sh" || \
   rg -n 'Library/Application Support/(Google|Firefox)|\.ssh' \
       "$scripts/uninstall-recovery.sh"; then
    echo "macOS packaging violation: recovery deletion scope is not product-only" >&2
    failed=1
fi

if [ "$failed" -ne 0 ]; then
    exit 1
fi
echo "PASS: macOS release packaging boundaries are clean"
