# macOS Alpha release, update, and recovery

This is the release packaging path. The development bundle remains separate and
may resolve GTK from Homebrew. A release bundle copies only recursively reached
non-system Mach-O dependencies into `Guard.app/Contents/Frameworks`, rewrites
their install names, bundles GTK runtime metadata/image loaders, applies the
hardened runtime, and signs nested code explicitly from the inside out.

## Scope and architecture

The current acceptance/build host is Apple Silicon. Until another architecture
is built and tested, the only valid claim is: **macOS Alpha tested on arm64
only**. The scripts verify every bundled Mach-O contains the expected host
architecture and do not claim universal2/x86_64.

The bundled CLI remains at:

```text
/Applications/Guard.app/Contents/MacOS/guardctl
```

Installation does not alter shell profiles or silently create `/usr/local/bin`
links. An administrator may create a symlink explicitly, but the signed in-app
path is the documented default.

## Build and local verification

Required external values are not stored in source control:

```sh
APP_BUNDLE_ID=com.example.Guard \
SYSTEM_EXTENSION_BUNDLE_ID=com.example.Guard.guard-es \
DEVELOPMENT_TEAM=ABCDE12345 \
SIGNING_IDENTITY='Developer ID Application: Example (ABCDE12345)' \
HOST_PROVISIONING_PROFILE=/secure/Guard.provisionprofile \
EXTENSION_PROVISIONING_PROFILE=/secure/GuardES.provisionprofile \
GUARD_VERSION=0.1.0 GUARD_BUILD_NUMBER=1 \
scripts/macos/build-release-app.sh
```

The result is `build/macos-release/Guard.app` plus an arm64 zip. The script
requires both provisioning profiles unless `LOCAL_SIGNING_ONLY=1` is explicitly
set. That override exists only for deterministic local packaging tests; its
output is not distributable, cannot prove ES activation, and is labeled as
such. `CODESIGN_TIMESTAMP=none` is likewise local-test-only.

Verification is repeatable:

```sh
scripts/macos/verify-bundle.sh build/macos-release/Guard.app
HOME="$(mktemp -d)" \
  build/macos-release/Guard.app/Contents/MacOS/Guard --packaging-smoke
```

For an explicitly local-only artifact built with `LOCAL_SIGNING_ONLY=1`, use
`VERIFY_SIGNING_MODE=local scripts/macos/verify-bundle.sh ...`. The normal
verification mode requires embedded provisioning profiles and the scoped
restricted entitlements; local mode instead requires those restricted
entitlements to be absent so AMFI can launch the smoke-test artifact.

`verify-bundle.sh` checks layout, plists, arm64 slices, explicit nested
signatures, hardened runtime, scoped entitlements, GTK loader metadata, and all
Mach-O dependency paths. Any `/opt/homebrew`, `/usr/local`, or Cellar runtime
reference fails the build. Verification may use `codesign --deep`; signing
never does.

Bundled components and license families are recorded in
`packaging/macos/THIRD_PARTY_NOTICES.md`, which is copied into
`Contents/Resources`. Exact corresponding-source archives/full license texts
must accompany the Alpha download or be offered beside it.

## Notarization

Store notarization credentials outside the repository, for example:

```sh
xcrun notarytool store-credentials GuardNotary \
  --apple-id ACCOUNT --team-id ABCDE12345 --password APP_SPECIFIC_PASSWORD
```

Then run:

```sh
NOTARY_KEYCHAIN_PROFILE=GuardNotary \
scripts/macos/notarize-release.sh build/macos-release/Guard.app
```

The script verifies, archives, submits with `notarytool --wait`, staples,
validates the ticket, runs Gatekeeper assessment, re-verifies, and recreates the
distribution zip from the stapled app. It never prints or copies credentials.

## Install and first activation

1. Place the notarized `Guard.app` in `/Applications`.
2. Launch Guard and request system-extension activation.
3. If macOS reports waiting for approval, approve the extension in ordinary
   System Settings. A restart-required result remains visible until restart.
4. Grant Full Disk Access through System Settings if status reports
   `REQUIRES_FULL_DISK_ACCESS`. Guard never edits TCC and never instructs users
   to disable SIP/Secure Boot.
5. Register the pending helper using the separate UI switch. Its SMAppService
   status/health is distinct from extension and FDA status.
6. Enable protection only after the backend state is `ACTIVE` or intentionally
   reviewed `DEGRADED`.

An extension lifecycle callback saying “activation completed” is not by itself
an enforcement claim. Product status is ACTIVE only after the ES client/XPC is
usable and policy is enabled.

## Stable data and update contract

Authoritative macOS state is stable across app replacement:

```text
/Library/Application Support/Sensitive Data Firewall/config.json
/Library/Application Support/Sensitive Data Firewall/audit.db
```

The directory and files are root-owned/restrictive when created. Updaters
replace only `Guard.app`; they do not move, read, or delete browser profiles,
SSH keys, config content, or audit rows. Phase 10 makes no config schema change;
the existing versioned schema remains compatible with the previous Alpha.

Update lifecycle:

```text
install new Guard.app
→ request activation/replacement of its bundled extension
→ honor approval/restart/failure state
→ new extension reloads the existing config/resource index
→ process graph, pending OS operations, and all leases start empty
→ one exact SMAppService label replaces/reuses the helper registration
→ protocol mismatch fails explicitly instead of running mixed implementations
```

SystemExtensions replacement returns the explicit Replace action. Do not run
old/new extensions concurrently. If activation fails, retain the previous app
until recovery is complete; use diagnostics below and request activation again
or reinstall the previously signed version. Temporary leases never cross an
extension restart or rollback.

Local two-version regression:

```sh
SIGNING_IDENTITY='Apple Development: …' DEVELOPMENT_TEAM=ABCDE12345 \
scripts/macos/test-release-update.sh
```

It builds/signs two local versions, initializes bundled GTK twice, verifies
version replacement, preserves synthetic config/audit/browser canaries, and
checks recovery dry-run targets. It never uses real protected data.

## Diagnostics and recovery

Metadata-only diagnostics:

```sh
scripts/macos/diagnose.sh /Applications/Guard.app
```

This inspects signatures, entitlements, lifecycle, authenticated health,
helper status, protocol/version, and config/audit file metadata. It never opens
config contents, audit rows, browser data, or SSH keys.

Before uninstall, disable protection in Guard. Then inspect the deterministic
plan:

```sh
GUARD_APP=/Applications/Guard.app \
scripts/macos/uninstall-recovery.sh --dry-run --preserve-data --remove-app --confirm
```

Run again without `--dry-run` to unregister SMAppService, request system
extension deactivation, and move the app to Trash. A restart-required state must
be completed before considering deactivation final. Config/audit are preserved
by default. Only the explicit `--remove-product-data --confirm` option removes
the four exact product DB/config paths, using administrator authorization.
Browser profiles and SSH keys are never deletion targets.
