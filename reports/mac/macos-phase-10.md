# macOS Phase 10 — Packaging, Signing, Installation, Update, and Recovery

## Phase and base

- Phase 10 — Packaging, Signing, Installation, Update, and Recovery
- starting commit / branch: `9cf41b0` / `main`
- macOS 26.6.1 (25G76), arm64
- Xcode 26.6 (17F113), macOS SDK 26.5
- rustc 1.97.0
- GTK 4.22.4 / libadwaita 1.9.3

## Implemented

- Added a deterministic self-contained `Guard.app` release path. It builds the
  Rust binaries in release mode, recursively follows only reached non-system
  Mach-O dependencies, copies 44 dylibs and 13 GdkPixbuf loader modules, and
  rewrites IDs/dependencies to bundle-relative `@rpath`/`@loader_path` values.
- Bundled compiled GLib schemas, GdkPixbuf loader metadata, hicolor icon-theme
  metadata, a release-runtime marker, and third-party notices. It does not copy
  an entire Homebrew prefix.
- Added pre-GTK runtime relocation in Guard. It creates a metadata-only loader
  cache under the current user's Library cache, escapes relocated app paths,
  and sets GTK data/loader paths before GTK threads start. Development bundles
  without the marker retain their normal development environment.
- Added hidden packaging smoke mode that initializes bundled GTK/libadwaita and
  exits without opening a control-plane window or contacting protected data.
- Added explicit inside-out hardened-runtime signing for runtime dylibs/loaders,
  CLI, helper, system extension, and host app. Signing never uses
  `codesign --deep`; recursive verification is used only to verify the result.
- Kept the host system-extension-install entitlement separate from the
  Endpoint Security client entitlement. Helpers receive neither entitlement.
  The normal release path requires and embeds separate host/extension
  provisioning profiles before applying those restricted entitlements.
- Separated local packaging tests from release signing. `LOCAL_SIGNING_ONLY=1`
  deliberately omits restricted entitlements because Apple AMFI requires a
  matching provisioning profile for them. Verification requires restricted
  entitlements to be absent in local mode and present/scoped in release mode.
- Added external-Keychain-profile notarization using `notarytool --wait`,
  stapling, ticket validation, Gatekeeper assessment, strict bundle
  re-verification, and archive recreation. Credentials are neither printed nor
  stored in the repository.
- Added deterministic SMAppService registration/unregistration commands for
  install/update/recovery automation while keeping helper state separate from
  extension and Endpoint Security health.
- Added a two-version update regression that launches bundled GTK for both
  versions and checks synthetic config, audit, and browser canaries remain
  byte-identical. Existing process graphs, pending OS operations, and leases
  remain memory-only and are not restored after extension restart.
- Added metadata-only diagnostics covering bundle signatures, lifecycle,
  helper state, authenticated XPC health, CLI version, and config/audit file
  metadata. It never opens configuration contents, audit rows, browser data,
  or SSH keys.
- Added an explicit recovery/uninstall path: fail if live enforcement is
  active, unregister the helper, request extension deactivation, preserve
  product state by default, optionally remove only four exact product state
  files, and optionally move Guard.app to Trash. Browser profiles and SSH keys
  are never deletion targets.
- Documented release vs development builds, arm64-only test claims,
  installation/approval/FDA, stable state, extension replacement, rollback,
  diagnostics, recovery, CLI location, license obligations, and notarization.

## Principal files

- `scripts/macos/bundle-gtk-runtime.sh`
- `scripts/macos/build-release-app.sh`
- `scripts/macos/verify-bundle.sh`
- `scripts/macos/notarize-release.sh`
- `scripts/macos/test-release-update.sh`
- `scripts/macos/diagnose.sh`
- `scripts/macos/uninstall-recovery.sh`
- `apps/guard-ui/src/main.rs`
- `apps/guard-ui/src/platform_service.rs`
- `packaging/macos/THIRD_PARTY_NOTICES.md`
- `tests/check_macos_packaging.sh`
- `docs/INSTALL_MACOS_RELEASE.md`
- `docs/INSTALL_MACOS_DEV.md`

## Commands run

```text
cargo fmt --check

cargo clippy \
  -p guard-audit -p guard-browser -p guard-client -p guard-core \
  -p guard-es -p guard-ipc -p guard-notify -p guard-platform \
  -p guard-runtime -p guard-ssh -p guard-test-fixtures \
  -p guard-test-probe -p guard-ui -p guardctl -p platform-macos \
  --all-targets --all-features -- -D warnings

cargo test \
  -p guard-audit -p guard-browser -p guard-client -p guard-core \
  -p guard-es -p guard-ipc -p guard-notify -p guard-platform \
  -p guard-runtime -p guard-ssh -p guard-test-fixtures \
  -p guard-test-probe -p guard-ui -p guardctl -p platform-macos \
  --all-targets --all-features

xcrun clang -fsyntax-only -fobjc-arc -fblocks -fmodules \
  -Wall -Wextra -Werror -mmacosx-version-min=13.0 -Inative/macos \
  native/macos/system_extension_bridge.m \
  native/macos/code_signature_bridge.m native/macos/xpc_bridge.m \
  native/macos/local_auth_bridge.m native/macos/user_agent_bridge.m \
  native/macos/xpc_wrong_signed_probe.m

xcrun clang -fsyntax-only -fblocks -Wall -Wextra -Werror \
  -mmacosx-version-min=13.0 -Inative/macos \
  native/macos/endpoint_security_bridge.c

tests/check_platform_boundaries.sh
tests/check_macos_boundaries.sh
tests/check_macos_packaging.sh
sh -n scripts/macos/*.sh tests/check_macos*.sh
git diff --check

SIGNING_IDENTITY='Apple Development: …' DEVELOPMENT_TEAM=YSGFZUQGW6 \
LOCAL_SIGNING_ONLY=1 CODESIGN_TIMESTAMP=none \
scripts/macos/build-release-app.sh

VERIFY_SIGNING_MODE=local \
scripts/macos/verify-bundle.sh build/macos-release/Guard.app

HOME=<isolated temporary directory> \
build/macos-release/Guard.app/Contents/MacOS/Guard --packaging-smoke

SIGNING_IDENTITY='Apple Development: …' DEVELOPMENT_TEAM=YSGFZUQGW6 \
scripts/macos/test-release-update.sh

VERIFY_SIGNING_MODE=local \
scripts/macos/diagnose.sh build/macos-release/Guard.app

build/macos-release/Guard.app/Contents/MacOS/Guard \
  --register-pending-helper
build/macos-release/Guard.app/Contents/MacOS/Guard \
  --pending-helper-status
build/macos-release/Guard.app/Contents/MacOS/Guard \
  --unregister-pending-helper

scripts/macos/uninstall-recovery.sh build/macos-release/Guard.app \
  --dry-run --preserve-data --remove-app --confirm
```

## Results

| Test | Result | Notes |
|---|---|---|
| Rust formatting | PASS | `cargo fmt --check` |
| macOS selected-package Clippy | PASS | Warnings denied; Linux excluded |
| Rust unit/integration | PASS | 203 passed, 0 failed; synthetic fixtures only |
| Native bridge strict compile | PASS | C/Objective-C warnings denied |
| Platform/packaging boundaries | PASS | No deep signing, TCC/SIP relaxation, Docker, or broad removal |
| Release-mode Rust build | PASS | Optimized arm64 binaries |
| Self-contained runtime graph | PASS | 44 dylibs and 13 loaders; no package-manager runtime paths |
| Bundled GTK launch | PASS | Isolated HOME; loader cache generated; exit 0 |
| Explicit nested signatures | PASS | Strict component and recursive verification |
| Hardened runtime | PASS | Host, extension, CLI, helper, and runtime code |
| Local entitlement separation | PASS | Restricted entitlement claims absent without profiles |
| Formal entitlement/profile gate | PASS | Missing host profile stops before release build |
| Local two-version update | PASS | 0.1.0 → 0.1.1; app restart succeeds |
| Synthetic state persistence | PASS | Config/audit/browser canaries unchanged |
| Runtime access reset | PASS | Pending operations/leases not restored by fresh runtime tests |
| SMAppService lifecycle | PASS | Registered → Enabled → unregistered → NotRegistered |
| Metadata-only diagnostics | PASS | Does not inspect protected/source contents |
| Recovery/uninstall dry-run | PASS | Product state preserved; source data excluded |
| Activation request path | PASS | Real SystemExtensions request made; failed closed without entitlement |
| User-approval-required lifecycle | PASS | Native callback/state mapping and UI presentation |
| FDA-required lifecycle | PASS | Typed ES error/backend-state/UI mapping; never edits TCC |
| Extension replacement action | PASS | Native replacement delegate returns Replace |
| Provisioned ES activation/restart | BLOCKED | Matching Apple profiles/authorized ES entitlement unavailable |
| Formal Developer ID release | BLOCKED | Host has only one Apple Development identity |
| Notarization/stapling | BLOCKED | No Keychain notary profile or distributable signed bundle |
| Gatekeeper local artifact | EXPECTED FAIL | Exit 3; local-only Apple Development artifact is not distributable |
| x86_64/universal2 | NOT RUN | Only arm64 is claimed/tested |
| Linux build/test | NOT RUN | Outside user scope |
| Docker | NOT STARTED | Explicitly prohibited |

The generated local artifact is 45 MiB and its zip is 16 MiB. Every bundled
Mach-O contains arm64. This is a local packaging-test artifact, not a
notarized/security-accepted distribution.

## Failures found and fixed during the phase

1. Initial dependency relocation did not resolve `@rpath/librsvg-2.2.dylib`.
   Dependency discovery now uses each source Mach-O's LC_RPATH values.
2. GdkPixbuf loader install IDs retained a Homebrew path. Loader IDs now use a
   loader-relative ID and dependencies point to bundled Frameworks.
3. The first local bundle carried restricted entitlements without matching
   provisioning profiles. Static `codesign` verification passed, but AMFI
   killed Guard at exec with `No matching profile found` (exit 137). The local
   and formal signing modes are now distinct and verify opposite entitlement
   expectations; the rebuilt bundle launches successfully.
4. The final Rust gate caught an incorrect escaped-path test literal. The test
   was corrected to assert the actual single-backslash cache escape, then the
   complete 203-test gate passed.

No failed check was reported as a pass.

## External blockers

Formal release mode stops deterministically before building without profiles:

```text
HOST_PROVISIONING_PROFILE: HOST_PROVISIONING_PROFILE is required
```

The actual local activation request failed closed:

```text
system-extension state=Failed diagnostic=Missing entitlement com.apple.developer.system-extension.install
system-extension state=Unknown diagnostic=system extension is not installed
```

This is expected for the intentionally entitlement-free local smoke artifact.
Adding an entitlement claim without its Apple-issued matching profile is not a
workaround: AMFI rejects it. Root/password access cannot manufacture the
restricted Endpoint Security authorization or a Developer ID identity.

Notarization also stops before reading/submitting an archive:

```text
NOTARY_KEYCHAIN_PROFILE: NOTARY_KEYCHAIN_PROFILE is required
```

On an authorized release host, the deterministic remaining commands are:

```text
SIGNING_IDENTITY='Developer ID Application: …' \
DEVELOPMENT_TEAM=<team> \
HOST_PROVISIONING_PROFILE=<secure host profile> \
EXTENSION_PROVISIONING_PROFILE=<secure ES profile> \
scripts/macos/build-release-app.sh

NOTARY_KEYCHAIN_PROFILE=<external Keychain profile> \
scripts/macos/notarize-release.sh build/macos-release/Guard.app
```

Then install the stapled app in `/Applications`, request activation, approve it
in System Settings, grant FDA through System Settings, and rerun the existing
Phase 03/07/08/09 live synthetic acceptance scripts. Do not disable SIP/Secure
Boot or modify TCC directly.

## Bundled component versions observed

The principal build-host components included GTK 4.22.4, libadwaita 1.9.3,
librsvg 2.62.3, HarfBuzz 14.3.0, GLib/GdkPixbuf/Pango dependencies, Graphene
1.10.8, Graphite2 1.3.15, AppStream 1.1.5, libxmlb 0.3.29, libfyaml 0.9.6,
libthai 0.1.30, libdatrie 0.2.14, X11/XCB libraries, Cairo/font/image libraries,
LZO 2.10, XZ 5.8.3, and zstd 1.5.7_1. Exact files are determined from the
recursive runtime graph. Notices are bundled; corresponding-source/full-license
delivery remains a release-distribution obligation.

## Security and privacy

- No real browser profile, cookie, password, session token, SSH private key,
  `~/.ssh`, or existing agent socket was read or modified.
- Update tests used only temporary synthetic config/audit/profile canaries.
- Diagnostics inspected product metadata only. They did not read config
  contents, audit rows, browser profile contents, or SSH key contents.
- The helper was unregistered after its lifecycle test; final status was
  `NotRegistered`.
- Recovery was dry-run only; no application or product data was removed.
- No TCC, SIP, Secure Boot, system-extension database, or global security
  setting was modified.
- No privilege escalation was needed. Linux was not handled and Docker was
  never invoked.

Phase 10 is complete for all locally testable packaging/update/recovery work.
Provisioned activation, Developer ID distribution, Gatekeeper acceptance, and
notarization remain accurately BLOCKED external acceptance items for Phase 11.
