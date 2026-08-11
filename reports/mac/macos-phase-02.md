# macOS Phase 02 — Mac Build, Guard.app, and System Extension Skeleton

## Phase

Name / number: Phase 02 — Mac Build, Guard.app, and System Extension Skeleton

## Base

- starting commit / branch: `41e55be` / `main`
- platform / macOS version: macOS 26.6.1 (Build 25G76)
- architecture / CPU: arm64 / Apple Silicon
- Xcode / SDK: Xcode 26.6 (17F113), macOS SDK 26.5
- GTK stack: GTK4 4.22.4, libadwaita 1.9.3

## Implemented

- Added the target-specific `platform-macos` crate. Its build script compiles a
  small Objective-C bridge only for macOS and links Foundation, Security, and
  SystemExtensions without leaking Apple frameworks into portable crates.
- Added a typed `SystemExtensionController` with activation, explicit
  deactivation, properties/status refresh, user-approval, active, restart,
  deactivated, and failure states.
- Added the `guard-es` Endpoint Security system-extension executable skeleton.
  It initializes logging, inspects only its own embedded entitlement claim, and
  deliberately subscribes to no Endpoint Security events in this phase.
- Added deterministic `Guard.app` and nested `.systemextension` assembly with
  externally supplied bundle IDs, signing identity, Team ID validation, build
  version, and build profile.
- Added minimal host and extension Info.plist/entitlement templates. The host
  alone claims system-extension install; the extension alone claims Endpoint
  Security client. No Team ID, certificate, or provisioning profile is stored.
- Added host lifecycle diagnostic commands to the existing GTK executable:
  `--activate-system-extension`, `--deactivate-system-extension`, and
  `--system-extension-status`. Product code uses SystemExtensions.framework and
  never shells out to `systemextensionsctl`.
- Added signing/layout inspection and macOS platform-boundary scripts.
- Documented development build prerequisites, signing inputs, lifecycle
  diagnostics, and the distinction between embedded entitlement claims and
  Apple authorization.

## Files changed

- Workspace and lockfile: `Cargo.toml`, `Cargo.lock`, `.gitignore`
- macOS platform adapter: `crates/platform-macos/`
- system-extension executable: `apps/guard-es/`
- Objective-C framework bridge: `native/macos/`
- GTK host integration: `apps/guard-ui/`
- bundle metadata: `packaging/macos/`
- developer tooling: `scripts/macos/`, `tests/check_macos_boundaries.sh`
- documentation: `README.md`, `docs/INSTALL_MACOS_DEV.md`

## Commands run

```text
cargo fmt --all -- --check

MACOSX_DEPLOYMENT_TARGET=13.0 cargo clippy \
  -p guard-core -p guard-browser -p guard-ssh -p guard-ipc \
  -p guard-client -p guard-audit -p guard-platform -p guard-runtime \
  -p guard-test-fixtures -p platform-macos -p guard-ui -p guard-es \
  --all-targets --all-features -- -D warnings

MACOSX_DEPLOYMENT_TARGET=13.0 cargo test \
  -p guard-core -p guard-browser -p guard-ssh -p guard-ipc \
  -p guard-client -p guard-audit -p guard-platform -p guard-runtime \
  -p guard-test-fixtures -p platform-macos -p guard-ui -p guard-es \
  --all-features

MACOSX_DEPLOYMENT_TARGET=13.0 cargo build --release \
  -p platform-macos -p guard-ui -p guard-es --all-features

scripts/macos/build-dev-app.sh
scripts/macos/inspect-signing.sh
build/macos/Guard.app/Contents/MacOS/Guard --system-extension-status
build/macos/Guard.app/Contents/MacOS/Guard

tests/check_platform_boundaries.sh
tests/check_macos_boundaries.sh
git diff --check
```

## Tests

| Test | Result | Notes |
|---|---|---|
| Rust formatting | PASS | `cargo fmt --all -- --check` |
| macOS-host Clippy | PASS | Selected portable/macOS/UI/extension targets; all features and targets; warnings denied |
| Rust unit/integration tests | PASS | 104 passed, 0 failed; synthetic fixtures only |
| macOS release build | PASS | `platform-macos`, `guard-ui`, and `guard-es` |
| Objective-C bridge warnings | PASS | ARC, blocks, modules, `-Wall -Wextra -Werror` |
| Bundle path construction | PASS | Unit tests verify the nested SystemExtensions layout and reject path-like IDs |
| Info.plist generation | PASS | Both rendered plists pass `plutil -lint` |
| Development bundle assembly | PASS | Deterministically assembled under `build/macos/Guard.app` |
| Ad-hoc signature structure | PASS | Deep/strict verification succeeds; TeamIdentifier is correctly reported absent |
| Entitlement placement | PASS | Host: install only; extension: Endpoint Security client only |
| Lifecycle status query | PASS | `state=Unknown`, diagnostic=`system extension is not installed`, exit 0 |
| Endpoint Security skeleton diagnostic | PASS | Reports embedded claim without claiming provisioning/acceptance; no ES subscriptions |
| GTK control-center window smoke | PASS | Bundled arm64 GTK executable stayed live with its window event loop until explicitly interrupted |
| Portable/macOS boundaries | PASS | No Apple dependency leaks and no Network Extension or lifecycle shell command |
| Diff whitespace | PASS | `git diff --check` |
| System Extension activation | BLOCKED | Restricted-entitlement provisioning is unavailable; exact evidence below |
| Linux build/test | NOT RUN | Explicitly excluded by the user; no Docker or Linux environment was started |

## Security invariants checked

- Phase 02 does not create an Endpoint Security client or subscribe to AUTH/NOTIFY events.
- The native bridge contains framework invocation and lifecycle translation only; no policy decision is implemented there.
- No activation state is called enforcement-active, and entitlement inspection is described as an embedded claim only.
- The host and extension carry disjoint least-privilege entitlement templates.
- Bundle/signing values remain external and the build rejects a supplied Team ID that differs from the certificate-derived TeamIdentifier.
- No Network Extension, `NEFilter*`, SwiftUI replacement, or `systemextensionsctl` product path was added.
- No real browser profile, cookie, password, session token, or SSH private key was read.

## Platform permissions / signing state

- Ad-hoc bundle: structurally valid and runnable for local layout/status/UI smoke tests; no TeamIdentifier.
- Available certificate: `Apple Development: zero_plfjy@icloud.com (ZN9S86U87M)`.
- Certificate-derived TeamIdentifier: `YSGFZUQGW6` (supplied and verified externally during the signed-build check).
- Endpoint Security entitlement: template and signed claim present on the extension; Apple authorization/provisioning not available or claimed.
- System Extension install entitlement: template and signed claim present on the host; provisioning not available or claimed.
- Full Disk Access: not requested and not exercised in Phase 02.
- SIP: not changed.

## Exact activation blocker

A certificate-signed bundle was successfully assembled and `codesign --verify
--deep --strict` passed, but neither the app nor extension contained an
`embedded.provisionprofile`. Gatekeeper's exact assessment was:

```text
$ spctl --assess --type execute --verbose=4 build/macos/Guard.app
build/macos/Guard.app: rejected
```

The same signed host exited with code 1 before it could service
`--system-extension-status`, while the unentitled build target returned the
deterministic `system extension is not installed` result. Direct `codesign`
accepted the checked-in restricted entitlement claims, but that is not proof
that Apple authorized them. Submitting activation from this artifact could only
produce an invalid-signature/provisioning failure or misleading user approval,
so activation was not submitted and is correctly marked BLOCKED.

Deterministic re-test after an Apple-approved Endpoint Security entitlement and
matching profiles are available:

```sh
APP_BUNDLE_ID='<approved host id>' \
SYSTEM_EXTENSION_BUNDLE_ID='<approved extension id>' \
DEVELOPMENT_TEAM='<certificate TeamIdentifier>' \
SIGNING_IDENTITY='<matching Apple Development or Developer ID identity>' \
scripts/macos/build-dev-app.sh
scripts/macos/inspect-signing.sh
build/macos/Guard.app/Contents/MacOS/Guard --activate-system-extension
build/macos/Guard.app/Contents/MacOS/Guard --system-extension-status
```

## Known limitations

- This is a development bundle and still links Homebrew GTK/libadwaita dylibs.
- The extension has no Endpoint Security client, subscriptions, authorization
  handling, identity collection, XPC transport, or enforcement yet.
- Lifecycle controls are developer CLI diagnostics in the GTK host; dedicated
  UI controls can be added when signed activation is testable.
- The app is not notarized, distributable, or accepted by Gatekeeper.
- Linux gates were intentionally omitted under the user's macOS-only scope.

## Next phase readiness

READY for Phase 03 compile/mock work. Real System Extension activation remains
BLOCKED only on Apple-approved entitlement/provisioning and is not required to
compile and test the Phase 03 Endpoint Security callback skeleton.
