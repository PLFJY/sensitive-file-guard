# macOS Phase 04 — Process Identity, Browser Discovery, and macOS Config

## Phase

Name / number: Phase 04 — Process Identity, Browser Discovery, and macOS Config

## Base

- starting commit / branch: `910570a` / `main`
- platform / macOS version: macOS 26.6.1 (Build 25G76)
- architecture / CPU: arm64 / Apple Silicon
- Xcode / SDK: Xcode 26.6 (17F113), macOS SDK 26.5

## Implemented

- Expanded normalized Endpoint Security process facts to include audit-token
  PID/UID/GID/PID-version, ES start time, canonical executable path and full
  file snapshot, code-signing flags/validity, Team ID, signing ID, cdhash,
  parent audit identity, responsible audit identity, and platform-binary state.
- Added only the three process notifications needed for ancestry:
  `NOTIFY_FORK`, `NOTIFY_EXEC`, and `NOTIFY_EXIT`. AUTH_OPEN remains the sole
  authorization event.
- Added a bounded `MacProcessGraph` keyed by PID plus audit-token PID version,
  with stable executable identity values, positive parent edges, 16-level
  maximum ancestry, ten-minute stale lifetime, and 4096-entry cap.
- Added a macOS `ProcessIdentityResolver`. Missing/stale parents, cycles, PID
  reuse, start-time changes, or incomplete ES facts fail closed; same UID is
  never treated as ancestry.
- Added strict Security.framework static-code inspection without shelling out
  from product code.
- Added signed browser trust based on exact canonical app/executable scope,
  valid kernel code-signing state, exact Team ID, exact signing ID, owner UID,
  and narrowly listed helper paths. A Team ID alone grants nothing.
- Added version-tolerant helper enrollment: signed Chromium-framework updates
  may change only the framework version component while retaining the enrolled
  bundle-relative helper suffix and exact signer. cdhash remains diagnostic,
  not a permanent vendor-version pin.
- Added explicit custom-browser enrollment. Unsigned/user-writable executables
  are hashed with SHA-256 and bound to path, `st_dev`, `st_ino`, size, mtime,
  and ctime. Configuration load revalidates outside the ES callback; changed
  bytes require reenrollment.
- Added verified Chrome, Chromium, and Firefox discovery with injected signature
  inspection for synthetic tests. Missing apps/wrong signers become
  custom-needed rather than guessed trust.
- Reused `guard-browser` classifiers and added concrete resource/tree inode
  indexes for later alias hardening. Firefox discovery remains under
  Application Support and does not include cache roots.
- Added a distinct versioned `MacBackendConfig` containing common policy plus
  macOS-only trust facts, with metadata consistency validation and no Linux
  enforcement mode.
- Chose `/Library/Application Support/Sensitive Data Firewall/config.json` as
  the future root-owned mode-0600 authoritative path. No file was created in
  this phase; authenticated writes arrive with Phase 05 transport.
- Added a metadata-only browser diagnostic command to the bundled GTK host:
  `--discover-macos-browsers`. It emits profile roots and signer review data,
  never browser database contents.

## Files changed

- ES process normalization: `native/macos/endpoint_security_bridge.{h,c}`,
  `crates/platform-macos/src/endpoint_security.rs`
- Static signature bridge: `native/macos/code_signature_bridge.{h,m}`,
  `crates/platform-macos/src/code_signature.rs`
- Stable process identity/graph: `crates/platform-macos/src/identity.rs`
- Browser trust/discovery: `crates/platform-macos/src/browser_trust.rs`,
  `crates/platform-macos/src/discovery.rs`
- macOS config/resource index: `crates/platform-macos/src/config.rs`,
  `crates/platform-macos/src/resource_index.rs`
- Diagnostic composition: `apps/guard-ui/src/platform_service.rs`
- PoC identity update: `apps/guard-es/src/main.rs`
- Documentation/tests/build metadata: `docs/`, Cargo files,
  `tests/check_macos_boundaries.sh`

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

target/debug/guard-ui --discover-macos-browsers --home "$HOME"
jq empty /tmp/guard-macos-browser-discovery-phase04.json

scripts/macos/build-dev-app.sh
scripts/macos/inspect-signing.sh
build/macos/Guard.app/Contents/MacOS/Guard \
  --discover-macos-browsers --home "$HOME"

tests/check_platform_boundaries.sh
tests/check_macos_boundaries.sh
git diff --check
```

## Tests

| Test | Result | Notes |
|---|---|---|
| Rust formatting | PASS | `cargo fmt --all -- --check` |
| macOS-host Clippy | PASS | Selected portable/macOS/UI/extension targets; warnings denied |
| Rust unit/integration tests | PASS | 133 passed, 0 failed; synthetic fixtures only |
| ES/process bridge build | PASS | Current SDK headers; C/Objective-C `-Wall -Wextra -Werror` |
| Stable graph valid ancestry | PASS | Exact stable parent returned |
| Missing/stale ancestry | PASS | Fails closed, never same-UID fallback |
| PID reuse/start mismatch | PASS | Old stable identity does not match; same audit key cannot change start |
| Graph exit/stale/bound | PASS | Terminal removal, ten-minute expiry, fixed capacity |
| Team ID/signing ID | PASS | Both require exact match independently |
| Same basename wrong path/signer | PASS | Untrusted |
| Helper scope | PASS | Outside-bundle helper enrollment rejected |
| Signed helper update | PASS | Version component may change; suffix and signer remain exact |
| Cross UID | PASS | Untrusted |
| Custom hash change | PASS | Changed bytes invalidate config load until reenrollment |
| Chrome/Chromium/Firefox synthetic discovery | PASS | Verified app/profile layouts with fake signer inspector |
| No profile root | PASS | No automatic enrollment |
| Wrong/missing app signer | PASS | Surfaced as custom-needed |
| Custom executable path | PASS | Canonical explicit hash enrollment |
| Portable browser classifiers | PASS | Concrete Chromium synthetic resources reused and inode-indexed |
| macOS config round-trip | PASS | No `enforcement_mode`; policy/trust metadata must agree |
| UI review DTO | PASS | No SHA-256, cdhash, audit token, or signing blob |
| Actual Security.framework discovery | PASS | Chrome/Firefox main and narrowly listed helpers validated |
| Actual diagnostic JSON | PASS | `jq empty`; no browser database/resource-name metadata |
| Root config parent check | PASS | `/Library/Application Support` exists, UID 0, mode 0755 |
| Development bundle/signature | PASS | App assembles, deep/strict ad-hoc signature verifies |
| Real ES process notification delivery | BLOCKED | Valid system-extension provisioning/FDA still unavailable |
| Linux build/test | NOT RUN | Explicitly excluded by the user; no Docker or Linux environment was started |

## Actual browser metadata diagnostic

The command examined app signatures and default-root existence only. It did not
enumerate profiles or open browser databases.

- Google Chrome: verified `EQHXZ8M8AV/com.google.Chrome`; exact helper IDs
  included `com.google.Chrome.helper` and
  `com.google.Chrome.helper.renderer`.
- Firefox: verified `43AQ936H96/org.mozilla.firefox`; exact helper IDs included
  `org.mozilla.plugincontainer`, `org.mozilla.firefox-gpu-helper`, and
  `org.mozilla.firefox-media-plugin-helper`.
- Chromium: the known profile root exists but `/Applications/Chromium.app` is
  absent, so it was reported as custom-needed and received no trust.
- Diagnostic output contained no `Cookies`, `Login Data`, `key4.db`,
  `logins.json`, or session resource metadata.

## Security invariants checked

- Browser/process trust never compares basenames.
- A process identity requires PID, audit PID version, ES start time, UID/GID,
  canonical executable path, and executable dev/inode.
- Missing ES start/path/file identity fails the AUTH_OPEN normalization path closed.
- Ancestry is positive, stable-instance graph evidence; missing evidence cannot match a lease.
- Vendor trust requires code-sign validity plus exact enrolled path scope,
  Team ID, and signing ID. Unlisted executables with the same Team ID are not trusted.
- Custom bytes are hashed outside the ES callback; hot classification uses the
  verified immutable snapshot fields and fails when they change.
- The unprivileged UI sees metadata-only DTOs and has no config-file writer.
- All resource tests used synthetic files. Actual diagnostics read only app
  signatures and directory existence, never browser data contents.

## Platform permissions / persistence state

- Endpoint Security/FDA: still externally BLOCKED as recorded in Phase 03.
- Security.framework static code validation: available and exercised without elevation.
- Intended config file: `/Library/Application Support/Sensitive Data Firewall/config.json`.
- Parent directory observation: root-owned (`uid=0`), mode `0755`.
- No authoritative config file was written and no permissions were changed.
- SIP: not changed.

## Known limitations

- ES fork/exec/exit delivery cannot receive real acceptance coverage until the
  system extension has Apple-approved provisioning and FDA.
- Config validation/DTOs exist, but authenticated persistence and transport are
  Phase 05 work. The GTK process still cannot write authoritative policy.
- Automatic browser catalog is deliberately limited to Chrome, Chromium, and
  Firefox. Other browsers require explicit custom handling until verified.
- Resource alias scanning and namespace mutation handling are later phases.
- No real browser/SSH policy is yet connected to AUTH_OPEN.

## External blockers

- Same Apple-approved Endpoint Security entitlement/provisioning and FDA blocker
  documented in Phases 02–03. It blocks only live ES process-event acceptance,
  not Phase 04 compilation, pure logic, static-signature, or discovery tests.

## Next phase readiness

READY for Phase 05. Stable macOS process identities, a bounded positive
ancestry graph, strict browser trust/discovery, metadata-only DTOs, distinct
macOS config, and the future root-owned config location are established.
