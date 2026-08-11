# macOS Phase 07 — Browser Protection and Migration

## Phase

Name / number: Phase 07 — Browser Protection and Migration

## Base

- starting commit / branch: `9d154bc` / `main`
- platform / macOS version: macOS 26.6.1 (Build 25G76)
- architecture: arm64 / Apple Silicon
- Xcode / SDK: Xcode 26.6 (17F113), macOS SDK 26.5
- Rust: rustc 1.97.0
- GTK / libadwaita: 4.22.4 / 1.9.3

## Implemented

- Replaced the diagnostic extension loop with a real macOS browser-policy
  service that runs Endpoint Security authorization and authenticated XPC from
  the same authoritative configuration. Missing configuration leaves policy
  disabled instead of silently enrolling user data.
- Added a dynamic protected-resource index for Chromium `Default` / `Profile N`
  stores, Firefox profiles, inode aliases, and supported storage trees. Cache
  trees are excluded, and resources created after initial indexing are
  classified without rescanning the profile for every open.
- Made trusted-browser checks depend on PID, start token, canonical executable,
  executable device/inode, signing identifier, Team ID, effective UID, browser,
  and profile. Missing or mismatched identity data denies immediately.
- Enforced exact requested flags for a trusted browser reading its own profile.
  Cross-browser migration authorization is returned through Endpoint Security
  as `FREAD` only; requested write flags are stripped by the macOS adapter.
- Added deadline-bounded migration pending work, a maximum queue of eight,
  fail-closed timeout/process-exit behavior, EUID-scoped authenticated
  resolution, LocalAuthentication before Allow, replay rejection, and explicit
  Block without authentication.
- Added ten-minute, root-process-bound migration leases. Descendants of the
  approved root can reuse the lease; unrelated roots cannot. Import-burst
  coalescing still revalidates and binds every sibling root independently, and
  root exit revokes its lease.
- Added typed metadata-only audit events for confirmation required, allowed,
  blocked, timed out, ordinary allow/deny, and lease use. Allow diagnostics and
  status explicitly expose `read_only_guaranteed=true`.
- Added live config reload plus XPC-backed browser/resource/status, pending,
  event/explain, lease/revoke, and config-check operations. SSH remains
  unavailable until Phase 08.
- Added an offline disposable-profile browser harness for installed Chrome and
  Firefox, plus a deterministic provisioned-host acceptance script for the
  Apple-controlled live Endpoint Security path.
- Documented the supported browser resource classes, read-only migration
  boundary, configuration rules, audit behavior, and exact external acceptance
  procedure.

## Principal files

- Policy/service: `apps/guard-es/src/policy.rs`,
  `apps/guard-es/src/service.rs`, `apps/guard-es/src/main.rs`
- Endpoint Security/resource boundary:
  `crates/platform-macos/src/endpoint_security.rs`,
  `crates/platform-macos/src/pending.rs`,
  `crates/platform-macos/src/resource_index.rs`
- Trust/config/runtime: `crates/platform-macos/src/browser_trust.rs`,
  `crates/platform-macos/src/config.rs`, `crates/guard-runtime/src/lib.rs`
- Protocol/client/UI: `crates/guard-ipc/src/lib.rs`,
  `crates/guard-client/src/macos.rs`, `apps/guardctl/src/main.rs`,
  `apps/guard-ui/src/platform_service.rs`
- Acceptance/docs: `scripts/macos/test-disposable-browsers.sh`,
  `scripts/macos/run-browser-policy-acceptance.sh`,
  `docs/MACOS_BROWSER_PROTECTION.md`, `docs/INSTALL_MACOS_DEV.md`

## Commands run

```text
cargo fmt --all -- --check

MACOSX_DEPLOYMENT_TARGET=13.0 cargo clippy \
  -p guard-core -p guard-browser -p guard-ssh -p guard-ipc \
  -p guard-client -p guard-audit -p guard-platform -p guard-runtime \
  -p guard-test-fixtures -p platform-macos -p guard-ui -p guard-es \
  -p guardctl -p guard-notify \
  --all-targets --all-features -- -D warnings

MACOSX_DEPLOYMENT_TARGET=13.0 cargo test -q \
  -p guard-core -p guard-browser -p guard-ssh -p guard-ipc \
  -p guard-client -p guard-audit -p guard-platform -p guard-runtime \
  -p guard-test-fixtures -p platform-macos -p guard-ui -p guard-es \
  -p guardctl -p guard-notify --all-targets --all-features

MACOSX_DEPLOYMENT_TARGET=13.0 cargo build -p guard-es
MACOSX_DEPLOYMENT_TARGET=13.0 cargo clippy \
  -p guard-es --all-targets -- -D warnings

MACOSX_DEPLOYMENT_TARGET=13.0 cargo build --release \
  -p platform-macos -p guard-client -p guard-ui -p guard-es \
  -p guardctl -p guard-notify --all-features

xcrun clang -fsyntax-only -fobjc-arc -fblocks -fmodules \
  -Wall -Wextra -Werror -mmacosx-version-min=13.0 -Inative/macos \
  native/macos/system_extension_bridge.m \
  native/macos/code_signature_bridge.m native/macos/xpc_bridge.m \
  native/macos/local_auth_bridge.m native/macos/user_agent_bridge.m

xcrun clang -fsyntax-only -fblocks -Wall -Wextra -Werror \
  -mmacosx-version-min=13.0 -Inative/macos \
  native/macos/endpoint_security_bridge.c

scripts/macos/test-disposable-browsers.sh
tests/check_platform_boundaries.sh
tests/check_macos_boundaries.sh
sh -n scripts/macos/*.sh
git diff --check

SIGNING_IDENTITY=<available Apple Development identity> \
DEVELOPMENT_TEAM=<signing Team ID> scripts/macos/build-dev-app.sh
scripts/macos/inspect-signing.sh
scripts/macos/test-xpc-auth.sh build/macos/Guard.app

scripts/macos/run-browser-policy-acceptance.sh build/macos/Guard.app
```

## Test results

| Test | Result | Notes |
|---|---|---|
| Rust formatting | PASS | `cargo fmt --all -- --check` |
| macOS-host Clippy | PASS | Full selected portable/macOS/app set; warnings denied |
| Rust unit/integration tests | PASS | 180 passed, 0 failed; synthetic fixtures only |
| Default extension build | PASS | Real service path compiled without the `es-poc` feature |
| Release build | PASS | macOS platform, client, GTK app, extension, CLI, and helper |
| Native bridge strict compile | PASS | Objective-C and Endpoint Security C; warnings denied |
| Platform boundary checks | PASS | Portable and macOS-specific checks |
| Inode alias and dynamic resource classification | PASS | Aliases and post-index resource creation remain protected |
| Own-profile browser access | PASS | Exact flags allowed only for exact trusted signer/UID/profile |
| Unknown/wrong signer/cross-UID access | PASS | Immediate deny; no prompt |
| Migration read-only mechanism | PASS | `FREAD` returned and `FWRITE` stripped in fake-ES authorization tests |
| Pending queue/deadline/replay | PASS | Bound eight-item queue, timeout deny, and replay rejection |
| Migration lease binding | PASS | Root/descendant scope, independent sibling roots, and exit revocation |
| Typed audit/privacy assertions | PASS | Required codes present; contents absent; read-only contract recorded |
| Installed Chrome disposable profile | PASS | Local `data:` workload wrote supported profile resources only under `mktemp` |
| Installed Firefox disposable profile | PASS | Offline local workload wrote supported profile resources only under `mktemp` |
| Browser/helper signing discovery | PASS | Chrome and Firefox main/helper IDs and Team IDs matched exact enrollment |
| Signed authenticated XPC path | PASS | Guard UI/CLI/helper reached the temporary authenticated service |
| Wrong-signature XPC clients | PASS | Ad-hoc and same-Team unlisted same-UID clients rejected |
| Development bundle/signing | PASS | App, extension, CLI, and helper satisfy designated requirements |
| Live ES own-profile deny/allow | BLOCKED | Activated Apple-provisioned Endpoint Security extension/FDA unavailable |
| Live importer Block/Allow compatibility | BLOCKED | Same Apple-controlled gate; no claim of real importer read-only compatibility |
| Linux build/test | NOT RUN | Explicitly excluded by user |
| Docker | NOT STARTED | Explicitly excluded by user |

## Real browser fixture boundary

Installed Google Chrome and Firefox were launched only with newly created
disposable profile roots and local `data:` content. Chrome ran with background
networking disabled; Firefox ran offline. The tests verified creation of
supported browser resources and exact main/helper code-signing identities.
They did not enumerate or read the developer's real browser profiles.

The disposable directories were moved to Trash, so cleanup remains recoverable:

```text
/Users/plfjy/.Trash/guard-phase07-disposable-profiles-20260812-0300
/Users/plfjy/.Trash/guard-phase07-firefox-topology-20260812-0305
/Users/plfjy/.Trash/guard-phase07-signature-discovery-20260812-0310
```

The user may empty Trash when those synthetic artifacts are no longer useful.

## Live Endpoint Security blocker

The deterministic live browser-policy script stopped before creating or
enrolling a test profile and returned exit status 77:

```text
BLOCKED: signed guardctl cannot reach the activated extension
guardctl: connecting to guardd IPC socket /run/guardd/guardd.sock: authenticated XPC request failed: Couldn’t communicate with a helper application.
```

This requires an installed, activated, Apple-provisioned Endpoint Security
extension with Full Disk Access. The project did not disable SIP, Secure Boot,
or another global control. `scripts/macos/run-browser-policy-acceptance.sh`
provides the exact deterministic procedure for that future host.

The `read_only_guaranteed=true` claim is therefore established at the ES flags
response mechanism, protocol, and synthetic integration-test boundary. It is
not a claim that Chrome/Firefox import-wizard compatibility completed against a
live kernel-mediated event on this unprovisioned host.

## Security and privacy state

- No real browser cookie, password, session, or credential store content was
  read, copied, exported, or logged.
- No real SSH private key was read; SSH policy is still disabled in this phase.
- Audit rows contain identity/resource metadata and typed results only.
- `/Library/Application Support/Sensitive Data Firewall/config.json` remained
  absent after testing.
- No temporary launchd test job remained after the signed XPC test.
- No network exfiltration test was created or run.
- No global macOS security setting was weakened.

## Next phase readiness

READY for Phase 08. Browser AUTH_OPEN policy, read-only migration flags,
deadline-bounded pending work, authenticated resolution, root-bound leases,
live configuration, and metadata-only audit are integrated. Only the explicitly
documented Apple provisioning/FDA live-kernel acceptance remains externally
blocked.
