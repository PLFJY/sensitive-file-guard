# macOS Phase 06 — GTK Control Center and User-Session Pending Agent

## Phase

Name / number: Phase 06 — GTK Control Center and User-Session Pending Agent

## Base

- starting commit / branch: `6bc75ef` / `main`
- platform / macOS version: macOS 26.6.1 (Build 25G76)
- architecture: arm64 / Apple Silicon
- Xcode / SDK: Xcode 26.6 (17F113), macOS SDK 26.5
- Rust: rustc 1.97.0
- GTK / libadwaita: 4.22.4 / 1.9.3

## Implemented

- Kept the GTK4/libadwaita application as the macOS control center and added a
  compact platform-service facade for backend lifecycle, signer-aware browser
  discovery, configuration application, LocalAuthentication, and helper state.
- Removed Linux enforcement-mode concepts from the rendered macOS UI. The macOS
  protection view reports independent Endpoint Security extension, Full Disk
  Access, policy-enabled, and pending-helper states.
- Made the ordinary macOS Protection switch update only `policy_enabled` in the
  authoritative extension configuration. It never activates, deactivates, or
  uninstalls the system extension.
- Added an `SMAppService` native bridge and embedded an unprivileged per-user
  LaunchAgent at
  `Contents/Library/LaunchAgents/io.github.plfjy.SensitiveFileGuard.guard-notify.plist`.
  Registration, unregistration, state inspection, and Login Items settings are
  exposed separately from the protection-policy switch.
- Added one authenticated, EUID-scoped `PendingHelperPoll` XPC operation that
  combines a helper heartbeat with the pending browser/SSH snapshot. Helper
  health is reported by EUID and expires after three seconds without a poll.
- Added the macOS `guard-notify` role. It polls every 500 ms while healthy,
  exponentially backs off to at most five seconds when XPC is unavailable,
  deduplicates pending IDs, and launches only its sibling `Guard --pending-only`.
  The helper contains no policy resolution operation.
- Reused the common pending-dialog controller for browser-import and SSH-key
  prompts. Dialogs show fixed process/resource metadata and remaining time;
  Allow crosses LocalAuthentication, Block and close fail closed, cancellation
  sends no Allow, and stale timeout/replay results terminate the prompt.
- Completed pending-only lifecycle handling: a transient UI exits after an
  empty initial snapshot or the final terminal prompt, while a manually opened
  control center remains open.
- Added signer-aware macOS browser enrollment and peer-owned path validation for
  browser profiles, enrolled executables, and SSH keys. First run remains
  disabled and does not automatically enroll resources.
- Added boundary, protocol, UI-state, helper-deduplication, sibling-launch,
  configuration-ownership, signed XPC, and real GTK pending-only tests.
- Documented macOS UI/helper behavior, installation layout, polling latency,
  CPU measurement, and the external SMAppService/Endpoint Security gates.

## Principal files

- GTK/platform facade: `apps/guard-ui/src/main.rs`,
  `apps/guard-ui/src/platform_service.rs`
- User helper: `apps/guard-notify/src/main.rs`
- Extension/protocol/client: `apps/guard-es/src/main.rs`,
  `crates/guard-ipc/src/lib.rs`, `crates/guard-client/src/macos.rs`
- Native user-agent boundary: `native/macos/user_agent_bridge.{h,m}`,
  `crates/platform-macos/src/user_agent.rs`
- macOS config/discovery: `crates/platform-macos/src/config.rs`,
  `crates/platform-macos/src/discovery.rs`
- Packaging/tests/docs: `packaging/macos/GuardNotify.LaunchAgent.plist.in`,
  `scripts/macos/build-dev-app.sh`, `scripts/macos/test-xpc-auth.sh`,
  `tests/check_macos_boundaries.sh`, `docs/MACOS_UI_AND_USER_AGENT.md`

## Commands run

```text
cargo fmt --all -- --check

MACOSX_DEPLOYMENT_TARGET=13.0 cargo clippy \
  -p guard-core -p guard-browser -p guard-ssh -p guard-ipc \
  -p guard-client -p guard-audit -p guard-platform -p guard-runtime \
  -p guard-test-fixtures -p platform-macos -p guard-ui -p guard-es \
  -p guardctl -p guard-notify \
  --all-targets --all-features -- -D warnings

MACOSX_DEPLOYMENT_TARGET=13.0 cargo test \
  -p guard-core -p guard-browser -p guard-ssh -p guard-ipc \
  -p guard-client -p guard-audit -p guard-platform -p guard-runtime \
  -p guard-test-fixtures -p platform-macos -p guard-ui -p guard-es \
  -p guardctl -p guard-notify --all-targets --all-features --quiet

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

tests/check_platform_boundaries.sh
tests/check_macos_boundaries.sh
sh -n scripts/macos/*.sh
git diff --check

SIGNING_IDENTITY=<available Apple Development identity> \
DEVELOPMENT_TEAM=<signing Team ID> scripts/macos/build-dev-app.sh
scripts/macos/inspect-signing.sh
scripts/macos/test-xpc-auth.sh build/macos/Guard.app
```

## Test results

| Test | Result | Notes |
|---|---|---|
| Rust formatting | PASS | `cargo fmt --all -- --check` |
| macOS-host Clippy | PASS | Full selected portable/macOS/app set; warnings denied |
| Rust unit/integration tests | PASS | 171 passed, 0 failed; synthetic fixtures only |
| Release build | PASS | macOS platform, client, GTK app, extension, CLI, and helper |
| Native bridge strict compile | PASS | Objective-C and Endpoint Security C; warnings denied |
| Platform boundary checks | PASS | Portable and macOS target checks |
| macOS GTK launch | PASS | Debug pending-only client entered the GTK application loop |
| macOS mode rendering | PASS | Strict/conservative selector is not rendered on macOS |
| Pending dialog deduplication | PASS | Repeated snapshots do not create duplicate dialogs/windows |
| Pending-only lifecycle | PASS | Final/empty queue exits; manual control center remains open |
| Allow cancellation/timeout | PASS | Cancellation sends no Allow; timeout/replay is terminal |
| Helper resolution boundary | PASS | Helper source contains no Allow/Block/config resolver call |
| Helper executable boundary | PASS | Only sibling `Contents/MacOS/Guard --pending-only` is launched |
| Helper EUID scope | PASS | XPC server keys heartbeat/snapshot handling from transport EUID |
| Signed pending-only XPC path | PASS | Team-signed temporary GTK app exited after an empty snapshot |
| Signed helper XPC path | PASS | Bundled helper reached the authenticated temporary service |
| Wrong-signature XPC clients | PASS | Ad-hoc and same-Team unlisted signing IDs were rejected |
| Polling performance | PASS | 500 ms polling: 0.02–0.03 s cumulative CPU and 0.0–0.1% sampled CPU over 5 s |
| Development bundle/signing | PASS | App, extension, CLI, and helper satisfy designated requirements |
| Embedded LaunchAgent plist | PASS | `BundleProgram`, label, run/keepalive, and throttle validated |
| Live SMAppService registration | BLOCKED | No provisioned, installed host app is available for a durable Login Items registration test |
| Live activated ES/FDA state | BLOCKED | Apple-approved ES provisioning and Full Disk Access are unavailable |
| Linux build/test | NOT RUN | Explicitly excluded by user |
| Docker | NOT STARTED | Explicitly excluded by user |

## Signed transport and lifecycle test boundary

The XPC test created a temporary user launchd service and a temporary copy of
the real binaries. Restricted Endpoint Security and system-extension-install
entitlements were removed from temporary copies so macOS could launch them
outside a provisioned extension/app container. Exact production signing IDs,
Team constraints, transport EUID checks, protocol paths, helper polling, and GTK
pending-only behavior were retained. Temporary jobs and files were removed.

The native `SMAppService` bridge is callable and returned `NotFound` for the
uninstalled diagnostic bundle. Registering a durable LaunchAgent from the
production-entitled build is blocked by the missing provisioned/installed host
app. Running that restricted-entitlement app directly outside its provisioned
container is killed by macOS (exit 137), so this report does not claim a live
Login Items registration result.

## Security invariants checked

- The pending helper is a per-user LaunchAgent, not a root LaunchDaemon.
- Helper ownership and health derive from the authenticated XPC peer EUID, not
  from a UID supplied in JSON.
- The helper cannot approve, block, mutate policy, or pass an approval ID on the
  command line.
- Duplicate snapshots cannot create duplicate pending windows.
- Close and explicit Block fail closed. LocalAuthentication cancellation sends
  no Allow; timeout/replay cannot recreate a permission.
- The normal Protection switch does not alter the system-extension lifecycle.
- UI/helper metadata excludes browser rows, cookie values, passwords, session
  tokens, and SSH private-key contents.
- Polling has bounded healthy latency and bounded unavailable-service backoff.

## Persistence and privacy state

- Only synthetic browser profiles, executable fixtures, and ephemeral test
  paths were used.
- `/Library/Application Support/Sensitive Data Firewall/config.json` remained
  absent; tests did not create authoritative system configuration.
- No real browser credential/session content or SSH private key was read.
- No network exfiltration test was created or run.
- No global macOS security control was weakened.
- No test launchd jobs remained after cleanup.

## External blockers

- Live durable `SMAppService` registration needs a provisioned app installed in
  an accepted macOS application location. That environment is unavailable.
- A valid Apple-provisioned Endpoint Security extension and Full Disk Access are
  still unavailable, so live ES event/FDA state remains blocked.
- Everything independent of those Apple-controlled gates was implemented and
  exercised through native, synthetic, and Team-signed temporary tests.

## Next phase readiness

READY for Phase 07. The GTK control center has macOS-native lifecycle/status
boundaries, the unprivileged helper can surface EUID-scoped pending work without
deciding policy, and pending resolution remains authenticated and fail-closed.
