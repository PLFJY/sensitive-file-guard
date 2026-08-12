# macOS Phase 09 — Namespace Hardening and Enforcement Health

## Phase and base

- Phase 09 — Namespace Hardening and Enforcement Health
- starting commit / branch: `3e9153c` / `main`
- macOS 26.6.1 (25G76), arm64
- Xcode 26.6 (17F113), macOS SDK 26.5
- rustc 1.97.0
- GTK 4.22.4 / libadwaita 1.9.3

## Implemented

- Added minimal Endpoint Security `AUTH_LINK` and `AUTH_RENAME` subscriptions
  beside `AUTH_OPEN` and process notifications. Namespace decisions are
  deterministic in the callback and use
  `es_respond_auth_result(..., cache=false)`; they never enter a UI queue.
- Normalized source/destination paths, source and existing-destination
  device/inode identity, exact process identity, truncation state, and deadline
  across C/Rust. Invalid, truncated, identity-incomplete, or expired events
  deny immediately.
- Unknown clients cannot link protected objects, rename them out, replace
  protected paths, or rename a containing directory. Only the exact enrolled
  owning browser may perform a narrow same-browser/same-profile atomic update.
  Migration/SSH read leases are not consulted. SSH key link/rename always
  denies.
- Added a bounded file-identity alias index: 65,536 protected identities and a
  bounded traversal budget. Startup scan records protected tree descendants
  without following symlinks, so a pre-existing hardlink outside a profile is
  still protected. Newly created protected objects are anchored by kernel
  device/inode identity.
- Added repair signaling after namespace activity and ES sequence loss. Repair
  clones and scans outside the callback and writer lock; only final snapshot
  replacement takes the writer lock.
- Added ES per-event/global sequence tracking. Gaps produce `DEGRADED`, request
  namespace repair, and mark ancestry uncertain. Graph uncertainty disables
  descendant-derived leases; direct exact browser identity can still classify,
  with no UID/name fallback.
- Split backend `active` from `degraded`. Startup errors map to stable
  `REQUIRES_APPROVAL`, `REQUIRES_FULL_DISK_ACCESS`, or `NOT_ENFORCING`; active
  runtime maps to `ACTIVE`/`DEGRADED`.
- Added typed optional `mac_health` XPC data: sequence gaps; pending
  created/allow/deny/timeout; insufficient deadlines; late responses;
  namespace allow/deny; alias size/capacity/saturation; and process-graph
  degradation. GTK FDA presentation uses `backend_state`, not diagnostic text.
- Bounded the retained ES registry and delivery channel at 1,024. Queue
  pressure and scheduler failure drop the owned permission and deny. Existing
  XPC request/concurrency and typed pending-store limits remain in force.
- Added semantic lifecycle counters at the retained-operation owner. Atomic
  terminal resolution records exactly one allow or deny; timer wins record
  timeouts; failed/late responses still release the retained message once.
- Shared browser trust between namespace callback and policy resolver so an
  authenticated configuration replacement updates both views atomically.
- Documented restart behavior: configuration/resources rebuild; process graph
  starts fresh; opaque pending ES operations and leases are memory-only and not
  restored. The unavoidable crash-to-restart mediation gap is disclosed.
- Added a provisioned-host disposable Chrome script covering pre-existing
  hardlink, symlink read, link-out, rename-out, parent rename, health metrics,
  and real-browser atomic-update compatibility.

## Principal files

- `native/macos/endpoint_security_bridge.h`
- `native/macos/endpoint_security_bridge.c`
- `crates/platform-macos/src/endpoint_security.rs`
- `crates/platform-macos/src/resource_index.rs`
- `crates/platform-macos/src/identity.rs`
- `crates/platform-macos/src/pending.rs`
- `crates/platform-macos/src/browser_trust.rs`
- `apps/guard-es/src/service.rs`
- `apps/guard-es/src/policy.rs`
- `crates/guard-platform/src/lib.rs`
- `crates/guard-ipc/src/lib.rs`
- `apps/guard-ui/src/platform_service.rs`
- `scripts/macos/run-namespace-health-acceptance.sh`
- `docs/MACOS_NAMESPACE_AND_HEALTH.md`

## Commands run

```text
cargo fmt --all -- --check

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

MACOSX_DEPLOYMENT_TARGET=13.0 cargo build -p guard-es
MACOSX_DEPLOYMENT_TARGET=13.0 cargo build --release \
  -p platform-macos -p guard-client -p guard-ui -p guard-es \
  -p guardctl -p guard-notify -p guard-test-probe --all-features

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
sh -n scripts/macos/*.sh
git diff --check

SIGNING_IDENTITY='Apple Development: zero_plfjy@icloud.com (ZN9S86U87M)' \
DEVELOPMENT_TEAM='YSGFZUQGW6' scripts/macos/build-dev-app.sh
scripts/macos/inspect-signing.sh
scripts/macos/test-xpc-auth.sh build/macos/Guard.app
scripts/macos/run-namespace-health-acceptance.sh
```

## Results

| Test | Result | Notes |
|---|---|---|
| Rust formatting | PASS | `cargo fmt --all -- --check` |
| macOS selected-package Clippy | PASS | Warnings denied; Linux excluded |
| Rust unit/integration | PASS | 202 passed, 0 failed; synthetic fixtures |
| Default and release builds | PASS | Extension, UI, CLI, helper, probe |
| Native bridge strict compile | PASS | C/Objective-C, warnings denied |
| Platform boundary scripts | PASS | link/rename and cache=false checked |
| Pre-existing hardlink alias | PASS | Anchored by target dev/ino |
| Symlink target read | PASS | Kernel target identity protected |
| Unknown link/rename-out | PASS | Deterministic policy denies |
| Protected parent rename | PASS | Containing-directory move denies |
| Browser atomic replacement | PASS | Exact signer/browser/profile required |
| Wrong signed client | PASS | Wrong signing ID denies |
| SSH namespace mutation | PASS | Always denied |
| Sequence gaps | PASS | Counters, degraded health, repair signal |
| PID reuse/missing ancestry | PASS | No UID fallback or descendant lease |
| Pending/timer races | PASS | One terminal response and release |
| Queue/index/XPC bounds | PASS | 1,024 / 65,536 / existing XPC bounds |
| Concurrent config replacement | PASS | Complete immutable snapshots |
| Restart clears runtime access | PASS | No pending items or leases restored |
| Signed development bundle | PASS | Team `YSGFZUQGW6`; requirements valid |
| Signed authenticated XPC | PASS | Trusted clients pass; two wrong clients fail |
| Live kernel link/rename | BLOCKED | Provisioned activated ES/FDA unavailable |
| Live disposable Chrome | BLOCKED | Same preflight; no fixture created |
| Linux build/test | NOT RUN | Outside user scope |
| Docker | NOT STARTED | Explicitly prohibited |

## Live Endpoint Security blocker

The live script stopped before `mktemp`, profile creation, or enrollment:

```text
BLOCKED: signed guardctl cannot reach the activated extension
guardctl: connecting to guardd IPC socket /run/guardd/guardd.sock: authenticated XPC request failed: Couldn’t communicate with a helper application.
PHASE09_LIVE_ACCEPTANCE_EXIT=77
```

The app has valid Apple Development signatures and embedded entitlement claims,
but this host lacks an Apple-provisioned, activated Endpoint Security extension
with Full Disk Access. A password/root shell cannot grant restricted-entitlement
provisioning. No privilege escalation or global security change was attempted.

## Execution-scope note

One initially broad `cargo clippy --workspace` caused Cargo on macOS to attempt
compiling the Linux-only fanotify/inotify crate and fail at target imports. It
ran no Linux test and changed no Linux state. It was discarded immediately;
all recorded gates above use an explicit macOS/portable package list. Docker
was never invoked.

The shared `StatusInfo` shape required mechanical compatibility changes in the
Linux response constructor, but no Linux policy logic, build, test, or runtime
was handled.

## Security and privacy

- No real browser profile, cookie, password, session token, SSH private key,
  `~/.ssh`, or existing agent socket was read or modified.
- Namespace/restart tests used `tempfile` synthetic data only. Live acceptance
  created no fixture because preflight failed.
- `/Library/Application Support/Sensitive Data Firewall/config.json` remained
  absent. The signed XPC test removed its temporary launchd job/bundle.
- No audit/status value contains secret contents.
- No TCC, SIP, Secure Boot, extension database, or global setting was changed.
- Linux was not tested and Docker was not started.
