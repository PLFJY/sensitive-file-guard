# macOS Phase 01 — Pre-Mac Platform Boundary Hardening

## Phase

Name / number: Phase 01 — Pre-Mac Platform Boundary Hardening

## Base

- starting commit / branch: `ab0da3064ffd34c85907fc29e8a303827b200519` / `main`
- platform / macOS version: macOS 26.6.1 (Build 25G76)
- architecture / CPU: arm64 / Apple Silicon

## Implemented

- Added `guard-runtime` as the portable owner of deterministic policy/lease state and bounded browser-migration/SSH-read pending queues.
- Changed shared pending queues to own `Box<dyn PendingPermission>` and use `ProcessIdentityResolver` for stable-instance liveness checks. The shared crate contains no fanotify, `/proc`, Polkit, XPC, or Endpoint Security implementation.
- Reconnected Linux composition to the shared runtime without moving fanotify descriptors or Linux identity mechanisms into portable code.
- Replaced the dead client transport decoration with a production `GuardClient<T: LocalTransport>` path. Requests now carry an explicit bounded or authorization-managed timeout policy; the Unix-socket adapter implements the same seam future XPC transport will implement.
- Removed service/privilege command execution from `guard-client`. Linux `pkexec`/service composition now lives in one target-specific GTK application module and the existing Linux CLI composition.
- Moved `EnforcementMode::{Conservative, StrictFilesystem}` and the backward-compatible Linux JSON wrapper into `platform-linux`. Portable configuration is now `PolicyConfig`.
- Evolved status/config IPC compatibly: semantic backend identity is explicit, while Linux mode, filesystem mark metrics, fanotify diagnostics, and topology details are optional. A macOS backend can omit them instead of inventing values.
- Updated the authorization contract and current security documentation to describe bounded typed browser and SSH confirmations, the short SSH read lease, and the absence of SSH network containment / Network Extension requirements.
- Extended the repository boundary test to cover `guard-runtime`.

## Files changed

- Workspace: `Cargo.toml`, `Cargo.lock`
- Portable runtime: `crates/guard-runtime/`
- Platform/client/config seams: `crates/guard-platform/`, `crates/guard-client/`, `crates/guard-ipc/`, `crates/platform-linux/src/config.rs`
- Linux composition consuming the runtime: `apps/guardd/`, `apps/guardctl/src/main.rs`
- GTK target composition/status rendering: `apps/guard-ui/`
- Contracts/docs/tests: `AGENTS.md`, `README.md`, `docs/PLATFORM_ARCHITECTURE.md`, `docs/SECURITY_MODEL.md`, `tests/check_platform_boundaries.sh`

## Commands run

```text
cargo fmt --all -- --check

cargo clippy \
  -p guard-core -p guard-browser -p guard-ssh -p guard-ipc \
  -p guard-client -p guard-audit -p guard-platform -p guard-runtime \
  -p guard-test-fixtures -p guard-ui -p guard-notify \
  --all-targets --all-features -- -D warnings

bash tests/check_platform_boundaries.sh

cargo test \
  -p guard-core -p guard-browser -p guard-ssh -p guard-ipc \
  -p guard-client -p guard-audit -p guard-platform -p guard-runtime \
  -p guard-test-fixtures -p guard-ui -p guard-notify \
  --all-features

cargo build --release \
  -p guard-core -p guard-browser -p guard-ssh -p guard-ipc \
  -p guard-client -p guard-audit -p guard-platform -p guard-runtime \
  -p guard-test-fixtures -p guard-ui -p guard-notify \
  --all-features

git diff --check
```

## Tests

| Test | Result | Notes |
|---|---|---|
| Rust formatting | PASS | `cargo fmt --all -- --check` |
| macOS-host Clippy | PASS | All selected portable/runtime/client/UI targets, all features and targets, warnings denied |
| Portable architecture boundary | PASS | Includes the new `guard-runtime`; no `platform-linux` dependency/import |
| Portable/runtime/client/UI tests | PASS | 105 tests passed; 0 failed; synthetic fixtures only |
| Browser deferred runtime | PASS | Require confirmation → pending → exact revalidation → bound lease → allow; Block and timeout deny |
| SSH deferred runtime | PASS | Require confirmation → pending → exact revalidation → 10-second-class reader lease → allow; Block and timeout deny |
| IPC macOS-shaped status | PASS | macOS backend status decodes without Linux mode/mark/fanotify fields |
| macOS-host release build | PASS | Selected portable/runtime/client/UI packages built in release mode |
| Diff whitespace | PASS | `git diff --check` |
| Linux build/test/privileged acceptance | NOT RUN | Explicitly excluded by the user; no Docker or Linux environment was started |

## Security invariants checked

- Pending OS permission ownership is opaque and terminal Allow/Deny consumes it once.
- All exercised Block/timeout paths fail closed, and the portable permission
  contract requires unresolved backend owners to fail closed on drop while the
  OS can still accept a response.
- Browser migration approval creates a source-profile/target-browser/UID/exact-process-root bound lease only after identity revalidation.
- SSH approval creates a one-resource/UID/exact-process-root short lease only after identity revalidation.
- Shared expiry uses backend-supplied stable process liveness, never PID-only checks or direct `/proc` reads.
- Authorization requests select a platform-managed human-auth timeout policy without blocking the platform callback thread.
- Status/config DTOs do not force a macOS backend to claim Linux enforcement mechanics.
- Tests used synthetic browser resources and synthetic SSH key metadata only; no real browser profile or SSH private key was read.

## Platform permissions / signing state

- Endpoint Security entitlement: not required / not exercised in Phase 01
- System Extension install entitlement: not required / not exercised in Phase 01
- Full Disk Access: not required / not exercised in Phase 01
- code signing identity: not required / not exercised in Phase 01
- SIP state used for this test: not changed; no SIP-dependent test was run

## Known limitations

- Phase 01 establishes the runtime, transport, configuration, and protocol seams only. It does not create `platform-macos`, an Endpoint Security client, XPC, or application/system-extension bundles.
- Linux gates were intentionally not run under the user's macOS-only scope. No Linux result is claimed.

## External blockers

- None for Phase 01's macOS/portable scope.

## Next phase readiness

READY
