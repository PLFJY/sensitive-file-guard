# macOS Phase 03 — Endpoint Security Authorization Backend

## Phase

Name / number: Phase 03 — Endpoint Security Authorization Backend

## Base

- starting commit / branch: `42f0d48` / `main`
- platform / macOS version: macOS 26.6.1 (Build 25G76)
- architecture / CPU: arm64 / Apple Silicon
- Xcode / SDK: Xcode 26.6 (17F113), macOS SDK 26.5

## Implemented

- Added a narrow C shim compiled against Apple's current EndpointSecurity
  headers. It exposes client create/delete, the single AUTH_OPEN subscription,
  normalized open/process/file facts, retain/release, flags response, and Mach
  absolute-time conversion only.
- Added a Rust `EndpointSecurityBackend` that subscribes exclusively to
  `ES_EVENT_TYPE_AUTH_OPEN`, performs exact synthetic-path fast classification,
  copies minimal process/resource identity, and returns from the ES callback
  without waiting for UI, IPC, disk databases, or long process scans.
- Added `MacPendingPermission`, implementing the portable
  `PendingPermission` contract with one atomic terminal transition. Allow
  returns the exact requested kernel FFLAGS, deny returns zero, and every path
  releases its retained message exactly once.
- Hardcoded `cache=false` inside the C shim's only flags-response API so callers
  cannot accidentally cache a protected decision.
- Added a single deadline scheduler thread. It services all deferred requests,
  denies at the effective event deadline, resolves shutdown safely while the ES
  client is live, and avoids an unbounded thread per open.
- Added current Darwin timebase conversion and conservative, documented
  constants: 1-second safety margin, 2-second minimum interactive budget, and
  45-second product prompt cap. Insufficient budgets fail closed immediately.
- Mapped every current `es_new_client` result to distinct diagnostics, including
  not entitled, TCC/FDA not permitted, not privileged, internal, invalid
  argument, and client-limit errors.
- Mapped flags-response duplicate, not-found, wrong-event, invalid-argument,
  and internal results to degraded backend health after releasing the message.
- Added an opt-in `es-poc` build feature and deterministic real acceptance
  script. It protects one temporary synthetic file and allows only the exact
  canonical probe executable plus its `st_dev`/`st_ino`; other processes deny.
- Extended bundle assembly to accept external host/extension provisioning
  profiles without storing them in the repository.

## Files changed

- Endpoint Security boundary: `native/macos/endpoint_security_bridge.{h,c}`
- Safe backend/deadlines/pending owner: `crates/platform-macos/src/`
- System-extension composition: `apps/guard-es/`
- Build and real-PoC tooling: `scripts/macos/build-dev-app.sh`,
  `scripts/macos/run-es-poc.sh`
- Static platform gates: `tests/check_macos_boundaries.sh`
- Documentation: `docs/MACOS_ENDPOINT_SECURITY.md`,
  `docs/INSTALL_MACOS_DEV.md`
- Dependency metadata: `Cargo.lock`, crate Cargo manifests

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

GUARD_ES_POC=1 \
GUARD_ES_POC_FILE='<temporary synthetic fixture>' \
GUARD_ES_POC_ALLOW_EXE='<canonical target/debug/guard-test-probe>' \
scripts/macos/build-dev-app.sh

scripts/macos/build-dev-app.sh
scripts/macos/inspect-signing.sh
build/macos/Guard.app/Contents/Library/SystemExtensions/\
io.github.plfjy.SensitiveFileGuard.guard-es.systemextension/Contents/MacOS/guard-es

tests/check_platform_boundaries.sh
tests/check_macos_boundaries.sh
sh -n scripts/macos/build-dev-app.sh \
  scripts/macos/inspect-signing.sh scripts/macos/run-es-poc.sh
git diff --check
```

## Tests

| Test | Result | Notes |
|---|---|---|
| Rust formatting | PASS | `cargo fmt --all -- --check` |
| macOS-host Clippy | PASS | Selected portable/macOS/UI/extension targets; warnings denied |
| Rust unit/integration tests | PASS | 114 passed, 0 failed; synthetic fixtures only |
| Ample ES deadline | PASS | Capped to 45 seconds |
| Shorter-than-cap deadline | PASS | Uses per-event remainder minus 1-second margin |
| Insufficient ES deadline | PASS | Fails closed without prompt dispatch |
| Exact requested FFLAGS allow | PASS | Fake responder received `0x1234`, not O_* flags |
| Explicit deny / unresolved Drop | PASS | Fake responder received zero and one release |
| Deadline vs user race | PASS | Exactly one terminal response and one release |
| Deadline primary path | PASS | Timer denied before a late user allow |
| ES response error | PASS | Duplicate response result degraded health and still released once |
| Client-result diagnostics | PASS | Entitlement, FDA/TCC, privilege, internal, and client-limit mappings checked |
| macOS release build | PASS | Rust and current-SDK C shim link to `/usr/lib/libEndpointSecurity.dylib` |
| C shim compiler gate | PASS | Blocks, `-Wall -Wextra -Werror` |
| Event/API boundary | PASS | Only AUTH_OPEN; flags response only; retain/release only; `cache=false` |
| Default app bundle assembly/signature | PASS | Deep/strict ad-hoc structural signature verification |
| PoC-feature app bundle assembly | PASS | Compiled exact temporary fixture and exact probe identity into extension |
| Direct client diagnostic | PASS | Returned not-privileged and exit 78; never reported ACTIVE |
| Real ES kernel deny/allow | BLOCKED | Apple-approved ES provisioning/FDA/runnable system extension unavailable |
| Linux build/test | NOT RUN | Explicitly excluded by the user; no Docker or Linux environment was started |

## Security invariants checked

- The callback validates that the normalized message is AUTH_OPEN and copies
  facts before returning.
- Deferred events retain before callback return; terminal resolution responds
  once, uses `cache=false`, and releases once.
- Allow returns the exact `es_event_open_t.fflag` request. Deny returns zero.
- A deadline timer—not Drop—is the primary late-response guarantee.
- Timer, user action, Drop, queue failure, and backend shutdown all race through
  one atomic terminal transition.
- Backend shutdown resolves all retained messages while the !Send ES client is
  still alive and deletes the client on its creator thread.
- Truncated/missing paths, invalid PID, or incomplete executable/target file
  identity fail closed.
- The C shim contains no browser, SSH, lease, or product policy.
- The PoC uses a temporary synthetic canary only, no real secrets and no network.

## Platform permissions / signing state

- Endpoint Security entitlement claim: present in the extension template and
  ad-hoc bundle; Apple authorization/provisioning remains unavailable.
- System Extension host entitlement claim: present; matching host provisioning
  remains unavailable.
- Full Disk Access: not granted/tested for a runnable extension.
- Available certificate: `Apple Development: zero_plfjy@icloud.com (ZN9S86U87M)`;
  certificate TeamIdentifier observed in Phase 02: `YSGFZUQGW6`.
- Direct unprivileged client creation result:

  ```text
  guard-es: Endpoint Security client is not running with required privilege; enforcement is not active
  exit=78
  ```

- Non-interactive privilege check:

  ```text
  $ sudo -n <guard-es>
  sudo: a password is required
  sudo_noninteractive_exit=1
  ```

- SIP: not changed.

## Exact real-PoC blocker

Phase 02 established that a certificate-signed host/extension pair has no
embedded provisioning profiles and Gatekeeper rejects the bundle. Running the
ad-hoc Phase 03 executable directly reaches `es_new_client` but returns
`ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED`. Elevation alone cannot turn an
unapproved restricted entitlement claim into valid provisioning, so no
activation request or kernel deny/allow claim was made.

The deterministic re-test is:

```sh
APP_BUNDLE_ID='<approved host id>' \
SYSTEM_EXTENSION_BUNDLE_ID='<approved extension id>' \
DEVELOPMENT_TEAM='<certificate TeamIdentifier>' \
SIGNING_IDENTITY='<matching Apple signing identity>' \
HOST_PROVISIONING_PROFILE='<matching host profile>' \
EXTENSION_PROVISIONING_PROFILE='<Apple-approved ES profile>' \
scripts/macos/run-es-poc.sh
```

The script assembles and verifies the bundle, requests activation, waits for an
ACTIVE lifecycle state, confirms `/usr/bin/cat` cannot read the synthetic
fixture, confirms the identity-bound `guard-test-probe` can read its canary, and
requests deactivation during cleanup.

## Known limitations

- Real AUTH_OPEN delivery and kernel allow/deny remain entitlement/FDA BLOCKED.
- Phase 03 protects exact synthetic paths only. Browser/SSH classification,
  process discovery, persistent configuration, leases, and UI/XPC approval
  belong to later phases.
- The default extension diagnoses client availability and exits non-active; it
  subscribes only in the explicit `es-poc` build.
- Path/inode namespace hardening and dropped sequence detection are later-phase
  work.
- The development bundle is not notarized or distributable.

## Next phase readiness

READY for Phase 04. The safe AUTH_OPEN wrapper, per-message deadline handling,
pending permission owner, health diagnostics, and deterministic synthetic real
PoC are present. Only the real kernel acceptance case remains externally
BLOCKED by Apple entitlement/provisioning/FDA.
