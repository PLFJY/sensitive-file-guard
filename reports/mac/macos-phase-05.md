# macOS Phase 05 — Authenticated XPC and Human Authorization

## Phase

Name / number: Phase 05 — Authenticated XPC and Human Authorization

## Base

- starting commit / branch: `8a57aac` / `main`
- platform / macOS version: macOS 26.6.1 (Build 25G76)
- architecture: arm64 / Apple Silicon
- Xcode / SDK: Xcode 26.6 (17F113), macOS SDK 26.5
- Rust: rustc 1.97.0
- GTK / libadwaita: 4.22.4 / 1.9.3

## Implemented

- Added a real macOS `LocalTransport` backed by one bounded NSXPC method that
  exchanges the existing versioned `guard-ipc` JSON envelope as `NSData`.
- Declared the explicit Endpoint Security Mach service
  `io.github.plfjy.SensitiveFileGuard.guard-es.control` through
  `NSEndpointSecurityMachServiceName`; custom build identifiers derive a
  matching `<extension-bundle-id>.control` service.
- Applied an exact Security.framework-parsed code-signing requirement to every
  client connection before activation. Accepted signing IDs are limited to the
  Guard app, bundled `guardctl`, and bundled `guard-notify`, all under the same
  runtime Team ID. The client independently requires the exact extension ID.
- Bound service access to the active console user's transport-reported EUID.
  JSON cannot claim a UID, signer, PID, or executable identity.
- Enforced the 64-KiB protocol request bound in native and Rust layers, checked
  protocol versions before dispatch, and capped concurrent handlers at 32.
- Added the shared authorization classes `Metadata`, `RestrictiveMutation`, and
  `SensitiveAllow`. Explicit Block operations remain noninteractive; every
  operation that can expand access is routed through LocalAuthentication.
- Added `LAContext + LAPolicyDeviceOwnerAuthentication` with an injectable Rust
  boundary. Cancellation, failure, unavailable authentication, or deadline
  expiry sends no sensitive XPC request.
- Added typed macOS client operations for metadata, migration, SSH, pending
  resolution, and configuration application. GTK and bundled CLI requests now
  use XPC on macOS; there is no `--yes`, environment/file token, or lower-level
  unsigned resolver path.
- Propagated pending expiry to GTK. Allow uses the remaining ES deadline;
  explicit Block does not open LocalAuthentication.
- Hardened migration and SSH pending stores with typed late, replay, invalid-ID,
  and wrong-owner outcomes. Expired permissions deny and are consumed; replay
  cannot create a second lease.
- Added authenticated authoritative configuration application. The extension
  validates browser/SSH ownership against the XPC peer, writes only the fixed
  system path atomically, and uses directory mode 0700 and file mode 0600.
  Configuration queries filter browser, executable, and SSH path metadata to
  the authenticated user.
- Preserved responsive metadata access by using independent XPC connections;
  LocalAuthentication occurs in the caller before the sensitive request is
  sent and does not serialize unrelated status queries.
- Added a Team-signed transport-only adversarial harness. It proves the signed
  Guard UI and CLI can exchange XPC requests while both an ad-hoc same-UID
  process and a same-Team/unlisted-signing-ID same-UID process are rejected.
- Kept server status honest: XPC can report diagnostics, but status remains
  `NOT_ENFORCING` until the Phase 07 policy runtime is connected.

## Principal files

- Native transport/authentication:
  `native/macos/xpc_bridge.{h,m}`,
  `native/macos/local_auth_bridge.{h,m}`
- Rust macOS adapters:
  `crates/platform-macos/src/xpc.rs`,
  `crates/platform-macos/src/local_auth.rs`,
  `crates/platform-macos/src/config.rs`
- Typed client/protocol/runtime:
  `crates/guard-client/src/macos.rs`, `crates/guard-ipc/src/lib.rs`,
  `crates/guard-runtime/src/lib.rs`
- Extension/UI/CLI composition:
  `apps/guard-es/src/main.rs`, `apps/guard-ui/src/platform_service.rs`,
  `apps/guardctl/src/main.rs`
- Packaging/tests/docs:
  `packaging/macos/GuardES.Info.plist.in`, `scripts/macos/`,
  `tests/check_macos_boundaries.sh`,
  `docs/MACOS_XPC_AND_AUTHORIZATION.md`

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
  -p guardctl -p guard-notify --all-features

MACOSX_DEPLOYMENT_TARGET=13.0 cargo build --release \
  -p platform-macos -p guard-client -p guard-ui -p guard-es \
  -p guardctl -p guard-notify --all-features

xcrun clang -fsyntax-only -Wall -Wextra -Werror -fobjc-arc \
  -mmacosx-version-min=13.0 -isysroot <current SDK> -Inative/macos \
  native/macos/xpc_bridge.m native/macos/local_auth_bridge.m \
  native/macos/xpc_wrong_signed_probe.m

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
| Rust unit/integration tests | PASS | 165 passed, 0 failed; synthetic fixtures only |
| Release build | PASS | macOS platform, client, GTK app, extension, CLI and notifier |
| Native Objective-C strict compile | PASS | XPC, LocalAuthentication and adversarial probe; warnings denied |
| Platform boundary checks | PASS | Portable layer and macOS target checks |
| Protocol size/version validation | PASS | Oversize/malformed/wrong-version requests fail closed |
| EUID source | PASS | Handler receives transport EUID; JSON has no trusted UID field |
| Exact signing policy | PASS | Exact Team + listed signing ID + expected EUID required |
| Requirement injection | PASS | Unsafe requirement atoms rejected before Security.framework parsing |
| Real signed XPC positive path | PASS | Signed Guard UI and bundled `guardctl` reached temporary Mach service |
| Ad-hoc same-UID XPC process | PASS | Connection produced no response and was rejected |
| Same-Team unlisted same-UID process | PASS | Connection produced no response and was rejected |
| LocalAuthentication success ordering | PASS | Sensitive bytes sent exactly once only after injected success |
| LocalAuthentication cancellation | PASS | No Allow/config-apply bytes sent |
| Block without authentication | PASS | Restrictive resolution sent without opening authentication |
| Metadata during authentication | PASS | Status remained responsive while another auth call was blocked |
| Pending replay | PASS | Browser and SSH pending IDs cannot be resolved twice |
| Late resolution | PASS | Browser and SSH permissions deny; no lease is recreated |
| Config peer scope | PASS | Other-user browser scope rejected/filtered |
| Config persistence | PASS | Synthetic atomic write, mode 0600, no temporary-file residue |
| Development bundle/signing | PASS | App/helpers/extension satisfy designated requirements |
| Live activated extension XPC/ES | BLOCKED | No Apple-approved provisioning profile/ES entitlement is installed |
| Interactive OS LocalAuthentication dialog | NOT AUTOMATED | Native API path compiles; deterministic injected success/cancel/deadline behavior tested |
| Linux build/test | NOT RUN | Explicitly excluded by user |
| Docker | NOT STARTED | Explicitly excluded by user |

## Real XPC adversarial test boundary

The test used a temporary user launchd job and a temporary copy of the actual
server binary. Restricted Endpoint Security and system-extension-install
entitlements were removed from those temporary copies so macOS could launch
them outside a provisioned system-extension container; exact production
signing identifiers and Team constraints were retained. The production bundle
was not altered. The job and temporary files were removed on exit.

This proves the real NSXPC connection, Mach service, EUID check, and code-signing
requirements. It does not claim Endpoint Security entitlement, Full Disk
Access, system-extension activation, or AUTH_OPEN delivery.

## Security invariants checked

- Same UID, same Team, process name, PID, pathname, or executable basename alone
  cannot access the control service.
- An Allow/configuration mutation is not serialized or sent until
  `LAPolicyDeviceOwnerAuthentication` succeeds.
- Authentication state is not persisted or represented by a reusable token.
- Blocking cannot expand access and remains available after cancellation.
- XPC and LocalAuthentication timeouts are bounded; native timeout conversion
  is overflow-safe.
- Listener shutdown retains the small callback state until process exit so an
  already-delivered XPC method cannot dereference freed memory.
- Pending resolution is single-consumption and owner-scoped. Late/replayed IDs
  fail without creating a lease.
- Audit/protocol/config metadata contain no browser rows, cookie values,
  passwords, session tokens, or SSH private-key bytes.
- Configuration writes use a fixed root-authoritative location; clients cannot
  choose the destination path.

## Persistence and privacy state

- Synthetic config fixtures only were written during testing.
- `/Library/Application Support/Sensitive Data Firewall/config.json` remained
  absent after the phase; no real system configuration was created.
- No real browser database, browser credential/session content, or SSH private
  key was read.
- No network exfiltration test was created or run.
- SIP and other global security controls were not changed.

## External blockers

- A valid Apple-provisioned Endpoint Security system extension and Full Disk
  Access remain unavailable. Therefore live activated-extension XPC and real ES
  event delivery are BLOCKED, with the same external Apple gate recorded in
  Phases 02–04.
- Everything independent of that entitlement was completed and tested,
  including real Team-signed NSXPC peer rejection through a temporary service.

## Next phase readiness

READY for Phase 06. The macOS app/CLI now have an authenticated, bounded XPC
control plane; sensitive mutations have an OS-owned human gate; metadata remains
responsive; and replay/late resolution is fail-closed.
