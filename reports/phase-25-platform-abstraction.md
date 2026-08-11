# Phase 25 — platform backend boundary

## BASE HEAD

`7abad1f7c0d00dabffa372f01fcecec86635474c` (`main`). The pre-existing
`packaging/aur/PKGBUILD` worktree change was preserved.

## DEPENDENCY AUDIT

| crate/app | before | after | reason |
|---|---:|---:|---|
| `guard-core` | no | no | portable domain policy |
| `guard-browser` | no | no | portable browser/resource logic |
| `guard-ssh` | no | no | portable SSH domain helpers |
| `guard-ipc` | no | no | protocol DTOs only |
| `guard-audit` | no | no | portable metadata audit store |
| `guard-platform` | new | no | semantic contracts and portable config |
| `guard-client` | yes | no | typed client plus bounded client transport |
| `guard-ui` | yes | no | portable config/view models and service facade |
| `guard-notify` | yes | no | typed client transport |
| `guard-tui` | test-only yes | no | synthetic test server uses client framing helpers |
| `guardctl` | yes | yes | Linux composition for discovery, service, and trusted process helpers |
| `guardd` | yes | yes | Linux composition and enforcement hot path |

Remaining direct dependencies are intentionally limited to Linux composition
code. The reusable client/UI/domain crates do not depend on `platform-linux`.

## OLD ARCHITECTURE

`guard-client`, `guard-notify`, `guard-tui` tests, and `guard-ui` reached into
`platform-linux` for ordinary transport/configuration behavior. The daemon's
Linux mechanisms and product orchestration were also interleaved.

## NEW ARCHITECTURE

`guard-platform` provides small semantic seams. Linux owns the adapters and
the daemon remains the Linux composition root. Configuration models are
portable; Linux browser path layouts remain in the Linux adapter. Client/UI
service and transport calls now cross semantic facades.

## PLATFORM CONTRACTS

Added contracts cover `ProtectedAccessRequest`, immediate/deferred
authorization, opaque `PendingPermission`, process identity/liveness/ancestry,
verified process-tree containment, SSH exposure/network incidents, browser
discovery, service health/control, local transport, and backend health.

## LINUX ADAPTER

Added Linux adapter types for process identity, containment, deferred
permission ownership, SSH behavior, browser discovery, and service control.
The existing fanotify/BPF/pidfd/identity implementations remain in their
Linux modules. The live migration pending store now uses the opaque Linux
permission owner, preserving fail-closed drop and exactly-once terminal
response behavior.

## GUARDD REFACTOR

`guardd` consumes portable configuration types and continues to compose the
existing Linux enforcement engine directly. No policy rule, lease duration,
SSH read decision, or quarantine behavior was changed.

## GUARD-CLIENT REFACTOR

Removed the direct `platform-linux` dependency. Typed client functions use a
bounded local framing transport owned by `guard-client`; server peer
authentication remains platform-side. Added a semantic service facade for
status and protection/notification operations.

## GUARD-UI REFACTOR

Removed the direct Linux backend dependency. GTK state uses
`guard-platform::config`, the daemon metadata snapshot, typed IPC DTOs, and
the client service facade. Native browser suggestions are requested through
the selected control helper and decoded as portable discovery data.

## IPC BOUNDARY

Protocol definitions remain in `guard-ipc`. CLI, notification, TUI, and GTK
ordinary requests no longer import Linux IPC implementation types. Linux
server framing and peer authentication remain in `platform-linux`/`guardd`.

## CONFIG BOUNDARY

`EnforcementConfig`, `BrowserEnrollmentConfig`, `EnforcementMode`, and
discovery DTOs now live in `guard-platform`; the Linux config module re-exports
them for compatibility while retaining only Linux layouts and discovery.
Existing JSON fields/defaults are unchanged.

## TEST BACKEND

`crates/guard-platform/tests/fake_backend.rs` models deferred permission
ownership, synthetic own-profile/unknown-process policy, and SSH exposure
arm/renew/block/allow/remove transitions without root, kernel interception,
service manager, or process-filesystem access.

## DEPENDENCY BOUNDARY TEST

Added executable `tests/check_platform_boundaries.sh`. It checks portable
manifests and source imports for direct Linux implementation dependencies and
checks that GTK does not import `platform-linux`.

## LINUX REGRESSION RESULTS

Passed during refactor and final gates:

- `cargo fmt --check`
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- `cargo test --workspace --all-features`
- `cargo build --release`
- `git diff --check`
- `./tests/check_platform_boundaries.sh`
- `cargo check --workspace`
- `cargo test -p guardd -p guard-client -p guard-ui -p guard-tui -p guard-notify`
- 83 `guardd` unit tests, client/UI/notify tests, and two TUI framed IPC tests

Full workspace gates and release build are recorded below after completion.

## PRIVILEGED ACCEPTANCE

Blocked by the execution environment. The process is `uid=1000` with
`CapEff=0000000000000000`, so the required kernel/service privileges are not
available. These commands were attempted and each returned exit code 2:

```text
bash scripts/test-browser-enforcement-root.sh
  ERROR: this script must be run as root (needs CAP_SYS_ADMIN for fanotify).
bash scripts/test-ssh-enforcement-root.sh
  ERROR: this script must be run as root (needs CAP_SYS_ADMIN for fanotify).
bash scripts/test-systemd-root.sh
  ERROR: run as root (sudo scripts/test-systemd-root.sh)
```

The deterministic follow-up is to run the same scripts as root on a Linux host
with `CAP_SYS_ADMIN` and a functioning service manager. No privileged success
is claimed here.

## KNOWN LIMITATIONS

The daemon orchestration is still Linux-specific and has not been extracted
into a new runtime crate. The local client transport is Unix-domain based and
does not itself authenticate peers; server-side authentication remains in the
selected platform adapter. No macOS implementation or compilation was tested.

## MACOS READINESS

Reusable domain, protocol, audit, client, and most GTK code can now be reused
without compiling `platform-linux`. A future backend must implement the
semantic contracts and provide its own local service/transport composition.

## FINAL STATUS

Architecture-only refactor complete. All non-privileged quality gates pass;
privileged acceptance is explicitly blocked as documented above. Linux
behavior remains the reference implementation; no fake macOS support was
created.
