# Platform boundary architecture

## Purpose

This document defines the boundary introduced by the platform-backend
refactor. Linux remains the reference implementation. No macOS backend is
implemented or implied by this document.

## Portable layers

`guard-core` owns identities, resources, leases, incidents, and deterministic
policy. `guard-browser` and `guard-ssh` own portable resource/domain helpers.
`guard-ipc` owns only versioned request/response DTOs. `guard-audit` owns the
metadata-only audit store. `guard-client` owns typed client semantics and
client-side framing. `guard-platform` owns semantic contracts and portable
configuration/discovery DTOs.

The reusable direction is:

```text
guard-core / guard-browser / guard-ssh / guard-ipc / guard-audit
                              ↑
                       guard-platform
                              ↑
                       platform-linux
                              ↑
                  guardd / guardctl composition
```

`guard-ui`, `guard-notify`, and `guard-tui` consume `guard-client`, IPC DTOs,
and portable view/config types. `guardd` is still a Linux composition root in
this phase; a separate `guard-runtime` crate was not created because the
existing daemon state machine remains closely coupled to the enforcement loop.

## Platform contracts

`guard-platform` deliberately has small, separable contracts:

- `PendingPermission`: opaque ownership of one deferred authorization request;
  terminal `allow` or `deny` is consumed exactly once.
- `ProcessIdentityResolver`: resolve a verified process, test a stable live
  instance, and obtain verified ancestry.
- `ProcessContainment`: terminate verified members of an incident tree.
- `SshBehavior`: arm/renew an exposure, poll blocked-send incidents, resolve
  incidents, and remove an exposure.
- `BrowserDiscovery`: return portable browser metadata; layout constants are
  adapter-owned.
- `ServiceController`: query semantic protection/notification health and
  apply start/stop/restart.
- `LocalTransport`: the seam for a future local IPC channel implementation.

The filesystem access request model is `ProtectedAccessRequest` plus
`ProtectedOperation` and `AccessDisposition::{Allow,Deny,Deferred}`. Product
policy receives domain data; it does not receive a descriptor or an OS event
handle.

## Linux implementation mapping

`platform-linux` implements the contracts while retaining its existing
mechanisms:

| Product seam | Linux adapter | Existing mechanism retained |
|---|---|---|
| deferred permission | `fanotify::LinuxPendingPermission` | permission event response and owned event descriptor |
| process identity | `identity::LinuxProcessIdentityResolver` | kernel process identity files and enrollment checks |
| containment | `containment::LinuxProcessContainment` | verified ancestry, pidfd pinning, stop/terminate |
| SSH behavior | `ssh_behavior::LinuxSshBehavior` | existing kernel network containment backend |
| browser discovery | `config::LinuxBrowserDiscovery` | Linux profile/executable layouts |
| service control | `service::LinuxServiceController` | Linux service manager and user-session service |

The daemon continues to use the richer Linux APIs directly where it is the
composition root. Extracting the contracts does not replace or weaken the
reference hot path.

## Permission mediation model

Browser migration remains asynchronous:

```text
access request → policy confirmation candidate → retain opaque pending request
               → user decision → one terminal allow/deny response
```

The Linux pending owner fails closed on drop and closes the underlying event
resource once. Portable code cannot inspect or duplicate that resource.

## Process identity boundary

Portable policy continues to use `ProcessIdentity`, `ProcessStableId`,
`ExeIdentity`, and `AncestorSummary`. Resolution, liveness checks, ancestry,
UID, executable path, and executable file identity are backend responsibilities.
The Linux implementation retains PID plus start token, canonical executable,
device/inode, ownership, and bounded ancestry checks. No naked numeric PID is
an authorization grant.

## Network behavior boundary

SSH key reads remain allowed and informational. When network behavior is
available, an exact process-tree exposure is observed, an external send is
blocked, and the existing Allow, Block, and Block-and-Quarantine decisions are
preserved. The product contract does not mention a particular hook, map, or
ring buffer.

## IPC boundary

`guard-ipc` contains protocol DTOs only. `guard-client` provides typed request
semantics and a bounded client-side local framing transport; server connection
and peer authentication remain in the selected platform adapter. `guardctl`,
GTK, notifications, and TUI no longer need the Linux transport crate merely to
issue ordinary protocol requests.

## Service boundary

The UI calls the semantic service facade in `guard-client`. The selected CLI
and Linux adapter own privileged service operations and notification-presenter
control. UI health is based on `ServiceStatus`; service-manager commands are
not part of GTK product logic.

## UI boundary

The GTK application consumes daemon configuration snapshots, IPC DTOs, and
`guard-platform::config` models. Linux browser discovery is requested through
the selected control helper and decoded as portable discovery data. This keeps
the GTK application reusable without linking the Linux backend implementation.

## Configuration boundary

`EnforcementConfig`, browser enrollment metadata, enforcement mode, and the SSH
observation window are portable models. Linux discovery layouts remain in
`platform-linux`. Existing JSON field names and defaults are unchanged, so
existing Linux installations require no migration.

## Testing strategy

`guard-platform/tests/fake_backend.rs` uses synthetic identities and a fake
pending owner to exercise immediate policy outcomes and deferred terminal
ownership without privileged facilities. Existing daemon tests and privileged
Linux scripts remain in place; fake tests supplement rather than replace them.
`tests/check_platform_boundaries.sh` checks direct dependency and import
direction with a small repository-readable rule.

## Future macOS mapping (planned, not implemented)

A future `platform-macos` can implement filesystem authorization, process
identity/lifecycle, SSH network containment, local privileged transport,
service health, artifact containment, and browser discovery behind the same
semantic seams. macOS APIs, entitlements, system extensions, and packaging are
intentionally not selected or tested in this phase. No macOS compilation claim
is made.

