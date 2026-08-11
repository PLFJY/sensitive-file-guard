# Platform boundary architecture

## Purpose

This document defines the boundary introduced by the platform-backend
refactor. Linux remains the reference implementation. No macOS backend is
implemented or implied by this document.

## Portable layers

`guard-core` owns identities, resources, leases, and deterministic
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

`guard-ui` and `guard-notify` consume `guard-client`, IPC DTOs,
and portable view/config types. `guardd` is still a Linux composition root in
this phase; a separate `guard-runtime` crate was not created because the
existing daemon state machine remains closely coupled to the enforcement loop.

## Platform contracts

`guard-platform` deliberately has small, separable contracts:

- `PendingPermission`: opaque ownership of one deferred authorization request;
  terminal `allow` or `deny` is consumed exactly once.
- `ProcessIdentityResolver`: resolve a verified process, test a stable live
  instance, and obtain verified ancestry.
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

## SSH confirmation boundary

SSH key reads are held at the fanotify access boundary. The Linux daemon owns
the pending permission descriptor, Polkit recheck, and short process-tree lease;
portable policy only evaluates the resulting resource and stable identity facts.

## IPC boundary

`guard-ipc` contains protocol DTOs only. `guard-client` provides typed request
semantics and a bounded client-side local framing transport; server connection
and peer authentication remain in the selected platform adapter. `guardctl`,
GTK, and notifications no longer need the Linux transport crate merely to
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

`EnforcementConfig`, browser enrollment metadata, and enforcement mode are
portable models. Linux discovery layouts remain in `platform-linux`. Legacy
unknown JSON fields are tolerated, so removed SSH observation settings do not
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
