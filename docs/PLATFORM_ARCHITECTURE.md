# Platform boundary architecture

## Purpose

This document defines the production boundary shared by the Linux reference
implementation and macOS backend work. It does not yet claim a working macOS
enforcement backend.

## Portable layers

`guard-core` owns identities, resources, leases, and deterministic
policy. `guard-browser` and `guard-ssh` own portable resource/domain helpers.
`guard-ipc` owns only versioned request/response DTOs. `guard-audit` owns the
metadata-only audit store. `guard-client` owns typed client semantics over an
injected local transport. `guard-platform` owns semantic contracts and portable
policy/discovery DTOs. `guard-runtime` owns shared lease transitions and bounded
browser/SSH pending queues.

The reusable direction is:

```text
guard-core / guard-browser / guard-ssh / guard-ipc / guard-audit
                              ↑
             guard-platform / guard-runtime
                              ↑
                       platform-linux
                              ↑
                  guardd / guardctl composition
```

`guard-ui` and `guard-notify` consume `guard-client`, IPC DTOs, and portable
view/config types. `guardd` remains the Linux composition root and injects its
fanotify permission owner and process-liveness adapter into `guard-runtime`.

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
- `LocalTransport`: byte transport plus explicit ordinary/authorization timeout
  policy; Unix sockets are the Linux implementation and XPC can implement the
  same typed client contract.

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

`guard-runtime` owns `Box<dyn PendingPermission>` values and bounded queue
state. The Linux pending owner fails closed on drop and closes the underlying
event resource once. Portable code cannot inspect or duplicate that resource.

## Process identity boundary

Portable policy continues to use `ProcessIdentity`, `ProcessStableId`,
`ExeIdentity`, and `AncestorSummary`. Resolution, liveness checks, ancestry,
UID, executable path, and executable file identity are backend responsibilities.
The Linux implementation retains PID plus start token, canonical executable,
device/inode, ownership, and bounded ancestry checks. No naked numeric PID is
an authorization grant.

## SSH confirmation boundary

SSH key reads are held at the fanotify access boundary. The Linux adapter owns
the permission descriptor and Polkit gate; the shared runtime owns queue and
short process-tree lease transitions after exact identity revalidation.

## IPC boundary

`guard-ipc` contains protocol DTOs only. `guard-client` provides typed request
semantics and a bounded client-side local framing transport; server connection
and peer authentication remain in the selected platform adapter. `guardctl`,
GTK, and notifications no longer need the Linux transport crate merely to
issue ordinary protocol requests.

## Service boundary

The GTK application selects a small target-specific service composition module.
Linux `pkexec`/systemd calls live there and in `guardctl`; `guard-client`
contains only typed protocol request/response behavior.

## UI boundary

The GTK application consumes daemon configuration snapshots, IPC DTOs, and
`guard-platform::config` models. Linux browser discovery is requested through
the selected control helper and decoded as portable discovery data. This keeps
the GTK application reusable without linking the Linux backend implementation.

## Configuration boundary

`PolicyConfig` and browser enrollment metadata are portable. Linux
`EnforcementMode` and the backward-compatible Linux configuration wrapper live
in `platform-linux`. Existing JSON with `enforcement_mode` still parses without
migration. Status/config IPC makes Linux mechanism fields optional and reports
the backend kind, so macOS need not invent filesystem-mark counters or a mode.

## Testing strategy

`guard-runtime` tests use synthetic identities, a fake process resolver, and a
fake pending owner to exercise production browser migration and SSH approval,
block, and timeout paths without privileged facilities. Existing daemon tests
and privileged Linux scripts remain in place; fake tests supplement them.
`tests/check_platform_boundaries.sh` checks direct dependency and import
direction with a small repository-readable rule.

## Future macOS mapping (planned, not implemented)

A future `platform-macos` adapter can implement Endpoint Security protected-file
authorization for both browser and SSH resources, process identity/lifecycle,
authenticated XPC, service health, and browser discovery behind these seams.
No Network Extension or SSH network containment is required by the current
model. Entitled Endpoint Security execution is not claimed in this phase.
