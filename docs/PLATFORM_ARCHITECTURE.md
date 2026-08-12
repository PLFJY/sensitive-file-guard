# 平台边界架构（技术参考）

> 用户流程请阅读[中文构建与部署手册](构建与部署手册.md)。本文件集中说明跨平台边界。

## Purpose

This document defines the production boundary shared by the Linux reference
implementation and the macOS backend. Platform security acceptance is recorded
separately: the current target is experimental SIP-off self-use with a local
certificate and FDA. It must pass the controlled synthetic rerun before it can
be called security-accepted; formal SIP-on distribution remains optional.

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
                    ↑                    ↑
             platform-linux       platform-macos
                    ↑                    ↑
                 guardd          guard-es system extension
                         ↑      ↑
                  guardctl / Guard / guard-notify
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

## macOS mapping

`platform-macos` implements deadline-safe Endpoint Security permission owners,
process identity/lifecycle, signer-aware browser discovery, bounded namespace
alias tracking, SystemExtensions/SMAppService adapters, and authenticated XPC.
The XPC adapter carries the same versioned `guard-ipc` JSON bytes used by the
Unix transport and authenticates exact signed Guard client identities plus the
transport EUID. `guard-client::macos::MacGuardClient` performs
LocalAuthentication before any Allow and sends Block directly. `guard-es` is
the macOS composition root inside the Endpoint Security system extension;
product policy and pending/lease transitions remain in `guard-core` and
`guard-runtime`.

macOS `AUTH_OPEN`, `AUTH_LINK`, and `AUTH_RENAME` responses remain at the OS
boundary. Deterministic allow/deny and namespace decisions never wait for UI.
Only typed browser-migration and SSH-read candidates retain an opaque
authorization operation within its bounded kernel deadline. Unknown identity,
deadline pressure, queue pressure, XPC disconnect, process exit, and response
errors fail closed and degrade typed health.

No Network Extension, BPF equivalent, second privileged daemon, or SSH network
containment is required by the current model. Live entitled Endpoint Security
execution with FDA and normal SIP remains a separate acceptance gate from
compile-time, synthetic adapter, authenticated-XPC, and packaging coverage.
