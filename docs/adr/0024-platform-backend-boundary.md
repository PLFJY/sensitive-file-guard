# ADR 0024: platform backend boundary

## Context

The Linux implementation is the working reference, but daemon, client, CLI,
and GTK code reached into Linux transport, configuration, process, service,
and enforcement modules. That coupling would make a second backend require a
policy rewrite or a copied application.

## Problem

Linux mechanisms and product semantics were interleaved. In particular,
deferred browser authorization exposed Linux ownership concerns, typed clients
depended on the Linux IPC crate, and GTK directly knew Linux configuration and
service details.

## Decision

Introduce `guard-platform` with small semantic contracts for deferred resource
authorization, process identity, process containment, SSH behavior, browser
discovery, service control, and local transport. Move portable configuration
models there. Keep Linux mechanism code in `platform-linux`; use adapters at
that boundary. Keep `guardd` as the Linux composition root for now.

`guard-client` owns typed client semantics and bounded client framing, while
the protocol DTOs remain in `guard-ipc`. The UI reaches service operations
through a semantic client facade and receives portable config/discovery models.

## Why not one giant Platform trait

Filesystem mediation, process identity, network behavior, containment,
discovery, and service control have different lifetimes and likely differ
independently across operating systems. One interface would expose Linux-shaped
arguments or force unrelated capabilities into every implementation.

## Why filesystem and network are separate

A protected-file authorization response and an SSH external-send containment
decision are different product events. SSH reads must remain allowed even when
network containment is unavailable. Separate contracts preserve that fail-open
read behavior and allow independent backend health.

## Why deferred authorization is first-class

Browser migration intentionally holds the current access while a user decides.
`PendingPermission` makes that ownership explicit without leaking a raw
descriptor. Its consuming terminal methods and fail-closed drop behavior keep
the one-request/one-response invariant visible at the seam.

## Why UI/client code must not import platform-linux

The GTK/client/TUI code is reusable product code. It needs typed state and
semantic actions, not Linux peer credentials, service commands, filesystem
layouts, or kernel event handles. Linux-specific work is now selected behind
the CLI/adapter boundary.

## Alternatives considered

- A giant backend object: rejected because it would be Linux-shaped and couple
  unrelated capabilities.
- A plugin or dynamic module framework: rejected as unnecessary indirection for
  one current backend and one planned backend.
- A full daemon/runtime rewrite: rejected because it would increase regression
  risk without isolating a genuinely portable state machine in this phase.
- Fake macOS modules: rejected because they would create unsupported claims.

## Consequences

Portable crates have a clear dependency direction and deterministic fake tests
can model authorization without privileged facilities. Linux still contains
the larger implementation and composition wiring, so the next phase can add a
real macOS adapter without pretending that this phase is cross-platform.
Some Linux diagnostics remain visible in status DTOs where backward compatibility
and operational evidence require them.

## Future macOS integration points

Implement the contracts in a new backend for the macOS authorization facility,
process identity/lifecycle APIs, network containment mechanism, privileged
local transport, service health, artifact containment, and browser layouts.
No such implementation is part of this ADR's change.

