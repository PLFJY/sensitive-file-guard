# ADR 0022: Allow SSH Reads and Block Immediate External Sends

Status: accepted for Phase 22.2

## Context and previous behavior

The earlier Phase 22/22.1 implementation began with a raw-key policy denial
and converted it to allow only after a BPF map update succeeded. Missing BPF
LSM support, attachment failure, identity/TGID resolution failure, or an arm
error therefore denied the read. Incidents were also key-scoped, so one TGID
reading two keys could compete for one kernel map slot. The response API had
only two actions rather than the required Block & Quarantine, Block, and Allow
flow.

That model interrupted ordinary local key consumers and treated network
backend availability as authority over filesystem access. It did not match the
product behavior.

## Decision

Protected SSH private-key reads always receive allow. Every resolved read is
reported and creates/updates one exact process-tree exposure. For a bounded
window, BPF LSM `socket_sendmsg` blocks actual external TCP/UDP payload sends
before egress. Local-only socket families and loopback remain allowed.

An external send creates a non-expiring pending incident. Human actions are
the typed snake_case values `block_and_quarantine`, `block`, and `allow`.
Closing the dialog has Block semantics. Same-UID IPC access is insufficient;
resolution crosses polkit.

Backend failure is explicit degradation: reads stay allowed/reported, and
status says immediate outbound blocking is unavailable. This tradeoff favors
uninterrupted legitimate local use over pretending a missing network backend
can be replaced by raw-read denial.

Correlation is process-tree scoped because the supported fact is that a
process recently accessed protected key material. Payload provenance and which
key, if any, influenced a packet are unknowable without full information-flow
tracking. Unrelated same-UID processes are deliberately unaffected.

## Quarantine dependency

Selected: `cap-std` 4.0.2, maintained by the Bytecode Alliance, licensed
Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT. Repository:
<https://github.com/bytecodealliance/cap-std>.

Maintenance/advisory review on 2026-08-11 found 4.0.2 to be the current
published release in its live docs (<https://docs.rs/cap-std/4.0.2/cap_std/>).
RustSec lists the historical Windows-only `cap-primitives` device-name issue
RUSTSEC-2024-0445 as fixed in 3.4.1; this Linux project resolves
`cap-primitives` 4.0.2. No direct `cap-std` advisory was found in the RustSec
database search. This is point-in-time evidence, not a substitute for ongoing
dependency scanning.

`cap-std::fs::Dir` scopes file creation, rename, removal, and copy operations
to open directory capabilities. The project retains a thin adapter for stable
inode attribution, SHA-256 metadata, restrictive permissions, and the existing
BPF inode mutation guard; it does not implement another general quarantine
storage engine.

Alternatives considered:

- `std::fs`: already used by the custom store, but it supplies ambient path
  operations and would not satisfy the third-party-library requirement.
- `fs-err`: useful contextual errors, but no capability boundary.
- a full antivirus quarantine engine: excessive dependency/scope and often
  brings scanning or service behavior the product does not need.

The crate's 4.0.2 release and current API documentation were available during
implementation, including capability-relative `Dir::rename`, `open_with`, and
directory creation. It is statically linked Rust code, so no new dynamic AUR
runtime package is required.

## Consequences and security tradeoff

Ordinary `git commit`-style local reads are never interrupted, including on a
host without BPF LSM. On such a host, immediate exfiltration is not blocked;
the UI and status must be honest about that loss.

This is not DLP. Waiting past the window, transferring data through an
unrelated process, alternate unhooked egress mechanisms, root/kernel
compromise, daemon failure, and ssh-agent signing abuse remain bypasses. No
payload is inspected, and UI/audit wording must not claim key theft or upload.
