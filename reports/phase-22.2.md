# Phase 22.2 — SSH Read-Allow / Immediate-Send Containment Rewrite

Date: 2026-08-11

## BASE HEAD

Implementation started from exact HEAD
`836eacfca0997c24b995899fe613cafe61b7c223`. The pre-existing local
`packaging/aur/PKGBUILD` version edit was preserved.

## PRODUCT CONTRACT

The implemented contract is: protected SSH-key read -> allow + metadata-only
event/notification; immediate external send by the exact reader process tree
-> block before payload egress + ask the user; decisions are Block &
Quarantine, Block, and Allow. Browser protected resources retain their
pre-open denial model.

## OLD BEHAVIOR REMOVED

The SSH raw-read and backend-unavailable deny reasons and the deny-on-read
fallback were removed. Expired, revoked, mismatched, wrong-UID, and used SSH
load leases no longer turn the raw read into denial; they simply do not supply
`AllowByLease`, and ordinary read allowance applies. Current tests, CLI copy,
UI copy, docs, and root scripts no longer assert SSH deny-on-read behavior.

## READ PATH

The narrow SSH `FAN_ACCESS_PERM` path always returns allow. Every classified
read produces `ssh_behavior_key_accessed`; unresolved identity and
classification paths also allow and emit an explicit untracked/degraded
event. The read hot path does not wait for GTK or polkit. Audit records contain
metadata only and the secret-marker tests pass.

## NETWORK PATH

An active BPF LSM `socket_sendmsg` hook blocks actual external IPv4/IPv6
payload attempts made during the observation window. It covers connected and
per-message destinations, including sockets connected before the key read.
AF_UNIX, AF_NETLINK, IPv4 loopback, and IPv6 loopback remain local allowances.

## BACKEND FAILURE PATH

Attachment, TGID resolution, and exposure-map failures degrade the behavioral
status but never deny an SSH read. `UNAVAILABLE` and `DEGRADED` UI/status copy
explicitly says key access is allowed/reported and external blocking is
unavailable or partial. A hidden privileged acceptance-only daemon switch
deterministically exercises this path against synthetic files.

## PROCESS/TREE MODEL

An exposure is keyed by stable root identity plus TGID and UID, not process
name or UID alone. Scheduler fork/exit hooks propagate and clean up future
children. An unrelated same-UID process is unaffected. `PendingDecision` and
`BlockedUntilExit` do not expire; an observing exposure does. Reconciliation
marks incidents `Exited` after the kernel no longer has a tree member.

## MULTI-KEY MODEL

One live process tree owns one coherent exposure. Additional key reads append
deduplicated `accessed_keys` metadata and reuse the same kernel incident ID.
They cannot create competing TGID map entries or reopen a pending/user-blocked
incident. Informational notifications deduplicate by exposure rather than key
path.

## NETWORK FILTERING

The deterministic privileged harness covers AF_UNIX, IPv4/IPv6 TCP loopback,
IPv4/IPv6 UDP loopback, external TCP/UDP on a disposable dummy interface,
pre-existing TCP connections, future fork/exec children, unrelated same-UID
processes, commit/push process separation, observation expiry, and pending
non-expiry. It measures zero bytes at the synthetic external sink for blocked
cases.

## UDP FIX

The `socket_sendmsg` LSM receives a kernel `msghdr` after syscall address copy.
The BPF code now reads UDP `msg_name` and sockaddr fields with
`bpf_probe_read_kernel`, replacing the incorrect user-memory helper.

## USER ACTIONS

IPC uses a closed enum serialized as `block_and_quarantine`, `block`, or
`allow`. Non-root resolution crosses the non-cached
`org.guardd.incident-resolve` polkit action after live peer PID/start-token and
incident ownership checks. Block leaves the verified tree alive and contained
until exit. Allow releases only that incident/tree. Block & Quarantine
terminates the verified tree and then attempts narrow artifact quarantine.
Closing/dismissing the GTK dialog maps to Block. A unit test confirms that
same-UID possession of an incident ID cannot silently authorize Allow.

## QUARANTINE LIBRARY SELECTION

- Name/version: `cap-std` 4.0.2 (with `cap-primitives` 4.0.2 resolved).
- Repository: <https://github.com/bytecodealliance/cap-std>.
- License: `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT`.
- Maintenance evidence: 4.0.2 was the current published docs.rs release on
  2026-08-11, with upstream under the Bytecode Alliance. The RustSec review
  found the historical Windows-only `cap-primitives` advisory
  RUSTSEC-2024-0445 fixed in 3.4.1; the resolved 4.0.2 is newer. No direct
  `cap-std` advisory was found in the point-in-time RustSec search.
- Why chosen: `cap_std::fs::Dir` provides maintained, capability-relative
  create/open/rename/copy/remove primitives without importing an antivirus or
  another service.

The local adapter remains responsible only for product-specific stable-inode
attribution, BPF mutation guard, restrictive permissions, SHA-256, and
metadata. It quarantines only a verified user-writable direct executable or
unambiguous explicit script. System interpreters and broad directories are
never targets.

## GTK FLOW

The incident dialog title is “Sensitive-key network activity blocked” and the
visible buttons are Block & Quarantine, Block, and Allow. It shows program,
PID, summarized key metadata, elapsed time, and destination when available,
and says only that a process accessed a key and attempted external activity.
Block is the default and dismiss behavior.

## NOTIFICATIONS

`ssh_behavior_key_accessed` creates one normal informational notification per
exposure. `ssh_behavior_network_blocked` creates a distinct critical
notification and activates guard-ui. Including the event code in notification
dedup state prevents the informational event from suppressing the later
critical event.

## AUDIT

SQLite and IPC now carry a stable `event_code`, including:

- `ssh_behavior_key_accessed`
- `ssh_behavior_network_blocked`
- `ssh_behavior_blocked_by_user`
- `ssh_behavior_allowed_by_user`
- `ssh_behavior_blocked_and_quarantined`

The schema migrates existing databases by adding the column with a safe
default. Release GTK Security Log renders explicit labels for all five.

## PRIVILEGED ACCEPTANCE

**BLOCKED / NOT RUN.** The exact attempted commands and results were:

```text
$ tests/phase22_privileged_acceptance.sh
BLOCKED: run as root

$ sudo -n tests/phase22_privileged_acceptance.sh
sudo: a password is required
```

The current user is UID 1000, so fanotify/BPF attachment and the synthetic
network matrix could not be executed. Deterministic rerun command from the
logged-in desktop user's shell:

```sh
sudo tests/phase22_privileged_acceptance.sh
```

The script uses only two synthetic marker files and a disposable dummy
interface; it contains no Internet exfiltration. It now exercises mandatory
read-only, forced-backend-unavailable, local/external TCP+UDP, pre-existing
connection, future child, unrelated process, multi-key, expiry/non-expiry,
Block, Allow, and attributable-script Block & Quarantine cases.

## REAL DESKTOP ACCEPTANCE

**BLOCKED / NOT RUN.** A live graphical session and D-Bus socket were present
(`DISPLAY=:0`, `WAYLAND_DISPLAY=wayland-1`, user bus present, notification
service active), but creating the required isolated synthetic enforcement
daemon still requires root. The already-installed daemon was deliberately not
used because its configuration may reference real browser or SSH resources.
No read-only notification, critical notification, dialog, dismissal, or
three-button screenshot/observation is claimed.

After the privileged synthetic daemon is running, manually execute the
read-only and read-then-dummy-send cases from the same desktop session, verify
one normal notification/no dialog for the first, then critical notification,
guard-ui activation, three visible buttons, and each decision outcome for the
second.

## REGRESSIONS

Executed successfully on 2026-08-11:

```text
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo build --release --workspace --all-features
bash -n tests/phase22_privileged_acceptance.sh and updated root scripts
git diff --check
```

The workspace suite passed, including 80 guardd tests, 46 platform-linux
tests, 36 guard-core tests, three notification tests, protocol/audit/browser/
broker tests, integration smoke, and doc-tests. Privileged browser, hardened
ssh-agent, systemd/polkit, BPF runtime, and desktop regressions were not rerun
because sudo was unavailable.

## KNOWN LIMITATIONS

- Backend unavailable/daemon failure means reads still succeed but network
  containment is absent.
- Waiting beyond the observing window or handing data to an unrelated process
  bypasses correlation by design.
- This is not payload provenance, DLP, malware classification, or permanent
  process reputation.
- BPF block events currently do not export destination address/port metadata,
  so GTK displays it only if a future backend supplies it.
- Alternate unhooked egress paths and root/kernel compromise remain out of
  scope.
- `cargo-audit` was not installed; the dependency advisory review was a
  point-in-time RustSec/manual review.

## FINAL STATUS

**IMPLEMENTATION AND NON-PRIVILEGED QUALITY GATES PASS; PHASE 22.2 SECURITY
ACCEPTANCE IS BLOCKED.** Do not promote Phase 22.2 to complete until the new
privileged BPF matrix and real desktop GTK/notification acceptance both run
and pass on the target host.
