# Phase 22.1 — SSH Behavioral Guard Hardening

Date: 2026-08-11  
Base HEAD: 3b596e7f00d565742dcd993cf7bc32464fdb830e  
Status: NOT SECURITY-ACCEPTED pending privileged runtime acceptance

This follow-up repairs the Phase 22 implementation. No real browser profile,
SSH private key, credential, token, or Internet destination was read or used.

## ROOT CAUSE

The reported false positive was an observed git-commit-like deployment failure:
the installed daemon denied the protected-key read because its behavioral
backend was unavailable. No real private key was used during this follow-up.
The raw-key
behavior path reused an existing incident, but the backend arm call
unconditionally rewrote its BPF value to EXPOSURE_OBSERVING. A reread after
the first blocked send could reopen a deadline in the kernel while userspace
still showed PendingDecision. Release builds also dropped ordinary
Decision::Allow audit records, so the successful behavioral key-read path had
no reliable event for guard-notify.

The original BPF send hook also treated every socket_sendmsg as external and
did not distinguish thread-group identity at fork.

## P0 FIXES

- ExposureTracker::arm renews the deadline only for Observing. Pending
  incidents update metadata only and remain indefinite.
- The backend arm API receives the incident state and shared deadline instead
  of forcing Observing.
- A kernel-owned pending_tgids map is set at the first external blocked send,
  copied to future children, checked before expiry/renewal, and cleared only
  by user resolution or process exit. This closes a send/read race in addition
  to the userspace regression.
- Added unit coverage for read → block → reread → wait → send and for a
  secondary thread reusing its TGID incident.
- Changed fork inheritance to a BTF-aware `sched_process_fork` attachment that
  compares the child task's PID and TGID. Thread clones no longer create a
  stale TID entry, while fork from a secondary thread still inherits state.
- Process-exit cleanup now uses the kernel `group_dead` tracepoint field, so
  exposure and pending state are removed only for the final thread in the
  group; neither a secondary thread nor an exiting leader with live siblings
  can release containment.

## BPF RUNTIME

The target host reports:

Linux plfjy-arch 7.1.6-arch1-1 x86_64
/sys/kernel/security/lsm: capability,landlock,lockdown,yama,bpf
/sys/kernel/btf/vmlinux: present
CONFIG_BPF_LSM=y, CONFIG_DEBUG_INFO_BTF=y, fanotify permission support
clang and libbpf are installed; bpftool is absent.

The BPF object compiles and contains BTF/BTF.ext, the send LSM, BTF-aware
fork/exit tracepoints, maps, and the new pending_tgids map. Live verifier/load/attach
acceptance is BLOCKED: the current shell has
CapEff=0000000000000000, and sudo -n returns "sudo: a password is required".
The attempted unprivileged acceptance command returns "BLOCKED: run as root".

The systemd unit now adds only CAP_BPF and CAP_PERFMON to the existing narrow
capability bounding set. LimitMEMLOCK=infinity remains in place. No broad
privileged mode or sandbox-wide weakening was added.

Deployment verification found the currently running installed daemon is still
the pre-follow-up /usr/bin/guardd: systemd ExecStart points to /usr/bin/guardd,
guardctl status reports version 0.1.0 with no build ID, and its live status is
ssh_behavior_backend=UNAVAILABLE with "loading BPF object: Permission denied
(os error 13)". The source release binary contains the new dirty build ID and
was not installed or used to claim runtime acceptance. This explicitly avoids
confusing the old installed daemon with the checkout under test.
The running unit's effective/bounding capabilities are
cap_dac_override,cap_dac_read_search,cap_fowner,cap_kill,cap_sys_ptrace,
cap_sys_admin; CAP_BPF and CAP_PERFMON are absent, matching the deployment
failure and the source unit change.

The source loader now supplies libbpf's kernel log buffer and includes a capped
verifier log in load errors. This is diagnostic instrumentation only; no live
verifier output was available without the missing capabilities.

## KEY-READ EVENT

A successful newly-created behavioral exposure now emits one release-visible,
metadata-only audit event with stable code ssh_behavior_key_read. It includes
incident ID, UID, TGID, PID/start identity through audit fields, executable,
protected resource path, and observation-window length. Repeated reads in an
observing or pending incident do not create duplicate events. guard-notify
maps this event to the normal SSH private key accessed notification.

Live desktop notification delivery could not be exercised without an attached
backend and session incident.

## NETWORK SCOPE

The BPF hook now checks socket family and destination. It considers only
non-loopback IPv4 and IPv6 eligible for behavioral blocking. AF_UNIX,
AF_NETLINK, other unknown/local-only families, IPv4 127.0.0.0/8, and IPv6 ::1
are allowed. Connected sockets use the kernel socket destination, preserving
the pre-existing-socket case; datagram destinations are read from msghdr when
supplied. No payload, TLS, DNS, hostname, or reputation logic was added.

## PROCESS/TGID MODEL

The exposure map remains keyed by TGID. BTF fork inheritance reads the parent
and child task TGIDs directly, and copies state only when child PID equals child
TGID (a new process, not a thread clone). New process children inherit exposure
and pending markers, including a fork from a secondary thread. Userspace incident
reuse also recognizes a secondary thread in the same TGID and retains stable
PID/start/executable metadata for authorization and audit; TGID reuse with a
different process start time does not reuse the old incident.

## COMMIT→PUSH REGRESSION

The rewritten privileged script models a reader process that exits followed by
a separate same-UID send-only process. It expects the later process to send
successfully and not inherit an incident. This was not run because root and the
required capabilities were unavailable.

## PENDING-DECISION REGRESSION

Unit test: PASS. The exact tracker sequence remains blocked after reread and
after the original observation deadline.

Privileged kernel case: BLOCKED pending root/BPF attach. The acceptance script
contains the deterministic two-send case against a non-loopback dummy address
and requires zero sink bytes.

## ALLOW FLOW

The existing polkit-mediated IncidentResolve boundary is unchanged:
org.guardd.incident-resolve uses auth_admin without a keep rule. Allow updates
only the current incident's process-tree entries and clears kernel pending
markers. No production auth bypass was added. Retry and no-permanent-trust
acceptance are BLOCKED until a real authorized incident can be created.

## QUARANTINE FLOW

Existing pidfd/stable-identity containment and conservative attributable
artifact rules were not broadened. Stop & Quarantine and interpreter
non-quarantine behavior require privileged runtime testing and remain BLOCKED.

## GTK + NOTIFICATIONS

The existing dialog exposes exactly Stop & Quarantine and Allow Upload. A
non-action close response does not resolve the incident, so containment remains
pending. The key-read normal event and network-block critical event strings are
wired in guard-notify; real delivery and GTK activation are BLOCKED without
the live backend and desktop authorization session.

## PRIVILEGED ACCEPTANCE

Updated tests/phase22_privileged_acceptance.sh to use only synthetic data and a
disposable dummy interface/address 198.18.0.1. It covers live backend evidence
and build/status metadata, successful key read and one key-read event, AF_UNIX
and 127.0.0.1 allow cases, external direct send with zero sink bytes, pending
incident creation and reread-after-expiry containment, pre-existing connected
socket and external IPv6 sends, future fork+exec child inheritance, unrelated
same-UID process, commit→push separation, and normal observation expiry.

The script is syntactically valid. Runtime execution is BLOCKED by the exact
capability/sudo condition above. Allow/quarantine/GTK and existing
browser/ssh-agent suites remain separate deployment acceptance work. The
deterministic userspace coverage for the one-shot `SshLoadLease`, polkit-bound
incident resolution, browser identity, hardlink, rename, and conservative
quarantine rules passed in the workspace test suite. No new Phase 22.1
performance benchmark was run; existing strict fanotify measurements do not
stand in for a live BPF host.

## BROWSER/SSH-AGENT REGRESSION

No browser protection code or SshLoadLease policy was changed. Workspace tests
covering browser classification, leases, IPC authorization, and quarantine
helpers passed. Privileged browser and ssh-agent suites were not run in this
unprivileged environment and are not claimed as passed.

## KNOWN LIMITATIONS

- Live BPF verifier acceptance, actual zero-byte network enforcement, process
  tree inheritance, expiry, user allow, quarantine, GTK, and desktop
  notification delivery remain unverified here.
- guardctl status now carries 0.1.0+<build-id>; deployment must compare it
  with the installed package/source build before acceptance.
- BPF destination parsing is intentionally limited to IPv4/IPv6 address scope.
- Observation remains bounded (default 10 seconds); only PendingDecision is
  indefinite.
- The updated privileged script was not executable on this host: root/BPF
  credentials were unavailable, so kernel, desktop, polkit, and deployment
  acceptance remain BLOCKED rather than inferred from compilation or tests.

## FINAL PHASE 22.1 STATUS

NOT SECURITY-ACCEPTED. Code-level fixes and non-privileged regression tests are
complete, but the mandatory privileged runtime matrix could not be executed.
A privileged Arch desktop run of the updated acceptance script and the
deployment/browser/ssh-agent suites is required before claiming completion.

## Validation

- cargo fmt --check: PASS
- cargo clippy --workspace --all-targets --all-features -- -D warnings: PASS
- cargo test --workspace --all-features: PASS
- cargo build --release: PASS
- BPF clang compile/ELF/BTF inspection: PASS
- BTF task PID/TGID and `group_dead` exit-layout inspection: PASS (static;
  live attach BLOCKED)
- bash -n tests/phase22_privileged_acceptance.sh: PASS
- rendered systemd unit verification: PASS
- makepkg --printsrcinfo and namcap: PASS
- git diff --check: PASS
- privileged runtime acceptance: BLOCKED, not substituted by build evidence
