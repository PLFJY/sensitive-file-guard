# Phase 22 — SSH Behavioral Exfiltration Guard

## Decision

```text
IN PROGRESS / NOT SECURITY-ACCEPTED — a BPF LSM socket-send backend is now
implemented and compiled, but this checkout could not attach it or run the
required privileged synthetic acceptance matrix. Stop & Quarantine performs
pidfd-based process containment and a conservative BPF-inode-guarded
quarantine transaction are implemented, but this checkout could not attach or
exercise them against the running kernel.
```

Base HEAD inspected: `24f15d3`. No real browser profile, SSH key, credential,
token, or Internet destination was read or used.

## Implemented behavior

- Added a bounded `1..=60` second `ssh_behavior_window_secs` configuration,
  defaulting to ten seconds.
- Preserved the hardened, exact one-shot `SshLoadLease` path for verified
  `ssh-add` and its verified agent. Browser resources retain their pre-open
  `FAN_OPEN_PERM` denial behavior.
- Moved ordinary protected SSH private-key reads to the exact
  `FAN_ACCESS_PERM` gate. The daemon first arms kernel containment and only
  then permits that access event. If BPF loading, attachment, or arming fails,
  the read is denied with `ssh_behavior_backend_unavailable`.
- Added an embedded GPL BPF object built with clang. Its BPF-LSM
  `socket_sendmsg` hook checks the calling TGID at the actual send operation,
  changes an observing exposure to pending, emits a compact ring-buffer event,
  and returns `EPERM` before the send proceeds. It examines no key or network
  payload bytes. This covers sockets created before the read because the check
  is at send time rather than connect time.
- Added tracepoint inheritance for future child processes and leader-exit
  cleanup. The exposure map is bounded to 16,384 active process entries and
  has no UID-wide or executable-name-wide taint.
- Added a pidfd-based Stop action. It freezes the exact incident root, refreshes
  the BPF map for future descendants, revalidates each candidate's UID and
  stable root ancestry, and then terminates only pidfd-pinned processes. The
  UI/CLI/audit result states the number terminated and whether a file was
  actually quarantined.
- Added a conservative quarantine store at `/var/lib/guardd/quarantine/`.
  Only an identity-pinned, regular, user-owned/user-writable direct executable
  or an unambiguous absolute first script argument to a trusted interpreter is
  eligible. A temporary BPF LSM inode guard blocks competing link, unlink,
  rename, setattr, and ordinary write operations while the daemon verifies,
  moves or copies/fsyncs, removes the guarded original, and stores private
  metadata including SHA-256 and original inode identity.
- Added an in-memory, incident-scoped model and typed IPC for listing,
  inspecting, and resolving incidents. A user can see only their own incidents
  unless root; resolution takes only an incident ID and fixed action, then
  requires polkit `org.guardd.incident-resolve` with `auth_admin`.
- Added audit, notifier, GTK, and `guardctl` surfaces for a key-read
  arm, first blocked network send, and authorized allow. Repeated blocked
  sends increment the incident count but do not create repeated alerts.
  If the first ring-buffer event is lost, the daemon reconciles pending map
  state without duplicating subsequent audit events.
  Notifications and dialogs say only that a process which recently read a
  protected key attempted outbound network activity; they do not claim the
  payload was a key.
- `guardctl status` exposes active/pending incidents, reads, blocked sends,
  user allows, quarantines, and `ssh_behavior_backend_failures`. The latter is
  nonzero whenever configured SSH keys cannot obtain an active send backend;
  in that state the daemon fails raw reads closed.
- Added runtime/package dependencies on libbpf and a clang build dependency.

## Deliberate limitations and incomplete work

- The current BPF event records TGID, UID, time, and send size. It does not
  decode destination address, port, protocol, or reliably distinguish
  loopback. The interface leaves destination optional and does not fabricate
  it. Destination enrichment needs a separately reviewed CO-RE/socket parser.
- `StopAndQuarantine` reports `TERMINATED` when no safe candidate is present;
  it reports the actual artifact path and digest only after a quarantine move
  succeeds. Existing writable memory mappings and untested exotic filesystem
  paths still require privileged adversarial acceptance before this is a
  security-accepted quarantine claim.
- The quarantine investigation found that `openat2` can constrain pathname
  resolution, and `linkat(AT_EMPTY_PATH)` can name an already-open file, but
  hard links cannot cross filesystems and Linux does not provide an unlink-by-
  fd primitive. The implementation therefore adds a temporary BPF inode guard
  before its recheck/move or copy/fsync/unlink transaction; without a loaded
  guard it never reaches the raw-read/incident path. See [openat2(2)](https://www.man7.org/linux/man-pages/man2/openat2.2.html),
  [linkat(2)](https://man7.org/linux/man-pages/man2/link.2.html), and
  [renameat2(2)](https://man7.org/linux/man-pages/man2/renameat2.2.html).
- Incidents are intentionally live in memory only. On daemon restart, kernel
  links/maps are detached and no process is represented as still contained.
- This is bounded correlation, not information-flow tracking. It does not
  cover activity after expiry, IPC/shared-memory transfer, temporary-file
  handoff, root/kernel compromise, or untested send paths.

## Host investigation and blocked acceptance

Observed host facts:

```text
kernel: Linux 7.1.6-arch1-1 x86_64
/sys/kernel/security/lsm: capability,landlock,lockdown,yama,bpf
/sys/kernel/btf/vmlinux: present
clang: /usr/bin/clang
libbpf: installed
bpftool: absent
CapEff: 0000000000000000
sudo -n true: sudo: a password is required
```

The build proves the embedded object is an ELF and the Rust loader is linked
to libbpf. It does not prove that the kernel verifier accepts the program or
that sends are blocked. This environment lacks `CAP_BPF`/`CAP_SYS_ADMIN` (and
non-interactive sudo), so the following remain BLOCKED rather than PASS:

- attach/load verification and verifier log review;
- synthetic raw-key read followed by a local sink, including a pre-existing
  socket and a future child process, proving zero payload bytes arrive;
- expiry, authorized allow, and daemon-restart behavior against a live hook;
- notifier and GTK activation against a real kernel incident;
- live BPF-backed process-tree termination or artifact-quarantine acceptance.

A privileged reviewer can start `guardd` with a synthetic SSH fixture and a
local test sink, then verify the kernel attachment, blocked first send, no sink
bytes, expiry behavior, and the explicit allow path. Do not use a personal SSH
key for this test.

`tests/phase22_privileged_acceptance.sh` is the deterministic first acceptance
step for a reviewer: it generates a marker-only key under `/tmp`, creates the
connection before the key read, then proves the loopback sink receives zero
dummy-payload bytes. It requires `sudo` from the intended desktop user and is
BLOCKED in this environment for the same capability reason.

An additional synthetic fixture was run inside an unprivileged user namespace.
It reached libbpf, which failed to load even its trivial probe with `EPERM`
while trying to raise `RLIMIT_MEMLOCK`; guardd reported `UNAVAILABLE` and
denied raw SSH reads. The production unit now sets `LimitMEMLOCK=infinity` so
an actually privileged systemd deployment does not depend on that best-effort
libbpf adjustment.

## Validation executed

```text
cargo fmt --check                                                       PASS
cargo clippy --workspace --all-targets --all-features -- -D warnings  PASS
cargo test --workspace --all-features                                  PASS (237 tests)
cargo build --release                                                  PASS
ldd target/release/guardd (libbpf.so.1)                                PASS
llvm-objdump BPF sections/BTF                                           PASS
git diff --check                                                        PASS
(cd packaging/aur && makepkg --printsrcinfo)                           PASS
namcap packaging/aur/PKGBUILD                                          PASS (no output)
systemd-analyze verify rendered guardd/guard-notify units              PASS
bash -n deploy/install.sh                                               PASS
```

The BPF object contains `lsm/socket_sendmsg`,
`tracepoint/sched/sched_process_fork`,
`tracepoint/sched/sched_process_exit`, `.maps`, `.BTF`, and `.BTF.ext`
sections. These build-time checks are not a substitute for a privileged kernel
attachment test.

The attempted privileged daemon command was:

```text
target/release/guardd --enforce-browser-config /dev/null
```

It stopped before configuration parsing with `CAP_SYS_ADMIN is required` and
`CapEff=0x0000000000000000`; this is the expected fail-closed result and not a
passing BPF attachment test.

## Acceptance status

The raw-read path remains fail-closed unless the BPF send hook attaches and
arms successfully before the access permission is granted. That is safer than
the previous unconditional raw-read deny while the privileged acceptance and
TOCTOU-safe Stop & Quarantine work are incomplete. Phase 22 is not complete
or security-accepted.
