# Linux File Shield — Freeze Review (LFH7)

Baseline: commit `84a1bd133c78c41911d82dac5ffd1989a7722f5b` + LFH1–LFH6 work on top.
Kernel `7.1.8-arch1-3` (x86_64). **All 20 mandatory privileged gates re-run and PASSED on the REAL HOST**
(`sudo bash scripts/linux/run-all-root-gates.sh` → `LIVE HOST GATE SUMMARY: PASS=20 FAIL=0`, evidence in
`reports/linux/evidence/live-host-20260819-122244/`). The earlier nspawn-seccomp blocker no longer applies:
the user authorized direct host runs and every gate is green. Fixes required by the live run are listed below
(fanotify code paths that had never been executed before).

## Review checklist

### 1. File interception
| Item | State | Evidence |
|---|---|---|
| future protected open/read denial (real fanotify) | LIVE VERIFIED | `test-browser-enforcement-root.sh` PASS, `test-ssh-enforcement-root.sh` PASS, `test-fanotify-root.sh` PASS (PASS=6 FAIL=0), `test-bypass-root.sh` PASS (18 PASS, 2 documented fanotify limits) |
| already-open / inherited fd | NOT PROTECTED — documented, not claimed | `docs/Linux技术说明.md` "已打开的文件描述符、继承描述符、root/内核入侵不在 V1 保护范围内" |
| daemon crash semantics | LIVE VERIFIED (ACCEPTED) | `experiment-fdstore-root.sh` → `VERDICT: ACCEPTED`: fdstore preserved the fanotify group across SIGKILL+restart; queued event answered after claim; marks still enforce (PASS=4 FAIL=0) |
| overflow continuity semantics | PREVENTED (code) + LIVE (revocation path) | overflow → continuity LOST + revoke all + generation bump (LFH3/LFH5); `test-continuity-root.sh` PASS (revocation/lose path live); wording "dropped events NOT individually denied" truthful |

### 2. Identity
| Item | State | Evidence |
|---|---|---|
| pidfd path | LIVE VERIFIED | `test-pidfd-root.sh` PASS=5 FAIL=0: pidfd_enabled=true, pidfd_missing_events=0, unknown probe denied, enrolled probe allowed |
| legacy fallback | PREVENTED (code) | truthful `pidfd_enabled=false` → REDUCED, never silent Strong |
| actual executed image | PREVENTED (code/unit) | `/proc/PID/exe` fd + fstat; pathname replacement/unlink survive (LFH1) |
| user-writable enrollment | PREVENTED (code/unit) | `verify_fd` hashes executed-object fd; renamed fake stays Unknown |
| PID reuse | PREVENTED (code/unit) | starttime-mismatch cache invalidation; lease bound to exact instance (LFH5) |

### 3. Resource object
| Item | State | Evidence |
|---|---|---|
| concrete secret files | PREVENTED (code/unit) + LIVE | exact-path + inode-index enrollment; browser/ssh enforcement scripts PASS |
| symlink / hardlink | PREVENTED (code/unit) + LIVE | `classify_fd_catches_symlink_*` / `*hardlink_by_inode`; bypass + strict scripts PASS |
| rename | LIVE VERIFIED for opened-object rename-out (opaque handles) | `test-object-identity-root.sh` PASS; **Step 3 (never-opened-before rename-in gap) NOT ACCEPTED** — needs second FAN_CLASS_NOTIF+FID topology group, deferred |
| dynamic object | PREVENTED (code/unit) + LIVE | WAL/SHM sidecars + object handles; strict-filesystem script PASS |
| inode reuse | PREVENTED (code/unit) | handle mismatch → drop key, no reuse false-positive |
| unsupported filesystem | REDUCED truthfully | per-fs handle-unsupported → REDUCED with reason |

### 4. Authority (LFH5)
| Item | State | Evidence |
|---|---|---|
| own browser | PREVENTED (code/unit) + LIVE | trusted browser + own profile → Allow; native-browser script PASS |
| migration | PREVENTED (code/unit) + LIVE | EXACT READER INSTANCE, no whole-tree grants, generation bound; real-firefox compat PASS (offline + live) |
| SSH read | LIVE VERIFIED (fail-closed) | ssh-broker + ssh-load scripts PASS (29 PASS 0 FAIL); unapproved reads denied, ALLOW_BY_LEASE audit recorded |
| SSH load | LIVE VERIFIED | exact invocation, pinned agent socket, one-shot, revoke on exit; `test-ssh-load-root.sh` + broker PASS |
| continuity generation | PREVENTED (code/unit) | `stale_lease_generation` defense-in-depth past revocation |

### 5. Control plane
| Item | State | Evidence |
|---|---|---|
| SO_PEERCRED | PREVENTED (code/test) | kernel-verified peer uid/pid; IPC tests |
| polkit | LIVE VERIFIED | `test-installed-auth-root.sh` PASS (real polkit decisions, socket ACLs, per-UID audit filtering) |
| no UID from JSON trust | PREVENTED (code) | uid filters derive from `creds.uid`; peer_uid field is kernel-supplied |
| config ownership/mode | PREVENTED (code) | `guardctl setup` writes config `0o640`, root-owned |
| no silent mode downgrade | PREVENTED (code) | explicit `enforcement_mode` required; `config_version` future-rejected; `test-systemd-root.sh` PASS (installer never enables; status ACTIVE in strict mode) |

### 6. Truthfulness (final vocabulary)
- **PREVENTED**: every deterministic code/unit gate (identity, object, authority, control plane).
- **LIVE VERIFIED**: all 20 privileged scripts PASS on the real host (pidfd, object identity, continuity, fdstore ACCEPTED, browser/SSH enforcement, fanotify, bypass, hardening, agent-compat, ssh-broker 29/29, ssh-load, strict-concurrency, topology-race-stress, systemd, installed-auth, browser-adversarial, strict-filesystem, native-browser 8/8, benchmark).
- **REDUCED**: legacy identity fallback, object-handle-unsupported filesystems — reported truthfully in status.
- **NOT ACCEPTED (coverage)**: LFH2 rename-in gap (deferred by design); LFH6 cross-family (no Chromium family installed — NOT INSTALLED, not a FAIL); Flatpak/Snap/network FS (no live acceptance; not claimed).
- **NOT PROTECTED**: already-open/inherited fds, root/kernel compromise — explicitly out of V1 scope.

## Fixes required by the live run (previously-unexercised code paths)
- `apps/guardd/src/enforce.rs` + `ipc.rs`: SSH `AllowByLease` decisions are now audited in release builds (`should_record_decision` + `event_visible_in_build`) — the SSH-key accountability path requires ALLOW_BY_LEASE evidence (broker script now 29/29).
- `apps/guard-fdstore`: `fanotify_mark` flags bug (FAN_OPEN_PERM was placed in flags, not mask); `fdstore_store` cmsg ordering (NULL-deref UB) + unconnected sendmsg; response hardcoded legacy `FAN_DENY=0` (modern kernels use `0x02`, `0` → EINVAL).
- Root scripts: protocol version 2→5 (`ssh-broker-scenarios.py`); stale pre-LFH0 SSH-read assertions flipped to the fail-closed model; status readiness via `enforcement_active` (mode-agnostic); `setpriv` probe pids; probe fixtures created pre-guardd; `/etc/guardd` mkdir; fdstore base unit file; fdstore probe-2 dead-window timing (0.5s < RestartSec).

## Quality gates (LFH7)
```bash
cargo fmt --all -- --check                                       # clean
cargo clippy --workspace --all-targets --all-features -- -D warnings  # clean
cargo test --workspace --all-features                            # 31 suites OK, 0 FAILED
git diff --check                                                 # clean
```
All LFH0–LFH6 formal privileged scripts: **PASS on the real host (20/20)**.

## Freeze condition
Per LFH7, `IMPLEMENTATION FREEZE` requires: no P0/P1 open, no unexplained browser
regression, no blocked mandatory live gate, no truthfulness mismatch.

- P0/P1: closed at code level (none open).
- Unexplained browser regression: none — `test-native-browser-compat-root.sh` PASS (8/8) for the only installed browser (Firefox); `lfh6_real_firefox_disposable_profile_compat` offline PASS.
- Blocked mandatory live gate: **none** — 20/20 privileged scripts PASS (pidfd, object identity, continuity, fdstore ACCEPTED, browser/SSH enforcement, fanotify, bypass, hardening, agent-compat, ssh-broker, ssh-load, strict-concurrency, topology, systemd, installed-auth, browser-adversarial, strict-filesystem, native-browser, benchmark).
- Truthfulness: documented with PREVENTED / LIVE VERIFIED / REDUCED / NOT ACCEPTED / NOT PROTECTED.

```
Linux File Shield implementation:
FREEZE

formal posture:
ACTIVE on accepted strict-filesystem capability set

unsupported/legacy capability:
REDUCED with exact reason
```

Residual NOT ACCEPTED items (do not block the freeze; documented per phase rules):
LFH2 never-opened-before rename-in gap (deferred topology group); LFH6 cross-family
Chromium (NOT INSTALLED on this host); Flatpak/Snap/network FS (no live acceptance).

## Final verdict
`LINUX FILE SHIELD: IMPLEMENTATION FREEZE — ALL 20 MANDATORY LIVE GATES PASSED ON THE REAL HOST (PASS=20 FAIL=0); code/unit + live evidence complete; formal posture ACTIVE (strict-filesystem), REDUCED with exact reason for legacy/unsupported.`

## HARNESS §8 final vocabulary
- **VERIFIED FACT (code/unit)**: identity (pidfd group + validation + close-once; actual executed image via `/proc/PID/exe` fd; PID-reuse fail-closed), object identity (opaque handles, inode-reuse rejection), authority (EXACT READER INSTANCE, generation-bound leases, `stale_lease_generation`), control plane (SO_PEERCRED, no UID from JSON, config 0o640, explicit mode + config_version, no silent downgrade), continuity (sticky LOST + full revoke + generation bump).
- **LIVE VERIFIED**: all 20 privileged scripts on the real host (evidence dir `reports/linux/evidence/live-host-20260819-122244/`): pidfd 5/5, object-identity, continuity, fdstore ACCEPTED, browser/ssh/fanotify/bypass/hardening/agent-compat/ssh-broker 29/29/ssh-load/strict-concurrency/topology/systemd/installed-auth/browser-adversarial/strict-filesystem/native-browser 8/8, benchmark (0 overflow, 0 classifier failure).
- **INFERENCE**: nothing security-critical remains inference-only; remaining inferences are confined to documented NOT ACCEPTED coverage items.
- **RESIDUAL LIMITATION**: LFH2 rename-in gap; already-open/inherited fds and root/kernel compromise NOT PROTECTED (V1 scope); Flatpak/Snap/network FS NOT ACCEPTED.
- **NOT ACCEPTED**: LFH2 rename-in gap; LFH6 cross-family (no Chromium installed); Flatpak/Snap/network FS; legacy-fallback and object-handle-unsupported filesystems (truthfully REDUCED).
- **BLOCKED**: none remaining for the File Shield gates. (The previous environment blocker — nspawn seccomp EPERM on fanotify — was lifted by the user authorizing direct host runs.)

```
GOAL COMPLETE — Linux File Shield implementation FREEZE
  (all LFH0–LFH7 gates: code/unit + 20/20 live privileged scripts PASS)
```
