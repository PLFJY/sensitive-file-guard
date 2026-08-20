# LFH2 — Dynamic Protected Object Identity

## Baseline
- commit: 84a1bd133c78c41911d82dac5ffd1989a7722f5b
- kernel: 7.1.8-arch1-3 (x86_64); / ext4
- relevant capabilities: `name_to_handle_at` supported (LFH0 probe); MAX_HANDLE_SZ=128
- historical privileged environment note: this phase predates the capsule fanotify allow-list update. Current capsule behavior and any explicitly user-authorized minimal polkit host fallback are recorded in the harness state; historical BLOCKED wording here is not a current instruction.

## Threat / invariant
Close BOTH:
1. dynamic sensitive object rename/move alias (object leaves the protected name; unknown reader opens the alias),
2. inode-reuse false positive (a different object reusing the inode must NOT look protected),
without trading one bug for the other.

## Step 1 — proven gap
LFH0 strict suite recorded `OBSERVED: an inode moved through a sensitive name without an open is not labeled by FAN_OPEN_PERM`. For objects that WERE opened under the protected path, this phase closes the rename-away leg via learned handles; the never-opened-before leg (rename in→immediately out) is analyzed below.

## Step 2 — object handle (`crates/platform-linux/src/object_handle.rs`)
- `ObjectHandle { mount_id, handle_type, handle_bytes }`; opaque payload, never interpreted as an inode number.
- `from_fd(fd)`: fanotify event fds are O_RDONLY, but `name_to_handle_at(AT_EMPTY_PATH)` needs O_PATH. Solution: open `/proc/self/fd/<fd>` with O_PATH (kernel magic link resolves the LIVE object, so the handle follows rename) then call `name_to_handle_at(AT_EMPTY_PATH)`.
- Kernel two-call pattern: first call may EOVERFLOW with required size; retry with an adequate buffer. Buffer always carries `sizeof(file_handle) + capacity` (MAX_HANDLE_SZ 128) — never a zero-length flexible array (the earlier implementation wrote/read out of bounds; fixed and covered by tests).
- `encode`/`decode` round-trip for storage.

## Step 2 integration (`apps/guardd/src/strict.rs`)
- `StrictClassifier.handle_index: (dev, ino) -> Vec<HandleCandidate>` (bounded, 8192 entries, oldest evicted).
- Learning: a dynamic protected object opened under its protected path gets its handle learned. Fast path: `nlink==1` unrelated opens never touch handles.
- Matching: path did not classify (renamed away) and `(dev, ino)` hits learned candidates → compare event fd handle. Equal handle ⇒ Protected (same object); different handle ⇒ inode reuse ⇒ Unrelated + whole key dropped (one inode holds one object at a time).
- Unsupported filesystem: `learn_handle` logs + increments `classifier_failures`; object stays protected via path/inode paths; dynamic rename guarantee REDUCED (reported elsewhere).

## Step 3 — rename-in / never-opened-before (CLOSED this review round, R1)
- The permission group only learns handles for objects it has SEEN under a protected open. A temp object renamed into a protected name and immediately out, never opened while inside, has no learned handle — the event-fd handle-learning alone cannot cover it.
- The SETTLED case is closed with TWO mechanisms (no `open_by_handle_at`, no topology-ordering trust on the permission hot path):
  1. **Startup snapshot** (`snapshot_dynamic_handles()`): on daemon start, walk the browser roots, O_PATH-open each pre-existing dynamic file, and learn its handle into the main `handle_index` via `from_fd` → a pre-existing object renamed out is deterministically identified (its handle was learned before any rename could happen).
  2. **Topology learner** (`apps/guardd/src/topology_learner.rs`, `fanotify.rs::new_topology`): a second `FAN_CLASS_NOTIF | FAN_REPORT_FID` group marks the tree dirs with `FAN_MOVE | FAN_EVENT_ON_CHILD`. Only `FAN_MOVED_TO` fids are learned into a handle-only index `topology_handles` keyed by `(handle_type, handle_bytes)` (MOVED_FROM's fid is the source DIRECTORY's handle — useless for file identity; verified by C probes). The permission hot path consults `topology_handles` only when non-empty and always via `from_fd`; a `from_fd` failure is fail-closed `StrictClassification::Error`, never an allow.
- **R1 (review) — cross-group ordering is now enforced, not assumed**: the reviewer rejected "F3 CLOSED" because the learner's docs admitted a sub-queue-latency REDUCED window and the acceptance test settled 5 s before reading. Fix: the permission hot path synchronously drains the topology queue under the SAME mutex the background learner uses (`sync_topology_if_pending` — poll+read+parse+publish atomic ⇒ no "consumed but not published" window). Syscall order (rename completes before the open begins) ⇒ the move event is enqueued to the topology group before the open's permission event, so the drain at decision time processes every causally-prior event — no settle, no scheduler-timing assumption.
- **KERNEL 7.1 MEASURED REALITY (definitive C probes, `fid-definitive.c`/`fid-sep.c`)**: a move event's fid is the MARKED/PARENT DIRECTORY's handle — NEVER the moved file's; back-to-back move-in+move-out coalesce into one event with mask `FAN_MOVE` (0xc0); `FAN_REPORT_DFID_NAME` (0xC00 = DIR_FID|NAME; note 0x400 alone is DIR_FID *without* the name) adds the moved object's NAME.
- **THE KEY: `FAN_REPORT_TARGET_FID` (0x1000, "report dirent target id")** — with it, a move event carries TWO records: the parent directory's fid (+name) FIRST and **the moved object's OWN fid LAST**. The learner learns that target fid directly from the event — NO userspace resolution, NO race with the immediate rename-out. This is what makes the zero-settle fast attack enforceable (verified by `fid-target.c`; inode check: target record = the moved file, parent record = the marked dir).
- **R1 — runtime-created subdirectories**: the learner now refreshes tree marks every ~2 s (`refresh_tree_marks`), so a subdirectory created after startup becomes watched without a restart (bounded creation→mark window, documented REDUCED).
- The learner is best-effort: `new_topology` failure → warn + `None`, daemon keeps running; no permission-group interaction (no `mark_fd(FAN_OPEN_PERM)` — that caused double permission events and unbounded mark growth).
- `open_by_handle_at` recovery was explored and abandoned: on this kernel (7.1) it returns EBADF for every tested mount-fd variant (O_PATH/O_RDONLY dir/file, loop ext4 and root fs) — hence handle-only indexes.
- **Zero-settle acceptance (live)** — `scripts/linux/test-step3-zero-settle-root.sh` (isolated loop ext4, evidence `live-host-step3-target-20260820-011146`):
  - **FAST attack** (rename-in → immediately rename-out → immediate open, 10k, zero settle): **LIVE PASS — 10000/10000 denied, 0 successful unauthorized reads** (target-fid learning, no resolution race).
  - SETTLED case (moved-in object that REMAINS, later renamed out + immediate open): **LIVE PASS — 1000/1000 denied, 0 recovery**.
  - Runtime-created subdirectory (marked by the learner's 2 s refresh): **LIVE PASS — 200/200 denied, 0 recovery**.

## Step 4 — filesystem capability
- `guardctl capabilities` already probes `name_to_handle_at(AT_EMPTY_PATH)` per protected filesystem (LFH0). Unsupported FS ⇒ dynamic rename guarantee NOT Strong (REDUCED).

## Tests

### Offline
- `cargo test --workspace --all-features`: green (30 suites).
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`: 0 errors.
- New unit tests:
  - object_handle: two-call resolve on ext4 fixture; encode/decode round-trip; truncated decode fails closed; distinct payloads not equal; negative fd fails; EINVAL on procfs handled.
  - strict: dynamic handle learned → rename-away still Protected; injected stale handle ≠ unrelated file handle → Unrelated + key dropped; existing structural/stale-inode/alias tests still pass.

### Privileged / live
- `scripts/linux/test-object-identity-root.sh` written (rename-out denied; unrelated file at reused name opens; delete/recreate no false positive; no log leak).
- **HISTORICAL / SUPERSEDED**: this early capsule run was blocked by nspawn seccomp. Current capsule and explicitly user-authorized minimal polkit host evidence are recorded separately in `harness-state.md`.

## Adversarial findings
1. Zero-length `file_handle` UB (out-of-bounds payload read) caught by the rename-away unit test failing on real handles — fixed with sized buffers.
2. `name_to_handle_at` on an O_RDONLY fd fails EINVAL/EOPNOTSUPP; the O_PATH-magic-link pattern is the correct way for event fds.
3. MAX_HANDLE_SZ=128: requesting a larger buffer returns EINVAL, not EOVERFLOW; the retry must cap at 128.

## Compatibility findings
- Ordinary nlink=1 unrelated opens: no handle computation (fast path preserved).
- Dynamic browser files (WAL/SHM/storage) no longer pinned by inode forever → no clipboard-DB-style false positives.
- WAL/SHM/sessionstore classifications unchanged (path classifier untouched).

## Performance
- No live benchmark in this phase (fanotify BLOCKED). Fast path adds no per-open handle work for unrelated files. LFH6 re-benchmarks against LFH0 baseline.

## Truthfulness verdict

| Claim | Verdict | Evidence |
|---|---|---|
| rename-out of an opened dynamic object still denied (handle identity) | LIVE VERIFIED | `scripts/linux/test-object-identity-root.sh` PASS on real host (dynamic rename-out recognized; inode reuse rejected); evidence/live-host-*/test-object-identity-root.log |
| inode reuse does not false-positive | PREVENTED (unit) | inode_reuse test + stale-key drop |
| handle payload opaque, never an inode number | PREVENTED (code) | ObjectHandle opaque bytes |
| unsupported FS degrades truthfully | PREVENTED (code) | learn_handle failure path + LFH0 capability probe |
| live rename-out acceptance | LIVE VERIFIED | test-object-identity-root.sh PASS (real host; note: /tmp fixtures stay tmpfs → object-handle steps use the ext4 target dir) |
| never-opened-before rename-in gap (SETTLED) | LIVE VERIFIED | startup snapshot (pre-existing dynamic handles learned before any rename) + topology group (MOVED_TO fid learned into `topology_handles`); `test-object-identity-root.sh` PASS 8/8 on real host (isolated loop ext4) incl. "snapshot of pre-existing dynamic object handles" + renamed-in probe denied with `DENY(` attribution |
| never-opened-before rename-in gap (ZERO-SETTLE attacker path) | LIVE VERIFIED (0 recovery) | `test-step3-zero-settle-root.sh`: 10000/10000 denied, 0 recovery (target-fid learning, no settle); evidence live-host-step3-target-20260820-011146 | **F3 CLOSED** |

## Residual limitations
- `open_by_handle_at` recovery is NOT used (EBADF on this kernel for all mount-fd variants) — identity recovery relies on learned handles + `from_fd`, never on opening by handle.
- The topology group needs a FAN_MOVE event to have been observed for a moved-in object that was NEVER opened and did NOT pre-exist at startup (e.g. object created and renamed out entirely while the daemon was DOWN). Startup snapshot covers pre-existing files; the live zero-settle gate covers observed moves.
- Runtime-created subdirectories are marked by the learner's ~2 s refresh; a move through a brand-new subdir inside that window is REDUCED (documented, not claimed closed).

## Final phase verdict
`PASS — LFH2 Step 3 CLOSED (R1): cross-group ordering (sync drain under the learner mutex) + FAN_REPORT_TARGET_FID target-fid learning; live zero-settle fast attack 10000/10000 denied (0 recovery), settled 1000/1000, runtime-subdir 200/200 (live-host-step3-target-20260820-011146)`
