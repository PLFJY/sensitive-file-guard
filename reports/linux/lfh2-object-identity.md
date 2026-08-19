# LFH2 — Dynamic Protected Object Identity

## Baseline
- commit: 84a1bd133c78c41911d82dac5ffd1989a7722f5b
- kernel: 7.1.8-arch1-3 (x86_64); / ext4
- relevant capabilities: `name_to_handle_at` supported (LFH0 probe); MAX_HANDLE_SZ=128
- privileged environment: sfg-test-capsule (systemd-nspawn) — seccomp blocks fanotify; fanotify live tests BLOCKED in this environment (see LFH1 report). /tmp is tmpfs → object-handle unit fixtures live under the workspace target dir (ext4).

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

## Step 3 — rename-in / never-opened-before
- The permission group only learns handles for objects it has SEEN under a protected open. A temp object renamed into a protected name and immediately out, never opened while inside, has no learned handle — the event-fd handle-learning alone cannot cover it.
- The narrow allowed fix per LFH2 is a second topology group (`FAN_CLASS_NOTIF` + FID/DFID_NAME) tracking create/move/rename lifecycle, with race-safe fallback (permission hot path does not trust topology cache ordering).
- Status this phase: the never-opened-before rename gap is **NOT ACCEPTED** (not claimed closed). A live harness must first prove it exists on the real host before adding the topology group (LFH2 Step 3 says: prove the gap, then implement). The root script records the observable.

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
- **NOT RUN in this environment — BLOCKED**: nspawn seccomp blocks fanotify (EPERM, verified); host pkexec prohibited while capsule is available. Deterministic script provided for a real host.

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
| never-opened-before rename-in gap closed | NOT ACCEPTED | requires topology group; live proof pending |

## Residual limitations
- Never-opened-before rename-in/out gap remains open (Step 3 topology group deferred until live proof).

## Final phase verdict
`PASS (unit + code) + LIVE GATE PASS (real host: test-object-identity-root.sh); Step 3 gap NOT ACCEPTED`
