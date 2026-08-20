# LFH4 — systemd FD Store Crash-Continuity Experiment

## Baseline
- commit: 84a1bd133c78c41911d82dac5ffd1989a7722f5b
- kernel: 7.1.8-arch1-3 (x86_64)
- historical privileged environment note: this phase predates the capsule fanotify allow-list update. Current systemd/fdstore evidence is in `harness-state.md`; an explicitly user-authorized minimal polkit host fallback is permitted when capsule differences prevent a final conclusion.

## Threat / invariant
fanotify permission events: queued unread → read by listener → moves to internal permission-wait list → response written OR group fd fully closed. Question: can systemd fdstore hold a duplicate of the fanotify group fd so a daemon crash does not fail open (the group stays alive and the kernel keeps the opener blocked)? Split into Experiment A (crash before event read) and Experiment B (crash after read, before response).

## Changes

### `apps/guard-fdstore` (new experiment helper binary)
- `guard-fdstore PROTECTED_FILE` auto-detects role: `LISTEN_FDS >= 1` (systemd passed a stored fd on restart) → CLAIM the group at fd 3; otherwise STORE a new `FAN_CLASS_CONTENT` group, mark the file, upload the group fd to the fdstore (`FDSTORE=1` + `SCM_RIGHTS` over `NOTIFY_SOCKET`), READY=1, and loop reading+DENYing every permission event.
- Validates the claimed fd is a live fanotify group by re-marking the protected file (EBADF/EINVAL otherwise).
- One ExecStart serves both roles — the production pattern.

### Test-only crash hook (`apps/guardd/src/main.rs`)
- `CRASH_AFTER_READ_BEFORE_RESPONSE=1` (plus optional `CRASH_AFTER_READ_MARKER`): fires once after reading a permission event, before writing the response — writes the marker and SIGKILLs the daemon. This is Experiment B's deterministic hook. Inert unless the env var is set.

### `scripts/linux/experiment-fdstore-root.sh`
- Sets up a transient systemd unit: `Type=notify`, `FileDescriptorStoreMax=1`, `FileDescriptorStorePreserve=restart`, `Restart=always`, `RestartSec=1`, `ExecStart=$HELPER $PROTECTED`.
- Oracle: (1) probe denied while alive; (2) SIGKILL helper; (3) probe still blocked 2s later (fdstore holds the group); (4) systemd restarts → helper claims stored group; (5) probe unblocks with denial; (6) fresh probe denied (marks survived).
- Prints ACCEPTED / PARTIAL / REJECTED from the evidence.

## Tests

### Offline
- `cargo test --workspace --all-features`: green (31 suites).
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`: 0 errors.
- guard-fdstore builds clean.

### Privileged / live
- **NOT RUN in this environment — BLOCKED**: the capsule's nspawn seccomp returns EPERM for `fanotify_init` (verified), and the booted capsule is stuck at systemd-firstboot (volatile root, interactive prompt) so no systemd service context is available. The experiment script is deterministic and runnable on a real host.

## Adversarial findings
1. `name_to_handle_at`/fanotify both blocked by nspawn seccomp → no fanotify File Shield live test can run in the capsule; this is an environment restriction, not a Guard defect.
2. Experiment B's recovery question (can a restarted daemon enumerate/respond to an already-read pending permission) has no reliable public kernel mechanism — if the live run confirms this, verdict is PARTIAL (hardening value, formal crash continuity stays REDUCED).

## Compatibility findings
- Clean `systemctl stop` vs crash/restart lifecycle differ; fdstore preserve only applies to restarts.
- Uninstall must clear fdstore (transient unit cleanup handles this).

## Truthfulness verdict

| Claim | Verdict | Evidence |
|---|---|---|
| fdstore can hold a fanotify group fd (mechanism implemented) | LIVE VERIFIED | `guard-fdstore` store/claim + SCM_RIGHTS; journal: stored group fd=3 → restart → claimed stored group fd=3 (LISTEN_FDS=1) |
| crash hook fires after read, before response | LIVE VERIFIED | CRASH_AFTER_READ_BEFORE_RESPONSE + CRASH_AFTER_READ_MARKER in guardd AND guard-fdstore; Experiment B marker written with the event pid |
| Experiment A: unread event survives the crash (group preserved) | LIVE VERIFIED | probe blocked 0.5s after SIGKILL (fdstore duplicate holds the group); fresh open denied after restart (marks survive). The "queued event answered after restart" probe-2 outcome was UNATTRIBUTED in the real-host runs (the probe's rc file was never captured; the canary was never read — no fail-open) |
| Experiment B: read-but-unanswered permission recovered by the claimed group | **NOT RECOVERABLE via public UAPI** | marker proves the daemon read the exact event (pid recorded); after restart the opener is **STILL BLOCKED** (permission pending, no responder exists — the response fd died with the crashed process); canary never read |

Live evidence: `reports/linux/evidence/live-host-review-batch-20260819-231529/experiment-fdstore-rerun.log` — PASS=7 FAIL=0 BLOCKED=0; probe2 "unblocked with denial after restart (rc=1)" (attribution race fixed: the probe subshell previously aborted on the nonzero denial before writing its rc — `set -e` inherited into the `( ... ) &` subshell; fixed with `set +e` + `KEEP_WORK` no longer deletes the kept dir); B: marker pid=…, "opener STILL BLOCKED after restart (pending permission not recoverable via public UAPI)", "synthetic canary never read"; `VERDICT: PARTIAL`.

## Final phase verdict
`PARTIAL — Experiment A group-preservation proven; Experiment B read-but-unanswered recovery NOT possible via supported public interfaces (the pending permission stays blocked after restart) → LFH4 = PARTIAL, crash continuity stays REDUCED. The fdstore mechanism is experimental hardening only; production guardd keeps `deploy/guardd.service` `Type=simple` with the documented fail-open-on-crash semantics (no fdstore integration claimed).`
