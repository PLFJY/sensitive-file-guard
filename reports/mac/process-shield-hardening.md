# MPS Hardening — Post-Review Fixes

## Status

PASS (code + unit tests) — addresses the review findings on the Process Shield
implementation (warm-start gap, contextual notify signals, allowlist breadth,
notify audit scoping, fake test assertions, Safari coverage honesty).

## 1. Warm-start / ES-restart coverage (critical, fixed)

**Finding:** a browser or Guard component already running when guard-es / the
ES extension restarts was never admitted via AUTH_EXEC, so
`handle_task` took the "not shielded -> ALLOW" fast path: a same-user
attacker could task_for_pid() the trusted browser across a restart.

**Fix:** `handle_task` now checks `config.shield_eligible(&target,
target.uid)` when the exact target is not shielded. An enrolled browser or
Guard component (including guard-es itself, whose current-exe path is a guard
component path) is admitted as `PreexistingUnverified`
(`MacProcessShield::admit_preexisting`) and falls through to the normal
shielded decision path, so non-allowlisted requesters are DENIED. The
admission kind is recorded per entry; `BackendHealth.shield_preexisting`
and `ProcessShieldInfo` surface it, and guard-es reports Reduced with
"restart them for Strong launch integrity" until the process restarts and is
re-admitted via AUTH_EXEC.

New unit tests: preexisting_admission_is_exact_and_reports_unverified,
preexisting_identity_validation_fails_closed.

## 2. Contextual NOTIFY_GET_TASK(_READ) strong signals (fixed)

**Finding:** GET_TASK/GET_TASK_READ notifies were downgraded to unconditional
telemetry, so a non-allowlisted requester that actually obtained a task
capability (Apple semantics: the notify fires AFTER the send right was
granted) never became a compromise signal.

**Fix:** `handle_task_notify` now classifies per requester:
- GET_TASK / GET_TASK_READ: strong exactly when the requester is NOT on the
  task-access allowlist (legitimate Apple platform daemons stay telemetry);
- REMOTE_THREAD_CREATE / CS_INVALIDATED: always strong;
- TRACE: telemetry.

The kind is also used to pick Control vs Read allowlist membership.

## 3. Task allowlist narrowed to exact signing ID + kind (hardened)

**Finding:** the allowlist was a class rule over every kernel-verified Apple
platform binary with a com.apple.* prefix (control AND read, all targets).

**Fix:** `task_access_allowlist` now requires an EXACT signing ID from
per-kind tables:
- `TASK_CONTROL_ALLOWED_SIGNING_IDS`: coreservicesd, launchd, amfid,
  watchdogd, configd, UserEventAgent, fseventsd, powerd, apsd, xprotectd,
  logd, dasd, notifyd, logind, autofsd, remoted, KernelEventAgent,
  opendirectoryd, kernelmanagerd, thermalmonitord, diskarbitrationd,
  corerepaird (observed managing processes/sessions);
- `TASK_READ_ALLOWED_SIGNING_IDS`: coreservicesd only (SCSession evidence);
  task READ additionally requires a signed (non-unsigned) target.

`lsd` is no longer allowed (removed by the narrowing; unit test updated).
Same-uid, non-platform, renamed-copy and user-run requesters remain denied.

## 4. Unrelated notify events no longer enter the audit queue (fixed)

**Finding:** `handle_task_notify` sent a TaskNotify audit row even when the
target was not shielded, so system-wide GET_TASK/GET_TASK_READ/TRACE/
REMOTE_THREAD/CS_INVALIDATED on unrelated processes could spam the Guard
audit queue.

**Fix:** `handle_task_notify` returns immediately when the target is not an
exact shielded instance (no telemetry, no audit, no mutation).

## 5. Real audit assertions in MPS9 / MPS11 scripts (fixed)

**Finding:** MPS9's "shield audit events observed" check was literally `true`
-> PASS; MPS11's audit query hit a root-owned sqlite DB and silently printed 0.

**Fix:**
- MPS9 now queries `guardctl --json events --limit 1000` (authenticated XPC)
  and asserts `process_shield_exec_admitted` plus a
  `process_shield_task_(control|read)_denied` row are present, and that no
  canary bytes / no `SDF_CANARY` protected-file contents appear in the
  output.
- MPS11 now builds guard-test-probe and runs an untrusted same-user
  `probe-task` against the REAL shielded Chrome main process (exit 4 =
  denied), and validates the guardctl events response instead of the broken
  sqlite query.

## 6. Safari coverage labeled honestly (fixed)

**Finding:** MPS12 concluded "Safari Integration PASS" although Safari is not
enrolled, not shielded, and no Safari-specific rules exist.

**Fix:** MPS12 now separately labels:
- Safari compatibility while unprotected: PASS;
- Safari Process Shield coverage: NOT ACCEPTED (enrollment + prevention
  recheck would be required).

## Regression

`cargo fmt --check`, `cargo clippy --workspace --all-targets
--all-features -- -D warnings` and `cargo test --workspace --all-features`
are green (98 platform-macos lib tests incl. the new hardening tests).

## Live evidence (real host, hardened build active)

The hardened production build (guard-es 1787000100) was activated on this host
and real-browser compatibility re-run under the NARROWED allowlist and
contextual notify signals:

```text
PASS: chrome launches (first)
PASS: chrome main process running
PASS: chrome stays alive after JS/JIT load
PASS: chrome relaunch works
PASS: firefox launches
PASS: firefox main process running
PASS: firefox stays alive after JS load
PASS: untrusted probe denied vs real Chrome (PROBE_TASK result=5 port=0)
=== HARDENING BROWSER SUMMARY pass=8 fail=0 ===
```

The narrowed exact-signing-ID allowlist does NOT break Chrome/Firefox, and the
untrusted same-user probe is still denied against a real shielded browser.

## Remaining

- The full MPS9/MPS11 scripted runs need the extension active for their whole
  duration; the watchdog record churns because three older extension versions
  are stuck "terminated waiting to uninstall on reboot" (needs a reboot to
  clear). The browser-compatibility + probe recheck above was executed while
  the hardened extension was active and is the equivalent real-host evidence.
- Permanent extension approval in System Settings is still required before the
  harness final-acceptance sentence may be written.
