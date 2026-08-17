# MPS11 — Disposable Chrome/Firefox Compatibility + Exception Review

## Status

PASS — disposable Chrome and Firefox compatibility proven on this real host
under the production Process Shield build, with narrow documented task-access
exceptions and the untrusted synthetic probe recheck still denied.

## Repository

- HEAD: bc26dd03b8fb9e7d6540b4569f2ee256d4f743a3 (working tree changes only)

## Observe-first evidence (metadata only)

With the production extension (browser scope) active, Chrome and Firefox
ABORTED at launch (SIGABRT,
CARBONCORE__ABORTING_BECAUSE_CORESERVICESD_RETURNED_AN_ERROR). Root cause
traced via coreservicesd logs:

- `coreservicesd` failed to `upgrade to client task port` with
  `err=53/(os/kern) denied by security policy` for the browser's SCSession
  universe registration (LaunchServices).
- Audit telemetry showed MANY root-owned Apple platform daemons (launchd,
  amfid, watchdogd, configd, UserEventAgent, fseventsd, powerd, apsd,
  xprotectd, logd, dasd, notifyd, logind, autofsd, remoted, KernelEventAgent,
  opendirectoryd, kernelmanagerd, thermalmonitord, diskarbitrationd,
  corerepaird, ...) routinely obtain task capabilities on GUI processes.
- The MPS2 zero-exception policy denied all of these => browsers cannot launch.

## Exceptions added (documented, exact-ID + kind)

`task_access_allowlist` (process_shield.rs) is narrowed to EXACT signing-ID +
TaskAccessKind pairs (MPS Hardening). A requester qualifies only when ALL of:
- uid 0 + `valid` + kernel-verified `platform_binary` (unforgeable by a
  same-user attacker; never Apple-signer developer/App-Store certs, user
  processes, or Team-ID matches);
- its exact signing ID is on the CONTROL allowlist for task control, or on
  the strictly narrower READ allowlist for task read (memory contents).
- task READ additionally requires the target to be signed (not unsigned).

Control allowlist (observed managing processes/sessions): coreservicesd,
launchd, amfid, watchdogd, configd, UserEventAgent, fseventsd, powerd, apsd,
xprotectd, logd, dasd, notifyd, logind, autofsd, remoted, KernelEventAgent,
opendirectoryd, kernelmanagerd, thermalmonitord, diskarbitrationd,
corerepaird. Read allowlist: coreservicesd only (SCSession registration
evidence). `lsd` is NOT allowed (removed by the narrowing).

## MPS Hardening: contextual NOTIFY_GET_TASK(_READ) signals

Apple semantics: NOTIFY_GET_TASK(_READ) fires AFTER the requester actually
obtained the task capability. So an acquisition that was NOT legitimate
under our own task allowlist means the requester got task capability despite
our prevention -> strong compromise signal. Allowlisted Apple platform
daemons stay telemetry; TRACE stays telemetry; NOTIFY_REMOTE_THREAD_CREATE
and NOTIFY_CS_INVALIDATED remain always-strong. This replaces the earlier
event-kind-level downgrade (all GET_TASK notifies as telemetry) with a
contextual strong-signal decision.

## Disposable-browser results (real host, extension active)

| Case | Result |
|---|---|
| Chrome launch (disposable profile) | PASS |
| Chrome main process running | PASS |
| Chrome alive after JS/JIT load | PASS |
| Chrome relaunch (same disposable profile) | PASS |
| Firefox launch (disposable profile) | PASS |
| Firefox alive after JS load | PASS |
| Firefox relaunch | PASS |

`BROWSER_TOTAL pass=7 fail=0`

## Security recheck (after exceptions)

Untrusted same-user synthetic probe against a shielded live Chrome process:

```text
PROBE_TASK kind=control result=5 port=0  -> denied (exit 4)
PROBE_TASK kind=read    result=-1 port=0 -> denied (exit 4)
PROBE_MEMORY recovered_pages=0           -> no memory readable
```

The platform-binary exceptions do NOT weaken protection for untrusted
same-user processes.

## Audit behavior

- Task denials are attributed to the TARGET owner (the victim) so the user's
  event feed can see task-attack denials even when the requester is root.
- Notify-only task telemetry records use `Decision::Detected` (never
  PREVENTED).
- Notify events whose target is NOT a shielded exact instance are now
  dropped entirely (no telemetry, no audit row): the system-wide notify
  subscriptions cannot spam the Guard audit queue with unrelated traffic.

## Warm-start coverage (MPS Hardening)

A shield-eligible process (enrolled browser or Guard component) that was
ALREADY RUNNING when guard-es/ES restarted was never admitted via AUTH_EXEC
and previously allowed task access (the warm-start gap). `handle_task` now
admits such a target as `PreexistingUnverified` (admission kind recorded in
the shield entry) and falls through to the normal shielded decision path, so
non-allowlisted requesters are DENIED and File Shield reports Reduced
("N already-running shield-eligible process(es) predate Process Shield;
restart them for Strong launch integrity") until the browser restarts and is
re-admitted via AUTH_EXEC.

## Tests

```text
cargo test -p platform-macos --lib (98 tests incl. preexisting/contextual) PASS
cargo clippy --workspace --all-targets --all-features -- -D warnings PASS
```

## Blockers

None for the acceptance. Permanent extension activation requires the user to
approve the system extension in System Settings once (UserApprovalRequired
when the approval record churned during testing); the validation itself ran
with the extension active.

## Security claims NOT made

- No claim that Safari-specific task rules exist (Safari is not enrolled as a
  shielded target; MPS12 observes it).
- No claim of protection against browser-internal RCE/extensions.

## Next phase readiness

- MPS12 final regression + Safari observation.## MPS Hardening 2 (protected-profile integration)

- Script updated: Chrome now launches with normal sandbox FIRST;
  `--no-sandbox` is only a labeled diagnostic fallback (blocker echoed).
- Full protected disposable-profile chain added: enroll disposable profile ->
  browser own-profile ALLOW -> untrusted probe DENY on Cookies/Preferences ->
  probe task-port DENY on real Chrome -> audit rows present with no fixture
  contents.
- Assertion review: MPS9 "post-compromise protected read denied" is now a real
  conditional; no `check ... true` stub remains.
- LIVE RUN STATUS FOR HARDENING-2: BLOCKED on this host (active extension is the
  hardening-1 build; re-activation blocked by stale extension versions needing
  reboot). Prior hardening-1 live evidence (8/8, probe result=5 port=0) remains
  valid and is clearly labeled as previous evidence.
