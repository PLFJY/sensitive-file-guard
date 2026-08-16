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

## Exceptions added (documented, narrow)

`task_access_allowlist` (process_shield.rs) now allows task access from
**kernel-verified Apple platform binaries** (uid 0 + `valid` +
`platform_binary` + `com.apple.*` signing id or absent):
- coreservicesd SCSession universe registration (the specific abort trigger);
- general macOS session/process management by platform daemons.
- The `platform_binary` flag is kernel-verified (Apple platform chain),
  unforgeable by a same-user attacker; this is NOT an "Apple signed => allow"
  rule (developer/App-Store certs and user processes never qualify), and it
  is NOT Team-ID based.

## MPS11 adjustment to compromise signals (documented)

NOTIFY_GET_TASK/GET_TASK_READ fire routinely on real browsers for legitimate
macOS + browser-internal task operations; treating them as strong signals
marked every browser process Compromised on launch. Per observed evidence,
task-capability notifies are now TELEMETRY (like TRACE); only
NOTIFY_REMOTE_THREAD_CREATE and NOTIFY_CS_INVALIDATED remain strong signals.

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

## Tests

```text
cargo test -p platform-macos --lib (96 tests) PASS
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

- MPS12 final regression + Safari observation.
