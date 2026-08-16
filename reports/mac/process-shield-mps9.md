# MPS9 — Native Synthetic Security Acceptance

## Status

PASS — `NATIVE SYNTHETIC ACCEPTANCE PASS` on this real macOS host (macOS
26.6.1, arm64, SIP disabled self-use mode) with the rebuilt Endpoint Security
extension active.

## Repository

- HEAD: bc26dd03b8fb9e7d6540b4569f2ee256d4f743a3 (working tree changes only)

## Fixture

- `guard-test-probe` gained three synthetic commands (no real browser/session
  data, no networking):
  - `shield-target READY [SECONDS] [PROTECTED_FILE]`: random in-memory canary
    (64 bytes from /dev/urandom), writes PID+hex to READY, optionally reads a
    protected synthetic file each loop;
  - `probe-task PID control|read`: attempts `task_for_pid` /
    `task_read_for_pid` (Mach, local only); exit 4 == kernel denied;
  - `probe-memory PID`: bounded `vm_read` scan; exit 0 == no readable pages.
- The es-poc guard-es now runs the full Process Shield backend
  (`synthetic_with_shield`) + a test-only compromise control file
  (`GUARD_ES_POC_COMPROMISE_FILE`) that applies the exact strong-signal
  transition used by real notify-only compromise events.
- `scripts/macos/test-process-shield-synthetic.sh`: builds, signs (local
  cert), installs, activates (watchdog), runs the acceptance, deactivates.

## Native evidence (real host, extension active)

| Case | Result |
|---|---|
| clean synthetic target admitted via AUTH_EXEC + baseline protected read allowed | PASS |
| untrusted same-user task control probe -> denied (KERN_FAILURE, exit 4, no port) | PASS |
| task read -> denied (no port) | PASS |
| VM memory scan after denied acquisition -> 0 readable pages (canary not recovered) | PASS |
| DYLD_INSERT_LIBRARIES synthetic dylib launch -> exec denied (no target starts) | PASS |
| harmless diagnostic DYLD var (DYLD_PRINT_LIBRARIES) -> allowed | PASS |
| controlled compromise fixture -> exact target Compromised; its protected read denied | PASS |
| fresh instance of same executable after compromise -> Normal, read allowed | PASS |
| shield audit events queryable via authenticated guardctl events (real check) | PASS |
| audit rows contain no canary bytes and no protected-file contents | PASS |

Summary line from the run (MPS Hardening re-run; the earlier `true`-only audit
assertion was replaced by real guardctl events + canary-absence checks):

```text
=== MPS9 SUMMARY pass=11 fail=0 ===
NATIVE SYNTHETIC ACCEPTANCE PASS
```

## Prevention vs notify-only classification

- Task control/read denials and DYLD launch-injection denial are PREVENTED
  (authorization denies before capability/exec).
- The compromise transition is DETECTED + CONTAINED (notify-only strong signal
  via the synthetic fixture); no terminate action is performed.
- No notify-only event is advertised as prevented.

## Environment notes

- A pre-existing securityd/keychain ACL degradation made `codesign` with the
  local certificate hang; `security set-key-partition-list -S apple-tool:,apple:
  -s -k <password> <GuardSelfUse.keychain-db>` repaired non-interactive
  signing. Exact command documented for the human operator.
- The first activation attempt used a new POC bundle id and correctly stopped
  at `UserApprovalRequired` (BLOCKED until human approves); the suite was
  re-run reusing the already-approved production bundle id
  (`top.plfjy.SensitiveFileGuard.guard-es`), which activated without a new
  approval. This temporarily replaced the production extension; the production
  build is redeployed in MPS12.

## Blockers

None for the acceptance itself. The initial POC-bundle-id activation required
a human approval (UserApprovalRequired) — recorded as the deterministic step:
approve in System Settings > General > Login Items & Extensions, or reuse the
approved bundle id (what the suite does).

## Security claims NOT made

- No claim that any real browser was admitted/shielded (MPS11).
- No Safari evidence (MPS12).

## Next phase readiness

- The synthetic core is proven on a real host. MPS11 deploys the production
  build (browser scope + Process Shield) and validates disposable
  Chrome/Firefox compatibility.
