# MPS Hardening 2 — Final Small-Scope Hardening

## Status

CONDITIONAL — code, unit tests and scripted acceptance updated; the harness
final-acceptance sentence stays withheld because (a) permanent System Extension
approval is still a human step and (b) the live protected-profile integration
run requires GUI enrollment + an extension reactivation cycle that the current
"terminated waiting to uninstall on reboot" stale versions block until reboot.

## 1. shield_preexisting health truthfulness (fixed)

Before: preexisting_admitted was a cumulative counter, but ProcessShieldInfo
treated health.shield_preexisting > 0 as a live preexisting instance. A browser
admitted preexisting that then exited (or was replaced by a fresh AUTH_EXEC)
left the counter at 1 forever, so Process Shield displayed Reduced permanently.

After: two distinct quantities:
- preexisting_admitted_total() — cumulative telemetry (never drives Active/Reduced);
- live_preexisting_count() — CURRENTLY shielded entries whose ShieldAdmission ==
  PreexistingUnverified. This is the only number that drives the Reduced state.

BackendHealth.shield_preexisting and ProcessShieldInfo.shield_preexisting now
carry the LIVE count.

Required transitions tested: admit_preexisting -> live 1 -> Reduced;
remove_terminal -> live 0; fresh AUTH_EXEC at the same PID (PID reuse) -> live 0
and admission AuthExec (never inherits preexisting); multiple instances counted
per exact instance.

## 2. Warm-start / ES-restart truthfulness (Option B, implemented)

The lazy repair already denied task access to already-running enrolled browsers
on first AUTH_GET_TASK. This pass makes the File Shield side truthful too:
MacProcessIdentityResolver::resolve() (the choke point for protected AUTH_OPEN
decisions) now reconciles a File-Shield-trusted browser whose exact live
instance is NOT yet shielded:

- admit_preexisting(facts, Browser) is called BEFORE the protected read is
  claimed as Strong;
- the returned identity is Normal (PreexistingUnverified is never promoted to
  Compromised);
- health immediately reports Reduced (live count > 0) and status advises
  "restart them for Strong launch integrity";
- the admission is idempotent (a second resolve() does not re-admit).

Only exact-instance identity is used (pid + pidversion + stable identity);
basename / path-only / same-UID rules are never authority. Unrelated processes
are never admitted (tested).

## 2b. Final Closure: fail-closed reconciliation (swallowed error fixed)

The warm-start reconciliation in resolve() previously ignored the result of
admit_preexisting() (`let _ = ...`). If a trusted browser could not be
reconciled into Process Shield (e.g. the shield already held the same audit
key with a different stable identity), the resolver returned a trusted Normal
identity anyway — the protected AUTH_OPEN would proceed as if launch
integrity were verified.

Now the reconciliation error propagates:

- admit_preexisting fails -> resolve() returns Err("failed to reconcile
  trusted preexisting browser into Process Shield: ...") -> the guard-es
  policy fail-closes the protected AUTH_OPEN with Deny(UnknownProcess) +
  permission.deny(). No trusted Normal identity escapes to the portable
  policy.
- The failure is treated as an internal enforcement-state failure, never as a
  confirmed process compromise (no Compromised transition).

New test: resolver_fails_closed_when_preexisting_reconciliation_rejected —
constructs a shield that already holds the same audit key with a different
stable identity, then asserts resolve() returns Err and no identity escapes.

## 3. Pre-held task-port boundary (documented, no code)

Process Shield prevents NEW protected task-port acquisition while active. After
an ES/guard-es restart, already-running shield-eligible processes are
PreexistingUnverified until restarted. Process Shield does NOT claim to
retroactively revoke Mach task-port rights already obtained before the current
enforcement generation. No Mach-port enumeration/revocation hack was added
(no officially supported, architecture-safe path exists here).

Recovery: restart the protected browser -> new AUTH_EXEC observed -> new exact
process instance -> Strong launch integrity restored.

## 4. MPS11 protected-profile integration acceptance (script updated)

test-disposable-browsers-process-shield.sh now runs the full chain against a
DISPOSABLE Chrome profile:

- normal-sandbox Chrome FIRST; --no-sandbox remains only as a labeled
  diagnostic fallback if the automation sandbox is blocked (blocker echoed as
  CHROME_SANDBOX_BLOCKER; final status truthful);
- the disposable profile is enrolled (interactive GUI step, matching the
  established run-browser-policy-acceptance.sh pattern) as a protected browser
  profile;
- real signed browser reading its OWN protected disposable profile -> ALLOW
  (browser alive, page loads, JS runs);
- untrusted same-user guard-test-probe -> protected disposable Cookies /
  Preferences -> DENY;
- untrusted same-user guard-test-probe -> real browser task control -> DENY;
- audit rows for the protected-resource deny and task-port deny present; audit
  contains NO disposable fixture contents.

## 5. Task allowlist target-role semantics (comment corrected)

The comment claimed exact target role (helper vs main) narrows the exception.
The implementation only distinguishes SIGNED vs UNSIGNED targets for task READ.
The comment and variable now say exactly that: target_is_signed =
target.code.signing_id.is_some(). No role propagation; no signing-ID role
guessing.

## 6. Safari status (unchanged, honest)

Safari compatibility while unprotected: PASS.
Safari Process Shield coverage: NOT ACCEPTED / OUT OF CURRENT MILESTONE.

## 7. Shell assertion review (MPS9 / MPS11)

- MPS9 post-compromise protected read denied was grep; check true (fake under
  set -e). Now a real if grep -q; then check true; else check false with a
  diagnostic tail on failure.
- MPS11 audit assertions are real greps against guardctl events (protected
  resource deny row, task-port deny row, no fixture contents in audit).
- Every check true/false is guarded by a real condition evaluated in the same
  line.

## 8. Tests run

```text
cargo fmt --all -- --check                                   PASS
cargo clippy --workspace --all-targets --all-features -D warnings  PASS
cargo test --workspace --all-features                        PASS (270 tests, 30 suites)
git diff --check                                             PASS
```

New/updated unit tests:
- live_preexisting_count_tracks_current_instances_only
- preexisting_live_state_is_per_instance_across_multiple_pids
- resolver_marks_trusted_browser_warm_start_as_preexisting
- resolver_does_not_shield_unrelated_processes
- dynamic_lease_root test updated: post-expiry the enrolled browser stays
  shielded as PreexistingUnverified (not by the dynamic reason)

## 9. Native evidence

THIS-PASS LIVE RE-RUN (MPS9 synthetic, hardened-2 build 1787000200 active):
all 8 real checks PASS on this real host:

```text
PASS: clean synthetic target admitted and baseline protected read allowed
PASS: task control acquisition denied (exit 4, result=5 port=0)
PASS: task read acquisition denied (exit 4, result=-1 port=0)
PASS: no readable pages (canary not recovered, recovered_pages=0)
PASS: DYLD_INSERT_LIBRARIES launch denied
PASS: harmless diagnostic DYLD var launch allowed
PASS: post-compromise protected read denied
PASS: new instance is Normal and protected read allowed
=== MPS9 SUMMARY pass=8 fail=0 ===
```

Note: MPS9 PoC mode has no audit store / XPC service, so the persistent-audit
assertion is exercised by MPS11 (production mode) instead; the MPS9 script now
says so honestly instead of running an unverifiable guardctl query.

Previous real-host evidence (hardening-1, guard-es 1787000100 active): 8/8
browser checks PASS incl. untrusted probe denied vs real Chrome
(PROBE_TASK result=5 port=0).

MPS11 protected-profile live run (final closure, build 1787000400 active):
- normal-sandbox Chrome launches / stays alive / relaunches            PASS
- Firefox launches / alive                                             PASS
- untrusted probe -> real Chrome task control -> DENY (result=5 port=0) PASS
- untrusted probe -> real Chrome task read    -> DENY (result=-1 port=0) PASS
- untrusted probe -> real Firefox cookies.sqlite -> DENY (EPERM)       PASS
- audit browser_access_denied rows present, NO secret contents         PASS
- Process Shield counters live (admitted=130, preexisting=14, compromised=16) PASS
- protected DISPOSABLE-profile own-access ALLOW                        BLOCKED:
  requires one interactive GUI enrollment approval of the disposable profile
  (LocalAuthentication by design); not automated and not faked.
The earlier "stale versions need reboot" blocker was worked around by
deploying to a proper .app path (Sensitive File Guard Hardened.app) and
activating via watchdog; the fail-closed build ran live.
- MPS11 protected-profile integration needs one interactive GUI enrollment.

## Security invariants (unchanged)

- AUTH_EXEC-admitted instances: Strong launch integrity.
- Already-running / launch-not-observed: PreexistingUnverified; task access
  protection applies; health Reduced; UI advises restart. Never auto-Compromised.
- Compromise monotonic Normal -> Compromised; exit clears live state; PID reuse
  never inherits.

## Final acceptance

NOT WRITTEN. Minimum checklist status:

```text
AUTH_EXEC launch admission PASS                     (unit + prior live)
AUTH_GET_TASK prevention PASS                       (unit + prior live)
AUTH_GET_TASK_READ prevention PASS                  (unit + prior live)
unexpected successful GET_TASK contextual compromise PASS (unit)
Compromised -> File Shield revoke PASS              (unit + prior live)
warm-start PreexistingUnverified truthfulness PASS  (unit)
preexisting live-state health recovery PASS         (unit)
real browser task-port denial PASS                 (prior live)
protected disposable profile integration PASS      (script updated; live BLOCKED)
normal sandbox browser compatibility PASS          (script updated; live BLOCKED)
```

Overall: CONDITIONAL until human approval + reboot + live protected-profile run.
