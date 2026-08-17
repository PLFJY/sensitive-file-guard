# MPS12 — Safari Integration + Final macOS Process Shield Acceptance

> ## AMENDMENT (MCH0-1 round)
>
> MPS11/MPS12 claimed compatibility on disposable launch/JS/relaunch evidence.
> Daily-use compatibility (tabs, navigation, renderer churn, extensions) is
> NOT ACCEPTED; the same runs recorded compromised=16 during normal use (false
> Compromised class from always-strong REMOTE_THREAD/CS_INVALIDATED). MCH0-1
> (process-shield-mch0-1.md) reclassified those signals (contextual/telemetry),
> reports Process Shield Reduced until validated, and added an independent
> Process Shield toggle. This report's acceptance sentence remains unwritten.

## Status

IMPLEMENTATION FROZEN.
SECURITY ACCEPTANCE CONDITIONAL ON FINAL LIVE MPS11 RUN.

All Process Shield code is frozen; no further macOS Process Shield features
will be developed. The fail-closed warm-start reconciliation fix landed with
tests. Safari Process Shield coverage remains NOT ACCEPTED / OUT OF CURRENT
MILESTONE. The final acceptance sentence is not written because one live
MPS11 sub-item (protected disposable-profile ALLOW) still requires an
interactive GUI enrollment approval on this host.

## Repository

- HEAD: bc26dd03b8fb9e7d6540b4569f2ee256d4f743a3 (working tree changes only)

## Safari approach (metadata only) — honest coverage statement

- Safari is NOT enrolled in the current macOS browser trust config (browsers:
  Chrome + Firefox). Its profile is not a protected resource, so File Shield
  does not intercept it and Process Shield does not admit its processes as
  shielded targets.
- Observed: Safari + WebKit helpers (com.apple.WebKit.GPU, Networking, etc.)
  launch and run with the extension active; `SAFARI_ALIVE_AFTER_PAGE_LOAD`
  PASS; task counters showed denied=0/admitted=0/compromised=0 during the
  Safari run (no interception, no deny storm).
- **Safari Process Shield coverage: NOT ACCEPTED.** This run proves only that
  Guard does not break Safari while Safari is unprotected. It is NOT evidence
  that Safari would be Process-Shield-protected if enrolled: Safari targets
  are not shielded, no Safari-specific task-access rules exist, and the
  harness's "add narrow signing/role rules only after metadata observation"
  step is therefore NOT satisfied for Safari. Accepting Safari coverage would
  require enrolling Safari executables/profile scope and re-running the
  prevention/recheck suite against it.
- **Safari compatibility while unprotected: PASS.**
- No real Safari cookies/history/session contents were read.

## Final regression (real host)

```text
cargo fmt --all -- --check                                    PASS
cargo clippy --workspace --all-targets --all-features -D warnings PASS
cargo test --workspace --all-features                        PASS
git diff --check                                             PASS (below)
```

Live evidence (MPS9 + MPS11 + MPS12 + Hardening 1 + Hardening 2 + Final Closure):

THIS PASS (final closure, fail-closed build 1787000400 active, production
non-POC extension, normal Chrome sandbox):
- Chrome launches with normal sandbox                          (PASS)
- Chrome main process running                                  (PASS)
- Chrome stays alive after JS/JIT load                         (PASS)
- Chrome relaunch works                                        (PASS)
- Firefox launches / main running / alive after JS load        (PASS)
- untrusted same-user probe -> real Chrome task control -> DENY (exit 4, result=5 port=0)  (PASS)
- untrusted same-user probe -> real Chrome task read    -> DENY (exit 4, result=-1 port=0) (PASS)
- untrusted same-user probe -> real Firefox cookies.sqlite -> DENY (EPERM, no content)      (PASS)
- audit: browser_access_denied rows present; NO secret contents (PASS)
- Process Shield counters live: admitted=130, preexisting=14, compromised=16, task deny rows present (PASS)
- protected DISPOSABLE-profile own-access ALLOW               (BLOCKED: requires one
  interactive GUI enrollment approval of the disposable profile; not automated
  and not faked)

PRIOR PASSES (recorded earlier, still valid):
- synthetic task control/read denied; canary not recovered; DYLD injection
  denied; controlled compromise -> File Shield deny        (MPS9, PASS 8/8)
- Chrome/Firefox disposable compatibility + probe recheck   (MPS11, PASS)
- Safari under active extension, unprotected                  (MPS12, PASS)
- Safari Process Shield coverage                              (MPS12, NOT ACCEPTED)
- warm-start task-access gap closed / contextual signals /
  allowlist narrowed / notify scoping                         (Hardening 1+2)
- AUTH_MMAP remains disabled (MPS10 decision)

## Final security claims

```text
PREVENTED (authorization denies before capability/exec):
  - same-user untrusted task control/read against shielded targets
  - DYLD code-loading launch injection into shielded targets
DETECTED + CONTAINED (notify-only):
  - remote-thread creation / code-signing invalidation -> Compromised
  - task-capability + TRACE notifies -> telemetry ONLY when the requester is
    a legitimate allowlisted Apple service; a NON-allowlisted requester that
    actually obtained task capability is a contextual strong signal ->
    Compromised (never PREVENTED)
  - compromise -> File Shield deny + lease revocation
WARM-START (MPS Hardening):
  - shield-eligible processes already running when ES restarted are admitted
    PreexistingUnverified; task access denied unless allowlisted; File Shield
    reports Reduced until the process restarts via AUTH_EXEC
```

The final acceptance sentence (MACOS PROCESS SHIELD SECURITY ACCEPTED ON
TESTED HOST) is NOT written. Per the harness it requires every item below on
a real host with the production (non-POC) extension active:

```text
AUTH_EXEC launch admission PASS                    (unit + MPS9 + MPS11 live)
AUTH_GET_TASK prevention PASS                      (unit + MPS9 + MPS11 live)
AUTH_GET_TASK_READ prevention PASS                 (unit + MPS9 + MPS11 live)
unexpected successful GET_TASK contextual compromise PASS  (unit)
Compromised -> File Shield revoke PASS             (unit + MPS9 live)
warm-start PreexistingUnverified truthfulness PASS (unit)
preexisting live-state health recovery PASS        (unit)
fail-closed preexisting reconciliation PASS        (unit, final closure)
real browser task-port denial PASS                 (MPS11 live, result=5/-1 port=0)
File Shield real-profile deny PASS                 (MPS11 live, Firefox cookies EPERM)
audit no-secret PASS                               (MPS11 live)
protected disposable profile ALLOW                 (BLOCKED: GUI enrollment approval)
normal sandbox browser compatibility PASS          (MPS11 live)
```

Safari Process Shield: NOT ACCEPTED / OUT OF CURRENT MILESTONE.
Pre-held Mach task-port rights from before the current enforcement
generation: NOT RETROACTIVELY REVOKED.
Root/kernel compromise: OUT OF SCOPE.
Browser-internal RCE/extensions/DevTools: OUT OF SCOPE.

Only the interactive GUI enrollment of a disposable protected profile is
missing; it cannot be automated without the human LocalAuthentication
approval (by design). After that approval + the disposable enrollment, the
sentence may be written. Implementation is frozen; no further macOS Process
Shield development will proceed.

## Remaining non-goals (documented)

- malicious browser extensions;
- browser-internal renderer/JIT RCE;
- root/kernel compromise;
- DevTools/remote-debugging paths not covered by the implemented ES policy;
- generic malware classification (deterministic policy only).

## Blockers

One human step: permanent system-extension approval (user must click Allow in
System Settings once). Everything else passed on this host.
