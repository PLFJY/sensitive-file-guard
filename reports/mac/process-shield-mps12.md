# MPS12 — Safari Integration + Final macOS Process Shield Acceptance

## Status

CONDITIONAL — final regression green and Chrome/Firefox compatibility PASS
under the active Process Shield extension (real host), plus a MPS Hardening
pass that closed the warm-start task-access gap, made NOTIFY_GET_TASK(_READ)
a contextual strong signal, and narrowed the task allowlist to exact
signing IDs per kind. Safari Process Shield coverage is explicitly NOT
ACCEPTED (see below); the harness final-acceptance sentence therefore stays
WITHHELD pending (a) permanent extension approval and (b) an enrolled
Safari coverage decision.

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

Live evidence (MPS9 + MPS11 + MPS12 + MPS Hardening):
- synthetic task control/read denied; canary not recovered; DYLD injection
  denied; controlled compromise -> File Shield deny        (MPS9, PASS)
- Chrome/Firefox disposable compatibility (7 cases)          (MPS11, PASS)
- untrusted same-user probe recheck after exceptions         (MPS11, PASS)
- audit handoffs now verified through authenticated guardctl events with
  no canary/protected content (MPS9, MPS11 scripts fixed)
- Safari under active extension, unprotected                  (MPS12, PASS)
- Safari Process Shield coverage                              (MPS12, NOT ACCEPTED)
- warm-start / ES-restart task-access gap closed             (Hardening)
- NOTIFY_GET_TASK(_READ) contextual strong signal            (Hardening)
- task allowlist narrowed to exact signing ID + kind         (Hardening)
- unrelated notify events no longer enter the audit queue    (Hardening)
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
TESTED HOST) is NOT written: per the harness, it may only be written when
prevention, compromise-state integration AND disposable-browser
compatibility all pass on a real host with the production (non-POC)
extension active, AND (per this hardening pass) Safari Process Shield
coverage is either enrolled and tested or explicitly declared NOT ACCEPTED
(it is). This run used the production build (service mode) but the permanent
system-extension activation still requires one human approval in System
Settings (the approval record churned during the repeated activation cycles).
The deterministic step is: open System Settings > General > Login Items &
Extensions > Endpoint Security Extensions > approve Guard Endpoint Security
once, or run `/Applications/Guard.app/Contents/MacOS/Guard
--activate-system-extension`. After approval, the machine keeps the Process
Shield build active.

## Remaining non-goals (documented)

- malicious browser extensions;
- browser-internal renderer/JIT RCE;
- root/kernel compromise;
- DevTools/remote-debugging paths not covered by the implemented ES policy;
- generic malware classification (deterministic policy only).

## Blockers

One human step: permanent system-extension approval (user must click Allow in
System Settings once). Everything else passed on this host.
