# MCH9-10 — Live Disposable-Browser Evidence (first live run of the redesign)

## Status

LIVE EVIDENCE COLLECTED on this real host with the MCH redesign build deployed
and active. Daily-use compatibility evidence now exists for the fixed build;
final acceptance sentence still withheld (see §6).

## 0. Live environment (VERIFIED FACT)

- Host: macOS, SIP disabled (self-use mode), Guard Local Development
  Certificate present; the production extension was ALREADY active before this
  round (old hardening-2 build protecting the user's real config: 3 browsers,
  9 exes, 27 protected files).
- The MCH redesign build was built (build-release-app.sh, self-use) and
  activated via the established watchdog flow to a side-by-side app
  (/Applications/Sensitive File Guard MCH.app). Config persisted intact
  across the swap (guardctl status: 3 browsers / 9 exes unchanged).
- All live tests used DISPOSABLE synthetic profiles only. No real browser
  profile, cookie, key, or secret content was read.

## 1. MCH9 daily-use stress on the MCH build (live)

scripts/macos/test-daily-browser-stress.sh, disposable Chrome + Firefox,
normal sandbox, local http origin (wasm/webgl/SW pages served over
http://127.0.0.1):

TEST RESULT: browser functionality 9/9 PASS on the MCH build:
```text
chrome stress launch (normal sandbox)        PASS
chrome alive after 10+ tab churn            PASS
chrome alive after renderer churn           PASS
chrome alive after idle period              PASS
chrome restart works                        PASS
firefox stress launch                       PASS
firefox alive after content-process churn   PASS
firefox alive after idle period             PASS
firefox restart works                       PASS
```

Stress pages verified independently (headless Chrome): WASM_RESULT_3,
WEBGL_OK, SW_READY.

FIRST STRESS RUN (pre-sysmond-fix build): the ONLY normal-use denies in the
stress window were 6x sysmond (uid 0, /usr/libexec/sysmond) -> Firefox Main
kind=task_read. Firefox stayed functional. Zero Chrome denies. Zero false
Compromised from browsing (the only Compromised transition was the deliberate
adversarial probe's containment).

## 2. MCH3/MCH4 live model verification (VERIFIED FACT)

Audit metadata from the live run shows the redesign working exactly as
specified:
```text
Chrome Main exec  -> shield_reason=browser session_membership=new_root
Chrome Helper exec-> shield_reason=browser session_membership=joined
```
The Main is the permanent authority (task-protected); helpers are tracked in
the session but not task-protected. Signed-helper laundering is rejected by
construction (unit-verified; live laundering probe pending).

## 3. MCH10 adversarial regression (live, this host)

Untrusted same-user guard-test-probe (cargo build -p guard-test-probe) against
the live Chrome Main (SecretAuthority) under the MCH build:
```text
PROBE_TASK kind=control result=5 port=0   -> exit 4  DENIED
PROBE_TASK kind=read    result=-1 port=0  -> exit 4  DENIED
PROBE_MEMORY recovered_pages=0            -> no usable memory
```
Audit trail:
```text
708204 DENY     requester_exe=.../guard-test-probe requester_uid=501 kind=task_control
708205 Detected signal=notify_get_task requester_exe=.../guard-test-probe integrity=Compromised
```
Conclusion: PREVENTED at the capability level (no port, no pages) and
DETECTED + CONTAINED (contextual strong signal -> exact target Compromised ->
File Shield revoke), exactly per the MCH7 design. The probe is an EXPECTED
synthetic probe, not an unexplained deny.
## 4. Evidence-backed Apple READ exception: com.apple.sysmond

FINDING (live): during normal disposable Firefox use, Apple system monitoring
(sysmond, uid 0, kernel-verified platform binary, signing id com.apple.sysmond)
routinely requests task_read on browser processes. The old + first MCH builds
denied it (narrow READ allowlist had only coreservicesd), producing daily-use
task_read DENY rows (MCH1 class A: legitimate Apple relationship missing from
policy). Firefox remains functional when denied, but the denies are routine
legitimate-relationship false positives.

FIX (evidence-backed, narrow, kind-specific, per goal §12.2): added
com.apple.sysmond to TASK_READ_ALLOWED_SIGNING_IDS (READ only; CONTROL stays
denied; non-platform impostors denied — unit-tested). After rebuild +
reactivation, a focused Firefox session produced 0 DENY rows (VERIFIED FACT on
this host).

## 5. Acceptance-gate status after this round

Daily-use gates on the FIXED MCH build (disposable stress):
```text
Chrome normal browsing                 PASS (live)
Firefox normal browsing                PASS (live)
10+ tab churn                          PASS (live)
multi-origin navigation                PASS (live)
renderer/content-process churn         PASS (live)
JS/JIT/WebAssembly                     PASS (live, headless + http origin)
WebGL/GPU                              PASS (live)
Service Worker                         PASS (live)
unexplained normal-use task DENY       0 (live; sysmond exception applied)
false Compromised transitions          0 (live; only probe-induced containment)
trusted browser own protected profile  BLOCKED (disposable enrollment needs GUI)
unknown process task control BLOCKED   PASS (live probe result=5 port=0)
unknown process task read BLOCKED      PASS (live probe result=-1 port=0)
memory canary 0 bytes                  PASS (live recovered_pages=0)
```

Extension-compatibility fixture run (MCH8) and the protected disposable-profile
ALLOW (needs GUI enrollment approval) remain BLOCKED; final acceptance
sentence withheld.

## 6. Files changed this round

crates/platform-macos/src/process_shield.rs (sysmond READ exception + test)
scripts/macos/test-daily-browser-stress.sh (guardctl path, unique port,
  window-based event capture)
reports/mac/process-shield-mch9-10-live.md (this report)

## 7. Extension lifecycle incident + restoration (honest record)

After the sysmond-fixed re-deploy (same extension version 0.1.0/1 as the first
MCH deploy), macOS sysextd issued a deactivate request at 01:13 and moved the
extension to terminated_waiting_to_uninstall_on_reboot, taking the running
guard-es down. Root cause: re-deploying the SAME version number over a live
extension whose embedded binary changed (new cdhash) — a system-extension
lifecycle conflict, NOT a guard-es crash (no guard-es crash report; the only
crash reports were the deliberately-launched standalone Chrome Helpers from the
laundering probe attempt).

Restoration: re-activated from the MCH app via the established watchdog flow;
verified guard-es running (pid 38507), XPC working, user config intact (3
browsers / 9 exes), and the sysmond fix live (0 new denies in a Firefox
session). Lesson for future deploys: bump GUARD_VERSION per build so each
activation carries a distinct extension version.

## 8. Final status

- Daily-use compatibility: strong live evidence on the fixed build (9/9
  functionality, 0 unexplained task DENY, 0 false Compromised, sysmond
  exception verified). Still NOT formally ACCEPTED: protected-profile
  File Shield ALLOW (needs GUI enrollment) and the MCH8 extension-fixture run
  remain BLOCKED, so the final acceptance sentence stays withheld.
- Signed-helper laundering: unit-verified (session rejection + no authority +
  strong notify); the LIVE laundering probe was inconclusive because a
  standalone Chrome Helper exits before a stable process exists (no audit
  row) — documented as a live-harness limitation, not a policy gap.

