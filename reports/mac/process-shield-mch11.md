# MCH11 — Final Acceptance Gate Status (honest)

## Status

NOT ACCEPTED. macOS Process Shield is NOT a freeze candidate. The acceptance
gate cannot close on this host because the daily-use family of gates requires
live runs that are BLOCKED by the documented human steps (permanent
system-extension approval + reboot to clear stale extension versions). Health
remains Reduced (not Active). This document maps every gate in goal §26 to its
exact current status; nothing is fabricated.

## Repository

HEAD: 8720595 (main). Working-tree changes only (MCH0-8 + MCH9/MCH11 docs).

## Gate status table (goal §26)

```text
gate                                            status
--------------------------------------------------------------
Chrome normal browsing                           BLOCKED (live; MCH9 script ready)
Firefox normal browsing                          BLOCKED (live; MCH9 script ready)
10+ tab churn                                   BLOCKED (live; MCH9 script ready)
multi-origin navigation                          BLOCKED (live; MCH9 script ready)
renderer/content-process churn                   BLOCKED (live; MCH9 script ready)
JS/JIT/WebAssembly                              BLOCKED (live; MCH9 script ready)
WebGL/GPU                                       BLOCKED (live; MCH9 script ready)
Service Worker                                  BLOCKED (live; MCH9 script ready)
harmless extension fixture                       BLOCKED (live; MCH8 fixture ready)
unexplained normal-use task DENY == 0            NOT ESTABLISHED (capture + classification needed)
false Compromised transitions == 0               NOT ESTABLISHED (design reduces; live needed)
false Process-Shield protected-profile DENY == 0 NOT ESTABLISHED (live needed)
trusted browser own protected profile access     PASS (unit) / BLOCKED (live protected-profile ALLOW)
unknown process protected-file access BLOCKED    PASS (unit + prior MPS11 live EPERM)
unknown process task control BLOCKED             PASS (unit + prior MPS11 live result=5 port=0)
unknown process task read BLOCKED                PASS (unit + prior MPS11 live result=-1 port=0)
signed helper laundering BLOCKED                 PASS (unit: session + notify + shield) / live pending
synthetic memory canary recovered == 0 bytes     PASS (prior MPS9 live recovered_pages=0)
DYLD launch injection BLOCKED                    PASS (prior MPS9 live)
confirmed compromise -> File Shield revoke       PASS (unit + prior MPS9 live)
```

Verdict: the security-core gates (unknown-process prevention, laundering,
canary, DYLD, compromise revoke) hold on unit + prior live evidence; the
compatibility gates (normal browsing, churn, extension) are BLOCKED on the
live harness. Therefore:

```text
daily-browser compatibility = NOT ACCEPTED
browser-extension compatibility = NOT ACCEPTED
Process Shield health = Reduced
macOS = NOT a freeze candidate
```

## Remaining deterministic artifacts (ready, live-blocked)

- scripts/macos/test-daily-browser-stress.sh   (MCH9; syntax-validated)
- scripts/macos/capture-process-authority-matrix.sh (MCH2; syntax-validated)
- scripts/macos/fixtures/mv3-harmless-extension/ (MCH8; JSON/JS validated)
- scripts/macos/test-disposable-browsers-process-shield.sh (MPS11; existing)
- scripts/macos/test-process-shield-synthetic.sh (MPS9; existing, prior live PASS)

## Exact commands a human must run to close the gate (after approval + reboot)

```sh
# 1. Authority matrix (MCH2 evidence for MCH4/5 targeting review)
LIVE_ES_ACCEPTANCE=I_ACCEPT_SYSTEM_EXTENSION_RISK \
  DISPOSABLE_CHROME_PROFILE=/tmp/guard-mch2-profile \
  scripts/macos/capture-process-authority-matrix.sh

# 2. Daily-use stress (MCH9) with counter capture for deny classification
LIVE_ES_ACCEPTANCE=I_ACCEPT_SYSTEM_EXTENSION_RISK \
  scripts/macos/test-daily-browser-stress.sh

# 3. Extension compatibility (MCH8): load the fixture into disposable Chrome
#    and exercise service-worker wake / content script / popup / options /
#    storage / tab churn, then classify every shield event.

# 4. Adversarial regression (MCH10): rerun MPS9 synthetic + real-browser
#    laundering probe against the protected disposable profile.
```

Only after (1)-(4) pass with 0 unexplained denials and 0 false Compromised
may the acceptance sentence be written.
