# LPS4 — Disposable Firefox Compatibility with Process Shield ON

Date: 2026-08-20. Verdict: **PASS for the accepted Firefox scope.**

Fresh user-authorized physical-host run:

```text
/tmp/sfg-lps4-firefox-20260820-223944.log
```

used normal-user-built release artifacts, root `guardd`, a disposable Firefox
profile, and `PROCESS_SHIELD_ENABLED=true`. It ran the existing LFH6 workload:
profile population, protected-profile startup/settle, local harmless page,
restart, browser writes/compaction, and concurrent unknown same-UID File Shield
probes. It did not read a real browser profile or secret.

```text
PASS: firefox continuity=INTACT
PASS: firefox fanotify_overflows=0
PASS: firefox classifier_failures=0
PASS: firefox unclassified=0
PASS: firefox audit_dropped=0
PASS: firefox Process Shield ptrace-only status=REDUCED
PASS: firefox Process Shield denies=0 on legal workload
PASS: firefox unknown probes denied (4/4)
PASS: firefox no unexpected DENY on legal workload
PASS: firefox legal workload left a live profile artifact
LPS4_FIREFOX_DISPOSABLE_WORKLOAD_NO_PROCESS_DENIALS=PASS
LPS4_FILE_SHIELD_COMPATIBILITY_GREEN=PASS
```

The File Shield was intentionally in conservative mode for this root-mount
safe disposable workload, so its status axis is expected to say `REDUCED` for
mode coverage rather than strict-filesystem `ACTIVE`. The explicit continuity,
overflow, classifier, unclassified, audit, unknown-probe, and browser-workload
oracles above are the compatibility result; this does not re-label conservative
mode as strict acceptance.

No browser-wide or browser-tree Process Shield allow was added. The zero deny
count covers all persisted `process_shield_ptrace_denied` events after an IPC
flush. Root remains outside the Process Shield guarantee to permit guardd's
own `/proc` observation.

Firefox is the only installed, LPS2-evidenced and accepted browser family.
Firefox ESR and Zen were not installed; Chromium and Chrome were intentionally
excluded while Process Shield is enabled because they have no LPS2 authority
evidence. They remain **NOT ACCEPTED**, not compatibility passes.
