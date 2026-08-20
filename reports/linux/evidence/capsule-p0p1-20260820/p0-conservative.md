# P0 — SSH mmap, conservative-mode capsule rerun

Date: 2026-08-20. After review found that conservative mode and runtime
`ssh protect` still used an ACCESS-only mark, the implementation was changed
to install `FAN_OPEN_PERM | FAN_ACCESS_PERM` for every SSH private key.

The capsule mounted a fresh private tmpfs (`st_dev=92`), distinct from both
capsule `/` and host-bound `/testfs`. Current staged `guardd` matched its
host-built SHA-256 before execution.

`ENFORCEMENT_MODE=conservative p0-capsule-run.sh` returned:

```text
PASS: mmap denied at open (no readable fd granted)
PASS: plain read denied at open
PASS: audit records the denied SSH open
P0 SSH mmap summary: PASS=3 FAIL=0 BLOCKED=0
```

The prior strict-filesystem P0 capsule run also returned PASS=3/3. This proves
the configured-key path in both Linux enforcement modes; runtime enrollment
uses the identical `FAN_OPEN_PERM|FAN_ACCESS_PERM` mask and is additionally
covered by unit/code review.
