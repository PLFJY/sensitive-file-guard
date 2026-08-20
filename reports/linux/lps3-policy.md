# LPS3 — Firefox SecretAuthority Admission and BPF Policy

Date: 2026-08-20.

## Verdict

**IMPLEMENTED, REDUCED (ptrace-only).** The product attaches its BPF LSM link
only when `process_shield_enabled: true`; File Shield-only configurations leave
this optional layer disabled. The current product policy prevents `ptrace` for
an admitted exact Firefox Main instance. It does not claim prevention for
`process_vm_readv`, `process_vm_writev`, or `/proc/PID/mem`.

## Admission boundary

LPS2 proved only Firefox Main reading `browser_web_storage` from a disposable
profile. The policy therefore never converts a Firefox family, UID, process
tree, or executable pathname by itself into SecretAuthority.

An instance is admitted only while File Shield is handling its own allowed
WebStorage `OPEN_PERM` event, before `guardd` responds and before that open
receives a readable fd. The admission checks all of:

- configured non-root owner UID;
- canonical `/proc/PID/exe` equal to the configured Firefox executable;
- root-owned non-group/other-writable executable trust tier;
- Firefox Main role (no content, utility, GPU, or extension role); and
- canonical `--profile` or `-profile` argument equal to the configured
  disposable/profile authority root.

The BPF map value records `(TGID, /proc start-time jiffies, clock tick rate)`.
The LSM hook independently computes the target start time from kernel
`task_struct.start_boottime`; a stale PID entry returns the prior kernel policy
and is removed by the cleanup thread. Unknown same-UID requesters to a matching
target receive `EPERM`. Root is explicitly outside this guarantee and is
allowed to retain guardd's own `/proc` observation path; no browser-tree or
browser-family allow exception exists.

The first-secret-open boundary removes the polling admission window. A process
already traced before its first protected open remains a residual limitation on
kernels whose ordinary ptrace policy permits that relation; LPS5 must retain
this as not accepted unless an earlier safe lifecycle admission is evidenced.

## Fresh physical-host evidence

The normal user built the debug artifacts and product BPF object. The
user-authorized polkit physical-host runs used only synthetic process canaries
and a disposable Firefox profile:

```text
LPS1_OFF_SAME_UID_PTRACE_CANARY_RECOVERED=PASS
LPS1_ON_SAME_UID_PTRACE_DENIED_AUDITED_CANARY_RECOVERY=0 PASS
LPS3_PRODUCT_BPF_PTRACE_CAUSALITY=PASS

LPS2_FIREFOX_ALLOW_EVENTS_LIVE_INSTANCE_VERIFIED=PASS
LPS2_SECRET_AUTHORITY_CANDIDATES=1
LPS2_ROLE=Main RESOURCE=web_storage
LPS3_FIREFOX_MAIN_BPF_ADMISSION_RUNTIME=PASS
LPS2_FIREFOX_SECRET_AUTHORITY_MATRIX=PASS
```

`test-lps3-product-ptrace-root.sh` loads the exact clang-produced object that
guardd embeds and reuses the LPS1 same-non-root-parent oracle. Its OFF case
recovers only a random synthetic in-memory canary; its ON case requires exact
requester/target ring attribution and reports zero canary recovery. This is
the causal ptrace result. The Firefox run is separate evidence that a live
LPS2-proven authority reaches product admission from the pre-response File
Shield WebStorage path; Firefox's launcher re-parenting means it is not used
as a Yama-independent ptrace causality oracle.

The latest Firefox metadata-only matrix is at:

```text
/tmp/sfg-lps3-preresponse-20260820-223502/lps2-firefox-authority-matrix.json
```

## Limits and next phase

- Chromium, Chrome, and Zen remain **NOT ACCEPTED / NOT INSTALLED**.
- The nspawn capsule still returns `EPERM` for BPF program loading, so these
  results are physical-host evidence only, not capsule/namespace equivalence.
- Process Shield remains `REDUCED` in status because only ptrace has a claimed
  LSM hook. File Shield status remains independent.
- LPS4 must run a disposable Firefox workload with this layer enabled and
  establish zero unexplained Process Shield denials. LPS5 must separately test
  every claimed process-control primitive; unhooked primitives stay NOT
  ACCEPTED.
