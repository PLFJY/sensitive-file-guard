# Linux Process Shield — Implementation Freeze

Verdict: **REOPENED — product-object scope is proven, but daemon-integrated
attack causality is not yet accepted.**

The reviewed implementation is commit
`8bb2213b026dba367138aa4bd28f35517a3ae7a0`. Its fresh physical-host formal
manifest is:

```text
/tmp/sfg-process-shield-final-8bb2213b026d
```

It records **4 mandatory PASS, 0 FAIL, 0 BLOCKED** on host kernel
`7.1.8-arch1-3`. Normal-user-built release artifacts were used for the product
and compatibility gates; the LPS2 authority gate explicitly used normal-user
built debug `guardd`/`guardctl`, because release audit intentionally does not
persist ordinary ALLOW events. The manifest records SHA-256 for both sets.

## Accepted scope

- LPS0: host BPF LSM loads and attaches to `ptrace_access_check`.
- LPS1/LPS5: the exact product BPF object denies same-UID parent attacks to an
  exact instance for `ptrace`, `process_vm_readv`, `process_vm_writev`, and
  `/proc/PID/mem`, after each Guard-OFF primitive succeeded. Each ON result has
  exact requester/target ring attribution and zero readable synthetic canary.
- LPS2/LPS3: only an evidence-proven disposable Firefox Main instance is
  admitted, and only while its File Shield WebStorage open is withheld. The map
  is `(TGID, start-jiffies, clock-tick-rate)`; a stale start-time entry does not
  bind a different instance.
- LPS4: the accepted disposable Firefox workload has zero Process Shield
  denials while File Shield stays healthy. No browser-wide/tree exemption was
  introduced.
- LPS6: the unpinned BPF link and maps are owned by daemon RAII; exit removes
  the link, and the cleanup loop removes departed/stale entries. The formal
  synthetic stale-entry check passed. Unprotected same-UID process control
  remains under normal kernel policy. Five 100-operation samples had median
  1,673,077 ns OFF and 1,932,035 ns ON, within the formal 5x + 1ms
  catastrophic-regression guard.

## Truthful limits

- Status remains `process_shield=REDUCED`, never ACTIVE: this is a
  `ptrace_access_check` boundary, not complete Linux process mediation.
- The nspawn capsule's BPF program load remains `EPERM`; its result is
  REDUCED/NOT HOST-EQUIVALENT. This freeze is physical-host evidence obtained
  through the explicitly user-authorized polkit path, not a capsule claim.
- Firefox is the only installed, LPS2-evidenced accepted browser. Firefox ESR,
  Chromium, Chrome, and Zen are NOT ACCEPTED/NOT INSTALLED as applicable.
- Interfaces that do not reach the proven hook, root/kernel compromise, and an
  attack already attached before the first admitted WebStorage open remain out
  of scope. A stale map entry must not protect a PID-reused unrelated process;
  it fails safe by matching neither instance, while the departed authority has
  no remaining secret-bearing process to protect.
- Disabling or failing to request Process Shield never disables or weakens File
  Shield. Requesting it on an unsupported environment fails daemon startup
  rather than silently claiming it is enabled.

Required next work: a daemon-integrated same-UID adversarial oracle against a
live File-Shield-admitted disposable SecretAuthority. Only after that causal
proof can LPS5/LPS6 and cross-layer `LINUX_PLATFORM_FREEZE` close.
