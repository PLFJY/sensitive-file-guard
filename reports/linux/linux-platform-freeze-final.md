# Linux Platform Freeze

Verdict: **LINUX_PLATFORM_FREEZE ACCEPTED (REDUCED capability scope).**

Fresh physical-host evidence was produced for implementation commit
`9673f6fcd6380447af307b8f7ecc13679d5fbc8d` on kernel `7.1.8-arch1-3`:

- File Shield one-shot manifest:
  `/tmp/sfg-platform-file-oneshot-9673f6fcd638/summary-oneshot.txt` — **23/23
  mandatory PASS**, 0 fail, 0 blocked; native-browser observation PASS.
- File Shield systemd manifest:
  `/tmp/sfg-platform-file-systemd-9673f6fcd638/summary-systemd.txt` — **1/1
  mandatory PASS**, 0 fail, 0 blocked; fdstore crash-continuity is explicitly
  **PARTIAL**, not accepted crash recovery.
- Process Shield manifest:
  `/tmp/sfg-process-shield-final-9673f6fcd638/summary.txt` — **5/5 mandatory
  PASS**, 0 fail, 0 blocked. It includes the daemon-integrated same-UID
  adversarial matrix, rather than relying only on an independently loaded BPF
  object.

All fixtures were disposable synthetic browser profiles and ephemeral SSH keys.
Strict filesystem tests used isolated loop-backed ext4 and did not mark the
host root filesystem or tmpfs.

## Cross-layer acceptance

- **File Shield ON, Process Shield OFF:** the File Shield 23-gate formal run
  uses the default disabled optional Process Shield and passes its SSH mmap,
  migration/installed authorization, topology, restart, adversarial, and
  performance gates.
- **File Shield ON, Process Shield ON:** the Process Shield manifest passes
  LPS2 authority admission, Firefox disposable compatibility with File Shield
  green, the daemon-integrated process-control matrix, and lifecycle/perf.
- **Process Shield unavailable:** nspawn blocks BPF program loading with
  `EPERM`; that is container-scoped REDUCED/NOT-HOST-EQUIVALENT evidence, not a
  host pass. The host physical-polkit run proves the supported path, and an
  unavailable/disabled Process Shield does not disable or weaken File Shield.
- **Process-control causality:** after an actual classified File Shield
  WebStorage allow admits the exact synthetic Firefox Main instance, each of
  ptrace, `process_vm_readv`, `process_vm_writev`, and `/proc/PID/mem` has
  Guard-OFF success and Guard-ON daemon denial, persisted requester/target
  audit, and zero canary recovery. The hook is `ptrace_access_check`; this is
  not a claim that unhooked process interfaces are prevented.

## Residual limits

- File Shield LFH4 crash continuity remains **PARTIAL / REDUCED**: a pending
  permission event cannot be restored after daemon crash through public UAPI.
- Firefox is the only accepted browser family. Firefox ESR, Chromium, Chrome,
  and Zen remain NOT ACCEPTED/NOT INSTALLED as applicable.
- Process Shield remains optional and status is **REDUCED**, never a claim of
  complete Linux process mediation. Root/kernel compromise, pre-existing
  attachment before first SecretAuthority admission, and interfaces outside
  the proven hook are out of scope.

There are no P0/P1 findings outstanding and no mandatory formal gate is
BLOCKED. The report-only commit following this evidence does not alter runtime
code or test artifacts.
