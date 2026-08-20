# LPS5 — Product BPF LSM Adversarial Process-Control Matrix

Date: 2026-08-20. Verdict: **PASS for the four accepted primitives on this
physical host.** This is not a capsule-equivalence claim: the nspawn capsule
still returns `EPERM` when it tries to load a BPF program.

## Causal test boundary

`scripts/linux/test-lps5-adversarial-root.sh` loads the exact clang-produced
`guardd-process-shield.bpf.o` object embedded by guardd. It uses a disposable
same-non-root-UID attacker/target pair where the attacker is the target's
parent. Therefore the Guard-OFF operation is permitted by Yama's normal
parent/child rule; a Guard-ON `EPERM` cannot be relabelled as DAC, Yama, a
container default, or a developer-owned secret.

For every protected-target case, the oracle requires all of:

- Guard OFF success (and exact recovery of a random in-memory canary for read
  primitives);
- Guard ON denial before a readable `/proc/PID/mem` fd is returned, or before
  the requested ptrace/process-vm operation completes;
- one ring audit from the product object with the exact non-root requester PID,
  target PID, and nonzero kernel `ptrace_access_check` mode; and
- zero recovered canary bytes in the Guard-ON case.

`process_vm_writev` has no read result; its OFF oracle instead proves a
one-byte write to synthetic target memory succeeds, while its ON result reports
zero canary recovery. The test never prints the synthetic canary.

## Fresh physical-host evidence

Normal-user-built debug artifacts were executed through the user-authorized
polkit physical-host fallback. The fresh run produced:

```text
LPS1_OFF_SAME_UID_PTRACE_CANARY_RECOVERED=PASS
LPS1_ON_SAME_UID_PTRACE_DENIED_AUDITED_CANARY_RECOVERY=0 PASS
LPS5_PROCESS_VM_READV_OFF_CANARY_RECOVERED=PASS
LPS5_PROCESS_VM_READV_ON_DENIED_AUDITED_CANARY_RECOVERY=0 PASS
LPS5_PROCESS_VM_WRITEV_OFF_SYNTHETIC_WRITE_SUCCEEDED=PASS
LPS5_PROCESS_VM_WRITEV_ON_DENIED_AUDITED_CANARY_RECOVERY=0 PASS
LPS5_PROC_MEM_OFF_CANARY_RECOVERED=PASS
LPS5_PROC_MEM_ON_DENIED_AUDITED_CANARY_RECOVERY=0 PASS
LPS5_UNRELATED_NORMAL_PROCESS_OFF_UNCHANGED=PASS
LPS5_UNRELATED_NORMAL_PROCESS_ON_UNCHANGED=PASS
LPS5_PRODUCT_BPF_ADVERSARIAL_MATRIX=PASS
```

The final two lines prove the loaded product object leaves an unrelated
same-UID child under the kernel's normal ptrace policy. LPS4 separately proves
the LPS2-evidenced Firefox Main relationship has zero Process Shield denials
during the disposable browser workload. Root is explicitly outside the Process
Shield guarantee.

## Hook coverage and limits

The accepted primitives reach the installed `lsm/ptrace_access_check` hook on
the tested kernel: upstream `kernel/ptrace.c` routes ptrace authorization
through `security_ptrace_access_check`; `mm/process_vm_access.c` obtains its
target mm with `PTRACE_MODE_ATTACH_REALCREDS`; and `fs/proc/base.c` opens
`/proc/PID/mem` through `mm_access` with an attach mode. The product audit kind
is that kernel mode, rather than a fabricated higher-level primitive name; the
matrix issues one operation per process and verifies its matching audit.

This establishes only these four primitives and the exact target-instance BPF
map semantics on the current physical host/kernel. It does not claim coverage
for an interface which does not traverse this hook, a different kernel, root
or kernel compromise, a pre-existing attachment before the first admitted
WebStorage open, or nspawn/container equivalence. Those cases remain outside
this acceptance until separately evidenced.

Sources inspected: [Linux ptrace authorization](https://github.com/torvalds/linux/blob/master/kernel/ptrace.c),
[process_vm access](https://github.com/torvalds/linux/blob/master/mm/process_vm_access.c),
[`/proc/PID/mem` access](https://github.com/torvalds/linux/blob/master/fs/proc/base.c),
and [BPF LSM documentation](https://docs.kernel.org/bpf/prog_lsm.html).
