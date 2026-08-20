# LPS0 — Linux BPF LSM Capability Probe

Date: 2026-08-20. This phase establishes capability only; it does not install
a persistent BPF policy or claim Process Shield enforcement.

## Verdict

- Host BPF LSM capability: **ACTIVE**.
- Capsule BPF LSM live capability: **REDUCED / NOT HOST-EQUIVALENT**.
- Current Linux Process Shield product state: **DISABLED (not implemented)**.
  This does not change File Shield, whose independent freeze remains restored.

## Host evidence

The current host reports:

- `/sys/kernel/security/lsm`: `capability,landlock,lockdown,yama,bpf`
- `/sys/kernel/btf/vmlinux`: present (6,460,072 bytes)
- kernel config: `CONFIG_BPF=y`, `CONFIG_BPF_SYSCALL=y`,
  `CONFIG_BPF_LSM=y`, and `CONFIG_DEBUG_INFO_BTF=y`
- local BTF contains the `ptrace_access_check` LSM hook signature
  `int (*)(struct task_struct *, unsigned int)`.

The repository's minimal LPS0 probe is deliberately non-enforcing:

- `scripts/linux/lps/lps0-ptrace-attach-probe.bpf.c` returns the preceding LSM
  result unchanged.
- `scripts/linux/lps/lps0-bpf-loader.c` loads it, attaches it through
  `bpf_program__attach_lsm`, then destroys the link before exiting. It pins no
  map and leaves no policy behind.

Built as the normal user, then run once through explicitly authorized polkit on
the physical host, it printed:

```text
LPS0_BPF_LSM_LOAD_AND_ATTACH=PASS
```

This is direct evidence of `BPF_PROG_TYPE_LSM` load and attachability for the
required ptrace-control hook, not merely a kernel-config inference. Kernel BPF
LSM documentation specifies `BPF_PROG_LOAD` and LSM link attachment for
`lsm/<hook>` programs; the local BTF determined the concrete hook name.

## Capsule result and limitation

The identical staged loader/object inside `sfg-test-capsule` failed during
libbpf's trivial program load probe with `EPERM`. The normal-user host run also
fails with `EPERM`, as expected without BPF privilege. The privileged physical
host run passes, so the capsule result is an nspawn BPF capability/seccomp
limitation, not host BPF LSM absence. It cannot support LPS live acceptance
without a launcher change that grants the needed `bpf()` access and associated
BPF capabilities.

## Scope for LPS1

LPS1 must bind targets by exact process instance (PID plus start time/pidfd),
establish a same-UID synthetic canary baseline, and test only primitives whose
actual LSM path is verified. No Process Shield denial is implemented by LPS0.
