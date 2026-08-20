# LPS1 — Synthetic Same-UID BPF LSM Process-Control Oracle

Date: 2026-08-20. This is a narrow synthetic causality test, not a browser
compatibility or full Process Shield acceptance claim.

## Verdict

- `ptrace` on one exact synthetic process instance: **PREVENTED** on the
  physical host.
- `process_vm_readv`, `process_vm_writev`, and `/proc/PID/mem`: **NOT
  ACCEPTED**. LPS1 does not claim that their paths traverse this LSM hook.
- Current product Process Shield: **DISABLED / not integrated**. The BPF
  program below is a test-only, short-lived LPS1 oracle and pins no map or
  link after exit.
- Capsule process-control live result: **REDUCED / NOT HOST-EQUIVALENT**. Its
  LPS0 BPF program-load probe fails with `EPERM`, so it cannot establish this
  BPF LSM result without a capsule launcher change.

## Design and causality

`guard-test-probe shield-target` allocates a fresh 64-byte random in-memory
canary. Its readiness file is ephemeral test metadata containing the PID,
canary comparison value, and stable heap address; normal output, audit events,
and this report contain no canary bytes.

`lps1-ptrace-oracle` runs as a short-lived root supervisor only to load and
attach `lps1-ptrace-guard.bpf.o`. It then drops the actual attacker process to
the invoking non-root UID before that attacker forks the synthetic target.
The attacker is therefore the target's same-UID parent: the current Yama
relationship permits the Guard-OFF `PTRACE_SEIZE` / `PTRACE_PEEKDATA` baseline
without relying on root or a DAC denial.

For Guard ON, the temporary BPF map keys on target TGID and validates the
target's `start_boottime` against the userspace-recorded `/proc/PID/stat`
start time. A reused PID cannot match a stale entry. On a match, the
`ptrace_access_check` hook emits requester PID, target PID, start time, and
operation kind to a ring buffer, then returns `-EPERM`. The oracle validates
the precise requester and target PIDs, does not print recovered bytes, and
reports recovery as zero only when the ptrace acquisition itself was denied.

## Fresh physical-host evidence

Built as the normal user:

```text
cargo build --release -p guard-test-probe
clang -target bpf -O2 -g -Wall -Werror -c scripts/linux/lps/lps1-ptrace-guard.bpf.c -o target/lps1/lps1-ptrace-guard.bpf.o
clang -O2 -Wall -Werror scripts/linux/lps/lps1-ptrace-oracle.c -lbpf -lelf -lz -o target/lps1/lps1-ptrace-oracle
```

The explicitly user-authorized physical-host polkit run of
`scripts/linux/test-lps1-ptrace-root.sh` used the normal user's UID and
printed:

```text
LPS1_OFF_SAME_UID_PTRACE_CANARY_RECOVERED=PASS
LPS1_ON_SAME_UID_PTRACE_DENIED_AUDITED_CANARY_RECOVERY=0 PASS
LPS1_SAME_NONROOT_UID_PTRACE_ORACLE=PASS
```

The direct normal-user invocation correctly exits `2` (BLOCKED), proving the
test does not silently claim BPF privilege. The physical-host result proves
only the current host kernel's `ptrace_access_check` path; namespaces,
container policy, and the other process-memory primitives remain outside this
acceptance.

## Next phase

LPS2 must derive Browser SecretAuthority from real File Shield ALLOW events on
disposable Firefox data. No browser identity or allow exception is implied by
this synthetic test.
