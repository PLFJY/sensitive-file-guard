# LPS5 — Adversarial Process Shield Acceptance

最终 synthetic + disposable browser adversarial。

至少：

```text
PTRACE_ATTACH
process_vm_readv
process_vm_writev
/proc/PID/mem
```

每项：

```text
baseline OFF success
Guard ON denial
Guard attribution
no canary recovery
```

再验证：

```text
unrelated process unchanged
legitimate proven system relationship unchanged
root attacker clearly out of scope
```

如果某 primitive不经过选定 LSM hook：

```text
NOT ACCEPTED
```

不要写 PREVENTED。

输出：

```text
reports/linux/lps5-adversarial.md
```
