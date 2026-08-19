# LPS1 — Synthetic BPF LSM Process-Control Oracle

## Goal

先证明 Guard causality，再碰浏览器。

## Target

synthetic `guard-test-probe` target，内存里放 canary。

## Baseline OFF

必须构造一个在当前 Yama/LSM 配置下**合法可读/可控**的关系。

证明至少一个 primitive：

```text
ptrace
process_vm_readv
process_vm_writev
/proc/PID/mem
```

Guard OFF时成功。

如果 OS 默认就阻止，调整 synthetic relationship，而不是把 denial算 Guard。

## Guard ON

BPF LSM exact target map。

验证：

```text
operation denied
+
BPF/Guard audit exact requester+target+kind
+
canary recovered = 0
```

不测试真实 browser secret。

输出：

```text
reports/linux/lps1-synthetic.md
```
