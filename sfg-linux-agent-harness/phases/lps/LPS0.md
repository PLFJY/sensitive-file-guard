# LPS0 — BPF LSM Capability Probe

## Goal

只建立 capability/runtime seam，不做 process-control deny。

探测：

```text
/sys/kernel/security/lsm
/sys/kernel/btf/vmlinux
BPF_PROG_TYPE_LSM load
required hook attachability
```

不要只看 kernel version。

状态：

```text
UNSUPPORTED
DISABLED
REDUCED
ACTIVE
```

File Shield必须在 Process Shield UNSUPPORTED 时继续正常 ACTIVE。

实现前查当前 kernel official BPF LSM docs和本机 BTF hook名，不凭记忆。

输出：

```text
reports/linux/lps0-capability.md
```
