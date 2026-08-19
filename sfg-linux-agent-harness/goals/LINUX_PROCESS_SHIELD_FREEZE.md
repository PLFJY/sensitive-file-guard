# Goal — LINUX_PROCESS_SHIELD_FREEZE

## Precondition

先验证：

```text
reports/linux/linux-file-shield-freeze-final.md
```

存在且没有 unresolved File Shield P0/P1。

若不存在，停止本 Goal，先执行 `LINUX_FILE_SHIELD_FREEZE`。

## Objective

在不改变 File Shield 可用性的前提下，实现可选 Linux Process Shield：

```text
BPF LSM
→ narrow process-control enforcement
→ exact SecretAuthority targets
```

Required phases：

1. `phases/lps/LPS0.md`
2. `phases/lps/LPS1.md`
3. `phases/lps/LPS2.md`
4. `phases/lps/LPS3.md`
5. `phases/lps/LPS4.md`
6. `phases/lps/LPS5.md`
7. `phases/lps/LPS6.md`

最终生成：

```text
reports/linux/linux-process-shield-freeze-final.md
```
