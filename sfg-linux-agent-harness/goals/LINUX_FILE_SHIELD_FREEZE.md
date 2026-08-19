# Goal — LINUX_FILE_SHIELD_FREEZE

## Objective

把当前 Linux Alpha 的 `root guardd + fanotify + strict-filesystem` 做成可正式 freeze 的 Linux-native File Shield。

不要实现 BPF LSM Process Shield；只记录 capability availability，保证未来有 seam。

## Required phases

按顺序执行：

1. `phases/lfh/LFH0.md`
2. `phases/lfh/LFH1.md`
3. `phases/lfh/LFH2.md`
4. `phases/lfh/LFH3.md`
5. `phases/lfh/LFH4.md`
6. `phases/lfh/LFH5.md`
7. `phases/lfh/LFH6.md`
8. `phases/lfh/LFH7.md`

若某 phase 发现新的 P0/P1 blocker：

```text
不要跳过
→ 写入 harness-state
→ 修复
→ 重新跑受影响的 earlier gates
```

## Non-goals

- 不写 kernel module / DKMS。
- 不启用真实 secret 测试。
- 不把 Flatpak/Snap/network FS 随便标成 ACCEPTED。
- 不为了 Linux 改坏已经 freeze 的 macOS semantics。
- 不用 Process Shield 补 File Shield 的 resource/identity bug。

## Completion

满足 `ACCEPTANCE.md` 的 Final File Shield gate 后：

```text
Linux File Shield implementation:
FREEZE

formal posture:
ACTIVE on accepted strict-filesystem capability set

unsupported/legacy capability:
REDUCED with exact reason
```

生成：

```text
reports/linux/linux-file-shield-freeze-final.md
```
