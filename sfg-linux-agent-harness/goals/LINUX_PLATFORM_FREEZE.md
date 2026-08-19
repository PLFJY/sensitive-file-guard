# Goal — LINUX_PLATFORM_FREEZE

依次完整执行：

```text
LINUX_FILE_SHIELD_FREEZE
        ↓
LINUX_PROCESS_SHIELD_FREEZE
        ↓
cross-layer regression acceptance
```

任何子 Goal 未完成，本 Goal 不得 COMPLETE。

最终补一轮：

- File Shield ON + Process Shield ON；
- File Shield ON + Process Shield OFF；
- Process Shield unsupported simulated/probed path；
- browser compatibility；
- SSH flow；
- migration flow；
- daemon restart/continuity；
- full workspace gates。

输出：

```text
reports/linux/linux-platform-freeze-final.md
```
