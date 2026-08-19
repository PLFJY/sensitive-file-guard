# Harness Goal Selection

当前 Goal：

```text
LINUX_FILE_SHIELD_FREEZE
```

Agent 只从 `HARNESS.md` 进入，然后读取：

```text
goals/LINUX_FILE_SHIELD_FREEZE.md
```

## 可选 Goal

- `LINUX_FILE_SHIELD_FREEZE`
  - 完成 LFH0 → LFH7。
  - **当前默认。**
  - Process Shield 只做 capability inventory，不进入实现。

- `LINUX_PROCESS_SHIELD_FREEZE`
  - 前提：Linux File Shield 已经 freeze。
  - 完成 LPS0 → LPS6。

- `LINUX_PLATFORM_FREEZE`
  - 先完整完成 `LINUX_FILE_SHIELD_FREEZE`；
  - 再完整完成 `LINUX_PROCESS_SHIELD_FREEZE`；
  - 最后做跨层 acceptance。

如果用户修改了这里的 Goal，按新的 Goal 执行；不要继续旧 Goal。
