# Harness Goal Selection

当前 Goal：

```text
LINUX_PLATFORM_FREEZE
```

Agent 只从 `HARNESS.md` 进入，然后读取：

```text
goals/LINUX_PLATFORM_FREEZE.md
```

## 可选 Goal

- `LINUX_FILE_SHIELD_FREEZE`
  - 完成 LFH0 → LFH7。
  - Process Shield 只做 capability inventory，不进入实现。

- `LINUX_PROCESS_SHIELD_FREEZE`
  - 前提：Linux File Shield 已经 freeze。
  - 完成 LPS0 → LPS6。

- `LINUX_PLATFORM_FREEZE`
  - 先完整完成 `LINUX_FILE_SHIELD_FREEZE`；
  - 再完整完成 `LINUX_PROCESS_SHIELD_FREEZE`；
  - 最后做跨层 acceptance。
  - File Shield 已在 `77dcd75edc3a10b95e4aa3051cd48fe29654e407` 重新 freeze；
    LPS5/LPS6 的 product-object oracle 已通过，但 daemon-integrated attack
    causality 未接受。当前第一个未完成 sub-goal 是该 LPS5 closure，之后才可进入
    final cross-layer `LINUX_PLATFORM_FREEZE` acceptance。

如果用户修改了这里的 Goal，按新的 Goal 执行；不要继续旧 Goal。
