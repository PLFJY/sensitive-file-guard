# Harness Goal Selection

当前 Goal：

```text
LINUX_PRODUCTIZATION_HARDENING
```

Agent 只从 `HARNESS.md` 进入，然后读取：

```text
goals/LINUX_PRODUCTIZATION_HARDENING.md
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
  - 在 `9673f6fcd6380447af307b8f7ecc13679d5fbc8d` 已完成 File Shield
    23/23 one-shot + 1/1 systemd mandatory gates 和 Process Shield 5/5
    manifest（含 daemon-integrated attack causality）。平台 freeze 对文档化的
    REDUCED capability scope 已接受；详见
    `reports/linux/linux-platform-freeze-final.md`。

- `LINUX_PRODUCTIZATION_HARDENING`
  - 前提：Linux Platform Freeze 已完成且其 evidence 不回写。
  - 完成正式 release artifact、用户化安全状态、Firefox enrollment/audit
    体验，以及 browser expansion 与 macOS backend 的 architecture contract。
  - runtime/security behavior 变更必须单独做 freeze-impact 评估；不得扩大
    unsupported scope，也不得把 Process Shield 宣传为完整 EDR。

如果用户修改了这里的 Goal，按新的 Goal 执行；不要继续旧 Goal。
