# LFH0 — Truthfulness, Baseline, Capability Inventory

## Goal

不做大规模机制重写。先锁定：

- 当前真实行为；
- formal mode semantics；
- health/continuity truthfulness；
- benchmark；
- kernel/filesystem capability matrix。

## Tasks

### 1. Inspect current Linux code

重点：

```text
crates/platform-linux/
apps/guardd/
apps/guardctl/
deploy/guardd.service
scripts/*linux* / *root*
docs/Linux*
docs/安全模型.md
```

记录现有 `strict-filesystem` / `conservative` 行为。

### 2. Config mode must be explicit

当前/历史 config 若缺 `enforcement_mode`，不得静默落到 security-weaker mode。

期望：

```text
authoritative config missing mode
→ explicit migration/config error
→ not ACTIVE
```

可以保留 `Conservative` 兼容模式，但：

```text
Conservative
→ REDUCED
```

不能 formal ACTIVE。

增加 config schema/version（若当前已有版本机制则复用）。

### 3. Split health

至少可区分：

```text
FileShieldHealth
ContinuityHealth
AuditHealth
ProcessShieldHealth(optional/unsupported)
```

不要让：

```text
audit_dropped
```

与：

```text
filesystem mark lost
```

看起来是同一种问题。

### 4. Fix fanotify overflow wording

代码可以继续处理后续事件，但语义必须是：

```text
overflow observed
→ continuity lost
→ NOT “all dropped events denied”
```

LFH3 再做完整 revoke/recovery。

### 5. Capability inventory

探测并报告：

```text
fanotify permission events
FAN_MARK_FILESYSTEM
FAN_REPORT_PIDFD
name_to_handle_at(AT_EMPTY_PATH) on each protected filesystem
BPF LSM availability (inventory only)
```

不要按 distro 名称推断。

### 6. Baseline performance

复用/升级：

```text
benchmark-strict-filesystem-root.sh
```

记录：

```text
absent
conservative
strict

ordinary unprotected
browser allowed
protected denied
```

保存 raw evidence。

### 7. Baseline adversarial

运行现有：

```text
fanotify
browser enforcement
browser adversarial
bypass
SSH/agent compatibility
hardening
```

只把实际跑过的标 PASS。

## Acceptance

- config silent downgrade removed；
- Conservative cannot report formal ACTIVE；
- health dimensions visible；
- capability report exists；
- baseline benchmark captured；
- existing privileged suite results recorded；
- no new behavior regression。

输出：

```text
reports/linux/lfh0-baseline.md
```
