# LFH3 — Protection Continuity

## Goal

把：

```text
“现在又健康”
```

和：

```text
“从启动以来保护从未出现不可验证间隙”
```

分开。

## State

实现类似：

```rust
enum ProtectionContinuity {
    Intact { generation: u64 },
    Lost {
        generation: u64,
        reason: ContinuityLossReason,
        since: ...,
    },
}
```

至少 reason：

```text
FanotifyQueueOverflow
FanotifyGroupRecreated
RequiredMarkLoss
FilesystemLifecycleLoss
UnrecoverableClassifierFailure
```

是否把 planned clean restart 当 loss，由 LFH4 fdstore evidence 决定。

## On FAN_Q_OVERFLOW

必须：

```text
set continuity Lost
revoke live Migration leases
revoke live SSH read leases
deny/drop pending Migration confirmations
deny/drop pending SSH confirmations
invalidate recent approval/grace state
trigger object/resource rescan
audit continuity_loss
```

之后 future events 可继续 enforce，但 overall security posture：

```text
REDUCED
```

直到明确的 operator reset/restart generation policy；不要偷偷清 sticky loss。

## Mark health

当前 filesystem mark count 检测继续保留。

若 required mark 消失：

```text
current File Shield != ACTIVE
continuity Lost
```

恢复 mark 后：

```text
current enforcement may ACTIVE
continuity remains Lost
```

## Root harness

新增：

```text
scripts/linux/test-continuity-root.sh
```

要有真实 overflow stress 尝试。

如果无法 deterministic 触发 kernel queue overflow：

- unit/integration 测 state transition；
- root harness 做最大可行 stress；
- live overflow gate标 `BLOCKED`, 不伪造 PASS；
- 可研究 test-only injection，但必须清楚标为 state-machine test，不是 kernel overflow proof。

## Acceptance

- overflow 不再只是 log+continue；
- all authority spanning continuity loss is revoked；
- status can represent current active + historical lost；
- docs 不再写“overflow dropped event 默认 deny”这类内核做不到的结论。

输出：

```text
reports/linux/lfh3-continuity.md
```
