# LFH1 — PIDFD + Actual Executed Image Identity

## Goal

把 process authority 从：

```text
PID + /proc pathname reopen
```

升级为：

```text
PID
+ fanotify-reported pidfd when supported
+ starttime cross-check
+ actual executed image object identity
```

## A. FAN_REPORT_PIDFD

### Requirements

主 permission group继续：

```text
FAN_CLASS_CONTENT
```

feature-probe：

```text
FAN_REPORT_PIDFD
```

解析：

```text
fanotify_event_info_header
fanotify_event_info_pidfd
```

信息记录顺序不能假设固定；遍历 event 的 info records 按 `info_type` 找 PIDFD。

不要启用 `FAN_REPORT_TID` 与 PIDFD 的不兼容组合。

### Ownership

pidfd 必须 RAII `OwnedFd` / 明确 close，不能泄漏。

### Failure semantics

```text
accepted kernel + event lacks usable pidfd unexpectedly
→ protected candidate fail closed / health degrade according to exact reason

legacy unsupported kernel
→ fallback PID+starttime
→ REDUCED(reason=legacy_process_identity)
```

先明确 product support policy，再实现，不要 silent fallback while saying Strong.

## B. Actual executed image

禁止：

```text
readlink /proc/PID/exe
→ stat/hash returned pathname
```

建立安全身份。

应 pin/inspect 实际 `/proc/PID/exe` object：

```text
open /proc/PID/exe
fstat actual fd
owner/mode
dev/ino
hash actual fd if enrollment requires
```

pathname 只用于 display/browser registry mapping，且需要与 executed-object enrollment relationship 明确。

### Enrolled user-writable executable

测试：

1. enroll executable A；
2. process starts executing A；
3. pathname A 被替换为 B；
4. resolver必须继续识别 running A 的实际 image，不能把 B 当成它；
5. 新启动 B 不继承 A trust。

测试 deleted executable：

```text
process running
path unlinked/replaced
/proc/PID/exe -> "... (deleted)"
```

不能因为字符串 suffix/canonicalize failure 就错误 allow。

## C. PID reuse

构造 deterministic test：

```text
old process identity cached
old exits
new process occupies same numeric PID if test infrastructure可控
```

如果无法 deterministic PID reuse，至少通过 synthetic resolver fixtures/unit tests 验证 starttime/pidfd mismatch fail closed；live test 标明限制。

## Acceptance

- accepted kernel path uses pidfd；
- event pidfd closed exactly once；
- PIDFD info parser has malformed/stacked record tests；
- actual executed image TOCTOU test pass；
- user-writable replacement test pass；
- legacy path truthfully REDUCED；
- benchmark no material regression。

输出：

```text
reports/linux/lfh1-process-identity.md
```
