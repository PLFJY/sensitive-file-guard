# Linux Harness Engineering Contract

## A. 平台边界

Linux authoritative File Shield backend：

```text
root guardd
  + fanotify permission events
  + strict-filesystem
  + systemd
  + polkit
```

`guard-core` 保持 portable policy/domain。
Linux OS facts 放在 `platform-linux` / Linux composition 层。

不要把：

```text
fanotify fd
pidfd
file handle
BPF map fd
/proc parsing
```

泄漏进 portable domain model，除非有真正跨平台语义。

---

## B. 两个独立 Shield

```text
File Shield
Process Shield
```

必须独立：

- File Shield 可以 ACTIVE，而 Process Shield UNSUPPORTED/DISABLED/REDUCED。
- Process Shield failure 不得自动关闭已经健康的 fanotify File Shield。
- UI/IPC 分别报告 health。
- overall health 可以取更保守状态，但不能掩盖哪层出问题。

---

## C. fanotify 机制边界

### Permission group

主 enforcement group：

```text
FAN_CLASS_CONTENT
FAN_OPEN_PERM
narrow FAN_ACCESS_PERM for SSH
```

可 feature-probe：

```text
FAN_REPORT_PIDFD
```

### FID 限制

**不要把 `FAN_REPORT_FID` 加进 `FAN_CLASS_CONTENT` permission group。**

Linux UAPI 明确禁止：

```text
FAN_CLASS_CONTENT | FAN_REPORT_FID
→ EINVAL
```

如果 LFH2 证明需要 directory-entry lifecycle/FID topology：

```text
Permission group:
FAN_CLASS_CONTENT + FAN_REPORT_PIDFD

Topology group:
FAN_CLASS_NOTIF
+ FAN_REPORT_FID / FAN_REPORT_DFID_NAME / FAN_REPORT_TARGET_FID
```

必须是两个 group，且要单独分析跨 group ordering/race；不要假设两个队列存在全局顺序。

对于已经拿到 event fd 的对象，可优先研究：

```c
name_to_handle_at(event_fd, "", ..., AT_EMPTY_PATH)
```

它可对任意 open fd 获取 filesystem file handle（filesystem 支持时）。

实现前再次查本机 kernel headers / man page，不凭记忆写 UAPI 常量。

---

## D. Process identity

安全身份不能等于：

```text
PID
basename
same UID
pathname only
```

目标：

```text
fanotify event
  ↓
PID + pidfd when available
  ↓
starttime
  ↓
actual executed image object
  ↓
dev + ino + owner + mode
  ↓
digest when user-writable enrollment requires
```

`/proc/<pid>/exe` 的 pathname 只作为显示/分类线索。

对于 `EnrolledUserWritable`，hash/security metadata 必须来自**实际正在执行的对象**，不能：

```text
readlink /proc/PID/exe
→ reopen pathname
→ hash pathname's current file
```

因为 pathname 可能已被替换。

---

## E. Resource identity

至少区分：

### Stable critical object
如 SSH private key / concrete Cookies/Login Data：

```text
path classification
+ dev/ino
+ file handle if supported/needed
```

### Dynamic browser object
如：

```text
Sessions
Session Storage
Local Storage
IndexedDB
WAL/SHM/journal variants
```

不能永久只靠 `(dev, ino)`，因为 inode reuse 会制造 false positive。

LFH2 必须同时解决：

```text
rename/move alias
AND
inode reuse
```

而不是修一边炸另一边。

---

## F. Human authorization

只有明确 typed flow 可以等待 human：

```text
Migration confirmation
SSH protected-read confirmation
```

必须有：

```text
bounded deadline
bounded queue
exact process revalidation
process exit handling
identity change handling
drop => deny
timeout => deny
queue pressure => deny
```

普通 deterministic deny 不等待 UI：

```text
DENY first
audit second
notify async
```

---

## G. Lease authority

默认：

```text
Exact process instance
```

不是：

```text
same UID
same browser
same executable family
entire descendant tree
```

Migration 若真实浏览器兼容性证明必须使用 helper：

```text
post-bind observed exact descendant
```

只能在实际 authority matrix 证明必要后加入。

SSH read：

```text
EXACT READER ONLY
```

SSH load：

```text
EXACT ssh-add invocation
ONE SHOT
SHORT TTL
```

---

## H. Continuity

必须区分：

```text
current enforcement health
vs
historical protection continuity
```

例如 fanotify queue overflow 后，marks 现在仍健康：

```text
File Shield current: ACTIVE
Continuity: LOST
Overall: REDUCED
```

不得因为恢复正常就把 continuity loss 擦掉。

所有 continuity-breaking transition 必须考虑：

```text
live migration leases
live SSH read leases
pending authorization
recent approval grace
object identity cache
```

---

## I. 安全结论词典

### PREVENTED
请求在 secret/control 成功前被 Guard authoritative mechanism 拒绝，且有 Guard attribution。

### DETECTED + CONTAINED
操作可能已经发生，但 Guard 有强证据，并在后续 secret delivery 前 fail-closed。

### DETECTED
只观测到；没有证明阻止或 containment。

### REDUCED
核心能力仍部分有效，但某安全 invariant / continuity / visibility 不完整。

### NOT ACCEPTED
设计/语义尚不足以形成安全承诺。

### BLOCKED
需要的 acceptance 无法在当前环境执行；不是 FAIL，也不是 PASS。
