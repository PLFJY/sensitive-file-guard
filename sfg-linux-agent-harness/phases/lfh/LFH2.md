# LFH2 — Dynamic Protected Object Identity

## Goal

同时关闭：

```text
dynamic sensitive object rename/move alias
```

与：

```text
inode reuse false positive
```

不能用一个 bug 换另一个。

## Step 1 — 先证明当前 gap

先写 synthetic root harness，至少测试：

```text
Local Storage / Session-like protected dynamic object
→ browser/trusted creator opens it under protected namespace
→ rename outside profile
→ unknown reader opens alias
```

先在未修代码上确认结果。

若攻击已被现有机制挡住：

```text
不要假设 gap 存在
→ 找出真实阻断机制
→ 更新本 phase 设计
```

## Step 2 — Object handle

优先尝试从已有 event fd：

```c
name_to_handle_at(event_fd, "", handle, &mount_id, AT_EMPTY_PATH)
```

保存 opaque：

```text
mount/filesystem identity
handle_type
handle_bytes
handle payload
```

不可把 opaque handle 解读成 inode number。

动态 index 可以用：

```text
(dev, ino) → small candidate list of protected object handles
```

fast path先 `(dev, ino)`，只有 candidate 才计算/比较 handle。

### Stale

若 object handle stale / no longer resolves：

```text
drop stale mapping
do not false-positive unrelated reused inode
```

## Step 3 — Rename-in / never-opened-before case

专门测试：

```text
unprotected temp object
→ rename/move into sensitive protected name
→ immediately rename outside
→ unknown open
```

如果 permission group 在对象成为 protected 后从未看到一次 protected-path open，则仅靠 event-fd handle learning 可能不够。

若 live harness 证明存在 gap：

### 允许的最窄方案

新增第二个 topology group：

```text
FAN_CLASS_NOTIF
+ FID/DFID_NAME/TARGET_FID feature set
```

追踪 protected namespace 的 create/move/rename lifecycle。

**禁止：**

```text
FAN_CLASS_CONTENT + FAN_REPORT_FID
```

该组合 UAPI 不允许。

### Ordering

permission group 与 topology group 是不同队列。

不要假设：

```text
topology event always processed before later permission event
```

必须设计 race-safe fallback，例如 permission hot path 在 ambiguous `(dev, ino)`/path transition 时同步验证 protected namespace/object handle，而不是只相信 topology cache。

## Step 4 — Filesystem capability

对每个 protected filesystem probe object-handle support。

结果：

```text
supported
unsupported
permission denied
stale/unstable
```

unsupported 时：

- stable concrete secrets仍可按已有 identity保护；
- dynamic rename guarantee不能声称 Strong；
- overall File Shield按定义降级 `REDUCED`，并给 exact reason。

## Root harness

新增：

```text
scripts/linux/test-object-identity-root.sh
```

覆盖：

```text
symlink
hardlink
rename protected concrete object
rename protected dynamic object out
rename temp in → immediately out
delete/recreate
WAL/SHM cycles
inode reuse（能 deterministic 则 live；否则 fixture/unit + honest limitation）
unicode path
nlink > 1
```

## Performance

特别 benchmark：

```text
ordinary nlink=1 unrelated open
dynamic candidate open
hardlink alias scan/flood
```

禁止每个普通 open 递归扫 profile。

## Acceptance

- proven rename-out gap closed；
- no known inode-reuse false positive；
- unsupported FS truthfully REDUCED；
- ordinary fast path within budget；
- root adversarial harness PASS。

输出：

```text
reports/linux/lfh2-object-identity.md
```
