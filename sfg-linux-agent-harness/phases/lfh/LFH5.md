# LFH5 — Migration + SSH Authority Tightening

## Goal

消灭“tree membership = SecretAuthority”这种过宽 lease。

## Migration

### First policy

默认改成：

```text
EXACT READER INSTANCE
```

绑定：

```text
PID/pidfd
starttime
executed image identity
UID
BrowserId
lease generation/continuity generation
```

manual executable-wide armed lease 若仍保留，下一次真正 reader出现时必须 bind exact process，再授权。

### Authority matrix

使用 disposable profiles记录真实 migration reader：

```text
Chrome/Chromium → Firefox
Firefox → Chromium/Chrome
same-family import where supported
```

记录：

```text
exact process
exe
argv role
parent
root
resource kind
```

不记录 secret。

如果实际 helper必须读：

```text
只允许 post-bind observed exact descendant
```

不能恢复：

```text
any descendant in tree
```

pre-existing descendant在 lease 创建前已存在时，默认不能靠 first read 自动升级成干净 authority，除非有单独 proven invariant。

### Read-only wording

Linux migration不能凭 fanotify `FAN_OPEN_PERM` 宣称：

```text
read_only_guaranteed=true
```

IPC/UI/audit必须 truthfully false/unknown。

## SSH read

必须：

```text
exact reader only
short TTL
continuity generation bound
```

## SSH load

保持/强化：

```text
trusted system ssh-add
stopped child validation
exact invocation
verified ssh-agent peer/socket identity
one-shot lease
revoke on exit/IPC delivery failure
```

## Tests

- wrong UID；
- PID reuse；
- stale generation；
- target exits before approval；
- helper descendant not explicitly bound；
- old lease after continuity loss；
- ssh-add path replacement；
- wrong ssh-agent listener；
- lease response not delivered to client → revoke。

## Acceptance

- no whole-tree authority；
- migration real browser flow仍可用；
- SSH flow real ephemeral key harness pass；
- all lease authority dies on continuity loss；
- no read-only overclaim。

输出：

```text
reports/linux/lfh5-authority.md
```
