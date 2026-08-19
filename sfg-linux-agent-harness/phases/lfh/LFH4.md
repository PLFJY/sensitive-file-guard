# LFH4 — systemd FD Store Crash-Continuity Experiment

## Goal

验证 systemd fdstore 能否保留 fanotify group，缩小/消除 daemon crash 的 fail-open window。

**这是 experiment。结果允许 ACCEPTED / PARTIAL / REJECTED。**

不要预设成功。

## Background invariant

fanotify permission event：

```text
queued unread
→ read by listener
→ moves to internal permission-wait list
→ response written OR fanotify group fd fully closed
```

systemd fdstore可以持有一个 duplicate fd并在 service restart 后传回。

问题必须拆成：

```text
A. crash before event read
B. crash after event read but before response
```

## Experiment A — unread event

1. 创建 fanotify group/marks；
2. 上传 group fd 至 systemd fdstore；
3. pause guardd before reading；
4. unknown process open protected synthetic file → should block；
5. SIGKILL guardd；
6. systemd duplicate仍在；
7. 验证 opener 是否持续 block；
8. restart guardd；
9. restore exact stored group；
10. process queued event；
11. DENY；
12. Guard attribution。

PASS 才能声称：

```text
unread queued-event crash continuity VERIFIED
```

## Experiment B — already-read pending permission

加入 test-only deterministic hook：

```text
CRASH_AFTER_READ_BEFORE_RESPONSE
```

流程：

```text
read permission event
→ confirm hook reached
→ SIGKILL
→ restart with stored group
```

验证：

- old opener结果；
- new daemon能否枚举/响应旧 waiting event；
- 是否永久 hang；
- 是否自动 allow；
- group是否可安全恢复。

如果没有可靠公开恢复机制：

```text
PARTIAL
```

不要逆向依赖 kernel private internals。

## Production adoption

只有 evidence 足够时再改 unit：

```ini
Type=notify
NotifyAccess=main
FileDescriptorStoreMax=1
FileDescriptorStorePreserve=restart
Restart=always
```

启动：

```text
receive fdstore group?
  yes → validate fanotify fd + mark state + generation
  no  → create + mark + store

engine ready
→ READY=1
```

若 restored group 状态无法验证，fail closed / recreate并标 continuity loss。

## Security notes

- clean `systemctl stop` 与 crash/restart lifecycle不同；
- fdstore preserve 设置不能让永久停用仍莫名阻塞 filesystem；
- uninstall必须清理 fdstore；
- corrupted/unrecognized stored fd必须拒绝使用。

## Acceptance

报告必须给一个明确 verdict：

```text
ACCEPTED
PARTIAL
REJECTED
```

`PARTIAL` 完全可以进入产品作为 hardening，但 formal crash continuity保持 REDUCED。

输出：

```text
reports/linux/lfh4-fdstore-continuity.md
```
