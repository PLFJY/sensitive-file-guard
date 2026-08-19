# LFH6 — Native Browser Compatibility + Adversarial Acceptance

## Goal

用真实安装的 browser executable + disposable synthetic profile 验证日用兼容性。

绝不使用真实 profile。

## Browser set

自动探测：

```text
Firefox
Chromium
Google Chrome
Zen
```

不存在的标 `NOT INSTALLED`，不是 FAIL。

至少要有：

```text
1 Gecko-family
1 Chromium-family
```

才能完成 formal cross-family acceptance。

## Workload

每个 browser：

```text
launch disposable profile
startup settle
new tabs
local/harmless page
profile writes
Cookies DB
saved-login metadata fixture
session state
Local Storage
IndexedDB
browser restart
DB replacement/compaction
harmless extension fixture if existing
```

同时 background unknown synthetic probe持续尝试：

```text
Cookies
Login Data/logins.json
session store
Local Storage/IndexedDB
```

合法 browser正常使用；
unknown每次均 denied。

## Observe

必须抓：

```text
fanotify_overflows
classifier_failures
continuity
unexpected DENY
allowed protected events
PIDFD failures
object-handle fallback
audit_dropped
```

每个 unexpected DENY都要解释；不能用 allowlist 抹平。

## Adversarial suite

整合/复用：

```text
renamed fake browser exe
symlink
hardlink
rename-out
relative path
unicode
WAL/SHM
child process
burst
mmap-after-denied-open
PID reuse fixtures
exe replacement
stale lease
continuity loss
```

## Performance

跑 LFH0 同一 benchmark。

若 regression 超 budget：

- profile before optimize；
- 优化 fast path；
- 不能缩安全覆盖来“过 benchmark”。

## Acceptance

```text
0 unexplained protected deny
0 overflow
0 classifier failure
continuity intact
unknown probes 100% denied
browser legal workload pass
performance within budget
```

输出：

```text
reports/linux/lfh6-live-acceptance.md
```
