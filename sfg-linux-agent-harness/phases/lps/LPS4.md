# LPS4 — Browser Daily Compatibility

Process Shield ON，用 disposable browser profile跑 LFH6 workload。

必须记录：

```text
all process-control denies
requester identity
target role
normal browser behavior
crash handlers
debugger-like system relationships
```

任何 allow exception：

```text
必须有 live compatibility evidence
必须窄到 exact relationship/access kind
```

不允许因“浏览器自己”整体放行。

目标：

```text
0 unexplained deny
0 browser false-compromise equivalent
File Shield仍全部 green
```

输出：

```text
reports/linux/lps4-browser-compat.md
```
