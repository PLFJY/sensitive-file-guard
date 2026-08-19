# LPS2 — Browser SecretAuthority Matrix

用 File Shield 的真实 protected ALLOW events记录：

```text
哪个 exact process 真正收到 Cookies/session/key material bytes
```

disposable profiles：

```text
Firefox
Chromium/Chrome
Zen if installed
```

记录：

```text
PID/pidfd
starttime
exe identity
argv/role
parent/ancestry
resource kind
```

不记录秘密。

产出 role/resource capability matrix：

```text
Main
Utility
Renderer
GPU
Extension
Other
```

只有证据证明会读 secret 的 role 才进入 Process Shield候选。

输出：

```text
reports/linux/lps2-authority-matrix.md
```
