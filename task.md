我把首个大提交的核心路径、README、Policy、fanotify、IPC、SSH、systemd 和最终验收报告都过了一遍。**整体架构确实已经成型了，但我现在不建议拿真实 Cookie / SSH 私钥直接上。** 有几个 AI 很容易“单测全绿但安全语义其实没成立”的坑。

仓库目前最新提交是 `3046976f`，一次性实现 Linux V1 的 15 个阶段；workspace 也基本严格按我们定的结构落下来了：`guard-core / guard-browser / guard-ssh / guard-ipc / guard-audit / platform-linux`，再加 `guardd / guardctl / guard-tui / guard-test-probe`。

## 总体评价

我会把当前状态定成：

> **Linux V1 implementation-complete Alpha，但还没有 security-accepted。**

好的地方很多：`FAN_OPEN_PERM` 真的是在 open 成功以前做决策；unknown identity 默认 deny；PID + start time + exe dev/inode 做稳定身份；critical files 还有 inode index，hardlink/symlink 思路正确；Audit 是 bounded channel 异步写 SQLite；Policy 也确实没有被 AI 搞成什么 `IResourcePolicyFactoryManagerStrategy`。😂

但我现在看到这些需要修：

| 优先级       | 问题                                                           | 影响                        |
| --------- | ------------------------------------------------------------ | ------------------------- |
| **P0**    | `SshLoadLease` 身份由 IPC 客户端自己声明                               | 可绕过 SSH 私钥保护              |
| **P0/P1** | Cookie 等关键文件被删除重建后，新 inode 不会自动重新保护                          | 浏览器运行一段时间后可能出现保护空洞        |
| **P1**    | Linux `MigrationLease.read_only` 实际无法按当前方法保证                 | “只读迁移”名不副实                |
| **P1**    | MigrationLease 是 10 分钟 executable-wide，不是真正绑定一次 process tree | 授权范围比设计目标大                |
| **P1**    | systemd 安装后 socket 是 `0660 root:root`                        | 普通用户实际上用不了 `guardctl`/TUI |
| **P1**    | root service 直接跑 `notify-send`                               | 实际桌面通知大概率发不到用户 session    |
| **P1**    | `ssh protect` 允许任意 IPC peer 请求保护任意“名字不像公钥”的普通文件              | 修好 socket 后会形成同机 DoS 接口   |
| **P2**    | Final report 把未实际运行的 root tests 写成 PASS                      | 验收状态有点自欺欺人 😭             |

### 1. 最严重的：`SshLoadLease` 有真实的授权漏洞

现在协议是客户端发送：

```text
ssh_add_exe
ssh_add_dev
ssh_add_ino
start_time
```

daemon 然后直接：

```rust
let target = StableIdentity {
    exe: PathBuf::from(&ssh_add_exe),
    start_time,
    dev: ssh_add_dev,
    ino: ssh_add_ino,
};
```

再生成 `SshLoadLease`。

问题是：

> **这些身份数据全是客户端说的，daemon 没验证。**

攻击程序理论上可以说：

```text
你好，我是 ssh-add：

exe=/path/to/myself
dev=<自己的>
ino=<自己的>
start_time=<自己的>
```

然后：

```text
Migration/SSH IPC
        ↓
guardd 给它 SshLoadLease
        ↓
恶意程序 open(id_ed25519)
        ↓
StableIdentity 刚好匹配
        ↓
ALLOW_BY_LEASE
```

等于：

> **“不许你读私钥，除非你自己告诉我你就是被授权的进程。”**

🤣

而且仅仅修成“daemon 验证这个 PID 真的是 `/usr/bin/ssh-add`”还不完全够。因为恶意程序还可以想办法让真的 `ssh-add` 把 key 加到攻击者控制的 agent socket。

我建议最终方案改成：

```text
User
 ↓
guardctl ssh load
 ↓
明确的 User Presence / polkit authorization
 ↓
guardd 自己创建/控制 ssh-add invocation
 ↓
guardd 从 /proc 验证 child PID + start_time + exe dev/ino
 ↓
one-shot lease
 ↓
SIGCONT
 ↓
ssh-add reads once
 ↓
lease dies
```

**客户端不能提供 security identity。security identity 必须由 guardd 自己观察。**

---

## 2. Browser Protection 还有一个比“递归 race”更大的洞

现在关键 Cookie 文件是在 daemon 启动时发现，然后直接给 inode 上 fanotify mark。

这对于：

```text
rename Cookies Cookies.old
```

其实挺好，inode mark 还跟着对象。

但是：

```text
unlink Cookies
create new Cookies
```

或者数据库更新机制做：

```text
Cookies.tmp
→ atomic replace
→ Cookies
```

**新 Cookies 是新 inode。**

原来的 fanotify mark 不会自动继承。

Linux fanotify 的 inode mark 跟的是 filesystem object；对象删除后 mark 也没了。([man7.org][1])

目前代码也没有看到：

```text
FAN_CREATE
FAN_MOVED_TO
FAN_DELETE_SELF
FAN_MOVE_SELF
```

之类的长期 topology watcher。

而 `mark_trees()` 只是：

```rust
startup:
    recursively walk directories
    mark existing directories
```

之后新目录并没有后台重新 mark。

所以报告里写的：

> “new nested directory race”

其实还说轻了。

当前更准确的是：

> **新目录不是“race 一小会”，而是如果没有重扫，它可以一直没 mark，直到 guardd 重启。**

同理：

* 新 Chrome Profile
* 新 Firefox Profile
* 新建 IndexedDB 子目录
* 被重建的 `Cookies`
* 启动以后才出现的 `Cookies-wal`
* 启动以后才创建的 Session DB

都需要考虑。

### 这个得优先修

有两条路。

**V1 Conservative Mode：**

```text
critical file parents
        ↓
topology watcher
        ↓
CREATE / MOVED_TO / DELETE / MOVE
        ↓
rediscover resource
        ↓
immediately FAN_OPEN_PERM mark new inode
```

仍然承认很小的 watcher → mark race。

**V1 Strict Mode：**

直接用 mount/filesystem 范围进行 permission monitoring，然后 userspace 根据路径/inode 判断是不是 ProtectedResource。fanotify 文档本来也明确说，对完整目录树而言，单纯 directory marks 不递归；要完整覆盖应使用 mount/filesystem scope。

我更倾向：

> **普通模式 topology watcher；Strict Mode `FAN_MARK_FILESYSTEM`。**

然后 benchmark。

---

## 3. `read_only MigrationLease` 目前其实是假的

这个特别典型：**Policy 单测是对的，OS 给你的信息却不是你以为的信息。**

你现在：

```rust
fd_is_writable(event_fd)
```

通过：

```text
fcntl(F_GETFL)
```

判断原调用是不是：

```text
O_RDONLY
O_WRONLY
O_RDWR
```

然后给 Policy：

```rust
AccessOperation::Open / Write
```

但代码自己的注释其实已经意识到问题了。

关键在于 `fanotify_init()` 的第二个参数 `event_f_flags`，决定的就是 **fanotify 给监听器生成的 event fd 自身的 flags**。官方 man page明确这么定义。

而你现在初始化就是：

```rust
fanotify_init(
    FAN_CLASS_CONTENT | FAN_CLOEXEC,
    O_RDONLY | O_LARGEFILE
)
```

所以：

```text
fcntl(event_fd, F_GETFL)
```

看见的基本就是：

> **guardd 自己要求 kernel 给它生成的 O_RDONLY event fd。**

不是：

> 原程序当初 `open(..., O_RDWR)` 的那个 flags。

因此目前：

```text
MigrationLease {
    read_only: true
}
```

只是 Policy Model 层 read-only。

**Linux enforcement layer 并不能靠这个方法保证它。**

我建议 Linux V1 先别装：

```text
read-only guaranteed
```

可以明确叫：

```text
MigrationAccessLease
```

等以后：

* 更现代的 fanotify 能力；
* LSM；
* 启动迁移进程时额外 filesystem sandbox；
* 或其他强制写保护

实现了再恢复真正的 `ReadOnly` invariant。

---

## 4. MigrationLease 也没有真正“绑定一次进程树”

我们原计划是：

```text
User approves

↓ first Firefox process

Lease:
    root_process = PID + start_time
    descendants = this tree
```

现在实际实现则是：

```text
target =
    canonical exe path
    +
    dev
    +
    inode
```

然后在 10 分钟内：

```text
opener exe == target
OR
some ancestor exe == target
```

就能使用 Lease。

也就是说：

> 不是“这次 Firefox 导入”。

而是：

> **“未来 10 分钟，任何这份 Firefox executable 发起的符合 source profile 的访问。”**

这个比我们的原始能力模型明显宽。

应该做：

```text
MigrationLeaseState

Armed {
    target_executable
}

        ↓ first valid browser launch/access

Bound {
    root: ProcessStableId,
    descendants...
}

        ↓ exit / timeout

Dead
```

这样才是真正的一次 Migration Capability。

---

# 5. IPC 现在出现了一个很搞笑的矛盾 😂

socket 创建后：

```rust
chmod 0660
```

但 daemon 是：

```text
User=root
Group=root
```

systemd `RuntimeDirectoryMode=0755`，也没有后续 `chgrp`。

installer 也没有创建类似：

```text
guardd
guardd-users
```

这样的 group。

结果安装完：

```text
/run/guardd/guardd.sock
rw-rw---- root root
```

普通用户：

```bash
guardctl status
```

大概率：

```text
Permission denied
```

而 README 又让普通用户直接：

```bash
guardctl status
guard-tui
```

这倒好修。

可以用 systemd `.socket`：

```text
SocketMode=0660
SocketGroup=guardd-users
```

或者 daemon bind 后主动：

```text
chown root:guardd-users
```

**但是！**

一旦这么修了，刚才那个 `SshLoadAuthorize` P0 就真正暴露给普通 same-user process 了。

所以正确顺序必须是：

```text
先修 Authorization Model
↓
再开放 IPC socket
```

不能反过来。

---

# 6. `SshProtect` 也不能给任何普通 IPC Peer

代码现在明确写：

> Any authenticated peer may add protection.

而 private key 判断其实只是：

```text
not *.pub
not known_hosts
not authorized_keys
not config
```

其他任何普通文件都接受。

所以理论上：

```text
guardctl ssh protect /home/user/some-important-file
```

甚至某些其它 regular file，都可能被登记成：

```text
SshPrivateKey
```

然后别人一读：

```text
DENY
```

这相当于一个 **root-powered denial primitive**。

现在 socket root:root 把这个 bug 阴差阳错挡住了；等 socket 修好就出来了。

这里至少要求：

```text
res.owner_uid == peer.uid
```

而我更建议：

> 修改 protection policy 的操作用 **polkit / explicit authorization**。

普通 read-only IPC 和 security mutation IPC 应该是两个权限等级。

---

# 7. Notification 现在实际上很可能看不到

`guardd` 是 system systemd service，root 身份。

然后代码直接：

```rust
Command::new("notify-send")
```

问题是 root system service 通常没有：

```text
DBUS_SESSION_BUS_ADDRESS
WAYLAND_DISPLAY
XDG_RUNTIME_DIR=/run/user/1000
```

所以最终大概率：

```text
notify-send failed
→ journal fallback
```

也就是安全防护是有效的，但用户看不到“xxx 读取 Cookie 已拦截”。

这里我反而建议增加一个极小的：

```text
guard-notify
```

用户 session service：

```text
guardd (root/security)
        ↓ authenticated IPC
guard-notify (user session)
        ↓
freedesktop notification
```

它**不是第二套 service policy engine**，只负责 UI presentation。

这也是未来 GTK GUI 最自然的落点。

---

# 8. 最终报告目前不能叫 COMPLETE

这点我比较在意。

Final report 顶部写：

> **Status: COMPLETE**

然后 Browser/SSH acceptance table 大量写：

```text
PASS | test-xxx-root.sh
```

但后面自己又明确写：

```text
privileged integration tests: BLOCKED
```

因为 agent 没有 `CAP_SYS_ADMIN`，根本没实际运行那些 root scripts。

仓库确实有 **7 个 privileged test scripts**；报告里也承认 agent 没法运行它们。

所以正确状态应该是：

```text
IMPLEMENTATION COMPLETE
NON-PRIVILEGED TESTS PASS
PRIVILEGED ACCEPTANCE PENDING
```

而不是：

```text
Linux V1 COMPLETE
```

这很重要，因为这类安全项目：

> **“unit Policy 认为 DENY”和“kernel 实际没有让 bytes 出去”完全是两回事。**

刚才那个 `read_only` bug就是完美例子。

---

# 我现在怎么评价这个 GLM 产物

它不是“AI 写了一坨不能看的 demo”。

反而整体组织得挺克制：Policy/Core、resource registry、inode classification、process start-time cache、SO_PEERCRED、bounded audit queue，这些方向都对，而且 Harness 约束明显确实生效了。

真正的问题已经进入**安全软件最危险的阶段**：

> 代码看起来完整、187 个测试绿、文档齐全，
> **但 OS primitive 的实际语义和 capability authorization 之间还有洞。**

所以我建议现在**先别让 GLM 加任何 Phase 16/17、eBPF、GUI、Windows**。

下一轮就叫：

# **Linux V1 Security Review / Hardening Pass 1**

重点只修：

```text
P0  SshLoadLease authoritative process verification + explicit user authorization
P0  dynamic Cookie/resource replacement protection
P1  remove/fix fake read-only MigrationLease guarantee
P1  armed → bound process-tree MigrationLease
P1  IPC permission architecture
P1  SshProtect authorization
P1  user-session notification helper
然后你亲自在 Arch 上跑 7 个 root integration suites
```

**这批修完，再拿那个真实的开源浏览器数据读取样本来狠狠干一次，才有资格说“Linux V1 真的出来了”。** 😈

[1]: https://man7.org/linux/man-pages/man7/fanotify.7.html "https://man7.org/linux/man-pages/man7/fanotify.7.html"
