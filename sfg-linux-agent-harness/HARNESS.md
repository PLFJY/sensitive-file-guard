# Sensitive File Guard — Linux Agent Harness

> **这是唯一入口文件。**
>
> Agent：从这里进入，不要等待用户逐阶段继续发 prompt。读取 `GOAL.md` 后，持续执行 **inspect → design → implement → test → privileged acceptance → adversarial review → fix → re-test → report**，直到 Goal 的全部 acceptance gates 达成，或者出现真正无法在当前主机解决的外部 blocker。

---

## 0. 启动协议

1. 阅读：
   - `GOAL.md`
   - `CONTRACT.md`
   - `ACCEPTANCE.md`
   - `goals/<GOAL>.md`
   - 该 Goal 引用的 phase 文件。
2. 在仓库根目录执行并记录：
   ```bash
   git status --short
   git rev-parse HEAD
   git log -1 --oneline
   uname -a
   ```
3. **不得假设 prompt 中写的历史 commit 仍是 HEAD。** 当前代码是唯一事实来源。
4. 检查现有实现、测试、文档和历史报告；不要基于旧计划直接重写已经实现的东西。
5. 创建/更新：
   ```text
   reports/linux/harness-state.md
   ```
   使用 `templates/STATE.md` 的结构。
6. 然后进入执行循环。**不要只给计划然后停下。**

---

## 1. Goal 执行循环

对 Goal 中每个未完成 gate：

```text
INSPECT
  ↓
明确 invariant / attacker path / compatibility expectation
  ↓
先写可复现 test 或 acceptance oracle（能先证明旧问题时优先）
  ↓
IMPLEMENT
  ↓
fmt / clippy / unit tests
  ↓
需要内核权限？
  ├─ no  → local integration
  └─ yes → 通过 polkit/pkexec 弹系统授权框
  ↓
LIVE ACCEPTANCE
  ↓
ADVERSARIAL SELF-REVIEW
  ↓
发现 blocker?
  ├─ yes → 创建 sub-goal，修复，重新完整验证
  └─ no
  ↓
更新 report + harness-state
  ↓
进入下一个 gate
```

不得因为“代码看起来合理”“unit test 绿”“实现完成”就跳过 privileged/live acceptance。

---

## 2. 权限规则：需要密码时必须走 polkit

用户明确允许在系统授权弹窗中输入管理员密码。

### 必须遵守

- **不要向用户索要密码。**
- **不要要求用户把密码复制到聊天、stdin、环境变量或文件。**
- **禁止 `sudo -S`、`echo password | sudo`、expect 自动输密码等。**
- 不要因为需要 root 就停下来让用户手工运行；优先自己发起 polkit 认证。
- 若项目已有受限 privileged helper / `guardctl privileged ...` 能完成目标，优先使用它。
- 否则使用 `pkexec` 触发桌面 polkit authentication agent。

推荐模式：

```bash
# 先以普通用户构建
cargo build --workspace --all-features

# root harness 不应重新编译；让脚本消费已构建 artifact
pkexec /usr/bin/bash scripts/linux/<root-test>.sh
```

若旧脚本强制 `cargo build`，优先改造成：

```text
普通用户 build
        ↓
root script --skip-build / 显式 binary path
```

避免以 root 编译用户仓库。

如果确实必须给 root command 一个工具路径，传**精确绝对路径**，不要把任意 user-writable PATH 整体送给 root。

### polkit 不可用时

只有以下情况才能标记 `BLOCKED`：

- `pkexec` 不存在；
- 当前 session 没有可用 polkit authentication agent；
- 系统策略明确拒绝；
- 用户在弹窗中主动取消。

必须记录**精确命令 + 精确错误**。继续完成所有不依赖该 blocker 的工作，但 Goal 中要求的 LIVE gate 仍不得声明 PASS。

---

## 3. 不许“降智收工”

以下都不是完成条件：

```text
“代码已实现”
“cargo test passed”
“看起来没问题”
“理论上 fanotify 会拦”
“EPERM 所以一定是 Guard”
“daemon 重启后最终又能保护”
```

对于安全断言，必须证明 **Guard causality**。

例如：

```text
probe open -> EPERM
```

只能证明 syscall 失败。

正式 `PREVENTED` 至少需要：

```text
kernel-visible operation failed
+
Guard-side exact event/audit/counter attribution
+
synthetic canary 没被读取
```

如果 OS 自己的 Yama / DAC / AppArmor / SELinux / sandbox 已经会拒绝攻击，acceptance harness 必须先构造 **Guard OFF 时能成功、Guard ON 时被 Guard 拒绝** 的 baseline，否则不能把 OS-default denial 算成 Guard 的功劳。

---

## 4. 安全范围

项目目标：

> 在 protected browser auth/session data 与 SSH private key 被成功打开/读取之前，阻止未经授权的本地进程。

它不是：

- antivirus
- malware classifier
- EDR
- network DLP
- root/kernel compromise defense

自动化测试：

- 只允许 synthetic browser profiles；
- 只允许 ephemeral SSH keys；
- 不读取真实 cookies/passwords/session tokens/SSH private keys；
- 不进行网络 exfiltration；
- audit/log 不得包含 secret bytes。

---

## 5. 保持 KISS

禁止为了“理论完美”无证据地：

- 写 DKMS/kernel module；
- 引入微服务；
- 加 risk score/ML；
- 把全部 browser helpers 都变成 SecretAuthority；
- 在每个 filesystem open 上递归扫描完整 browser profile；
- 因 Process Shield 不支持而关闭 File Shield；
- 把 Linux 强行做成 macOS Endpoint Security 的结构镜像。

先证明真实问题，再加最窄机制。

---

## 6. Phase 完成后的强制自审

每个 phase 完成前回答：

### Attacker view
1. 同 UID unknown process 怎么绕？
2. PID reuse 怎么绕？
3. executable path replacement 怎么绕？
4. symlink / hardlink / rename / inode reuse 怎么绕？
5. stale lease / pre-existing descendant 怎么绕？
6. daemon crash / queue overflow 怎么绕？
7. 哪个 security claim 其实只是 OS default behavior？

### Compatibility view
1. Chrome/Chromium/Firefox/Zen 哪些正常行为会被误拒？
2. SQLite WAL/SHM、Session Storage、Local Storage、IndexedDB 是否被误分类？
3. ordinary unrelated filesystem open 的热路径有没有明显恶化？
4. systemd/polkit/SSH agent flow 有没有被破坏？

### Truthfulness view
把每个结论归类为：
`PREVENTED / DETECTED+CONTAINED / DETECTED / REDUCED / NOT ACCEPTED / BLOCKED`

如果证据不足，降级结论，不准升级措辞。

---

## 7. Git 工作规则

- 禁止 `git reset --hard`。
- 禁止 `git clean -fd`。
- 禁止丢弃或覆盖用户已有改动。
- 开始前检查 dirty tree，并区分：
  - pre-existing user changes
  - Agent changes
- 不得为了让测试绿而回滚用户工作。
- 每个 phase 尽量保持独立、可 review。
- 只有在没有混入用户未提交改动时，才为 Agent 自己的 phase 创建 commit。
- **不要 push / force-push / 开 PR，除非 Goal 明确要求。**

---

## 8. 最终收官

只有 Goal 文件中所有 acceptance gates 都 PASS，才能输出：

```text
GOAL COMPLETE
```

最终必须：

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
git diff --check
```

并运行 Goal 要求的全部 root/live acceptance scripts。

最后生成：

```text
reports/linux/<goal>-final.md
```

内容必须区分：

- VERIFIED FACT
- LIVE VERIFIED
- INFERENCE
- RESIDUAL LIMITATION
- NOT ACCEPTED
- BLOCKED

若任何正式 gate 被 BLOCKED：

```text
GOAL NOT COMPLETE — BLOCKED
```

不要用“基本完成”替代。
