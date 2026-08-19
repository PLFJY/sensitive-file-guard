# LFH0 — Truthfulness, Baseline, Capability Inventory

## Baseline
- commit: 84a1bd133c78c41911d82dac5ffd1989a7722f5b
- kernel: 7.1.8-arch1-3 (x86_64, Arch Linux)
- fs: / ext4
- relevant capabilities: CAP_SYS_ADMIN on host root; fanotify permission events real; `name_to_handle_at` supported; BPF LSM `CONFIG_BPF_LSM=y` (inventory only); `FAN_REPORT_PIDFD` supported on this kernel
- installed browsers: firefox only (chromium/google-chrome/zen NOT installed)

## Threat / invariant
- 当前 Linux Alpha 的真实行为必须与文档一致；缺失 `enforcement_mode` 的配置不得静默降级；健康状态必须拆分维度；fanotify 溢出不得声称“全部 dropped 事件都被拒绝”。
- 现有 privileged suite 必须真实跑过才能标 PASS。

## Changes

### Config explicit mode + schema version (`crates/platform-linux/src/config.rs`)
- `EnforcementMode` 不再 `Default`；`enforcement_mode` 字段不再 `#[serde(default)]` → 缺失字段 = 显式 parse error，guardd 拒绝启动（绝不静默落到 Conservative）。
- 新增 `CONFIG_VERSION = 1` + `config_version` 字段（缺失默认 v1）；`validate()` 拒绝未来版本。
- `guardctl setup` 写入 `config_version`；`deploy/guardd-config.example.json` 同步。
- 单元测试：missing mode error / future version rejected / missing version defaults。

### Health split (`guard-ipc`, `guardd/src/ipc.rs`, `guardctl`)
- `StatusInfo.linux_health: Option<Box<LinuxHealthInfo>>`：`file_shield`（ACTIVE/REDUCED/NOT_ENFORCING）、`continuity`（INTACT/LOST + `continuity_reason`）、`audit`（HEALTHY/DEGRADED）、`process_shield`（UNSUPPORTED）。
- `handle_status` 分别计算各维度；Conservative 整体状态 = `REDUCED`，不能报告 formal `ACTIVE`。
- `guardctl status` 打印拆分维度。
- macOS 侧 `linux_health: None` 保持兼容。

### Overflow wording (`guardd/src/main.rs`)
- `FAN_Q_OVERFLOW` → “protection continuity LOST; dropped events were NOT denied by Guard (kernel dropped them unseen)”，不再是中性的 “events may have been dropped”。
- 两个运行模式（browser-enforcement + protect-test-file）统一措辞；`fanotify_overflows > 0` → continuity=LOST。

### Capability inventory (`crates/platform-linux/src/capability.rs` + `guardctl capabilities`)
- 运行时探测：fanotify permission events（`FAN_CLASS_CONTENT`）、`FAN_MARK_FILESYSTEM`、`FAN_REPORT_PIDFD`、`name_to_handle_at(AT_EMPTY_PATH)`（含 EOVERFLOW 两段式重试）、BPF LSM（BTF + kernel config，Unreadable 时明确标注）。
- 输出 JSON / 人类可读报告；不按 distro 推断；无权限时如实 EPERM。
- 本机（unprivileged）：`name_to_handle_at` supported；fanotify EPERM（无 CAP_SYS_ADMIN）；BPF LSM =y。

### Script harness 改造（HARNESS §2：root 不编译）
- 所有 `*root*.sh` + benchmark 增加 `SKIP_BUILD=1` 守卫：root harness 消费预构建 artifact。
- benchmark 的 `cargo_wall` 在 SKIP_BUILD 下跳过（root 不再编译用户仓库）。
- 修复测试基建与过期语义（见下）。

### Pre-existing P1 修复：SSH load one-shot lease
- 根因：`SshLoadLease.used` 在**第一个** `FAN_ACCESS_PERM` 事件即置位，而真实 `ssh-add` 一次 load 产生多次 permission event（open + reads）→ 第二次被降级 `RequireSshKeyConfirmation`，`guardctl ssh load` 完全不可用（test-ssh-load-root.sh 在 HEAD 上 4/6 FAIL，原二进制复现一致）。
- 修复：lease 增加 `pid` 字段；hot path 在 `AllowByLease` 后检查 `/proc/<pid>/stat` start_time —— 仅当精确进程退出或身份变化才置 `used`；agent-socket binding 在 load 全程保留。
- 单元测试改写为：同一活进程多次 event 全 allow、进程退出后 require confirmation、revoked 语义不变。
- 结果：`test-ssh-load-root.sh` 10/10 PASS；`test-ssh-enforcement-root.sh` 27/27 PASS。

### 过期测试期望修复（exact-reader 模型）
- 旧 behavioral 模型下直接 `cat`/`ssh-add` 读 SSH key 被期望 allowed；当前 exact-reader 模型要求 confirmation → headless harness 应 deny。更新 `test-bypass`、`test-agent-compat`、`test-ssh-broker-adversarial`、`test-ssh-load` 的原始读取断言为 denied-without-lease。
- `test-hardening-root.sh` 重写：fixture 写入通过 enrolled browser identity（`guard-test-probe write-file` 新命令），denial 断言用 unenrolled probe copy。
- `scripts/helpers/ipc-request.py` 协议版本 2→5（与 `guard-ipc::PROTOCOL_VERSION` 同步）—— 这导致所有用该 helper 的 root 测试在 HEAD 上失败。

## Tests

### Offline
- `cargo test --workspace --all-features`：全绿。
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`：0 error（修复了 guard-test-probe 的 pre-existing dead_code warning）。
- `cargo fmt --all -- --check`：通过。
- 新增单测：config missing mode / future version / health 语义 / capability parse / ssh lease 多事件与退出消费。

### Privileged / live（host，real fanotify，pre-capsule）
见 `evidence/lfh0-privileged-suite.txt` 摘要：
- fanotify 6/6、browser-enforcement 14/14、browser-adversarial 23/0/1、bypass 18/0/2、hardening PASS、agent-compat 9/9、strict-filesystem 25/1 OBSERVED、strict-concurrency PASS、topology-race PASS（gap measured）、ssh-enforcement 27/27、ssh-load 10/10。
- benchmark：absent/conservative/strict 全档位，0 overflow / 0 classifier failure（`evidence/lfh0-benchmark.txt`）。

### Capsule 环境（BLOCKED for fanotify）
- `sfg-test-capsule`（systemd-nspawn）默认 seccomp whitelist 显式排除 `fanotify_init`/`fanotify_mark`（systemd v261 `nspawn-seccomp.c`，经验证 syscall 300/301 在 capsule 内 EPERM，即使 CAP_SYS_ADMIN 存在；mount 正常）。
- 因此 fanotify File Shield live 测试**不能在 capsule 内运行**；本 phase 的 live 证据全部来自 host（policy 变更前已采集）。Capsule `boot` 模式卡在 systemd-firstboot（volatile root 交互式 prompt），`exec` 无法连接 machine bus。

## Adversarial findings
1. **SSH load one-shot 语义 bug（P1，已修）**：见上。旧实现把“one-shot”理解为“第一个 permission event”，与 fanotify 多事件语义冲突。
2. **Rename-away 未 open 的 inode 不被 `FAN_OPEN_PERM` 标记（OBSERVED）**：strict-filesystem suite 明确记录该 gap —— 正是 LFH2 要关闭的 rename-out gap。
3. **Topology race 测量 gap**：新 inode 在被 topology refresh 标记前存在可被读取窗口（已测量，非 PASS claim）—— LFH2 处理。
4. **`/proc/PID/fd` 场景**：kernel procfs 策略在 fanotify 之前拒绝 → 不算 Guard 的 PREVENTED（BLOCKED 记录）。

## Compatibility findings
- 浏览器合法自读 allow、跨浏览器无 lease deny、WAL/SHM/Local Storage/IndexedDB 分类正常（browser-enforcement + adversarial）。
- SSH agent 普通流程不受影响；`ssh-add -l` 能看到 load 的 identity。
- 普通未保护 open 有 fanotify 快路径；benchmark 见下。

## Performance
- baseline（host，pre-capsule）：见 `evidence/lfh0-benchmark.txt`。
- strict unprotected p95 ≈ 3.06x（35.3us vs 10.3us absent）；browser allowed 6.57x；denied 4.01x；0 overflow / 0 classifier failure。
- 该 baseline 是 LFH0 的锁定数据；LFH6 回归预算以此为基准评估。

## Truthfulness verdict

| Claim | Verdict | Evidence |
|---|---|---|
| missing `enforcement_mode` → 显式错误，不静默降级 | PREVENTED (config-level) | unit tests + guardd parse error |
| Conservative 不能报告 formal ACTIVE | PREVENTED | `handle_status` → REDUCED + linux_health.file_shield=REDUCED |
| overflow → continuity LOST，dropped 不宣称被 deny | PREVENTED (wording) | main.rs wording + status mapping |
| 健康维度拆分可见 | PREVENTED | StatusInfo.linux_health + guardctl 输出 |
| 能力清单真实（本机） | DETECTED (inventory) | guardctl capabilities 输出 |
| 未知进程读 protected 文件被拒（host fanotify） | PREVENTED | fanotify/browser/strict/bypass suites 全 PASS |
| `guardctl ssh load` 可用 | PREVENTED | ssh-load 10/10 + ssh-enforcement 27/27 |
| rename-away 未 open 对象立即受保护 | NOT ACCEPTED | strict suite OBSERVED（LFH2） |
| 新 inode topology 间隙为零 | NOT ACCEPTED | topology-race measured gap |
| Flatpak/Snap/network FS 受保护 | NOT ACCEPTED | 无 live acceptance |
| Capsule 内 fanotify 可用 | BLOCKED | nspawn seccomp EPERM（syscall 300/301） |

## Residual limitations
- 仅 host 采集 fanotify live 证据；capsule 环境无法复现（nspawn seccomp）。
- 浏览器跨族 live acceptance 缺 Chromium 系 executable。
- audit/log 中从未出现 secret bytes（各 suite 检查通过）。

## Final phase verdict
`PASS`
