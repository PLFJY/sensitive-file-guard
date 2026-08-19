# Linux 技术说明

本文描述当前 Linux 版本的有效实现边界。安装和运行命令请阅读[Linux 安装指南](Linux安装指南.md)。

## 后端与权限

Linux 的 authoritative backend 是 root 身份运行的 `guardd`，通过 fanotify permission events 在文件打开前作出决定。服务需要 `CAP_SYS_ADMIN`，并通过 systemd 管理生命周期；polkit 负责需要修改配置、迁移授权和 SSH 操作的敏感请求。

## 防护模式

- `strict-filesystem` 是 Linux 的主要防护模式，使用严格的文件系统资源索引和 inode 身份。
- `conservative` 保留兼容性，但不应被描述为与严格模式等价的安全验收后端，状态始终报告 `REDUCED`，不能报告正式的 `ACTIVE`。
- 配置必须显式携带 `enforcement_mode`；缺失该字段的旧配置会被明确拒绝（guardd 不会静默降级到较弱模式）。
- 配置带有 `config_version`；未知的更高版本会被显式拒绝，而不是被当前版本误读。`guardctl setup` 会写入当前版本。
- 没有非空、经过审阅的 `/etc/guardd/config.json` 时，服务不得显示为已配置或已保护。

## 事件与决策

fanotify 事件先按资源范围筛选，再验证 PID、启动时间、规范化可执行路径、设备号、inode 和 UID。未命中受保护范围的事件立即放行；命中后，未知进程默认拒绝。浏览器迁移和 SSH 读取可以进入有界人工确认，但超时、队列压力、进程退出或身份变化都拒绝。

Linux fanotify 不总能提供打开者原始的读写标志，因此迁移授权不能宣称始终只读。已打开的文件描述符、继承描述符、root/内核入侵不在 V1 保护范围内。

fanotify 队列溢出后，被丢弃的事件**不是**由 Guard 逐个拒绝的——内核在 Guard 看到它们之前就丢掉了。溢出把保护连续性置为 `LOST`，整体状态降级；之后的普通事件仍可继续被强制执行。

### 进程身份（LFH1）

- 在支持的内核上，permission group 使用 `FAN_REPORT_PIDFD`：每个事件携带内核钉住的 pidfd，daemon 在决策全程持有它并在结束后恰好关闭一次；pidfd 与事件 pid 不符时对受保护候选 fail closed。
- 不支持 `FAN_REPORT_PIDFD` 的内核回退为 `PID + starttime`，状态如实报告 `pidfd_enabled=false`（REDUCED），不会静默声称 Strong。
- 可执行身份来自**实际正在运行的对象**：打开 `/proc/<pid>/exe` 并对该 fd `fstat`，而不是重新 stat pathname；pathname 只作显示/注册表线索。被替换或删除（`(deleted)`）的已执行对象仍按其真实对象识别；新进程不继承旧路径的 enrollment。

### 动态对象身份（LFH2）

- 短命动态对象（SQLite WAL/SHM、Local Storage、IndexedDB、Sessions 等）不会永久钉住 inode：inode 号码会复用，永久钉住会造成误报。
- 在受保护路径下被打开过的动态对象，Guard 学习其**不透明 filesystem handle**（`name_to_handle_at`）。此后同一对象被 rename 出 profile 仍按其 handle 识别为受保护；而一个复用了同一 inode 的无关文件，其 handle 不同，判为无关（无 inode-reuse 误报）。
- 普通 `nlink=1` 无关 open 不计算 handle（fast path）；只有命中候选表才比较 handle。不支持 object handle 的文件系统上，动态 rename 保证降级为 REDUCED，具体原因上报。

### 授权精确性（LFH5）

- 所有 lease 都是 **EXACT READER INSTANCE**：绑定的是被观察到的精确进程实例（PID + starttime + executed image identity + UID + BrowserId），不是“整棵进程树”。手工 armed lease 在真实 reader 出现时绑定到精确进程；descendant helper 只有在绑定时刻被观察到、并被精确绑定该 helper 实例时才能读（post-bind observed exact descendant），预先存在的其他 descendant 不会自动升级。策略层不存在 tree-membership 授权。
- 每个 lease 记录创建时的 protection-continuity generation。连续性是 sticky 的：任何连续性丢失（fanotify 溢出、必需 mark 丢失）都会撤销全部 lease 并递增 generation；即使某个 lease 因缺陷逃过撤销，陈旧 generation 也会在策略层拒绝（`stale_lease_generation`）。
- SSH read lease 只授权精确 reader 实例、短 TTL、绑定 continuity generation。SSH load one-shot 只授权精确 `ssh-add` 调用（StableIdentity + PID），绑定 daemon 预先验证的 agent socket；进程退出或身份变化即消耗，agent socket 不符 fail closed。
- Linux 迁移授权不宣称只读保证（fanotify 不提供打开者标志），IPC/UI/audit 如实报告 `read_only_guaranteed=false/unknown`。

## 健康维度

状态按独立维度报告，避免把不同问题混为一谈：

- `file_shield_health`：`ACTIVE` / `REDUCED` / `NOT_ENFORCING`（Conservative 模式、分类失败、拓扑降级或 mark 丢失时 REDUCED）。
- `continuity_health`：`INTACT` / `LOST`，附 `continuity_reason`（如 `fanotify_queue_overflow`、`required_filesystem_mark_lost`）。
- `audit_health`：`HEALTHY` / `DEGRADED`（审计事件被丢弃时 DEGRADED）。
- `process_shield`：Linux 文件盾阶段为 `UNSUPPORTED`（仅能力清点，不实施）。

## 能力清点

`guardctl capabilities` 对当前内核做运行时探测并输出 JSON（不依赖发行版名称推断）：fanotify permission events、`FAN_MARK_FILESYSTEM`、`FAN_REPORT_PIDFD`、`name_to_handle_at(AT_EMPTY_PATH)`（对每个受保护文件系统）以及 BPF LSM 可用性（仅清点）。完整的 fanotify 结果需要 root（`CAP_SYS_ADMIN`）；无权限时如实报告 EPERM。

## IPC 与服务边界

`guardctl`、`guard-ui` 和 `guard-notify` 通过本地 IPC 与 `guardd` 通信。socket 传输组只解决连接权限；真正的配置变更和授权仍需 polkit。不能把同 UID、进程名或 socket 路径当作信任依据。

## 配置与审计

`guardctl setup --home "$HOME"` 只根据已发现并验证的浏览器元数据生成配置，不猜测 SSH 私钥，也不会覆盖已有配置。审计日志只保存决策、资源类别和进程元数据，不保存 Cookie、密码、session token、数据库行或私钥内容。

审计数据库最多保留最新 1000 条事件。写入器在每次批量提交时自动删除更早的记录；查询接口的 `limit` 只是返回数量上限。若写入队列瞬时满载，系统会丢弃新事件并增加 `audit_dropped` 计数，不会删除已经保存的旧事件。

## 通知和 GUI

`guard-notify` 是用户会话中的可选通知服务，不拥有防护策略；`guard-ui` 显示来自 daemon 的 authoritative 状态。GUI 的“刷新状态”会重新查询服务、策略、健康、浏览器保护和 SSH Key 保护，不等同于“扫描原生浏览器”。

## 验收重点

使用合成浏览器 profile 和临时 SSH key 验证：未知进程读取被拒绝；自有浏览器访问允许；迁移和 SSH 读取弹出确认并受 lease 期限约束；daemon 重启、配置错误、队列压力和 fanotify 溢出均进入可见的降级状态。
