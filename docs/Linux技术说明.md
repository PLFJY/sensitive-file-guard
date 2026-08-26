# Linux 技术说明

本文描述当前 Linux 版本的有效实现边界。安装和运行命令请阅读[Linux 安装指南](Linux安装指南.md)。

## 后端与权限

Linux 的 authoritative backend 是 root 身份运行的 `guardd`，通过 fanotify permission events 在文件打开前作出决定。服务需要 `CAP_SYS_ADMIN`，并通过 systemd 管理生命周期；polkit 负责需要修改配置、迁移授权和 SSH 操作的敏感请求。

## 防护模式

| 模式 | permission 范围 | 普通系统 I/O 成本 | 递归/新对象保证 |
| --- | --- | --- | --- |
| `scoped`（默认） | 仅受保护的文件和目录树 | 受保护命名空间外接近零 | topology watcher 刷新；新建嵌套目录仍有狭窄发现/标记竞态 |
| `strict-mount` | 包含浏览器 profile 的现有 mount | 这些 mount 上的所有 open 都要经过 permission round trip | mount 范围的广覆盖 |
| `strict-filesystem` | 包含浏览器 profile 的整个 filesystem | 可能很高；共享 FS 时会影响 `/usr` 和系统 exec | filesystem 范围的广覆盖 |

`scoped` 不安装 filesystem 或 mount mark。它保留精确文件、SSH
`FAN_ACCESS_PERM` 和已发现目录树标记；watcher 会重建替换对象的标记，但
fanotify 目录标记不会自动继承给未来的新子目录，因此不能把它描述为无竞态的
递归覆盖。旧 JSON 值 `conservative` 仅作为输入兼容，解析为 `scoped`；daemon
启动时不会重写配置。

Btrfs 上 `/` 和 `/home` 可以是同一文件系统中的不同 subvolume mount。
`strict-mount` 标记实际的 `/home` mount，因而可以避开 `/`；
`strict-filesystem` 则会标记整个 Btrfs filesystem，并可能拦截 `/usr/bin/*`。
若 profile 本身在 `/`，strict-mount 也会有相应的广泛开销。记录的约 15–17 ms
exec 回归仅是开发主机实测，不是通用平台延迟承诺。

没有非空、经过审阅的 `/etc/guardd/config.json` 时，服务不得显示为已配置或已保护。

## 事件与决策

fanotify 事件先按资源范围筛选，再验证 PID、启动时间、规范化可执行路径、设备号、inode 和 UID。未命中受保护范围的事件立即放行；命中后，未知进程默认拒绝。浏览器迁移和 SSH 读取可以进入有界人工确认，但超时、队列压力、进程退出或身份变化都拒绝。

Linux fanotify 不总能提供打开者原始的读写标志，因此迁移授权不能宣称始终只读。已打开的文件描述符、继承描述符、root/内核入侵不在 V1 保护范围内。

## IPC 与服务边界

`guardctl`、`guard-ui` 和 `guard-notify` 通过本地 IPC 与 `guardd` 通信。socket 传输组只解决连接权限；真正的配置变更和授权仍需 polkit。不能把同 UID、进程名或 socket 路径当作信任依据。

## 配置与审计

`guardctl setup --home "$HOME"` 只根据已发现并验证的浏览器元数据生成配置，不猜测 SSH 私钥，也不会覆盖已有配置。审计日志只保存决策、资源类别和进程元数据，不保存 Cookie、密码、session token、数据库行或私钥内容。

手动迁移：把 `"enforcement_mode": "strict-filesystem"` 改为 `"scoped"`
即可采用默认的低开销范围；若浏览器 profile 位于合适的独立 mount，且需要更强的
首次打开覆盖，可选择 `"strict-mount"`。已有 `strict-filesystem` 配置保持原行为。

审计数据库最多保留最新 1000 条事件。写入器在每次批量提交时自动删除更早的记录；查询接口的 `limit` 只是返回数量上限。若写入队列瞬时满载，系统会丢弃新事件并增加 `audit_dropped` 计数，不会删除已经保存的旧事件。

## 通知和 GUI

`guard-notify` 是用户会话中的可选通知服务，不拥有防护策略；`guard-ui` 显示来自 daemon 的 authoritative 状态。GUI 的“刷新状态”会重新查询服务、策略、健康、浏览器保护和 SSH Key 保护，不等同于“扫描原生浏览器”。

## 验收重点

使用合成浏览器 profile 和临时 SSH key 验证：未知进程读取被拒绝；自有浏览器访问允许；迁移和 SSH 读取弹出确认并受 lease 期限约束；daemon 重启、配置错误、队列压力和 fanotify 溢出均进入可见的降级状态。
