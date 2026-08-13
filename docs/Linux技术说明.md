# Linux 技术说明

本文描述当前 Linux 版本的有效实现边界。安装和运行命令请阅读[Linux 安装指南](Linux安装指南.md)。

## 后端与权限

Linux 的 authoritative backend 是 root 身份运行的 `guardd`，通过 fanotify permission events 在文件打开前作出决定。服务需要 `CAP_SYS_ADMIN`，并通过 systemd 管理生命周期；polkit 负责需要修改配置、迁移授权和 SSH 操作的敏感请求。

## 防护模式

- `strict-filesystem` 是 Linux 的主要防护模式，使用严格的文件系统资源索引和 inode 身份。
- `conservative` 保留兼容性，但不应被描述为与严格模式等价的安全验收后端。
- 没有非空、经过审阅的 `/etc/guardd/config.json` 时，服务不得显示为已配置或已保护。

## 事件与决策

fanotify 事件先按资源范围筛选，再验证 PID、启动时间、规范化可执行路径、设备号、inode 和 UID。未命中受保护范围的事件立即放行；命中后，未知进程默认拒绝。浏览器迁移和 SSH 读取可以进入有界人工确认，但超时、队列压力、进程退出或身份变化都拒绝。

Linux fanotify 不总能提供打开者原始的读写标志，因此迁移授权不能宣称始终只读。已打开的文件描述符、继承描述符、root/内核入侵不在 V1 保护范围内。

## IPC 与服务边界

`guardctl`、`guard-ui` 和 `guard-notify` 通过本地 IPC 与 `guardd` 通信。socket 传输组只解决连接权限；真正的配置变更和授权仍需 polkit。不能把同 UID、进程名或 socket 路径当作信任依据。

## 配置与审计

`guardctl setup --home "$HOME"` 只根据已发现并验证的浏览器元数据生成配置，不猜测 SSH 私钥，也不会覆盖已有配置。审计日志只保存决策、资源类别和进程元数据，不保存 Cookie、密码、session token、数据库行或私钥内容。

审计数据库最多保留最新 1000 条事件。写入器在每次批量提交时自动删除更早的记录；查询接口的 `limit` 只是返回数量上限。若写入队列瞬时满载，系统会丢弃新事件并增加 `audit_dropped` 计数，不会删除已经保存的旧事件。

## 通知和 GUI

`guard-notify` 是用户会话中的可选通知服务，不拥有防护策略；`guard-ui` 显示来自 daemon 的 authoritative 状态。GUI 的“刷新状态”会重新查询服务、策略、健康、浏览器保护和 SSH Key 保护，不等同于“扫描原生浏览器”。

## 验收重点

使用合成浏览器 profile 和临时 SSH key 验证：未知进程读取被拒绝；自有浏览器访问允许；迁移和 SSH 读取弹出确认并受 lease 期限约束；daemon 重启、配置错误、队列压力和 fanotify 溢出均进入可见的降级状态。
