# Linux 技术说明

本文描述当前 Linux 版本的有效实现边界。安装和运行命令请阅读[Linux 安装指南](Linux安装指南.md)。

## 后端与权限

Linux 的 authoritative backend 是 root 身份运行的 `guardd`，通过 fanotify permission events 在文件打开前作出决定。服务需要 `CAP_SYS_ADMIN`，并通过 systemd 管理生命周期；polkit 负责需要修改配置、迁移授权和 SSH 操作的敏感请求。

## 防护范围

Linux 只对已配置的具体浏览器资源和受保护目录树安装 fanotify permission
mark：具体认证文件使用精确文件标记，Sessions、Session Storage、Local
Storage、IndexedDB 以及 Firefox/Zen 的对应存储树使用
`FAN_OPEN_PERM | FAN_EVENT_ON_CHILD`，SSH 私钥使用精确的
`FAN_ACCESS_PERM`。不会安装 filesystem 或 mount mark，因此无关的文件打开和
程序执行不会进入 guardd 的同步 permission 路径。

Topology watcher 观察 profile 和 SSH 资源拓扑，在替换对象或新目录出现后重建
索引并重新应用标记。fanotify 的目录标记不会自动继承给未来的新嵌套目录，因而
在 watcher 发现并标记之前存在一个狭窄的首次打开竞态。这里不通过扩大到整个
filesystem 或 mount 来消除该竞态；本产品是本地敏感文件访问防火墙，不是内核级
反恶意软件/EDR。

没有非空、经过审阅的 `/etc/guardd/config.json` 时，服务不得显示为已配置或已保护。

## 事件与决策

fanotify 事件先按资源范围筛选，再验证 PID、启动时间、规范化可执行路径、设备号、inode 和 UID。未命中受保护范围的事件立即放行；命中后，未知进程默认拒绝。浏览器迁移和 SSH 读取可以进入有界人工确认，但超时、队列压力、进程退出或身份变化都拒绝。

Linux fanotify 不总能提供打开者原始的读写标志，因此迁移授权不能宣称始终只读。已打开的文件描述符、继承描述符、root/内核入侵不在 V1 保护范围内。

## IPC 与服务边界

`guardctl`、`guard-ui` 和 `guard-notify` 通过本地 IPC 与 `guardd` 通信。socket 传输组只解决连接权限；真正的配置变更和授权仍需 polkit。不能把同 UID、进程名或 socket 路径当作信任依据。

## 配置与审计

`guardctl setup --home "$HOME"` 只根据已发现并验证的浏览器元数据生成配置，不猜测 SSH 私钥，也不会覆盖已有配置。审计日志只保存决策、资源类别和进程元数据，不保存 Cookie、密码、session token、数据库行或私钥内容。

旧配置中的 `enforcement_mode` 已废弃，不会被静默转换；启动或配置校验会给出迁移
错误，删除该字段后再重试。Linux 配置只描述浏览器、已登记可执行文件和 SSH 私钥
资源。

审计数据库最多保留最新 1000 条事件。写入器在每次批量提交时自动删除更早的记录；查询接口的 `limit` 只是返回数量上限。若写入队列瞬时满载，系统会丢弃新事件并增加 `audit_dropped` 计数，不会删除已经保存的旧事件。

## 通知和 GUI

`guard-notify` 是用户会话中的可选通知服务，不拥有防护策略；`guard-ui` 显示来自 daemon 的 authoritative 状态。GUI 的“刷新状态”会重新查询服务、策略、健康、浏览器保护和 SSH Key 保护，不等同于“扫描原生浏览器”。

## 验收重点

使用合成浏览器 profile 和临时 SSH key 验证：未知进程读取被拒绝；自有浏览器访问允许；迁移和 SSH 读取弹出确认并受 lease 期限约束；daemon 重启、配置错误、队列压力和 fanotify 溢出均进入可见的降级状态。

性能与范围回归使用 `sudo bash scripts/benchmark-linux-root.sh`。该基准只比较
guardd 不运行和使用 Linux 唯一的窄范围架构两种状态；无关文件打开和程序执行的
permission-event 增量必须为 0，受保护资源的允许/拒绝结果、队列溢出和 topology
健康状态是硬断言，耗时仅作参考。
