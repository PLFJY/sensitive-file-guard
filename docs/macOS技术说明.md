# macOS Endpoint Security 技术说明

本文只记录当前 macOS 自用实现的有效边界；安装和构建请阅读[macOS 安装指南](macOS安装指南.md)。

## 运行链路

`Guard.app` 负责 GUI、配置、用户确认和 macOS 系统通知；嵌套的 `guard-es.systemextension` 创建 Endpoint Security client；`guardctl` 和 `guard-notify` 通过经过签名身份验证的 XPC 与控制面通信。`guard-notify` 在 macOS 上只负责发现 pending 请求并唤起 Guard，不发送拒绝通知，避免通知代理和 GUI 重复发送。策略、资源索引、进程身份、审计和 deadline 逻辑只有一份，不在 GUI 中复制。

## 审计日志保留

macOS 与 Linux 共用 `guard-audit` 的 SQLite 写入器。每次批量提交后只保留最新 1000 条审计事件，超出部分按事件 ID 从旧到新删除。这个上限是全局的，不按用户分别计算；GUI 的分页数量只是查询限制，不改变保留策略。日志只保存元数据，不保存 Cookie、密码、会话内容或私钥字节。

## AUTH_OPEN 决策

- 未命中受保护资源时立即允许，不要求进程身份完整。
- 命中后必须验证 PID、启动时间、规范化可执行路径、文件身份和浏览器签名。
- 自有浏览器只允许自己的 profile；未知进程默认拒绝；跨浏览器迁移和 SSH 读取进入有界人工确认。
- 允许响应只保留请求允许的读取标志，迁移读取保持只读保证。
- 有效 deadline 是产品上限与 Endpoint Security 消息 deadline 减安全余量的较小值；余量不足直接拒绝。

## 状态判定

GUI 只有在以下证据同时成立时显示 Active：系统扩展生命周期状态、`guard-es` 进程、Endpoint Security client 已创建、authenticated XPC 可用、策略运行时健康。activation delegate 回调本身不足以证明防护正在运行。

## 错误和诊断

`es_new_client` 的 `NOT_ENTITLED`、`NOT_PERMITTED`、`NOT_PRIVILEGED`、`TOO_MANY_CLIENTS` 和 `INTERNAL` 必须分别记录。诊断工具只输出路径、版本、状态和计数，不输出浏览器内容、Cookie、密码或私钥。

## 测试

使用合成文件完成 deny/allow、同 UID XPC 对抗、deadline、命名空间和重启验收。真实用户数据不属于自动化测试范围。
