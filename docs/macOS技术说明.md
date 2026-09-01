# macOS Endpoint Security 技术说明

本文只记录当前 macOS 自用实现的有效边界；安装和构建请阅读[macOS 安装指南](macOS安装指南.md)。

## 运行链路

`Sensitive File Guard.app` 负责 GUI、配置和用户确认；嵌套的 `guard-es.systemextension` 创建两个 Endpoint Security client：授权 client 只订阅 `AUTH_OPEN`、`AUTH_LINK`、`AUTH_RENAME`，并在订阅前以 Ventura 的 target-path mute inversion 选择受保护路径；进程图 client 全局订阅 `NOTIFY_FORK`、`NOTIFY_EXEC`、`NOTIFY_EXIT`。因此普通文件打开不会进入同步授权回调，而进程身份跟踪不会被路径选择意外过滤。`guardctl` 和 `guard-notify` 通过经过签名身份验证的 XPC 与控制面通信。macOS 上的 `guard-notify` 是用户会话常驻通知投递者：它在完成初始审计基线后向新拒绝事件发送系统通知，并在出现待确认请求时先通知、再唤起 Sensitive File Guard。GUI 不重复发送这些通知，因此关闭控制中心窗口不影响拒绝提示。关闭控制中心会先隐藏原生窗口，再退出 GUI 进程；重新激活应用时会恢复任一仍可见的控制中心窗口，已关闭或不可见的窗口对象不会阻塞新窗口创建。已验证的 macOS Spotlight 索引器仍会被阻止读取受保护的浏览器资源；这些预期的后台索引拒绝保留在安全日志中，但不重复发送桌面通知。SSH 私钥读取拒绝仍会显示通知。策略、资源索引、进程身份、审计和 deadline 逻辑只有一份，不在 GUI 中复制。

资源索引同时生成原生选择计划：Chromium/Firefox/Zen 使用各自 profile root，SSH 使用精确路径；Safari 只选择 Cookie 路径和 WebKit website-origin storage 路径，绝不选择整个 `~/Library`。SDK 对硬链接和符号链接没有额外保证，因此启动和配置时会在已批准命名空间内比较受保护 inode 的已见目录项数与 `st_nlink`；存在无法在选择范围内观察的外部硬链接时，配置被拒绝，运行状态不会虚报 `ACTIVE`。真实符号链接行为通过 `scripts/macos/run-target-selection-acceptance.sh` 的合成 fixture 测量。

## 浏览器资源范围

Common（默认）保护 Chromium `Network/Cookies*`/profile-root `Cookies*`、`Login Data*`、`Local State`，Firefox `cookies.sqlite*`、`logins.json`、`key4.db`，以及 Safari `Cookies.binarycookies`。Safari 保存的密码由系统 Keychain 管理，File Shield 不虚构对应的密码文件。

Strict 额外保护 Chromium `Session Storage/`、`Local Storage/`、`IndexedDB/`，Firefox `storage/` 与 `webappsstore.sqlite*`，以及 Safari 的 `WebKit/WebsiteData/Default/` 和 `WebKit/WebsiteDataStore/<profile>/Origins/`。Safari `HTTPStorages` 与 `WebExtensions` 不属于该网站 origin storage 集合。

Open Tabs、Cloud Tabs、最近关闭标签、tab restore、History、Bookmarks、Reading List 与普通 UI/导航状态不会进入资源索引。浏览器保护等级不改变 Endpoint Security AUTH_OPEN、identity、pending authorization、migration、SSH 或 Process Shield 的机制。

实时配置采用保守顺序：先扩大 ES 选择集，再发布新策略，最后缩小选择集并写入 authoritative config；任一步失败都会保留或恢复已知安全状态，磁盘配置不会先于有效选择状态提交。状态接口还公开 `target_path_inversion_active`、`authorization_events_delivered`、`protected_authorization_events` 和 `process_lifecycle_events`，分别用于验证内核选择已启用、授权回调负载和全局生命周期跟踪。

## 审计日志保留

macOS 与 Linux 共用 `guard-audit` 的 SQLite 写入器。每次批量提交后只保留最新 1000 条审计事件，超出部分按事件 ID 从旧到新删除。这个上限是全局的，不按用户分别计算；GUI 的分页数量只是查询限制，不改变保留策略。日志只保存元数据，不保存 Cookie、密码、认证 token 或私钥字节。Safari 的配置根目录显示为 `~/Library`，但资源索引只允许 Safari Cookie 与 WebKit website-origin storage 路径，不会把整个 Library 纳入保护。

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
