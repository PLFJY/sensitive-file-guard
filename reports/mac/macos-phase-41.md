# macOS 阶段 41：分级白名单与通知降噪

## 目标

为 macOS 系统集成提供精确身份、窄资源范围的例外，同时避免 Spotlight 等系统进程产生重复用户通知；第三方工具不按名称自动信任。

## 实现

- `MacAllowlistConfig` 加入版本化后向兼容配置字段。
- 系统进程规则绑定规范化路径、Apple 签名标识、platform binary、文件所有者和资源类型。
- 内置 `com.apple.mdworker_shared` 规则只允许 `History` 元数据读取；Cookie、Session Store、Browser Key Material、Saved Credentials 和 SSH 私钥不会自动放行。
- 第三方工具登记绑定路径、设备号、inode、签名身份和所有者；当前不会因为 App 名称或 `/Applications` 路径自动信任。
- Spotlight 敏感资源拒绝记录为 `system_process_access_suppressed`，`guard-notify` 不发送系统通知，但审计仍保留。
- GUI 显示当前 macOS 受信任工具边界，配置通过认证 IPC 元数据传递。

## 测试

```text
cargo fmt --check                                      PASS
cargo test -p platform-macos -p guard-es -p guard-notify \
  -p guard-ipc -p guard-ui --all-features              PASS
```

结果：macOS 79 项、guard-es 8 项、guard-notify 6 项、guard-ipc 11 项、guard-ui 19 项测试通过。

## 当前限制

App Cleaner 的逐次人工确认需要独立的 pending IPC 类型和 deadline 流程，尚未伪装复用浏览器迁移请求；因此它当前仍默认拒绝关键资源，后续阶段单独实现。

## 状态

阶段通过。真实 Spotlight 事件和第三方工具事件需在用户的 SIP-off 实机重新加载包后验收。
