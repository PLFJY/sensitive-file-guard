# macOS 阶段 39：确认助手与系统通知修复

## BASE HEAD

`7766023`

## 问题

- 确认助手开关失败时只回滚开关并写 tooltip；状态轮询还可能覆盖错误，用户看到的是“打开后立刻关闭”。
- 历史版本曾通过 `osascript` 间接发送，来源会显示为 Script Editor；该路径已移除，当前版本由 Guard.app 原生通知桥发送。

## 修复

- 开关异步失败时保留页面可见的中文错误副标题，并在下一次轮询中保留错误；成功时清除错误。
- 修复开关同步期间的回调保护，避免程序设置 `set_active` 重新启动第二次注册/注销操作。
- 保留 `SMAppService` 的状态模型：`Enabled`、`RequiresApproval`、`NotRegistered`、`NotFound` 都明确展示。
- 新增 macOS 原生 `NSUserNotificationCenter` bridge，通知不再依赖 `osascript`；只发送进程名和资源类别元数据，不发送路径或内容。
- 通知 helper 的原生错误会返回给日志，方便区分通知权限关闭、通知中心不可用和投递失败。

## 测试

通过：

```text
cargo fmt --check
cargo test -p guard-ui -p guard-notify -p platform-macos --all-features
cargo clippy -p guard-ui -p guard-notify -p platform-macos --all-targets --all-features -- -D warnings
git diff --check
```

## 人工验证

重新构建并替换 `/Applications/Guard.app` 后，在 Protection 页面开启确认助手。若 macOS 显示需要批准，请到“系统设置 → 通用 → 登录项”批准 Guard；失败原因现在会直接显示在开关副标题中。通知首次发送可能触发系统通知授权，必须选择允许；若仍不可见，查看 `guard-notify` 的 stderr 中的原生错误。

## FINAL STATUS

确认助手竞态和通知发送路径已修复并通过 macOS 相关离线质量门；真实系统通知显示仍需在用户当前登录会话中人工确认一次。
