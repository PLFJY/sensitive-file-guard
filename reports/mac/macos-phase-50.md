# macOS 阶段 50：Guard.app 退出行为

## 根因

macOS GTK 窗口默认关闭只隐藏窗口，`GApplication` 进程继续驻留，因此 Dock/任务栏图标一直存在。Endpoint Security 扩展本身并未因此停止。

## 修复

- macOS 关闭 Guard 主窗口时调用 `GApplication.quit()`，Dock 图标随 GUI 进程退出。
- 增加标准 `⌘Q` `app.quit` 动作。
- pending-only 确认窗口完成后仍按原逻辑关闭并退出 GUI；`guard-es` 防护扩展和 `guard-notify` 生命周期不受影响。
- Linux 生命周期保持不变。

## 测试

```text
cargo fmt --check                                      PASS
cargo test -p guard-ui --all-features                  PASS (21)
cargo clippy -p guard-ui --all-targets --all-features \
  -- -D warnings                                       PASS
git diff --check                                        PASS
```

## 状态

阶段通过。未现场退出用户进程、未修改 SIP/TCC 或系统扩展。
