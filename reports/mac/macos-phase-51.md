# macOS 阶段 51：Guard GUI 关闭与待确认唤起生命周期

## 范围

修复 Guard 窗口关闭后仍残留 Dock 白点、以及待确认 helper 将完整控制中心
常驻启动的问题。未修改 Endpoint Security、策略判定、通知内容或权限设置。

## 只读现场证据

- `/Applications/Guard.app/Contents/MacOS/Guard` 在窗口关闭后仍存活，父进程为
  `launchd`，对应 LaunchServices 应用任务。
- 现场没有 `guard-notify` 进程；因此残留的是 GUI 生命周期，不是通知 helper
  持续拉起 GUI。
- 原 helper 使用 `/usr/bin/open -a Guard.app`，未传递 pending-only 参数。

## 修复

1. GTK `close-request` 返回后再通过 idle callback 调用 `GApplication::quit`，
   避免同步退出留下无窗口进程。
2. LaunchServices 唤起待确认窗口时传递
   `--args --pending-only`，待处理队列清空后自动退出。
3. 激活时忽略不可见的旧窗口对象，避免 LaunchServices 激活后只得到 Dock
   图标而不创建可见窗口。

## 测试

- `cargo fmt --check`: PASS
- `cargo test -p guard-ui -p guard-notify --all-features`: PASS（27 tests）
- `cargo test --workspace --all-features`: PASS（全部 workspace 测试）
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`: PASS
- `cargo fmt --check`: PASS
- `git diff --check`: PASS
- `cargo build --release`: BLOCKED：本机编译 `gio` 时收到 SIGTERM，未产生 Rust 编译错误；Debug 测试构建已成功。

## 状态

源码修复已完成；需要在当前 macOS 会话中重新构建并替换 Guard.app 后，验证
“关闭主窗口”和“合成待确认出现/解决”两条路径。未执行任何进程终止或系统设置修改。
