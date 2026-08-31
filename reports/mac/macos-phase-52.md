# macOS 阶段 52：关闭 GUI 后可靠唤起确认窗口

## 复现与根因

关闭 Sensitive File Guard GUI 后触发 SSH 私钥读取确认，控制中心有时不会重新出现。现场同时存在两条失效路径：

1. `SMAppService` 已处于 `Enabled` 时，普通启用操作仍先注销 helper 再立即注册；launchd 的异步 bootout 会让该刷新留下 `NotRegistered` 状态。
2. helper 对每个 pending ID 只调用一次 `/usr/bin/open`，且只确认子进程创建，没有检查 LaunchServices 的退出状态。activation 撞上正在退出的 GUI 时不会重试。

统一日志确认 GUI 曾成功被重新启动，随后同一 GUI 进程调用注销，launchd 向 `guard-notify` 发送 SIGTERM。现场最终状态为系统扩展 `Active`，helper `NotRegistered`。

## 修复

- 普通 helper 启用改为幂等：已 `Enabled` 时直接成功，不再注销健康任务。
- `RequiresApproval` 返回可见错误，不再伪装成注册成功。
- App 替换脚本独占注册刷新职责，并验证 `NotRegistered -> Enabled -> launchd loaded` 的完整后置条件。
- pending 通知仍按请求去重；GUI activation 在请求仍存在时最多尝试三次，间隔两秒。
- `/usr/bin/open` 改为等待退出状态并保留非零退出诊断。

所有测试仅使用状态机和合成元数据，没有读取真实 SSH 私钥或浏览器数据。

## 验证

- `cargo test -p guard-notify -p guard-ui -p platform-macos --all-features`：PASS（111 项）
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`：PASS
- `cargo test --workspace --all-features`：PASS
- `cargo fmt --check`：PASS
- `git diff --check`：PASS
- `sh -n scripts/macos/build-deploy-self-use.sh`：PASS
- `scripts/macos/build-deploy-self-use.sh --test-legacy-migration`：PASS

真实“关闭 GUI 后由 Endpoint Security pending 请求冷启动窗口”的验收需要先部署新签名包。当前检查未替换 `/Applications` 中的应用、未修改 helper 注册、未触发真实受保护文件读取。
