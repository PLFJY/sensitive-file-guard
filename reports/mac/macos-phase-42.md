# macOS 阶段 42：第三方工具登记与撤销

## 目标

为 App Cleaner 等第三方工具提供明确的用户登记入口，同时避免按名称、安装目录或 UID 自动信任。

## 修改

- GUI 增加“添加受信任工具…”和“撤销”列表。
- 添加前通过 macOS Security.framework 检查有效签名，并保存规范化路径、设备号、inode、Team ID、signing identifier 和所有者 UID。
- staged 配置只有在用户点击“应用策略”后才提交。
- 二进制替换、路径变化、文件身份变化或签名变化会使登记失效。
- 登记工具只允许低敏感度浏览器元数据读取；关键浏览器数据和 SSH 私钥仍拒绝或要求独立人工确认。

## 测试

```text
cargo fmt --check                                      PASS
cargo test -p platform-macos -p guard-es -p guard-ui \
  -p guard-notify -p guard-ipc --all-features           PASS
cargo clippy -p platform-macos -p guard-es -p guard-ui \
  -p guard-notify -p guard-ipc --all-targets \
  --all-features -- -D warnings                         PASS
git diff --check                                        PASS
```

## 状态

阶段通过。逐次人工确认 pending IPC 尚未新增；因此没有把第三方工具伪装成浏览器迁移请求，也没有提供永久关键数据放行。

## 质量门说明

macOS 主机无法运行仓库全量 Linux 质量门：`platform-linux` 使用 fanotify/inotify 和 Linux libc 符号，在 Darwin 上编译失败。该失败与本阶段 macOS 代码无关；macOS 相关 workspace 子集的测试、clippy 和 `git diff --check` 均通过。
