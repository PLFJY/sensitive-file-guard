# Sensitive Data Firewall（敏感文件防火墙）

这是一个本地访问防火墙：在文件被成功打开前，阻止未经授权的进程读取受保护的浏览器认证数据和 SSH 私钥。它不是杀毒软件，也不是网络 DLP。

## 当前状态

| 平台 | 交付方式 | 状态 |
| --- | --- | --- |
| Linux | root `guardd` + fanotify + systemd | 仅保护已配置的浏览器文件、目录树和 SSH 私钥读取 |
| macOS | `Sensitive File Guard.app` + Endpoint Security system extension | 自用实验路径；需要 SIP 关闭、开发模式、本地签名和用户授权 |

macOS 自用路径是当前首选开发路径，故意不等待 Apple provisioning、Developer ID 或公证。它不是 SIP 开启的消费者分发包。Guard 不会自动关闭 SIP、修改 TCC 数据库或自动授予完全磁盘访问权限。

## 浏览器保护等级

File Shield 使用跨平台的 `Browser Protection Level`，默认是 `Common`：

| 资源 | Common | Strict |
| --- | --- | --- |
| 浏览器 Cookie store 及必要 sidecar | 保护 | 保护 |
| 保存的登录凭据 | 保护 | 保护 |
| 解密上述资源所需的浏览器密钥材料 | 保护 | 保护 |
| 支持的网站 origin storage（可能保存认证 token） | 不保护 | 保护 |
| 已登记 SSH 私钥 | 独立保护 | 独立保护 |

Open Tabs、Cloud Tabs、Tab Groups、最近关闭标签、会话恢复状态、History、Bookmarks、Reading List、浏览器 UI/导航状态不属于 File Shield 保护范围。Linux 后端始终采用 Scoped resource enforcement；Common/Strict 只决定保护哪些资源，不改变 fanotify 或 macOS Endpoint Security 的执行机制。

## 快速入口

- [中文文档目录](docs/README.md)
- [构建与部署总手册](docs/构建与部署手册.md)
- [macOS 自用保护启用指南](docs/macOS安装指南.md)
- [Linux 安装指南](docs/Linux安装指南.md)
- [Linux 技术说明](docs/Linux技术说明.md)
- [安全模型](docs/安全模型.md)
- [Credential Scope 验证报告](reports/credential-scope-refactor-2026-08-31.md)
- [macOS 阶段报告](reports/mac/)

## 一键流程

Linux（普通用户执行，安装阶段脚本按需询问 sudo）：

```sh
scripts/build-deploy-linux.sh
```

只构建：

```sh
scripts/build-deploy-linux.sh --build-only
```

macOS 自用包（必须先在 Recovery 手动关闭 SIP；脚本不会自动激活扩展）：

```sh
scripts/macos/build-deploy-self-use.sh
```

脚本会把已安装的 `/Applications/Sensitive File Guard.app` 和遗留的 `/Applications/Guard.app` 移入 `~/.Trash` 作为可恢复备份，不会删除旧包。

## 安全测试规则

所有自动化测试只使用 `crates/guard-test-fixtures` 中的合成浏览器 profile、临时 SSH key 和临时目录。禁止把真实 cookies、密码、session token、浏览器数据库或 SSH 私钥交给测试。日志只记录元数据，不记录秘密内容。

每个阶段都应按以下顺序执行：检查代码 → 实现 → `cargo fmt --check` → 相关 clippy/test → 更新 `reports/mac/` 报告 → 独立提交。除非用户明确要求，不启动 Docker。

## 从源码构建

```sh
cargo build --release
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
git diff --check
```

Linux 与 macOS 平台 crate 在反平台上只编译为空边界，`guardd` 在非 Linux 平台只提供明确的 unsupported 入口。因此上述 workspace 检查应在 Linux 和 macOS 主机上都通过；Endpoint Security、fanotify 和系统权限行为仍只在对应原生平台执行。

## 设计边界

- Linux 的 authoritative daemon 以 root 运行，使用 fanotify permission events。
- macOS 的 authoritative backend 是 Endpoint Security；自用包保留 restricted entitlements，并使用本地证书锚定的 XPC 身份验证。
- 同 UID 不等于可信；Guard、`guardctl`、`guard-notify` 和 `guard-es` 都必须满足签名身份与标识符要求。
- 迁移和 SSH 读取确认受内核 deadline 约束，超时默认拒绝。
- 浏览器分类以已验证的可执行文件和资源身份为准；macOS Safari 使用独立的窄路径分类，其他浏览器沿用共享主逻辑。
- `browser_protection_level` 取值为 `common` 或 `strict`；字段缺失时安全迁移为默认 `common`。

## 许可与贡献

请先阅读[安全模型](docs/安全模型.md)和[平台架构](docs/平台架构.md)。提交 macOS 改动时附上对应的 `reports/mac/` 测试报告，并明确区分离线测试、人工验收和阻塞项。
