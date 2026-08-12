# 文档目录

## 用户先读

1. [构建与部署手册](构建与部署手册.md)：Linux/macOS 的依赖、手工构建、一键脚本、安装、启动、升级、卸载和故障排查。
2. [macOS 自用保护启用指南](INSTALL_MACOS.md)：SIP-off、开发模式、签名身份、系统扩展和完全磁盘访问。
3. [Linux 安装指南](INSTALL_LINUX.md)：systemd、polkit、配置生成和通知服务。
4. [安全模型](SECURITY_MODEL.md)：保护范围、威胁模型和明确不保护的边界。

## 平台参考

- [平台架构](PLATFORM_ARCHITECTURE.md)
- [macOS Endpoint Security](MACOS_ENDPOINT_SECURITY.md)
- [macOS XPC 与身份验证](MACOS_XPC_AND_AUTHORIZATION.md)
- [macOS 浏览器保护](MACOS_BROWSER_PROTECTION.md)
- [macOS SSH 保护](MACOS_SSH_PROTECTION.md)
- [macOS 命名空间与健康状态](MACOS_NAMESPACE_AND_HEALTH.md)
- [浏览器迁移模型](BROWSER_MIGRATION_MODEL.md)
- [SSH 访问模型](SSH_ACCESS_MODEL.md)

## 历史材料

`reports/` 和 `docs/adr/` 是阶段报告、决策记录和验收证据。它们可能保留当时的英文原文或旧状态，不能替代上面的中文主入口；阅读报告时以报告中的 BASE HEAD 和 FINAL STATUS 为准。

## 文档维护规则

- 新的用户可见流程必须先写入中文主入口，再在平台参考中补充细节。
- 旧命令不得静默保留；如果仍需兼容，必须写明“历史/不作为安装入口”。
- 每个 macOS 阶段报告放在 `reports/mac/`，记录命令、通过项和阻塞项。
