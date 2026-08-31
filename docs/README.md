# 文档目录

## 用户先读

1. [构建与部署手册](构建与部署手册.md)：Linux/macOS 的依赖、手工构建、一键脚本、安装、启动、升级、卸载和故障排查。
2. [macOS 自用保护启用指南](macOS安装指南.md)：SIP-off、开发模式、签名身份、系统扩展和完全磁盘访问。
3. [Linux 安装指南](Linux安装指南.md)：systemd、polkit、配置生成和通知服务。
4. [安全模型](安全模型.md)：保护范围、威胁模型和明确不保护的边界。

## 平台参考

- [平台架构](平台架构.md)
- [Linux 技术说明](Linux技术说明.md)
- [macOS Endpoint Security 技术说明](macOS技术说明.md)
- [SSH 访问模型](SSH访问模型.md)

## 阶段证据

`reports/mac/` 保存按阶段产生的历史测试证据，不是当前产品范围或安装教程。当前范围以本目录的安全模型和平台技术说明为准。

当前 Credential Scope 实现与质量门记录见 [`reports/credential-scope-refactor-2026-08-31.md`](../reports/credential-scope-refactor-2026-08-31.md)。

## 文档维护规则

- 新的用户可见流程必须先写入中文主入口，再在平台参考中补充细节。
- 命令兼容边界必须同步记录在本目录和脚本帮助中。
- 每个 macOS 阶段报告放在 `reports/mac/`，记录命令、通过项和阻塞项。
