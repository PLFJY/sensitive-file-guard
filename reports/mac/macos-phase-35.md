# macOS 阶段 35：构建部署脚本与文档主线

## BASE HEAD

`2eab14c`

## PRODUCT TARGET

为 Linux 和 macOS 提供可审计的一键构建/部署入口，同时把面向用户的构建、安装、启动、升级和回滚说明收敛为中文主线。macOS 仍是 `SELF_USE_SIP_OFF` 自用实验路径；脚本不自动关闭 SIP、不自动激活系统扩展、不修改 TCC、不读取受保护内容。

## 实现

- 新增 `scripts/build-deploy-linux.sh`：普通用户编译，安装阶段才使用 `sudo`；已有配置不覆盖；支持 `--build-only`、`--no-start`、`--yes`。
- 新增 `scripts/macos/build-deploy-self-use.sh`：检查 SIP、复用/创建本地 Keychain 身份、构建并验证 entitlement-bearing 包，将旧 app 移到废纸篓备份，再安装新包和注册可选 helper。
- 重写中文主入口：根目录 `README.md`、`docs/README.md`、`docs/构建与部署手册.md`、`docs/macOS安装指南.md`、`docs/Linux安装指南.md`。
- 历史报告和 ADR 保留为证据，不再作为安装入口。

## TESTS

通过：

```text
bash -n scripts/build-deploy-linux.sh
sh -n scripts/macos/build-deploy-self-use.sh
scripts/build-deploy-linux.sh --help
scripts/macos/build-deploy-self-use.sh --help
git diff --check
```

未在 Linux 主机上启动服务或执行提权安装；未在当前阶段触发 macOS 一键部署，以避免重复修改已运行的系统扩展。完整构建/激活验收仍按手册中的人工步骤执行。

## 安全性说明

- Linux 脚本不会以 root 编译，也不会写空配置或覆盖现有配置。
- macOS 脚本只允许目标 `/Applications/Guard.app`，旧包使用带时间戳的废纸篓备份；不使用递归删除清理系统安装。
- 两个脚本均明确不启动 Docker。

## FINAL STATUS

一键脚本语法和帮助路径通过；中文用户主线已整理。系统级安装、服务启动和 macOS 扩展激活必须在对应平台由用户按手册逐步执行，不能将未执行的人工步骤标记为通过。
