# Linux 安装指南

Linux 使用 root `guardd`、fanotify permission events、systemd 和 polkit，与 macOS Endpoint Security 路径完全不同。本项目不需要 Docker。

## 一键安装

在仓库根目录、普通用户下执行：

```sh
scripts/build-deploy-linux.sh
```

选项：`--build-only` 只构建，`--no-start` 安装但不启动，`--yes` 跳过首次配置确认。脚本不会以 root 编译 Rust，也不会覆盖已有 `/etc/guardd/config.json`。

## 手工安装

先安装 Rust、Cargo、GTK4、libadwaita、pkg-config、systemd 和 polkit。然后：

```sh
cargo build --release
sudo deploy/install.sh
sudo /usr/local/bin/guardctl setup --home "$HOME"
sudo systemctl enable --now guardd
systemctl --user daemon-reload
systemctl --user enable guard-notify
systemctl --user restart guard-notify
guardctl status
```

`guardctl setup` 会根据当前用户已验证的浏览器可执行文件和 profile 元数据生成 `browser_protection_level: common` 的 Scoped 配置，并且不会猜测或自动加入 SSH 私钥。Protection 页面可在 Common（推荐）与 Strict 之间切换：Common 保护 Cookie、保存的登录凭据和所需密钥材料；Strict 额外保护支持的网站 origin storage。SSH 私钥单独登记，不受该选择影响。无关的文件与程序不会进入同步 permission 路径。Topology watcher 会刷新替换对象和新目录的标记，但新建嵌套目录在 watcher 发现前存在一个狭窄的首次打开竞态。空配置不代表防护已启用；必须存在经过审阅的非空 `/etc/guardd/config.json`。

## 检查

```sh
sudo systemctl status guardd
systemctl --user status guard-notify
guardctl events --limit 20
```

## 卸载

先在每个已启用通知服务的桌面会话中停止它：

```sh
systemctl --user disable --now guard-notify
sudo deploy/uninstall.sh
```

默认卸载移除 source install 写入的二进制、systemd unit、polkit policy、示例配置和桌面入口，并清理空的 `/run/guardd`。它保留 `/etc/guardd` 中经过审阅的配置、`/var/lib/guardd` 中的审计/state 数据和 `guardd-users` 的现有成员关系；不会删除浏览器 profile、SSH 私钥或系统依赖。

确认不再需要配置和审计记录时，才使用完整清除：

```sh
sudo deploy/uninstall.sh --purge
```

`--purge` 额外删除 Guard 专用的 `/etc/guardd`、`/var/lib/guardd` 和 `/var/log/guardd`。它仍不会删除浏览器 profile、SSH 私钥、用户账号或系统包。
