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
systemctl --user enable --now guard-notify
guardctl status
```

`guardctl setup` 会根据当前用户已验证的浏览器可执行文件和 profile 元数据生成窄范围配置，并且不会猜测或自动加入 SSH 私钥。Linux 只保护配置中的具体浏览器文件、目录树和 SSH 读取；无关的文件与程序不会进入同步 permission 路径。Topology watcher 会刷新替换对象和新目录的标记，但新建嵌套目录在 watcher 发现前存在一个狭窄的首次打开竞态。空配置不代表防护已启用；必须存在经过审阅的非空 `/etc/guardd/config.json`。

## 检查和卸载

```sh
sudo systemctl status guardd
systemctl --user status guard-notify
guardctl events --limit 20
sudo deploy/install.sh --uninstall
```

卸载会移除服务、二进制和桌面入口，但保留配置目录与审计数据库，便于恢复和复核。
