# Linux 安装指南

Linux 使用 root `guardd`、fanotify permission events、systemd 和 polkit，与 macOS Endpoint Security 路径完全不同。本项目不需要 Docker。

## 一键安装

在仓库根目录、普通用户下执行：

```sh
scripts/build-deploy-linux.sh
```

选项：`--build-only` 只构建，`--no-start` 安装但不启动，`--yes` 跳过首次配置确认。脚本不会以 root 编译 Rust，也不会覆盖已有 `/etc/guardd/config.json`。

## 正式 release artifact

面向发布的离线 artifact 与源码树安装分开。普通用户执行：

```sh
packaging/linux/build-release.sh
sha256sum -c dist/sensitive-file-guard-linux-*.tar.gz.sha256
tar -xzf dist/sensitive-file-guard-linux-*.tar.gz
cd sensitive-file-guard-linux-*
sudo ./install.sh install
```

release 安装到 `/usr/bin`、`/usr/lib/systemd` 和 `/usr/share`。升级前会用候选
`guardctl` 验证现有配置；降级默认拒绝，只有显式 `--allow-downgrade` 且配置兼容
才会继续。完整 lifecycle 与权限契约见 [Linux release pipeline](linux-release.md)。

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

`guardctl setup` 会根据当前用户已验证的浏览器可执行文件和 profile 元数据生成严格配置，并且不会猜测或自动加入 SSH 私钥。空配置不代表防护已启用；必须存在经过审阅的非空 `/etc/guardd/config.json`。

也可以直接打开 `guard-ui` 完成首次配置：Linux 首次运行会展示发现的浏览器和 SSH
候选项；勾选并确认资源后点击 Apply。然后点击 Overview 页的“Protection +
notifications”开关，GUI 会通过 polkit 写入并健康检查配置，并执行
`systemctl enable --now guardd.service` 与 `systemctl --user enable --now
guard-notify.service`。GUI 不会自行安装发行版 package；若 unit 不存在，会提示先
安装 release/AUR 包。

如果当前 enrollment 是已经接受的原生 Firefox，并且内核确实具备已验证的 BPF LSM
能力，可以在首次生成配置时显式请求可选的 Process Shield：

```sh
sudo /usr/local/bin/guardctl setup --home "$HOME" --process-shield
```

Firefox ESR、Chromium、Chrome 和 Zen 目前不会因此自动获得接受状态。完成配置并启动
daemon 后，使用 `guardctl browser status` 查看 File Shield 捕获到真实认证状态访问后，
某个精确 Firefox 进程实例是否已被接纳。

## 面向用户的状态与审计

`guardctl status` 的默认输出只展示产品级状态：File Shield、可选 Process Shield、
browser authority 和已经启用的 SSH key 数量。`guardctl --json status` 保留稳定的机器
可读健康字段与诊断原因。

`guardctl events --limit 20` 默认把拒绝访问、browser authority 接纳、Process Shield
阻止和保护连续性/拓扑降级显示为可读事件；`guardctl --json events --limit 20` 输出原始
JSON 合约，不通过人类文本推断事件类别。

## strict-filesystem 与根文件系统标记（SAFETY REFUSAL）

`strict-filesystem` 会在受保护 profile 所在的**整个文件系统**上安装 `FAN_MARK_FILESYSTEM`，
使该文件系统上的每一次 `open()` 都要先经过 guardd 裁决。如果这个文件系统是**根文件系统**，
那么全机每个进程的每个文件打开都要排队等 guardd——一旦 daemon 繁忙或停滞，会造成**整机 IO
阻塞**（真实发生过两次全盘锁死）。因此：

1. **formal accepted strict-filesystem 部署不包括根文件系统标记。**
2. 如果浏览器 profile 与 `/` 在**同一个文件系统**（`st_dev` 相同），guardd 会**默认拒绝启动**
   （这是 **SAFETY REFUSAL**，不是 fanotify 不支持）。
3. 检查方式：
   ```sh
   stat -c %d /                       # 根文件系统的设备号
   stat -c %d "$HOME"                 # 你的家目录（通常是同一设备号）
   stat -c %d <实际 browser profile path>
   ```
   若三者相同，则该 profile 位于根文件系统上。
4. 推荐方案：把浏览器受保护 profile/资源放到**专门的、非根的文件系统**上（例如独立分区或
   隔离的 loop-backed ext4），guardd 才能以 strict-filesystem 正常启动。
5. `GUARDD_ALLOW_ROOT_FS_MARK=1` 是一个**危险的显式 override**：
   - 它会让整个根文件系统的 `open` 都经过 guardd；
   - daemon 停滞可导致整机 IO wedge；
   - **不属于正式的 accepted/frozen deployment capability**；
   - **测试代码永远不得设置该变量**。
6. 因此"安装 → `systemctl enable --now guardd`"在**所有普通单分区 Linux 上都一定能启动成功**
   这一假设不成立：若 profile 位于根文件系统，guardd 会拒绝启动，这是有意为之的安全保护。

如果启动被拒绝，先检查 profile 所在文件系统，把 profile 移到非根文件系统；除非你明确接受
整机门控风险，否则不要设置 `GUARDD_ALLOW_ROOT_FS_MARK=1`。

## 检查和卸载

```sh
sudo systemctl status guardd
systemctl --user status guard-notify
guardctl events --limit 20
sudo deploy/install.sh --uninstall
```

卸载会移除服务、二进制和桌面入口，但保留配置目录与审计数据库，便于恢复和复核。
