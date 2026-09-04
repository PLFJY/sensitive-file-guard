# macOS 自用保护启用指南

macOS 当前支持形态是自用/实验版，主路径需要：SIP 关闭、本地 Guard 自签名证书、System Extension developer mode、用户手动批准完全磁盘访问。这是明确的产品取舍，不代表 SIP 开启、已公证或可直接面向消费者分发。

Guard 不会自动关闭 SIP、修改 TCC 数据库、注入完全磁盘访问，也不会自动读取真实浏览器或 SSH 数据。

## 推荐的一键流程

```sh
scripts/macos/build-deploy-self-use.sh
```

脚本会检查 SIP、创建/复用本地 Keychain 身份、以无外部时间戳的本地签名构建并验证 entitlement-bearing 包，并把已安装的 `/Applications/Sensitive File Guard.app` 和遗留 `/Applications/Guard.app` 可恢复地移到 `~/.Trash`。在停止当前 helper 或移动应用前，脚本会先验证 `/Applications` 安装权限；取消密码提示不会改变当前运行状态。它不会自动激活系统扩展。

## 手工流程

1. 在 SIP 仍开启时创建身份：`scripts/macos/create-self-use-signing-identity.sh`。若出现 keychain 密码提示，使用脚本生成并保存在登录 Keychain 中的专用密码，不是 macOS 登录密码；无法解锁旧 keychain 时换新路径，不要删除旧 keychain。
2. 构建并验证：

   ```sh
   SELF_USE_SIP_OFF=1 CODESIGN_TIMESTAMP=none scripts/macos/build-release-app.sh
   VERIFY_SIGNING_MODE=self-use scripts/macos/verify-bundle.sh build/macos-release/Sensitive File Guard.app
   ```

3. 重启进入 macOS Recovery，手动执行 `csrutil disable`，再重启回系统并运行 `csrutil status`。Guard 不执行这一步。
4. 执行 `sudo systemextensionsctl developer on`，打开 `Sensitive File Guard.app`，在 Protection 页面点击“安装/更新防护扩展”，并按系统提示批准完全磁盘访问。重复点击不是无条件跳过：macOS 会按当前包版本提交安装或替换更新请求；页面会明确显示 Active、等待批准、需要重启或失败原因。
5. 在 Protection 页面选择 Browser Protection Level。Common（推荐）保护浏览器 Cookie、保存的登录凭据和所需密钥材料；Strict 额外保护支持的网站 origin storage。SSH 私钥单独登记，不受该选择影响。
6. 运行现有 `scripts/macos/run-*-acceptance.sh`。target-selection 验收会自动暂存和恢复合成 profile；它只会请求 macOS 本机认证，不要求手工录入 profile。

## 确认助手和通知自检

“遇到确认请求时自动打开 Sensitive File Guard”是可选的 LaunchAgent。Protection 页面现在提供“Install / retry confirmation helper”和“Open Login Items settings”按钮：注册失败时可直接重试，若 macOS 要求批准则打开“系统设置 → 通用 → 登录项”批准 Sensitive File Guard；需要批准不再被当成注册成功，页面会保留具体错误。macOS 的拒绝和确认通知由常驻的 `guard-notify` LaunchAgent 发送，因此关闭控制中心窗口不会停止 helper；GUI 只显示安全日志和确认界面，不再重复投递。

在当前用户登录会话中测试系统通知（必须使用新包；该入口由常驻 `guard-notify` 发送）：

```sh
/Applications/Sensitive File Guard.app/Contents/MacOS/guard-notify --test-notification
```

这条命令只发送一条合成通知，不读取受保护文件。若命令失败，查看终端中的原生通知错误；若命令成功但横幅不可见，检查系统设置中的 Guard 通知权限、专注模式和通知中心摘要设置。真实拒绝事件只有在 `guard-notify` 已运行并完成初始事件基线后才会通知新事件。

如果通知来源仍显示为 Script Editor，说明旧版 helper 仍被 launchd 运行，通常是之前移入废纸篓的旧应用。退出 Sensitive File Guard 后重新运行一键部署脚本；脚本会停止旧 helper、安装新包、显式刷新 `SMAppService` 注册，并验证状态为 `Enabled` 且 launchd 已加载任务。需要登录项批准或未能加载时，部署会明确失败，不会留下一个看似成功但无法唤起 GUI 的安装。也可以只检查当前状态：

```sh
/Applications/Sensitive\ File\ Guard.app/Contents/MacOS/SensitiveFileGuard --pending-helper-status
launchctl print "gui/$(id -u)/top.plfjy.SensitiveFileGuard.guard-notify" 2>/dev/null || true
```

第一条必须输出 `Enabled`，第二条必须能看到正在运行的任务。当前版本中，关闭“防护服务”会同时注销并停止 `guard-notify`；重新打开防护服务后才允许重新注册 helper。helper 不能脱离主服务单独轮询或发通知。检测到新的浏览器迁移或 SSH 确认请求时，helper 通过 macOS LaunchServices 打开/激活当前 `Sensitive File Guard.app`；如果第一次 activation 恰好撞上 GUI 退出，它会在请求仍有效时进行少量有界重试，系统通知仍只发送一次。包含空格的安装路径也会安全处理。

## 三种构建模式

- `LOCAL_SIGNING_ONLY=1`：无受限 entitlement，只做 GUI/打包 smoke test，不能真实拦截。
- `SELF_USE_SIP_OFF=1`：本地证书签名、保留 host/extension entitlement，用于 SIP-off 自用保护。
- 不设置上述模式：正式 Apple provisioning/Developer ID/公证路径，当前不是自用路径的前置条件。

## 诊断与回滚

```sh
scripts/macos/diagnose.sh /Applications/Sensitive File Guard.app
systemextensionsctl list
```

在已签名、已批准的扩展上运行纯合成 target-path 选择验收：

```sh
GUARD_APP="/Applications/Sensitive File Guard.app" \
  scripts/macos/run-target-selection-acceptance.sh
```

该脚本只创建临时 Chromium fixture。已签名的 `guardctl` 会通过认证 XPC 暂时追加该 fixture、验证 target-path inversion、无关 open/exec 的授权事件增量为零、`NOTIFY_EXEC` 仍到达进程图、未知进程拒绝受保护数据、外部符号链接拦截和预先存在硬链接的配置拒绝，随后恢复运行前的策略。macOS 会为这三次策略变更请求本机认证；不再需要在 GUI 中手动录入 profile。扩展未激活或签名/XPC 不匹配时会报告 `BLOCKED`。

一键脚本不会删除旧包；从 `~/.Trash/Sensitive File Guard.app.backup-*` 或 `~/.Trash/Guard.app.legacy-backup-*` 恢复前先退出 Sensitive File Guard，并记录扩展状态。如系统出现异常，优先回到 SIP 开启状态并停用旧扩展，不要使用未经确认的递归删除命令。
