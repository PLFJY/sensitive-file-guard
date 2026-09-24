# macOS 自用保护启用指南

macOS 当前支持形态是自用/实验版，主路径需要：SIP 关闭、本地 Guard 自签名证书、System Extension developer mode、用户手动批准完全磁盘访问。这是明确的产品取舍，不代表 SIP 开启、已公证或可直接面向消费者分发。

Guard 不会自动关闭 SIP、修改 TCC 数据库、注入完全磁盘访问，也不会自动读取真实浏览器或 SSH 数据。

## 推荐的一键流程

```sh
scripts/macos/build-deploy-self-use.sh
```

脚本会检查 SIP、创建/复用本地 Keychain 身份、以无外部时间戳的本地签名构建并验证 entitlement-bearing 包，并把已安装的 `/Applications/Sensitive File Guard.app` 和遗留 `/Applications/Guard.app` 可恢复地移到 `~/.Trash`。在停止当前 helper 或移动应用前，脚本会先验证 `/Applications` 安装权限；取消密码提示不会改变当前运行状态。待处理确认 helper 是防护服务的必需组成：启用或应用启用的策略时，应用会自动注册它；若 macOS 要求批准，仍须在登录项设置中批准。它不会自动激活系统扩展。

## 手工流程

1. 在 SIP 仍开启时创建身份：`scripts/macos/create-self-use-signing-identity.sh`。构建脚本会从登录 Keychain 读取生成的专用密码、仅在签名期间解锁专用 Keychain，并在构建成功或失败退出时重新锁定。若 macOS 要求批准读取已保存凭据，使用本机登录认证。脚本绝不会因为解锁失败而删除或替换已有签名 Keychain；凭据缺失或不匹配时会停止，并要求先显式移走旧 Keychain 再创建新身份。
2. 构建并验证：

   ```sh
   SELF_USE_SIP_OFF=1 CODESIGN_TIMESTAMP=none scripts/macos/build-release-app.sh
   VERIFY_SIGNING_MODE=self-use scripts/macos/verify-bundle.sh build/macos-release/Sensitive File Guard.app
   ```

3. 重启进入 macOS Recovery，手动执行 `csrutil disable`，再重启回系统并运行 `csrutil status`。Guard 不执行这一步。
4. 执行 `sudo systemextensionsctl developer on`，打开 `Sensitive File Guard.app`，在 Protection 页面点击“安装/更新防护扩展”，并按系统提示批准完全磁盘访问。重复点击不是无条件跳过：macOS 会按当前包版本提交安装或替换更新请求；页面会明确显示 Active、等待批准、需要重启或失败原因。
5. 在 Protection 页面选择 Browser Protection Level。Common（推荐）保护浏览器 Cookie、保存的登录凭据和所需密钥材料；Strict 额外保护支持的网站 origin storage。SSH 私钥单独登记，不受该选择影响。
6. 运行现有 `scripts/macos/run-*-acceptance.sh`。target-selection 验收会自动暂存和恢复合成 profile；它只会请求 macOS 本机认证，不要求手工录入 profile。

## 本机定制浏览器（Firefox AutoConfig）

Firefox AutoConfig 在 macOS 上会把配置文件放进 `Firefox.app/Contents/Resources`，因此修改后的包不再满足 Mozilla 的原始资源签名。Guard 不会仅凭 Firefox 的名称或路径忽略这个失败。

需要保留 AutoConfig 时，推荐保留一份独立命名的定制 Firefox.app，在所有 AutoConfig 文件就位后对整个 app bundle 做本机代码签名，并用 `codesign --verify --deep --strict` 验证。然后在 Protection 页选择“Add custom browser…”，明确选择 Firefox family、对应 profile root 和该 app 内的真实 `Contents/MacOS/firefox`，再应用配置。不要把 shell launcher 选作浏览器可执行文件。

具有有效本机签名的显式自定义 app 会按固定签名登记（无论本机证书是否带 Team ID）：运行时必须同时匹配 canonical path、signing ID、有效 `CS_VALID` 状态和登记时的完整 CDHash。CDHash 覆盖代码签名的资源清单；修改 AutoConfig、更新 Firefox 或再次签名后，旧登记会失效，必须重新检查并登记。这条路径不会自动信任签名已经无效的原始 Firefox，也不会仅按主程序文件名放行。

若直接把签名无效的 Firefox 作为普通自定义可执行文件登记，只能得到现有的文件 SHA-256 身份；它不能把 AutoConfig 资源纳入签名封装，安全边界较弱，不建议用于 Firefox AutoConfig。

## 确认助手和通知自检

“遇到确认请求时自动打开 Sensitive File Guard”由必需的 LaunchAgent 提供。Protection 页面不提供关闭它的开关；若 macOS 要求批准，可通过“Open Login Items settings”打开“系统设置 → 通用 → 登录项”批准 Sensitive File Guard。macOS 的拒绝和确认通知由常驻的 `guard-notify` LaunchAgent 发送，因此关闭控制中心窗口不会停止 helper；GUI 只显示安全日志和确认界面，不再重复投递。

在当前用户登录会话中测试系统通知（必须使用新包；该入口由常驻 `guard-notify` 发送）：

```sh
/Applications/Sensitive File Guard.app/Contents/MacOS/guard-notify --test-notification
```

这条命令只发送一条合成通知，不读取受保护文件。若命令失败，查看终端中的原生通知错误；若命令成功但横幅不可见，检查系统设置中的 Guard 通知权限、专注模式和通知中心摘要设置。真实拒绝事件只有在 `guard-notify` 已运行并完成初始事件基线后才会通知新事件。

如果通知来源仍显示为 Script Editor，说明旧版 helper 仍被 launchd 运行，通常是之前移入废纸篓的旧应用。退出 Sensitive File Guard 后重新运行一键部署脚本；脚本会停止旧 helper、安装新包并清理旧注册。启用或应用启用的策略会重新注册必需 helper；若未运行，检查登录项批准状态。也可以只检查当前状态：

```sh
/Applications/Sensitive\ File\ Guard.app/Contents/MacOS/SensitiveFileGuard --pending-helper-status
launchctl print "gui/$(id -u)/top.plfjy.SensitiveFileGuard.guard-notify" 2>/dev/null || true
```

helper 已安装并获批准时，第一条会输出 `Enabled`，第二条能看到正在运行的任务；`NotRegistered` 或 `NotFound` 表示必需 helper 未能安装，应用会在下次启用策略或状态刷新时重新请求注册。关闭“防护服务”会同时注销并停止 `guard-notify`。helper 不能脱离主服务单独轮询或发通知。检测到新的浏览器迁移或 SSH 确认请求时，helper 通过 macOS LaunchServices 打开/激活当前 `Sensitive File Guard.app`；如果第一次 activation 恰好撞上 GUI 退出，它会在请求仍有效时进行少量有界重试，系统通知仍只发送一次。包含空格的安装路径也会安全处理。

## 三种构建模式

- `LOCAL_SIGNING_ONLY=1`：无受限 entitlement，只做 GUI/打包 smoke test，不能真实拦截。
- `SELF_USE_SIP_OFF=1`：本地证书签名、保留 host/extension entitlement，用于 SIP-off 自用保护。
- 不设置上述模式：正式 Apple provisioning/Developer ID/公证路径，当前不是自用路径的前置条件。

`SELF_USE_SIP_OFF=1` 会在编译时固定为自用认证模式：XPC 的每条消息先通过系统提供的 audit token 绑定发送进程，再验证完整静态代码签名、准确的 signing identifier、本地证书指纹、canonical executable path 和稳定的 `st_dev + st_ino`。任一字段缺失或文件可被组/其他用户写入时均拒绝。正式 Apple Team 构建仍使用系统动态 trusted-execution 校验，运行时环境变量不能在两种模式之间切换。

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
