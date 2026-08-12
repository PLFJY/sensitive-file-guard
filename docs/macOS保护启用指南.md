# macOS 保护启用指南

当前 macOS 产品定位是自用、开源实验。主要路径是：本地自签名证书、保留
Endpoint Security entitlement、关闭 SIP、由用户正常批准系统扩展和完全磁盘访问。
它不是已公证的普通消费者安装包，也不代表支持 SIP-on 分发。

## 先看安全边界

不要一上来关闭 SIP。先在 SIP 开启状态完成构建、单元测试、签名和包检查；只有这些
离线门槛全部通过，并确认旧 Guard 扩展已经移除，才考虑进入 Recovery 关闭 SIP。

`SELF_USE_SIP_OFF=1` 构建会强制执行 `scripts/macos/self-use-safety-gate.sh`。当前安全门
要求至少证明：

- 空策略不会因目标或进程元数据异常而拒绝普通文件操作；
- AUTH_OPEN 先确认目标属于保护集合，之后才允许身份、期限、队列错误 fail-closed；
- link/rename 同样先确认涉及保护命名空间；
- 带空格路径按原始字节长度处理，不经过 shell 分词；
- 旧的自用包没有 `SAFETY_GATE=mac-auth-scope-v1` 标记时，GUI 禁止安装扩展。

这些措施显著缩小故障影响范围，但任何系统级安全软件都不能诚实承诺“100% 不会出现
故障”。首次 live 验收只使用一个合成文件，并提前保留恢复方案；不要直接登记真实
浏览器或 SSH 私钥。

## 自用构建与离线验证

保持 SIP 开启，在仓库根目录执行：

```sh
scripts/macos/create-self-use-signing-identity.sh

SELF_USE_SIP_OFF=1 \
SELF_USE_SIGNING_IDENTITY='Guard Local Development Certificate' \
SELF_USE_SIGNING_KEYCHAIN="$HOME/Library/Keychains/GuardSelfUse.keychain-db" \
CODESIGN_TIMESTAMP=none \
scripts/macos/build-release-app.sh
```

`GuardSelfUse.keychain` 的密码是脚本生成并保存在登录 Keychain 中的随机密码，不是 macOS
登录密码。脚本会为这个专用私钥配置 `/usr/bin/codesign` 的非交互权限。若中断过的旧签名
任务仍留下“codesign wants to use GuardSelfUse keychain”弹窗，直接取消并重新运行证书创建
脚本；不要反复尝试登录密码，也不要把任何密码贴进命令或聊天。

若脚本明确报告已有专用 Keychain 的保存凭据无法解锁，应保留旧文件并指定一个新的路径；
后续构建也必须继续使用同一路径：

```sh
SELF_USE_SIGNING_KEYCHAIN="$HOME/Library/Keychains/GuardSelfUse-v2.keychain-db" \
scripts/macos/create-self-use-signing-identity.sh
```

构建必须显示安全门、测试、clippy 和 `VERIFY_SIGNING_MODE=self-use` 验证通过。最终包内
主程序应有 `com.apple.developer.system-extension.install`，扩展应有
`com.apple.developer.endpoint-security.client`；本地证书和私钥只留在 Keychain，不能
出现在仓库或应用包内。

## 受控启用流程

完成离线评审后，按以下顺序操作：

1. 确认 `systemextensionsctl list` 中没有旧 Guard 扩展处于 enabled/active；若显示
   `terminated waiting to uninstall on reboot`，先重启完成移除。在重启清空这些记录以前，
   不要替换后再启动新版本 App；macOS 可能把同 bundle ID 的新扩展当作更新自动登记并
   激活，从而生成更多待卸载记录。
2. 在 Recovery 里手动执行 `csrutil disable`，然后重启。Guard 不会替你做这一步。
3. 登录后执行 `csrutil status`，确认明确显示 disabled。
4. 执行 `sudo systemextensionsctl developer on`。
5. 将审查过的 `Guard.app` 放入 `/Applications`，不要从 `build/` 目录请求激活。
6. 打开 Guard。Protection 页面必须显示当前安全门有效、SIP 已关闭、Host/Extension
   entitlement 均存在，安装按钮才可用。
7. 点击“安装防护扩展”，按 macOS 提示批准；再点击“授予完全磁盘访问权限”，由用户
   在系统设置中正常授权。Guard 不修改 TCC 数据库。
8. 暂时保持保护策略关闭。先验证扩展 Active、`guard-es` 运行、认证 XPC 可用、
   Endpoint Security backend Active。
9. 只创建一个临时合成文件，先验证普通系统文件仍可打开，再验证该合成文件的
   `/bin/cat` DENY 和明确登记 probe 的 ALLOW。当前 macOS 系统没有
   `/usr/bin/cat`，验收脚本会先确认 `/bin/cat` 确实存在且可执行，避免把“命令不存在”
   错报为内核拒绝。
10. 基础安全验收通过后，才继续合成浏览器、临时 SSH key、deadline、namespace 和
    restart/update 验收。

运行 live PoC 还必须显式设置：

```sh
LIVE_ES_ACCEPTANCE=I_ACCEPT_SYSTEM_EXTENSION_RISK
```

缺少该确认或 SIP 仍开启时，脚本会拒绝激活。它不是跳过安全门的开关。

首次 PoC 使用 90 秒自动卸载看门狗。后续需要人工操作的合成浏览器、SSH 和 namespace
验收也必须通过 `--activate-system-extension-watchdog` 启动；可用
`GUARD_EXTENSION_WATCHDOG_SECONDS` 将会话明确延长，但范围强制限制为 15–1800 秒。
看门狗每 500 毫秒执行一次普通文件和进程探测，单次 2 秒未完成即请求卸载；激活等待、
运行探测或验收本身失败时也不会跳过卸载请求。

## GUI 尺寸

当前控制中心默认窗口为 `800 × 560` 点，侧栏约 `192` 点；在 Retina 屏幕截图中物理
像素通常会显示为两倍，但窗口不应再被 `980 × 680` 点的旧默认值挤到接近全屏。Overview
中的长状态摘要会按内容区宽度自动换行。若仍看到旧的大窗口，说明打开的不是最新构建，
先退出所有 Guard 进程，再确认 `/Applications/Guard.app` 已被最新验收包替换。

扩展激活后出现的长状态不会让隐藏的 Protection 页面参与整个窗口的最小宽度计算；动态
subtitle 最多显示三行。可在不连接或激活扩展的情况下运行回归测试：

```sh
scripts/macos/test-ui-layout.sh build/macos-release/Guard.app
```

macOS 图标由 Linux 使用的同一个
`data/io.github.plfjy.SensitiveFileGuard.svg` 确定性生成 `Guard.icns`。最终 bundle 验证会
同时检查 `CFBundleIconFile` 和 ICNS 文件，避免再次产生 Finder/Dock 空白图标。

## 浏览器扫描与迁移确认

Protection 页面只会把已核验签名和可识别资料目录的浏览器显示为可开启的开关。当前原生
扫描支持 Chrome、Chromium、Firefox 和 Microsoft Edge。扫描到 Edge 后，先打开它的开关，
再点击 Apply configuration；仅“扫描到”不会自动信任或自动保护它。

迁移确认不是所有被拒绝访问都会弹出：它只发生在**已开启保护且已核验的浏览器 B**读取
**另一个已开启保护的浏览器 A**资料时。例如已配置的 Edge 导入已配置 Chrome 的资料，
系统会挂起这一笔 `AUTH_OPEN` 并显示确认；允许后才给该次导入的精确进程树一个限时、只读
租约。未知程序、伪造浏览器、未配置的 Edge 或跨用户访问均会立即拒绝，故意不弹窗，避免
把“是否允许读取 Cookie”变成任意程序的自我授权通道。

Safari 的资料目录会显示为“Detected — not protected”，没有开关。这是诚实的能力边界：Safari
使用 WebKit 和不同的资料布局；在专用的资源分类和可信 WebKit 进程核验完成前，Guard 不会
把它误当 Chromium 保护，也不会声称能对它迁移挂起或确认。Safari 显示出来是为了让用户知道
它被发现了，但当前版本尚未纳入保护范围。

## 紧急恢复

如果启用扩展后普通软件无法打开：

1. 不再尝试继续测试或反复启动 Guard。
2. 进入 Recovery，执行 `csrutil enable`，重启。当前自用扩展在 SIP 开启后不会运行。
3. 到“系统设置 → 通用 → 登录项与扩展 → Endpoint Security Extensions”关闭或移除
   Guard；若显示待卸载，重启完成。
4. 用 `systemextensionsctl list` 确认 Guard 不再 enabled/active，并确认没有
   `guard-es` 进程。

不要执行 `systemextensionsctl reset`，它会影响机器上的其他厂商扩展。不要修改
TCC.db，也不要删除浏览器配置或 SSH key。

## 确认助手

“遇到确认请求时自动打开 Guard”只是可选登录项。它负责在浏览器迁移或 SSH 读取
出现待确认请求时打开 GUI，不安装 Endpoint Security，不拥有保护策略，也不授予
完全磁盘访问。

## 可选的未来 SIP-on 分发

正式分发路径仍保留，未来可使用 Apple 管理的 Endpoint Security capability、
Developer ID、匹配 provisioning profiles、公证和 staple。它与当前本地证书的
SIP-off 自用路径是两个明确模式，不应互相冒充。
