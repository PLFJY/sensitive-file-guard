# macOS Phase 21：实时激活前隔离与 `top.plfjy` 标识迁移

## BASE HEAD

`3dfbcd12a0eef2e50d248d638836e80055876bb6`

## PRODUCT TARGET

仅处理 macOS 自用、SIP 关闭的 Endpoint Security 路径。本阶段不安装、不激活系统扩展，目标是在重新实时测试前完成产品标识迁移、误判修复和自动退出保护。

## PREVIOUS BLOCKER

旧实时扩展曾把普通应用打开纳入失败关闭路径，造成系统范围拒绝。此前 `5bda6ae` 已将普通未保护目标提前放行；本阶段进一步限制实时验收只能使用隔离 PoC ID，并增加有界看门狗。

另发现旧验收脚本使用不存在的 `/usr/bin/cat`，可能把“命令不存在”误报为“Endpoint Security 成功拒绝”。本机正确路径为 `/bin/cat`。

## SELF-USE SIGNING MODEL

- 本地代码签名身份：`Guard Local Development Certificate`
- `security find-identity` 唯一有效身份：`E640217586EA797109605A205995F48BA53163B4`
- 最终发布包宿主和扩展提取出的叶证书 SHA-1 均为该值
- Keychain 当前 service 改为 `top.plfjy.SensitiveFileGuard.self-use-keychain`
- 旧 `io.github...` service 仅保留只读迁移兼容，不作为当前产品 ID

## SIP STATUS

实机重启后 `csrutil status`：`System Integrity Protection status: disabled.`

本阶段没有因 SIP 已关闭而自动执行任何激活操作。

## SYSTEM EXTENSION DEVELOPER MODE

尚未修改；留到下一阶段，在实时激活前单独执行并核验。

## EMBEDDED ENTITLEMENTS

从最终签名产物 `build/macos-release/Guard.app` 验证：

- 宿主 ID：`top.plfjy.SensitiveFileGuard`
- 扩展 ID：`top.plfjy.SensitiveFileGuard.guard-es`
- Mach service：`top.plfjy.SensitiveFileGuard.guard-es.control`
- 宿主：`com.apple.developer.system-extension.install = true`
- 扩展：`com.apple.developer.endpoint-security.client = true`
- 自用标记：`SAFETY_GATE=mac-auth-scope-v1`

隔离 PoC 使用：

- `top.plfjy.SensitiveFileGuard.poc`
- `top.plfjy.SensitiveFileGuard.poc.guard-es`

## XPC IDENTITY

当前 macOS 产品 ID、扩展 ID、Mach service、辅助程序签名 ID 和 LaunchAgent 名称均迁移到 `top.plfjy`。本地证书 XPC requirement 的单元测试通过，仍要求精确证书加精确二进制 identifier；没有降级到同 UID 信任。

## SYSTEM EXTENSION ACTIVATION

本阶段未激活。`systemextensionsctl list` 只显示 OBS Camera 和 karing Network Extension，没有 Guard；`pgrep -x guard-es` 无结果。

新增激活看门狗行为：

- 最长激活等待 120 秒，可等待原生用户批准状态
- 激活后先对普通系统文件、`/bin/cat` 和 `/usr/bin/true` 做 2 秒有界探测
- 运行期间每 500 毫秒重复普通目标探测
- 任一失败或超时立即请求卸载
- 正常验收最长 90 秒并自动卸载
- 未能证明卸载时保留 PoC 应用与诊断目录，不删除恢复载体

## FULL DISK ACCESS

未触碰 TCC/FDA。本阶段不需要 FDA。

## ENDPOINT SECURITY CLIENT

未创建实时 ES client；离线构建和最终签名检查通过。

## AUTH_OPEN SYNTHETIC DENY

未运行实时 deny。脚本现强制检查 deny probe 可执行文件；`CAT_PROBE=/usr/bin/cat` 在任何构建或激活前以退出码 2 拒绝，防止假阳性。

## AUTH_OPEN SYNTHETIC ALLOW

未运行实时 allow。合成探针与隔离 PoC 已完成 build-only 构建。

## BROWSER ACCEPTANCE

未运行；必须等待基本合成 `AUTH_OPEN` deny/allow 真实通过。

## BROWSER MIGRATION

未运行。

## SSH BLOCK

未运行。

## SSH ALLOW

未运行。

## DEADLINE SAFETY

既有 deadline 测试在 macOS safety gate 中通过；本阶段没有改弱内核授权截止时间逻辑。

## NAMESPACE SAFETY

既有 hardlink、rename、alias 容量、sequence gap 与 fail-closed 分类测试在 macOS safety gate 中通过。带空格受保护路径和带空格看门狗停止文件测试通过。

## RESTART / UPDATE

已在用户重启且 SIP 关闭后的新启动中做只读检查。更新/重启实时验收尚未运行。

## FALLBACK STATUS

未实现 LaunchDaemon fallback。System Extension 路径尚未在本轮有界 PoC 中证明失败。

## REMAINING LIMITATIONS

- 开发者模式尚未启用或验证
- 隔离系统扩展尚未激活
- 实时 ES client、合成 deny/allow、XPC 对抗、浏览器、SSH、namespace 和重启验收仍待后续阶段
- `cargo clippy --workspace --all-targets --all-features` 在 macOS 会编译 Linux 专属 `fanotify/inotify`，因 Darwin `libc` 不提供这些 API 而失败；未修改 Linux。macOS 专属严格门禁通过

## FINAL STATUS

`OFFLINE SELF-USE BUNDLE AND SAFETY GATE ACCEPTED; LIVE ENDPOINT SECURITY NOT YET ACTIVATED`

本阶段不能声明真实 Endpoint Security 防护已通过。

## TEST RESULTS

- `scripts/macos/self-use-safety-gate.sh`：PASS（121 tests：8 + 3 + 4 + 19 + 15 + 72）
- `cargo test -p platform-macos -p guard-ui --all-features`：PASS（72 + 19）
- `cargo clippy -p platform-macos -p guard-ui --all-targets --all-features -- -D warnings`：PASS
- `cargo fmt --check`：PASS
- `git diff --check`：PASS
- `SELF_USE_SIP_OFF=1 scripts/macos/build-release-app.sh`：PASS，44 个递归非系统 GTK 依赖已打包，arm64 最终签名验证通过
- `ES_POC_BUILD_ONLY=1 scripts/macos/run-es-poc.sh`：PASS，仅构建与签名检查，无安装、无激活
- 错误 `/usr/bin/cat` probe 防假阳性测试：PASS
