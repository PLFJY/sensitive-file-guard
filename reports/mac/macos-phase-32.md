# macOS Phase 32：Edge 可信发现与 Safari 能力边界

## BASE HEAD

`0181c37c9c5b2a044986136fcaf77eaea7d91dc0`

## PRODUCT TARGET

让 macOS 控制中心正确发现可核验的 Microsoft Edge，并让 Safari 资料目录明确显示为“已发现、未保护”；同时澄清并保持浏览器迁移确认只适用于两个已受信任、已配置浏览器之间的跨资料目录读取。

## PREVIOUS BLOCKER

- 原生 macOS discovery 只定义了 Chrome、Chromium、Firefox，Edge 即使安装和资料目录存在也不会显示，因而无法被用户审核并配置。
- Safari discovery 错误要求 `~/Library/Safari` 和 `/System/Applications/Safari.app` 同时存在。这台机器有 Safari 资料目录，但标准 App 位置不存在，UI 因而连未支持提示都没有。
- 审计中 Edge 访问 Chrome/Firefox 资料被记为 `browser_access_denied` / `Deny(UnknownProcess)`；这是未配置 Edge 的正确 fail-closed 行为，不是可迁移候选，故不会弹窗或挂起。

## SELF-USE SIGNING MODEL

build 32 使用现有本地 self-use 证书和 `SELF_USE_SIP_OFF=1` 构建。没有读取、导出或登记任何真实浏览器资料内容。

## SIP STATUS

本阶段没有改变 SIP 状态，也没有请求新的系统扩展 activation。

## SYSTEM EXTENSION DEVELOPER MODE

未修改。

## EMBEDDED ENTITLEMENTS

build 32 的最终 self-use bundle verification 通过：host 保留 system-extension install entitlement，nested extension 保留 Endpoint Security client entitlement。

## XPC IDENTITY

未改变。所有产品标识继续是 `top.plfjy.SensitiveFileGuard...`；本阶段没有放宽同 UID 或任意 Chromium 程序的 XPC/浏览器信任。

## SYSTEM EXTENSION ACTIVATION

未请求 activation。build 32 安装替换后检查，仍是 build 31 extension
`top.plfjy.SensitiveFileGuard.guard-es (0.1.0/31)` `[activated enabled]`，运行中的
`guard-es` PID 仍来自原有 `/Library/SystemExtensions/...` 路径；因此这次 App 替换没有触发
extension 更新或重启。

## FULL DISK ACCESS

未修改 FDA/TCC。

## ENDPOINT SECURITY CLIENT

未修改正在运行的 `guard-es`。现有状态继续为 enforcement active；本阶段没有把真实 profile 加入测试范围。

## AUTH_OPEN SYNTHETIC DENY

未重复；本次修改不触及 AUTH_OPEN 判定路径。

## AUTH_OPEN SYNTHETIC ALLOW

未重复；本次修改不触及 AUTH_OPEN 判定路径。

## BROWSER ACCEPTANCE

最终 signed build 32 的 metadata-only discovery 实测：Chrome、Microsoft Edge、Firefox 均成为可审核的 native browser；Edge 的 main、helper、GPU helper、renderer helper 均验证为 Microsoft Team ID `UBF8T346G9` 和预期 signing ID。没有读取 profile 内容。

## BROWSER MIGRATION

未对真实浏览器执行迁移。策略和文档确认：只有已配置 Edge 读取已配置 Chrome/Firefox（反向亦然）才会保留 `AUTH_OPEN` 并显示确认。未配置的 Edge、未知程序、伪造签名或跨 UID 访问必须立即拒绝且不弹窗。

## SSH BLOCK

未运行。

## SSH ALLOW

未运行。

## DEADLINE SAFETY

未改变。`guard-es` 迁移 pending/deadline 单元测试通过。

## NAMESPACE SAFETY

未改变。macOS safety-gate 和 namespace scoped/fail-closed 单元测试通过。

## RESTART / UPDATE

build 32 先在 `build/macos-release-v2/Guard.app` 完成最终验证，随后以可恢复方式安装：原
build 31 App 已移动至废纸篓中的 `Guard.app.build31.phase32-backup`，build 32 被复制到
`/Applications/Guard.app`。最终 `CFBundleVersion=32` 与 deep strict codesign 均通过。

没有打开 Guard、没有调用 `OSSystemExtensionRequest`、没有改保护策略或配置；当前 live
extension 因而保持 build 31 active。build 32 的 bundle 内 `--discover-macos-browsers` 再次
实测发现 Edge，并将 Safari 资料目录列为 unsupported。

## FALLBACK STATUS

不需要 LaunchDaemon fallback。

## REMAINING LIMITATIONS

- Safari 目前只有资料目录发现提示，尚无专用 Safari resource classifier 或可信 WebKit process enrollment；它不能被安全地当作 Chromium 开关，也不会产生 Safari 迁移确认。
- 要让 Edge 出现在当前控制中心，需要在完成审阅后用 build 32 替换 `/Applications/Guard.app` 并由用户打开新 App；随后用户自行开启 Edge 开关并 Apply configuration。该动作不在本阶段自动执行。

## FINAL STATUS

`EDGE NATIVE DISCOVERY VERIFIED; SAFARI DATA IS EXPLICITLY REPORTED AS DETECTED BUT NOT PROTECTED; UNTRUSTED EDGE REMAINS FAIL-CLOSED WITHOUT A PROMPT`

## TEST RESULTS

- `cargo fmt --check`: PASS
- `cargo test -p platform-macos -p guard-ui --all-features`: PASS（platform-macos 73；guard-ui 19）
- `cargo clippy -p platform-macos -p guard-ui --all-targets --all-features -- -D warnings`: PASS
- `git diff --check`: PASS
- self-use safety gate: PASS
- build 32 self-contained GTK/signing/entitlement bundle: PASS
- final signed build 32 metadata-only native discovery: Edge PASS；Safari detected-but-unsupported PASS
- `scripts/macos/test-ui-layout.sh build/macos-release-v2/Guard.app`: PASS（Overview / Protection 均为 `800 × 560`）
- `/Applications/Guard.app` staged build 32: PASS（`CFBundleVersion=32`、deep strict codesign）
- App staging did not request an extension update: PASS（build 31 extension remains active）
