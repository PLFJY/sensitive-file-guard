# macOS Phase 33：Safari 专用保护开关与系统通知

## BASE HEAD

`7e41532019b0bf0524d4302af71b57ddec40fe9e`

## PRODUCT TARGET

修正不存在 Chromium.app 时残留 `~/Library/Application Support/Chromium` 目录被误呈现为浏览器来源的问题；将 Safari 实现为 macOS 专用、可由用户明确开关的保护来源；使 macOS `guard-notify` 对新检测到的拒绝和待确认行为实际发送系统通知。

## PREVIOUS BLOCKER

- 仅有 Chromium 资料目录但没有经过验证的 Chromium.app 时，旧 discovery 会把目录放入 unsupported 列表，容易被误认为已进入保护范围。
- Phase 32 只报告 Safari detected-but-unsupported，没有 Safari 开关。
- macOS pending helper 只轮询 pending 并打开 Guard；它从未轮询审计拒绝事件，也没有调用任何 macOS 通知 API，因此拒绝不会触发系统通知。

## SELF-USE SIGNING MODEL

build 33 使用现有 self-use 本地证书和 `SELF_USE_SIP_OFF=1`。没有读取、复制或输出任何浏览器资料内容；只检测文件路径、App 签名与可执行文件哈希。

## SIP STATUS

未改变。

## SYSTEM EXTENSION DEVELOPER MODE

未改变。

## EMBEDDED ENTITLEMENTS

最终 build 33 self-use bundle verification 通过，host 和 Endpoint Security extension 的嵌入 entitlement 保持有效。

## XPC IDENTITY

未放宽。`guard-notify` 使用现有的认证 XPC 身份读取仅属于当前 UID 的审计 cursor；通知助手没有任何 Allow/Block 决策能力。

## SYSTEM EXTENSION ACTIVATION

本阶段没有请求 activation 或更新当前运行的 extension。build 33 安装和 notification helper
重新注册后，`top.plfjy.SensitiveFileGuard.guard-es (0.1.0/31)` 仍为
`[activated enabled]`。

## FULL DISK ACCESS

未修改 FDA/TCC。

## ENDPOINT SECURITY CLIENT

未修改 live `guard-es`。build 33 的新 UI/notification helper 通过已 active extension 的认证 XPC 元数据轮询；没有加载真实浏览器资料。

## AUTH_OPEN SYNTHETIC DENY

Safari classifier、Safari dynamic path classifier 和 Safari namespace boundary 均使用合成路径/文件测试。已断言 `~/Library/Application Support/Google/Chrome` 不会因 Safari 开关被分类或纳入 Safari namespace scope。

## AUTH_OPEN SYNTHETIC ALLOW

未重复；本阶段未改变 Allow/lease 语义。

## BROWSER ACCEPTANCE

- 没有 verified Chromium.app 的残留资料目录不再显示为可保护来源。
- 最终签名 build 33 metadata-only discovery 实测发现 Edge 与 Safari。
- Safari 是可开关来源，使用独立 Safari classifier：Cookies、HTTP storage、标签/会话和 History 的明确路径；不会套用 Chromium 规则。
- Safari 可执行文件必须有效、identifier 为 `com.apple.Safari`，并以当前精确 hash enrollment。Safari 更新后将 fail-closed，用户需重新 Apply configuration。

## BROWSER MIGRATION

未改变：只有两个已配置且已信任浏览器之间的跨资料读取会进入 pending confirmation。未知进程仍立即拒绝，不获得自我授权弹窗。

## SSH BLOCK

未运行。

## SSH ALLOW

未运行。

## DEADLINE SAFETY

未改变；pending deadline 单元测试通过。

## NAMESPACE SAFETY

Safari 的 namespace gate 只接受 `Library/Safari` 与 `Library/Containers/com.apple.Safari/Data/Library` 子树。合成测试确认 Chrome 路径不在该 scope；现有 hardlink/rename 机制未放宽。

## RESTART / UPDATE

build 33 先在 `build/macos-release-v2/Guard.app` 中验证，随后以可恢复方式安装：原 build 32
App 已移入废纸篓中的 `Guard.app.build32.phase33-backup`，build 33 已复制到
`/Applications/Guard.app`，`CFBundleVersion=33` 和 deep strict codesign 均通过。

新 App 没有被打开，也没有调用 `OSSystemExtensionRequest`；当前 live extension 因而继续保持
build 31。为使新通知逻辑立即生效，已通过 Guard 的受限 SMAppService 操作依次 unregister / register
pending helper。LaunchAgent 现为 running，parent bundle version 为 33，实际运行的是
`Contents/MacOS/guard-notify`；这不改变 Endpoint Security 扩展或保护策略。

## FALLBACK STATUS

不需要 LaunchDaemon fallback。

## REMAINING LIMITATIONS

- Safari 先信任 Safari 主程序；未验证的 Safari 辅助/XPC 进程不会因名字相同自动信任，必要时仍 fail-closed。
- macOS 系统通知受用户的 Focus/系统通知设置影响；本阶段已执行无敏感信息的 `osascript` system-notification delivery call 并获得成功退出。首次 helper 启动只设审计基线，不补发历史事件。
- `cargo clippy --workspace`/`cargo build --release` 在 macOS 会因仓库既有 Linux fanotify/inotify libc symbols 而失败；本阶段新增的 `BrowserFamily::Safari` 已在 Linux config/strict 路径穷尽处理，未引入新的 Linux 编译错误。

## FINAL STATUS

`SAFARI IS A USER-SWITCHABLE MACOS-ONLY PROTECTION SOURCE; ORPHAN CHROMIUM DATA IS NOT PRESENTED AS PROTECTED; NEW MACOS DENIALS AND PENDING CONFIRMATIONS TRIGGER PRIVACY-PRESERVING SYSTEM NOTIFICATIONS`

## TEST RESULTS

- `cargo fmt --check`: PASS
- `cargo test -p guard-browser -p platform-macos -p guard-ui -p guard-notify --all-features`: PASS（24 + 75 + 19 + 5）
- macOS scoped clippy `-D warnings`: PASS
- `git diff --check`: PASS
- macOS self-use safety gate: PASS
- build 33 self-contained GTK/signing/entitlement verification: PASS
- final build 33 Safari/Edge metadata-only discovery: PASS
- final build 33 UI layout smoke: PASS（Overview / Protection 均为 `800 × 560`）
- final build 33 `guard-notify --once` authenticated XPC poll: PASS
- one harmless macOS system-notification delivery call: PASS（exit 0）
- `/Applications/Guard.app` staged build 33: PASS（`CFBundleVersion=33`、deep strict codesign）
- pending helper re-registered from build 33: PASS（LaunchAgent running；没有 extension activation）
- workspace-wide Linux gate: BLOCKED by pre-existing macOS-host Linux libc/fanotify/inotify incompatibility
