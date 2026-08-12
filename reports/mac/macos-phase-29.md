# macOS Phase 29：紧凑 GUI 与真实环境人工拦截验收

## BASE HEAD

`29e7a7db2d86eab8175ca96998bd8d84bd047bdf`

## PRODUCT TARGET

修复 Retina 笔记本上控制中心接近全屏、侧栏过宽和状态摘要横向溢出的问题；同时按用户要求，用 Guard 元数据审计日志复核用户执行的外部浏览器信息提取人工测试。

## PREVIOUS BLOCKER

- GTK 默认窗口为 `980 × 680` 点，在 2x Retina 截图上接近 `1960 × 1360` 物理像素。
- sidebar 请求 220 点、paned 固定 260 点。
- Overview 状态摘要虽然启用了 wrap，但没有自然宽度上限，会以长单行文本参与尺寸请求。
- Phase 28 中 synthetic 自动验收已因误登记真实 profile 安全中止；用户另行报告此前外部人工工具已被实际拦截，尚需审计证据复核。

## SELF-USE SIGNING MODEL

使用唯一可恢复的 v2 本地身份重新构建，不再使用锁死的旧 Keychain：

```text
Certificate: Guard Local Development Certificate
SHA-1: 7F2BC8D1F634F8139A7E596AC7EF36EBBEABAAB6
Keychain: ~/Library/Keychains/GuardSelfUse-v2.keychain-db
```

## SIP STATUS

SIP disabled；本阶段没有激活 Endpoint Security extension。

## SYSTEM EXTENSION DEVELOPER MODE

未修改。

## EMBEDDED ENTITLEMENTS

`build/macos-release-v2/Guard.app` build number 29 通过最终 self-use bundle verification。宿主保留 system-extension install entitlement，嵌套扩展保留 Endpoint Security client entitlement。

## XPC IDENTITY

最终 Guard、guardctl、guard-notify 和 guard-es 继续使用同一 v2 证书及精确 `top.plfjy` identifier。没有放宽 same-UID 或 identifier-only 信任。

## SYSTEM EXTENSION ACTIVATION

未激活。现有 Guard 记录均保持 disabled/inactive、`terminated waiting to uninstall on reboot`。

## FULL DISK ACCESS

未修改 TCC/FDA。

## ENDPOINT SECURITY CLIENT

本阶段不启动 `guard-es`。人工验收证据来自停用后对既有 root-owned `audit.db` 的只读 SQL 查询。

## AUTH_OPEN SYNTHETIC DENY

未重复；Phase 22 已通过。

## AUTH_OPEN SYNTHETIC ALLOW

未重复；Phase 22 已通过。

## BROWSER ACCEPTANCE

用户执行的真实环境人工对抗测试记为 PASS。元数据审计在 2026-08-13 00:45:22 记录外部进程：

```text
/Users/plfjy/Downloads/hack-browser-data-osx-arm64.tar/hack-browser-data
```

同一 PID 的四次访问分别命中 `saved_credentials`、`cookie_store`、`web_storage`、`browser_key_material`，均记录为：

```text
event_code=browser_access_denied
decision=deny
deny_reason=unknown_process
```

查询只输出时间、PID、事件、决策、资源类别和可执行路径；没有读取或输出 Cookie、密码、会话值或受保护文件内容。

## BROWSER MIGRATION

未运行。

## SSH BLOCK

未运行。

## SSH ALLOW

未运行。

## DEADLINE SAFETY

未改变。已有 deadline tests 全部通过。

## NAMESPACE SAFETY

未改变。macOS scope/space-path/namespace 单元门禁全部通过。

## RESTART / UPDATE

尚未替换 `/Applications/Guard.app`；待 UI commit 完成后再用 build 29 唯一候选包原子替换，之后清理 build 历史产物。

## FALLBACK STATUS

不需要 LaunchDaemon fallback。

## REMAINING LIMITATIONS

- `systemextensionsctl` 的四条同 bundle ID 待卸载记录只能通过重启完成；不能使用会影响其他厂商扩展的全局 reset
- 新 UI 包尚未复制到 `/Applications`
- synthetic browser acceptance 的真实 profile 隔离问题仍保持安全中止状态，不以本次人工测试替代该自动化门禁

## FINAL STATUS

`COMPACT GUI BUNDLE VERIFIED; USER-RUN LIVE BROWSER EXTRACTION ADVERSARIAL TEST CORROBORATED BY FOUR DENY AUDIT EVENTS`

## TEST RESULTS

- `cargo fmt --check`：PASS
- macOS/portable workspace clippy（排除明确 Linux-only 的 `platform-linux`、`guardd`）：PASS
- macOS/portable workspace tests：PASS
- macOS/portable release build：PASS
- self-use safety gate：PASS（121 tests）
- build 29 self-contained GTK bundle：PASS
- build 29 final codesign/designated requirements：PASS
- build 29 embedded entitlements：PASS
- 实际启动窗口 CoreGraphics bounds：`800 × 560` 点，PASS
- 状态摘要 WordChar wrap + 72 字符自然宽度上限：PASS
- 人工外部浏览器提取审计：4/4 `browser_access_denied`，PASS
- 全 workspace `--all-features`：NOT RUN；macOS 主机不能编译 Linux fanotify/inotify API，且用户明确排除 Linux 工作
- `git diff --check`：PASS
