# macOS Phase 31：统一 App 图标与扩展状态布局回归修复

## BASE HEAD

`fcc8722c0ae4e0fcb61d124fc7c91399da3f57b6`

## PRODUCT TARGET

让 macOS Finder/Dock 图标与 Linux 使用完全相同的 Guard SVG；修复扩展安装成功、动态状态变长后 GTK 窗口被隐藏 Protection 页面重新撑大的可复现问题。

## PREVIOUS BLOCKER

- `Guard.Info.plist.in` 没有 `CFBundleIconFile`，bundle 没有 `.icns`，因此 macOS 显示空白 App 图标。
- `GtkStack` 默认横向 homogeneous，隐藏页面仍参与整个窗口最小宽度计算。
- 扩展激活后多个 ActionRow subtitle 变成长诊断文本，Protection 页的自然宽度会把当前 Overview 窗口一起撑大。
- 第一轮 icon bundle 测试发现 `bundle-gtk-runtime.sh` 会重建 `Contents/Resources`，因此 dev 阶段生成的图标必须在 GTK bundling 后再次生成，才能进入最终签名。

## SELF-USE SIGNING MODEL

build 31 继续使用 v2 本地证书 `7F2BC8D1F634F8139A7E596AC7EF36EBBEABAAB6`，没有改变或放宽签名/XPC 模型。

## SIP STATUS

SIP disabled；本阶段没有激活扩展。

## SYSTEM EXTENSION DEVELOPER MODE

未修改。

## EMBEDDED ENTITLEMENTS

build 31 最终 self-use bundle verification 通过，宿主与 nested extension entitlement 保持不变。

## XPC IDENTITY

所有 identifier 继续使用 `top.plfjy.SensitiveFileGuard...`，最终包继续由 v2 证书统一签名。

## SYSTEM EXTENSION ACTIVATION

没有执行 `open /Applications/Guard.app`，没有 activation request。build 31 只通过 staging 替换进 `/Applications`；替换前后 Guard extension database record count 都是 6，enabled/active count 保持 0。

## FULL DISK ACCESS

未修改 FDA/TCC。

## ENDPOINT SECURITY CLIENT

所有测试结束后 `guard-es` 不存在，Guard GUI 不存在。

## AUTH_OPEN SYNTHETIC DENY

未重复。

## AUTH_OPEN SYNTHETIC ALLOW

未重复。

## BROWSER ACCEPTANCE

未重复；沿用 Phase 29 人工验收。

## BROWSER MIGRATION

未运行。

## SSH BLOCK

未运行。

## SSH ALLOW

未运行。

## DEADLINE SAFETY

未改变；macOS 安全门相关测试通过。

## NAMESPACE SAFETY

未改变；macOS 安全门相关测试通过。

## RESTART / UPDATE

最终安装包现在是：

```text
/Applications/Guard.app
CFBundleIdentifier=top.plfjy.SensitiveFileGuard
CFBundleVersion=31
CFBundleIconFile=Guard.icns
```

`Guard.icns` 从 Linux 的唯一 SVG 源 `data/io.github.plfjy.SensitiveFileGuard.svg` 生成 16、32、64、128、256、512、1024 px 表示，视觉复核为同一个蓝色盾牌白色勾。

测试完成后，本阶段重新生成的 61 MB `build/` 和 2.4 GB `target/` 已分别移入废纸篓中的 phase31 明确命名目录；仓库活动路径再次不包含这两类可重建产物。

窗口布局修复：

- Stack 横向与纵向 homogeneous 均关闭，隐藏页面不再决定当前页面最小尺寸
- extension/FDA/SIP/developer mode/entitlement 动态 subtitle 最多三行
- setup message 与 overview detail 使用 WordChar wrap 和 72 字符自然宽度上限
- `--ui-layout-smoke` 与 `--ui-layout-smoke-protection` 注入扩展成功后的长状态，但不连接 XPC、不激活扩展

## FALLBACK STATUS

不需要 LaunchDaemon fallback。

## REMAINING LIMITATIONS

- 6 条 Guard extension 记录仍为 `terminated waiting to uninstall on reboot`，必须重启完成清理
- 不得在重启前打开 build 31，否则 macOS 可能把同 bundle ID nested extension 自动登记为 update

## FINAL STATUS

`LINUX-MATCHING MACOS ICON VERIFIED; POST-ACTIVATION LONG-STATUS OVERVIEW AND PROTECTION LAYOUTS REMAIN 800x560`

## TEST RESULTS

- `cargo fmt --check`：PASS
- macOS/portable workspace clippy（排除 Linux-only 包）：PASS
- macOS/portable workspace tests：PASS
- macOS/portable release build：PASS
- self-use safety gate：PASS（121 tests）
- build 31 self-contained GTK/signing/entitlement bundle：PASS
- `CFBundleIconFile=Guard.icns`：PASS
- ICNS 文件格式与 16–1024 px 表示：PASS
- 1024 px icon 视觉复核与 Linux SVG 一致：PASS
- Overview long activation status：`800 × 560`，PASS
- Protection long activation status：`800 × 560`，PASS
- UI smoke leaked Guard process：NO，PASS
- UI smoke activated `guard-es`：NO，PASS
- build 31 `/Applications` staging/final deep codesign：PASS
- App 替换前后 extension record count：6 → 6，PASS
- App 替换后 Guard extension active count：0，PASS
- repo `build/` absent：PASS
- repo `target/` absent：PASS
- shell syntax：PASS
- `git diff --check`：PASS
