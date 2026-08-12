# macOS Phase 30：唯一 App 安装与可恢复产物清理

## BASE HEAD

`54db1f4d2cc43776d7f6db955812b3d3bc0d7620`

## PRODUCT TARGET

只保留一个 `top.plfjy` Guard 安装包和一个可恢复本地签名身份；移出仓库中的历史 App/build 缓存、旧证书 Keychain、旧 identifier 偏好和缓存，并在不影响其他厂商扩展的前提下处置 Guard 系统扩展记录。

## PREVIOUS BLOCKER

- `/Applications/Guard.app` 仍是 build 1、旧证书 `E640...63B4`
- `build/` 含 13 组历史 Guard.app，约 520 MB
- `target/` 是约 7.9 GB 的可重建 Cargo 编译缓存
- 旧 `GuardSelfUse.keychain-db` 无法用保存凭据解锁
- `io.github.plfjy.SensitiveFileGuard` 偏好/缓存仍存在
- 四条 build 1 extension 记录等待重启卸载

## SELF-USE SIGNING MODEL

最终只保留：

```text
Keychain: ~/Library/Keychains/GuardSelfUse-v2.keychain-db
Certificate SHA-1: 7F2BC8D1F634F8139A7E596AC7EF36EBBEABAAB6
```

旧 Keychain 已移入废纸篓，对应旧路径 credential 和 legacy `io.github` credential 已移除。v2 Keychain 的 codesigning identity 复核为 1 个有效身份。

## SIP STATUS

SIP disabled；未修改。

## SYSTEM EXTENSION DEVELOPER MODE

未修改。

## EMBEDDED ENTITLEMENTS

build 29 在 staging、最终 `/Applications/Guard.app` 两个位置分别执行 deep/strict codesign 和 `VERIFY_SIGNING_MODE=self-use`，均通过。最终 App 与 nested extension 保留所需 entitlement。

## XPC IDENTITY

最终安装包证书精确为 v2 `7F2B...AAB6`；所有 identifier 为 `top.plfjy.SensitiveFileGuard...`。

## SYSTEM EXTENSION ACTIVATION

替换 App 后的首次 `open` 触发了 macOS 对同 bundle ID build 29 extension update 的自动登记/激活，尽管 GUI 没有点击安装。发现后立即执行：

```text
/Applications/Guard.app/Contents/MacOS/Guard --deactivate-system-extension
```

返回 `system extension deactivation completed`。当前 6 条 Guard 记录（四条 build 1、两条 build 29）全部没有 enabled/active 标记，均为 `terminated waiting to uninstall on reboot`。

不能使用 `systemextensionsctl reset`，因为系统中还有 Karing 和 OBS 的有效扩展。下一步必须重启，让 macOS 完成 Guard 专属待卸载记录清理。

## FULL DISK ACCESS

未修改 TCC/FDA。

## ENDPOINT SECURITY CLIENT

最终检查 `guard-es` 不存在，Guard GUI 不存在。

## AUTH_OPEN SYNTHETIC DENY

未重复。

## AUTH_OPEN SYNTHETIC ALLOW

未重复。

## BROWSER ACCEPTANCE

沿用 Phase 29 已由审计元数据确认的用户人工对抗 PASS；本阶段未访问浏览器文件。

## BROWSER MIGRATION

未运行。

## SSH BLOCK

未运行。

## SSH ALLOW

未运行。

## DEADLINE SAFETY

未改变。

## NAMESPACE SAFETY

最终停用后 `/bin/cat /etc/hosts` 成功。

## RESTART / UPDATE

唯一安装包：

```text
/Applications/Guard.app
CFBundleIdentifier=top.plfjy.SensitiveFileGuard
CFBundleVersion=29
Certificate SHA-1=7F2BC8D1F634F8139A7E596AC7EF36EBBEABAAB6
```

新 App 实际窗口 bounds 为 `800 × 560` 点。由于扩展 update 自动激活已被停用，重启前不得再次打开 Guard。

## FALLBACK STATUS

不需要 LaunchDaemon fallback。

## REMAINING LIMITATIONS

- 必须重启才能清空 6 条 `terminated waiting to uninstall on reboot` 记录
- 可重建产物和旧 App 采用可恢复清理，约 8.4 GB 目前位于废纸篓；需要用户确认后在 Finder 永久删除这些明确命名的项目，不能自动清空包含其他用户文件的整个废纸篓
- 重启后才能验证系统扩展列表真正只剩零条 Guard 记录

## FINAL STATUS

`ONE V2-SIGNED BUILD-29 APP INSTALLED; REPOSITORY ARTIFACTS CLEANED; ALL GUARD EXTENSIONS DEACTIVATED AND AWAITING REBOOT REMOVAL`

## TEST RESULTS

- staging App deep/strict codesign：PASS
- final `/Applications/Guard.app` deep/strict codesign：PASS
- final self-use bundle/entitlement/GTK verification：PASS
- final bundle ID/build number：`top.plfjy.SensitiveFileGuard` / `29`，PASS
- final leaf certificate：v2 `7F2B...AAB6`，PASS
- final GUI bounds：`800 × 560`，PASS
- `guard-es` stopped：PASS
- Guard GUI stopped：PASS
- ordinary `/bin/cat /etc/hosts`：PASS
- repo `build/` absent：PASS
- repo `target/` absent：PASS
- old Keychain absent from active Keychains path：PASS
- v2 identity remains valid：PASS
- Guard extension enabled/active count：0，PASS
- Guard extension database record count：6，BLOCKED until reboot

