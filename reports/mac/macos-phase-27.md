# macOS Phase 27：Keychain 凭据恢复与验收 JSON 门禁修复

## BASE HEAD

`f912732e1aadfb9047e2a032876b4152fae7bcb2`

## PRODUCT TARGET

修复本地签名证书在重启后的不可用密码弹窗，保证未来重建仍有稳定本地证书；同时修复正式浏览器、SSH、namespace 验收脚本无法识别 pretty JSON 状态的问题。

## PREVIOUS BLOCKER

- `codesign wants to use the GuardSelfUse keychain` 弹窗要求的不是 macOS 登录密码，而是脚本曾生成的专用随机密码。
- 旧 Keychain 的当前与 legacy generic-password 值均不能解锁文件；用户不可能通过反复输入登录密码解决。
- 证书 helper 在已有 identity 路径过早退出，未刷新 codesign ACL。
- generic-password 的 `-U` 在条目不存在时失败。
- 新 Keychain 首次创建路径曾在私钥导入前调用 ACL 更新，因没有 key 而失败。
- 三个 live acceptance 脚本把 JSON 写死为无空格形式，而 `guardctl --json` 当前输出 pretty JSON。

## SELF-USE SIGNING MODEL

凭据现以 `top.plfjy.SensitiveFileGuard.self-use-keychain` service 加“完整 Keychain 路径 account”存储，避免多个专用 Keychain 相互覆盖；旧 USER account 只作为迁移兼容。

旧锁死 Keychain完整保留：

`~/Library/Keychains/GuardSelfUse.keychain-db`

新的长期 identity：

```text
Keychain: ~/Library/Keychains/GuardSelfUse-v2.keychain-db
Certificate: Guard Local Development Certificate
SHA-1: 7F2BC8D1F634F8139A7E596AC7EF36EBBEABAAB6
```

创建失败的无证书空壳没有删除，移动到 `build/recovery/GuardSelfUse-v2-empty-20260813.keychain-db`。

## SIP STATUS

SIP disabled；本阶段的签名操作不依赖 SIP。

## SYSTEM EXTENSION DEVELOPER MODE

未修改。

## EMBEDDED ENTITLEMENTS

在独立目录 `build/macos-release-v2/Guard.app` 完成完整 self-use Release 构建。最终签名、宿主 install entitlement、扩展 Endpoint Security entitlement、GTK runtime 和 arm64 bundle verification 均通过。

从最终宿主签名提取的叶证书 SHA-1 精确为新的 `7F2B...AAB6`。

## XPC IDENTITY

新包的宿主、扩展和客户端统一由 v2 证书签名，保留精确证书加精确 `top.plfjy` identifier 模型。当前正在运行的正式扩展仍使用 Phase 26 的旧证书包；本阶段没有热替换签名 identity。

## SYSTEM EXTENSION ACTIVATION

没有提交新的激活或替换请求。Phase 26 正式扩展继续由有界看门狗托管并保持 active。

## FULL DISK ACCESS

未修改 TCC/FDA。

## ENDPOINT SECURITY CLIENT

当前正式 ES backend 保持 Active；Keychain 与构建修复不影响运行时 ES。

## AUTH_OPEN SYNTHETIC DENY

未重复；Phase 22 已通过。

## AUTH_OPEN SYNTHETIC ALLOW

未重复；Phase 22 已通过。

## BROWSER ACCEPTANCE

修复了 `read_only_guaranteed` 和 `enforcement_active` pretty JSON 匹配；真实 fixture 验收尚未运行。

## BROWSER MIGRATION

尚未运行。

## SSH BLOCK

修复了 `enforcement_active` 与 `ssh_protected_keys` pretty JSON 匹配；尚未运行。

## SSH ALLOW

修复了 `descendant_read` pretty JSON 匹配；尚未运行。

## DEADLINE SAFETY

未改变。

## NAMESPACE SAFETY

修复了 `backend_state` 与 `enforcement_active` pretty JSON 匹配；尚未运行 live fixture。

## RESTART / UPDATE

主动锁定 v2 Keychain 后，helper 能用保存的路径级 credential 解锁、解析同一 identity 并刷新非交互 ACL。未来 rebuild 路径已证明。新证书包尚未安装，避免对当前 active 旧证书扩展做未经验证的热替换。

## FALLBACK STATUS

不需要 LaunchDaemon fallback。

## REMAINING LIMITATIONS

- 需要在完成当前运行时验收并安全卸载后，用 v2 包执行证书迁移/重启与同证书更新验收
- 浏览器、迁移、SSH、实时 deadline、namespace 尚待运行
- 旧锁死 Keychain 只能保留，不能声称其私钥可再次用于签名

## FINAL STATUS

`PATH-SCOPED SELF-USE KEYCHAIN AND NON-INTERACTIVE REBUILD ACCEPTED; LIVE POLICY ACCEPTANCE CONTINUES`

## TEST RESULTS

- 旧不匹配 credential：明确退出 2，无交互密码框，PASS
- v2 identity 首次创建：PASS
- v2 identity 第二次稳定解析：PASS
- 主动 lock 后 helper 自动 unlock：PASS
- 非交互临时 codesign：PASS
- v2 self-use Release 全构建：PASS
- macOS self-use safety gate：PASS（121 tests）
- v2 最终包 verification：PASS
- v2 最终叶证书精确匹配：PASS
- 6 个修改 shell 脚本 `sh -n`：PASS
- 当前 pretty JSON 状态门禁：PASS
- `git diff --check`：PASS
