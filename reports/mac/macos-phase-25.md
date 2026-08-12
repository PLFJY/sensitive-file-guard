# macOS Phase 25：重启清理与 `top.plfjy` 正式包部署

## BASE HEAD

`7f2ab67f0c2a6ad94509dfdd2a5233231506bd17`

## PRODUCT TARGET

在隔离 PoC 完成卸载并正常重启后，以可恢复方式替换 `/Applications` 中旧命名空间包，部署经过离线验证的 `top.plfjy` 自用包；本阶段不激活系统扩展。

## PREVIOUS BLOCKER

`top.plfjy.SensitiveFileGuard.poc.guard-es` 曾显示 `terminated waiting to uninstall on reboot`。重启前禁止安装或激活正式扩展。

## SELF-USE SIGNING MODEL

部署包由本地 `Guard Local Development Certificate` 签名；最终包验证通过。

## SIP STATUS

重启后：`System Integrity Protection status: disabled.`

## SYSTEM EXTENSION DEVELOPER MODE

此前已启用；本阶段未修改。

## EMBEDDED ENTITLEMENTS

`VERIFY_SIGNING_MODE=self-use scripts/macos/verify-bundle.sh /Applications/Guard.app` 通过，证明安装位置中的最终包仍保留宿主 system-extension install entitlement 和嵌套扩展 Endpoint Security entitlement。

## XPC IDENTITY

安装包 ID 为 `top.plfjy.SensitiveFileGuard`，嵌套扩展和 Mach service 使用对应 `top.plfjy` 命名空间。未启动 XPC server。

## SYSTEM EXTENSION ACTIVATION

重启后 `systemextensionsctl list` 只显示 OBS 和 karing，PoC 待卸载记录已完全消失。无 `guard-es` 进程。本阶段没有提交正式激活请求。

## FULL DISK ACCESS

未修改 TCC/FDA。

## ENDPOINT SECURITY CLIENT

未启动。

## AUTH_OPEN SYNTHETIC DENY

未重复运行；Phase 22 已通过。

## AUTH_OPEN SYNTHETIC ALLOW

未重复运行；Phase 22 已通过。

## BROWSER ACCEPTANCE

未运行。

## BROWSER MIGRATION

未运行。

## SSH BLOCK

未运行。

## SSH ALLOW

未运行。

## DEADLINE SAFETY

未修改。

## NAMESPACE SAFETY

未修改。

## RESTART / UPDATE

正常重启已证明 PoC 注册记录被 macOS 清除。旧 `/Applications/Guard.app` 没有覆盖或删除，而是移动到仓库忽略的可恢复路径：

`build/recovery/Guard-legacy-io.github.pre-top-plfjy.app`

新包复制到 `/Applications/Guard.app`，其 ID 为 `top.plfjy.SensitiveFileGuard`。

## FALLBACK STATUS

不需要 LaunchDaemon fallback。

## REMAINING LIMITATIONS

- 正式系统扩展尚未激活
- 正式 ES/XPC 联合健康、FDA、浏览器、迁移、SSH、实时 deadline、namespace 和更新验收仍待后续阶段

## FINAL STATUS

`CLEAN REBOOT AND TOP.PLFJY APPLICATION DEPLOYMENT ACCEPTED; FORMAL EXTENSION NOT YET ACTIVATED`

## TEST RESULTS

- 重启证据：uptime 2 分钟，PASS
- SIP disabled：PASS
- PoC 注册记录清除：PASS
- 无 `guard-es`：PASS
- `/bin/cat`、`/bin/ls`、`sw_vers`、`true`：PASS
- TextEdit/Safari app resolution：PASS
- `/Library/Application Support/Sensitive Data Firewall` 不存在，无继承权威配置：PASS
- 安装包 ID `top.plfjy.SensitiveFileGuard`：PASS
- 安装位置最终签名及 bundle 验证：PASS
- 安装位置 GTK packaging smoke：PASS
