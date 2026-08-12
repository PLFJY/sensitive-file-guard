# macOS Phase 26：正式 `top.plfjy` System Extension 与 XPC 联合激活

## BASE HEAD

`e86f3fe9e472107036d2c685f3521f1e43ccce88`

## PRODUCT TARGET

从 `/Applications/Guard.app` 激活正式 `top.plfjy` 自用 System Extension，在空配置、策略关闭状态下验证真实 Endpoint Security backend、认证 XPC、系统证据和同 UID 对抗。

## PREVIOUS BLOCKER

隔离 PoC 待卸载记录已在 Phase 25 的正常重启中完全清除；正式激活前无 Guard 扩展或 `guard-es` 进程。

## SELF-USE SIGNING MODEL

- Host：`top.plfjy.SensitiveFileGuard`
- Extension：`top.plfjy.SensitiveFileGuard.guard-es`
- XPC：`top.plfjy.SensitiveFileGuard.guard-es.control`
- Authority：`Guard Local Development Certificate`
- TeamIdentifier：`not set`，符合本地证书模式

## SIP STATUS

`System Integrity Protection status: disabled.`

## SYSTEM EXTENSION DEVELOPER MODE

已启用；系统允许本地自签名扩展进入用户批准和 active 状态。

## EMBEDDED ENTITLEMENTS

Phase 25 已从 `/Applications` 最终签名包验证宿主 install entitlement 和扩展 Endpoint Security entitlement。本阶段真实 ES client 成功启动进一步证明嵌入 entitlement 被系统接受。

## XPC IDENTITY

真实运行服务通过：

- 签名 `guardctl` 查询完整状态
- 签名 Guard UI `--xpc-status` 查询完整状态
- ad-hoc 同 UID SSH Allow 攻击被拒绝
- 同一本地证书、同 UID、但错误 signing identifier 的 SSH Allow 攻击被拒绝

没有降级到 UID、进程名或证书单因素信任。

## SYSTEM EXTENSION ACTIVATION

系统证据：

```text
* * - top.plfjy.SensitiveFileGuard.guard-es (0.1.0/1) Guard Endpoint Security [activated enabled]
```

运行进程：

```text
PID=4599
Identifier=top.plfjy.SensitiveFileGuard.guard-es
Authority=Guard Local Development Certificate
TeamIdentifier=not set
```

激活由 1800 秒有界看门狗托管，首轮及持续普通系统访问探测通过。

## FULL DISK ACCESS

系统没有返回 `NOT_PERMITTED`；真实 ES backend 已 Active，因此当前运行环境允许 ES client 工作。本阶段没有修改 TCC 数据库。

## ENDPOINT SECURITY CLIENT

认证状态返回：

```text
backend_state=ACTIVE
backend_diagnostic=Endpoint Security AUTH_OPEN/AUTH_LINK/AUTH_RENAME and bounded process graph subscriptions are active
read_only_guaranteed=true
```

`enforcement_active=false` 是预期状态：权威配置不存在，策略为空且关闭。`protected_files=0`、`protected_trees=0`、`browsers=0`、`ssh_protected_keys=0`。

## AUTH_OPEN SYNTHETIC DENY

未在正式服务重复；Phase 22 隔离 PoC 已通过。正式服务当前空策略只允许普通访问。

## AUTH_OPEN SYNTHETIC ALLOW

未在正式服务重复；Phase 22 已通过。

## BROWSER ACCEPTANCE

尚未运行；正式 ES/XPC 联合运行已经准备好接收仅合成配置。

## BROWSER MIGRATION

尚未运行。

## SSH BLOCK

尚未运行真实 key fixture；伪造 SSH Allow XPC 请求已被拒绝。

## SSH ALLOW

尚未运行。

## DEADLINE SAFETY

本阶段没有 pending 授权；状态计数 `late_responses=0`、`insufficient_deadline=0`。

## NAMESPACE SAFETY

`AUTH_LINK/AUTH_RENAME` 订阅 Active。空策略期间 `namespace_allowed=56`、`namespace_denied=0`、sequence gaps 为 0、process graph 未 degraded。

## RESTART / UPDATE

正式扩展是在清理 PoC 后的新启动中首次激活。更新验收尚未运行。

## FALLBACK STATUS

不需要 LaunchDaemon fallback：System Extension 正式路径可真实运行 ES 与认证 XPC。

## REMAINING LIMITATIONS

- 当前空策略，因此尚未证明正式服务下的浏览器/SSH保护语义
- 浏览器迁移、实时 deadline、namespace、update/restart 验收仍待执行
- 当前激活由最长 30 分钟看门狗托管，阶段结束必须获取 Deactivated 回调或明确保留恢复状态

## FINAL STATUS

`FORMAL TOP.PLFJY SYSTEM EXTENSION, ENDPOINT SECURITY BACKEND, AND AUTHENTICATED XPC ACTIVE ON TESTED SIP-OFF MAC`

该状态不等于全产品安全验收完成。

## TEST RESULTS

- `systemextensionsctl` enabled + active：PASS
- 精确签名 `guard-es` 进程：PASS
- Endpoint Security AUTH_OPEN/LINK/RENAME backend Active：PASS
- Guard CLI XPC：PASS
- Guard UI XPC：PASS
- ad-hoc 同 UID攻击：PASS（被拒绝）
- 同证书错误 ID 同 UID攻击：PASS（被拒绝）
- 空配置、策略关闭：PASS
- ES sequence/global gaps：0
- namespace denied：0
- process graph degraded：false
- 普通系统文件和进程访问：PASS
