# macOS Phase 22：隔离 Endpoint Security `AUTH_OPEN` 实机验收

## BASE HEAD

`fb401e26c15949a77ec8a31ff5e6b39aa47e995b`

## PRODUCT TARGET

在用户明确关闭 SIP 后，只使用临时合成文件和隔离 bundle ID 验证真实 Endpoint Security `AUTH_OPEN` deny/allow，不访问真实浏览器资料或 SSH 私钥。

## PREVIOUS BLOCKER

此前真实扩展错误地把普通未保护文件纳入失败关闭范围，造成系统应用无法打开。`5bda6ae` 已修复分类顺序，`fb401e2` 又加入普通目标看门狗、隔离 ID、有界激活和自动卸载。

## SELF-USE SIGNING MODEL

- 宿主：`top.plfjy.SensitiveFileGuard.poc`
- 扩展：`top.plfjy.SensitiveFileGuard.poc.guard-es`
- 本地签名身份：`E640217586EA797109605A205995F48BA53163B4`
- TeamIdentifier 按本地自签名设计为空
- 没有 provisioning profile，没有 notarization

## SIP STATUS

激活前：`System Integrity Protection status: disabled.`

## SYSTEM EXTENSION DEVELOPER MODE

通过用户在本机 Terminal 的管理员授权成功执行：

```sh
sudo /usr/bin/systemextensionsctl developer on
```

成功命令创建了临时完成标记。自动 AppleScript 授权路径因无法交互而被系统拒绝，没有绕过授权。

## EMBEDDED ENTITLEMENTS

实时 PoC 激活前从最终签名产物确认：

- 宿主 `com.apple.developer.system-extension.install = true`
- 扩展 `com.apple.developer.endpoint-security.client = true`
- 宿主和扩展均由同一本地证书签名

## XPC IDENTITY

PoC 本阶段只验证 Endpoint Security 内核路径，没有启动产品控制 XPC。精确证书加精确 identifier 的 XPC 单元测试仍通过；没有使用同 UID 降级。

## SYSTEM EXTENSION ACTIVATION

真实系统证据：

```text
* * - top.plfjy.SensitiveFileGuard.poc.guard-es ... [activated enabled]
```

真实运行进程：

```text
guard_es_process=29802:/Library/SystemExtensions/.../top.plfjy.SensitiveFileGuard.poc.guard-es.systemextension/Contents/MacOS/guard-es
```

验收完成后，原生生命周期回调：

```text
WATCHDOG_DEACTIVATED state=Deactivated diagnostic=system extension deactivation completed
```

卸载后系统行状态为：

```text
top.plfjy.SensitiveFileGuard.poc.guard-es [terminated waiting to uninstall on reboot]
```

该行没有 enabled/active 星号；`pgrep -x guard-es` 无进程。PoC 应用已删除。macOS 将在下次重启清除残留注册记录。

## FULL DISK ACCESS

未修改或绕过 TCC。本次 `/tmp` 合成 fixture 不需要 FDA。

## ENDPOINT SECURITY CLIENT

`guard-es` 成功成为真实运行中的 System Extension；合成 `AUTH_OPEN` 行为证明 Endpoint Security client、订阅和响应链实际工作。没有观察到 `NOT_ENTITLED`、`NOT_PERMITTED` 或 `NOT_PRIVILEGED`。

## AUTH_OPEN SYNTHETIC DENY

普通、未登记的 `/bin/cat` 读取精确临时受保护文件失败：

```text
PASS: deny probe received no protected bytes
```

deny 输出不含 canary，满足 0 个受保护字节返回。

## AUTH_OPEN SYNTHETIC ALLOW

仅精确登记了路径与文件身份的 `guard-test-probe` 成功读取精确 canary：

```text
PASS: explicitly enrolled synthetic probe read the fixture
```

## BROWSER ACCEPTANCE

未运行。按顺序应先完成本地 XPC 同 UID 对抗测试，再进入仅合成浏览器 fixture 的验收。

## BROWSER MIGRATION

未运行。

## SSH BLOCK

未运行。

## SSH ALLOW

未运行。

## DEADLINE SAFETY

实时 PoC 没有出现超时或迟响应；既有 deadline 单元测试在激活前 safety gate 中通过。完整实时 deadline 验收仍待后续阶段。

## NAMESPACE SAFETY

激活期间普通系统文件和进程看门狗持续通过。完整实时 hardlink/rename 验收仍待后续阶段。

## RESTART / UPDATE

未运行产品更新验收。隔离 PoC 注册项当前等待下次重启完成系统记录清理，但扩展已经 inactive、进程已经停止。

## FALLBACK STATUS

不需要 LaunchDaemon fallback。经验证的 SIP-off、developer mode、本地证书 System Extension 路径能够真实激活 Endpoint Security 并执行 `AUTH_OPEN`。

## REMAINING LIMITATIONS

- 本阶段仅接受最小合成 deny/allow，不代表浏览器、迁移、SSH、deadline、namespace、XPC 或重启全量通过
- 当前不是 Apple 正式分发、notarized 或 SIP-on 包
- PoC 的 terminated 注册记录需下次重启由 macOS 清除；它当前不 active 且没有进程

## FINAL STATUS

`BASIC SELF-USE SIP-OFF ENDPOINT SECURITY AUTH_OPEN ACCEPTED ON THIS MAC`

该状态仅覆盖隔离合成 `AUTH_OPEN` deny/allow 里程碑，尚不能声明整个 macOS 产品最终验收完成。

## TEST RESULTS

- 激活前 `scripts/macos/self-use-safety-gate.sh`：PASS（121 tests）
- System Extension activation：PASS，系统证据 enabled + active
- 精确签名 `guard-es` 进程证据：PASS
- 普通系统文件/进程初始与持续看门狗：PASS
- 合成 `/bin/cat` deny、0 canary bytes：PASS
- 精确登记合成 probe allow、精确 canary：PASS
- 原生 deactivation 回调：PASS
- 卸载后 `guard-es` 不运行：PASS
- 卸载后 `/bin/cat`、`/bin/ls`、`sw_vers`、`true`、TextEdit/Safari app resolution：PASS
