# macOS Phase 28：真实配置误登记的安全中止与隔离

## BASE HEAD

`46a1c1b627bba78db65c8b289d1609ff7c197bd7`

## PRODUCT TARGET

在只允许 synthetic fixture 的 live acceptance 中，一旦发现配置包含开发者真实浏览器目录，立即停止验收、撤销 Endpoint Security 扩展并隔离配置，证明普通系统读取和进程启动恢复正常。

## PREVIOUS BLOCKER

浏览器验收等待人工启用 disposable policy 时，签名客户端的只读状态查询显示 active policy 实际登记了以下真实目录：

```text
/Users/plfjy/Library/Application Support/Google/Chrome
/Users/plfjy/Library/Application Support/Firefox/Profiles
```

这违反仓库“测试只能使用 synthetic browser fixtures”的门禁。查询只取得控制面的路径与计数元数据；没有打开、读取、复制或导出任何真实浏览器文件内容。

## SELF-USE SIGNING MODEL

未改变签名模型。正在运行的 Phase 26 旧证书包只用于完成受控停用；v2 包没有安装。

## SIP STATUS

SIP disabled。处置过程中没有修改 SIP、TCC 或其他全局系统安全设置。

## SYSTEM EXTENSION DEVELOPER MODE

未修改。

## EMBEDDED ENTITLEMENTS

未修改。

## XPC IDENTITY

使用已验收的签名 Guard 客户端读取配置元数据并确认误登记范围。没有放宽 XPC 身份验证。

## SYSTEM EXTENSION ACTIVATION

通过 Phase 24 的有界看门狗 stop file 请求正常 deactivation。看门狗返回：

```text
WATCHDOG_DEACTIVATED state=Deactivated diagnostic=system extension deactivation completed
```

`systemextensionsctl list` 随后只显示 Guard extension 为 `terminated waiting to uninstall on reboot`，不再 enabled/active。

## FULL DISK ACCESS

未修改 FDA/TCC。

## ENDPOINT SECURITY CLIENT

`guard-es` 进程已经停止。Guard GUI 同时退出，防止它在检查期间重新写入 active config。

## AUTH_OPEN SYNTHETIC DENY

本阶段没有执行。发现真实路径后，在运行任何浏览器 probe 前中止。

## AUTH_OPEN SYNTHETIC ALLOW

本阶段没有执行。

## BROWSER ACCEPTANCE

`run-browser-policy-acceptance.sh` 收到 SIGINT 并执行自身 synthetic 临时目录清理。结果为安全中止，不记为通过。

## BROWSER MIGRATION

未运行。

## SSH BLOCK

未运行。

## SSH ALLOW

未运行。

## DEADLINE SAFETY

停用沿用已有 15–1800 秒有界看门狗，没有无界持有 Endpoint Security 授权消息。

## NAMESPACE SAFETY

没有运行 namespace live acceptance。停止后 `/bin/cat /etc/hosts` 成功，普通 `/usr/bin/true` 启动成功。

## RESTART / UPDATE

系统级 active config 在管理员授权下原样改名为：

```text
/Library/Application Support/Sensitive Data Firewall/config.accidental-real-profiles-20260813.disabled
```

活动路径 `config.json` 已不存在。文件未被解析或读取，备份可恢复但不会被 Guard 自动加载。扩展当前等待重启完成卸载。

## FALLBACK STATUS

不需要 LaunchDaemon fallback。

## REMAINING LIMITATIONS

- 必须修复 GUI/验收流程，禁止 disposable acceptance 隐式采用自动发现的真实 profile
- 在安全配置修复通过 review 和非 live 测试前，不重新激活 Endpoint Security extension
- 后续重新激活前需要重启，清理系统扩展的 waiting-to-uninstall 状态

## FINAL STATUS

`REAL PROFILE ENROLLMENT DETECTED BEFORE PROBE; LIVE ACCEPTANCE ABORTED, EXTENSION DEACTIVATED, CONFIG QUARANTINED`

## TEST RESULTS

- 浏览器验收进程：SIGINT 中止，PASS（安全处置）
- Watchdog deactivation：PASS
- `guard-es` 进程不存在：PASS
- Guard extension enabled/active 标记均不存在：PASS
- active `config.json` 不存在：PASS
- 误登记配置原样 `.disabled` 隔离：PASS
- `/bin/cat /etc/hosts`：PASS
- `/usr/bin/true`：PASS
