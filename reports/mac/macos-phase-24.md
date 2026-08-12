# macOS Phase 24：交互验收长时自动卸载看门狗

## BASE HEAD

`c4249e54bea009ea60eb87a3f468eb924a64ce4c`

## PRODUCT TARGET

在正式浏览器、SSH 和 namespace 合成验收需要人工操作时，继续保持普通系统访问探测、有界运行和可靠卸载，不把短 PoC 的 90 秒限制变成绕过看门狗的理由。

## PREVIOUS BLOCKER

Phase 22 的看门狗最多只允许 180 秒，不足以完成 GUI 配置和人工确认。并且激活请求提交后，若等待激活或初始状态验证直接报错，旧实现可能在该错误路径返回而不由看门狗本身发起卸载。

## SELF-USE SIGNING MODEL

未改变。重新生成的 `top.plfjy.SensitiveFileGuard` 最终包仍由本地唯一 identity `E640217586EA797109605A205995F48BA53163B4` 签名。

## SIP STATUS

`System Integrity Protection status: disabled.` 本阶段没有激活任何扩展。

## SYSTEM EXTENSION DEVELOPER MODE

未修改。

## EMBEDDED ENTITLEMENTS

重新构建并以 `VERIFY_SIGNING_MODE=self-use` 检查最终包：宿主 install entitlement 和嵌套扩展 Endpoint Security entitlement 均保留，bundle verification 通过。

## XPC IDENTITY

未改变；本地证书和精确 `top.plfjy` identifier 认证保持不变。

## SYSTEM EXTENSION ACTIVATION

本阶段只改离线控制逻辑，没有提交激活请求。看门狗现在：

- 默认仍为 90 秒；显式范围扩大为 15–1800 秒
- 每 500 ms 执行普通文件和进程探测；单次 2 秒超时
- 激活请求一旦提交，激活等待失败、状态不是 Active、初始探测失败、持续探测失败、停止文件或正常超时，均汇合到同一个 deactivation 路径
- deactivation 必须获得原生 `Deactivated` 状态，否则返回组合错误而不宣称安全卸载

## FULL DISK ACCESS

未触碰 TCC/FDA。

## ENDPOINT SECURITY CLIENT

未启动。Phase 22 的 PoC 仍 inactive 且无 `guard-es` 进程。

## AUTH_OPEN SYNTHETIC DENY

未重复实时运行；Phase 22 已通过。

## AUTH_OPEN SYNTHETIC ALLOW

未重复实时运行；Phase 22 已通过。

## BROWSER ACCEPTANCE

尚未运行。现在具备最长 30 分钟且持续探测的有界会话基础。

## BROWSER MIGRATION

尚未运行。

## SSH BLOCK

尚未运行。

## SSH ALLOW

尚未运行。

## DEADLINE SAFETY

既有 Endpoint Security deadline 测试通过；新增的 2 秒普通系统访问看门狗超时独立于授权事件 deadline，不修改内核授权截止时间。

## NAMESPACE SAFETY

既有 namespace 测试通过；未改变分类或修复逻辑。

## RESTART / UPDATE

当前系统仍显示隔离 PoC `terminated waiting to uninstall on reboot`，因此遵守安全门，不安装或激活正式扩展。下一步必须正常重启清除此记录。

## FALLBACK STATUS

不需要 LaunchDaemon fallback。

## REMAINING LIMITATIONS

- PoC 待卸载注册记录必须重启清除
- 正式扩展联合 ES/XPC、浏览器、迁移、SSH、实时 deadline、namespace、restart/update 尚待验收
- 看门狗显著降低故障持续时间，但不能作出任何系统软件“100% 不故障”的绝对保证

## FINAL STATUS

`BOUNDED INTERACTIVE ACCEPTANCE WATCHDOG OFFLINE ACCEPTED; REBOOT STILL REQUIRED`

## TEST RESULTS

- `cargo test -p guard-ui --all-features`：PASS（19 tests）
- `cargo clippy -p guard-ui --all-targets --all-features -- -D warnings`：PASS
- `scripts/macos/self-use-safety-gate.sh`：PASS（121 tests）
- `SELF_USE_SIP_OFF=1 scripts/macos/build-release-app.sh`：PASS
- `VERIFY_SIGNING_MODE=self-use scripts/macos/verify-bundle.sh`：PASS
- `cargo fmt --check`：PASS
- `git diff --check`：PASS
- 系统扩展激活：NOT RUN（安全门要求先重启清除 PoC 待卸载记录）
