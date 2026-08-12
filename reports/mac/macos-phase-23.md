# macOS Phase 23：本地证书 XPC 与同 UID 对抗验收

## BASE HEAD

`8629056bfb133d91a7ef8de4757d42ec2f38aaf1`

## PRODUCT TARGET

验证 `top.plfjy` 自用构建的控制平面仍以精确本地证书和精确 signing identifier 认证，SIP 关闭不允许同 UID 普通进程自行批准敏感操作。

## PREVIOUS BLOCKER

既有 `scripts/macos/test-xpc-auth.sh` 只接受带 TeamIdentifier 的 Apple Team 构建，无法实测 TeamIdentifier 为空的本地自签名模式。

## SELF-USE SIGNING MODEL

测试脚本现支持两条明确路径：

- Apple Team：保留既有 TeamIdentifier 行为
- 本地证书：必须显式提供 identity 和 Keychain，解析唯一有效 identity，并用最终代码签名 requirement 验证精确叶证书

本机本地证书：`E640217586EA797109605A205995F48BA53163B4`。

## SIP STATUS

SIP 关闭。本阶段不依赖 SIP 状态，也不激活 Endpoint Security。

## SYSTEM EXTENSION DEVELOPER MODE

上一阶段已启用；本阶段未修改。

## EMBEDDED ENTITLEMENTS

输入包为 Phase 21 已验证的 `build/macos-release/Guard.app`。测试复制扩展可执行文件并重新签名为无 entitlement 的临时 transport-only server；原始包及其 entitlement 未修改。

## XPC IDENTITY

实测通过：

- `top.plfjy.SensitiveFileGuard.guardctl` 可查询状态
- `top.plfjy.SensitiveFileGuard` GUI 可查询状态并完成空 pending snapshot
- `top.plfjy.SensitiveFileGuard.guard-notify` 可访问服务
- ad-hoc、同 UID probe 的 SSH Allow 请求在进入 handler 前被拒绝
- 同一本地证书、同 UID、但未列入白名单的 signing identifier 也被拒绝

允许的 client identifier 仍仅为 Guard、guardctl、guard-notify；server identifier 仍仅为 guard-es。

## SYSTEM EXTENSION ACTIVATION

未激活。transport-only `guard-es` 由临时用户 LaunchAgent 启动且没有 ES entitlement，测试完成后 bootout。`pgrep -x guard-es` 无残留进程。

## FULL DISK ACCESS

未触碰 FDA/TCC。

## ENDPOINT SECURITY CLIENT

本阶段刻意不运行 Endpoint Security client，仅验证 XPC transport。Phase 22 的隔离 ES PoC 保持 inactive。

## AUTH_OPEN SYNTHETIC DENY

未重复运行；Phase 22 已通过。

## AUTH_OPEN SYNTHETIC ALLOW

未重复运行；Phase 22 已通过。

## BROWSER ACCEPTANCE

未运行；下一阶段才可进入合成浏览器验收。

## BROWSER MIGRATION

未运行。

## SSH BLOCK

未运行真实 ES SSH fixture；本阶段只验证伪造 SSH Allow 控制请求无法穿过 XPC。

## SSH ALLOW

未运行。

## DEADLINE SAFETY

XPC 客户端仍使用有界请求超时；未改变 Endpoint Security deadline 逻辑。

## NAMESPACE SAFETY

未修改。

## RESTART / UPDATE

未运行。

## FALLBACK STATUS

不需要 LaunchDaemon fallback。

## REMAINING LIMITATIONS

- transport-only 测试不等于产品 System Extension 的完整 XPC/ES 联合运行验收
- 浏览器、迁移、SSH、实时 deadline、namespace、restart/update 仍待后续阶段
- Phase 22 PoC 注册行仍为 inactive、`terminated waiting to uninstall on reboot`

## FINAL STATUS

`LOCAL-CERTIFICATE XPC AUTHENTICATION AND SAME-UID ADVERSARIAL TEST ACCEPTED`

## TEST RESULTS

- `scripts/macos/test-xpc-auth.sh build/macos-release/Guard.app`：PASS
- 合法 Guard UI/CLI/helper XPC：PASS
- ad-hoc 同 UID SSH Allow 对抗：PASS（被拒绝）
- 同证书、错误 identifier、同 UID SSH Allow 对抗：PASS（被拒绝）
- `guard-notify` 500ms polling 5 秒：CPU time `0:00.02`，采样 CPU `0.0%`
- `cargo test -p platform-macos --all-features xpc::tests`：PASS（8 tests）
- `cargo clippy -p platform-macos --all-targets --all-features -- -D warnings`：PASS
- `cargo fmt --check`：PASS
- `sh -n scripts/macos/test-xpc-auth.sh`：PASS
- `git diff --check`：PASS
- 清理后无 `guard-es` 进程，普通 `/etc/hosts` 读取和 `/usr/bin/true`：PASS
