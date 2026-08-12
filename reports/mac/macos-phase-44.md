# macOS 阶段 44：通知进程与主服务生命周期统一

## 根因

实际运行的 `guard-notify` 来自废纸篓中的旧版 `Guard.app`，不是当前源码构建包。旧二进制包含 `/usr/bin/osascript`，并由 `top.plfjy.SensitiveFileGuard.guard-notify` 登录项继续运行，因此系统把通知显示为 Script Editor。

## 修复

- `guard-notify` 在 macOS 上不再包含通知发送逻辑；测试通知也只委托给同一包内的 `Guard.app`。
- `Guard.app` 负责原生 macOS 通知，通知正文只含进程名和资源类别元数据。
- 防护服务开关关闭时，统一注销 `guard-notify`；打开时才允许重新注册。helper 不再能脱离主服务独立轮询。
- 自用部署脚本替换应用前先停止旧的同标识 launchd helper，避免废纸篓旧包继续运行。
- 最终包校验拒绝包含历史 Script Editor/osascript 通知路径的 Guard 或 helper 二进制。

## 测试

```text
cargo fmt --check                                      PASS
cargo test -p guard-ui -p guard-notify -p platform-macos --all-features PASS
cargo clippy -p guard-ui -p guard-notify -p platform-macos \
  --all-targets --all-features -- -D warnings          PASS
git diff --check                                        PASS
```

## 现场清理

已停止当前用户会话中发现的旧 `top.plfjy.SensitiveFileGuard.guard-notify` 任务；没有删除废纸篓备份包。重新部署新包后，通知来源应为 Guard.app。

## 状态

阶段通过。未执行重启、SIP 修改、TCC 修改或真实敏感数据访问。
