# macOS 阶段 47：确认请求重新唤起 Guard.app

## 根因与修复

旧逻辑由 `guard-notify` 直接执行 `Contents/MacOS/Guard --pending-only`。当用户已经关闭 Guard 窗口、但应用仍由 macOS 的 `GApplication`/LaunchServices 管理时，直接执行嵌套 Mach-O 不一定会把现有应用实例重新激活；如果应用进程已退出，也没有走标准应用启动路径。

现在 pending helper 检测到新的确认请求后，使用：

```text
/usr/bin/open -a <当前 Guard.app bundle>
```

由 LaunchServices 负责启动或激活正确的 Guard.app。路径作为单独参数传递，包含空格的安装路径不会被拆分。测试通知入口仍保留直接调用 Guard 二进制，因为它需要同步返回测试结果。

## 测试

```text
cargo fmt --check                                      PASS
cargo test -p guard-notify -p guard-ui --all-features  PASS
cargo clippy -p guard-notify -p guard-ui \
  --all-targets --all-features -- -D warnings          PASS
git diff --check                                        PASS
```

新增测试覆盖 `/Applications/Guard Test.app` 这类带空格路径，以及非法 bundle 路径拒绝。

## 状态

阶段通过。未启动真实确认请求、未修改系统扩展、未修改 TCC 或 SIP；重新部署新包后生效。
