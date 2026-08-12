# macOS 阶段 43：通知职责收归 Guard.app

## 变更

- macOS `Guard.app` GUI 轮询新的审计拒绝事件并调用原生通知桥。
- `guard-notify` 在 macOS 上只发现 pending 请求、唤起 Guard，不再发送拒绝或确认通知。
- 保留 `guard-notify --test-notification` 作为兼容诊断入口，但正常事件通知不再由它发送。
- 通知正文只包含进程 basename 和资源类型代码，不包含路径、Cookie、密码、数据库行或 SSH 私钥内容。
- Linux 通知服务逻辑未修改。

## 测试

```text
cargo fmt --check                                      PASS
cargo test -p guard-ui -p guard-notify --all-features  PASS
cargo clippy -p guard-ui -p guard-notify \
  --all-targets --all-features -- -D warnings          PASS
git diff --check                                        PASS
```

## 状态

阶段通过。重新构建并启动新的 `Guard.app` 后，macOS 拒绝/确认通知应显示为 Guard 进程发送；旧版正在运行的 `guard-notify` 需随新包更新后退出并重新注册。
