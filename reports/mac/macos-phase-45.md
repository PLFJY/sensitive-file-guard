# macOS 阶段 45：防护扩展重复安装/更新提示

## 结论

重复点击不会被 Guard 静默当成“跳过”。macOS 收到的是同一 bundle identifier 的 activation request；当前桥接层明确返回 `OSSystemExtensionReplacementActionReplace`，因此包版本变化时会请求替换旧扩展。

## UI 修复

- Protection 页面按钮改为“安装/更新防护扩展”。
- 状态说明明确区分安装、替换更新、等待用户批准、需要重启和失败。
- 点击后等待生命周期回调，不再刚提交请求就立刻显示模糊的“已安装”。
- Active 状态只有在系统扩展生命周期回调确认后才显示为成功；不会因提交请求本身宣称更新完成。
- 文档补充重复点击的行为和验证命令。

## 测试

```text
cargo fmt --check                                      PASS
cargo test -p guard-ui -p platform-macos --all-features PASS
cargo clippy -p guard-ui -p platform-macos \
  --all-targets --all-features -- -D warnings          PASS
git diff --check                                        PASS
```

## 现场风险控制

本阶段没有调用系统扩展激活、没有重启、没有修改 SIP/TCC，也没有读取真实浏览器或 SSH 内容。新的 UI 只在用户点击按钮时提交更新请求。
