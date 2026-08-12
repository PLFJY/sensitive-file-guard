# macOS 阶段 38：Protection 页面状态刷新

## BASE HEAD

`15412f3`

## 变更

- 删除 macOS Protection 页面“管理登录项”按钮；登录项只保留实际的启用/停用开关，不再提供没有实质帮助的系统设置跳转。
- 在主窗口 Overlay 中加入 Protection 页面右下角悬浮“刷新状态”按钮。按钮不属于滚动内容，因此页面上下滚动时始终固定在窗口右下角。
- 悬浮按钮调用完整状态刷新：daemon、策略、扩展、FDA、SIP、开发模式、entitlement、健康状态、事件、浏览器资源和 SSH Key 资源都会重新查询；它不复用“Refresh native browsers”动作。
- 删除无调用的登录项系统设置函数，保持 `-D warnings` 通过。

## 测试

通过：

```text
cargo fmt --check
cargo test -p guard-ui --all-features       # 19 passed
cargo clippy -p guard-ui --all-targets --all-features -- -D warnings
git diff --check
```

## 说明

按钮只在 Protection 页面显示；切换到 Overview 或 Security Log 时隐藏。点击期间按钮暂时禁用，避免重复查询；后台轮询仍保持原有两秒周期。

## FINAL STATUS

Protection 页面状态刷新入口已与浏览器扫描入口分离，UI 逻辑和 macOS 相关质量门通过。
