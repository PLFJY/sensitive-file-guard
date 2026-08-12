# macOS 阶段 40：进程身份路径稳定性

## 目标

修复 Endpoint Security 在同一审计进程键下因等价路径表示差异（例如符号链接或 `/var` 与 `/private/var`）触发全局降级的问题。

## 修改

- `MacProcessFacts::stable_id` 在比较前规范化可执行路径。
- 启动时间、设备号、inode、UID 仍是强制身份字段，任何真实变化继续失败关闭。
- 增加带空格路径和符号链接别名的回归测试。

## 测试

```text
cargo fmt --check                         PASS
cargo test -p platform-macos identity::tests --all-features  PASS (8)
```

## 安全边界

此修改只消除同一文件的路径拼写差异，不按进程名、UID 或 basename 放行，也不会扩大非受保护路径的授权范围。

## 状态

阶段通过。真实 SIP-off Endpoint Security 运行状态仍需在用户机器上重新加载构建包后验证。
