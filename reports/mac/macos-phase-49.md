# macOS 阶段 49：双端安全日志显示日期时间

## 变更

- Linux 与 macOS 共用的 Guard UI 日志行现在在每条事件标题前显示本地日期时间：`YYYY-MM-DD HH:MM:SS`。
- 原有事件 ID、决策、进程和资源信息保留不变。
- 时间戳格式化使用 GLib 标准本地时区转换，不新增平台专用代码。
- 异常时间戳使用“时间未知”兜底，不影响日志渲染。

## 测试

```text
cargo fmt --check                                      PASS
cargo test -p guard-ui --all-features                  PASS
cargo clippy -p guard-ui --all-targets --all-features \
  -- -D warnings                                       PASS
git diff --check                                        PASS
```

## 状态

阶段通过。未修改审计数据、系统扩展、SIP 或 TCC。
