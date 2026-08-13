# macOS 阶段 48：Safari 防护应用失败修复

## 根因

Safari 的资源布局跨越 `~/Library/Safari` 与 `~/Library/Containers/com.apple.Safari/Data/Library`，因此配置使用 `~/Library` 作为根目录，再由 Safari 专用分类器限制到两个精确子命名空间。原配置校验只按路径前缀判断浏览器根目录重叠，把 Safari 与 Chrome/Firefox 的合法组合错误拒绝，GUI 只显示了笼统的 `Apply failed`。

## 修复

- Safari 与其它浏览器根目录重叠时允许通过配置校验；非 Safari 浏览器之间仍保持重叠拒绝。
- Safari 资源索引的窄路径过滤保持不变，不会保护整个 `~/Library`。
- GUI 现在保留并显示真实应用错误，而不是只显示 `Apply failed`；失败后按钮可继续重试。
- 文档明确说明 Safari 根目录与实际保护命名空间的区别。

## 测试

```text
cargo fmt --check                                      PASS
cargo test -p platform-macos -p guard-ui --all-features PASS
cargo clippy -p platform-macos -p guard-ui \
  --all-targets --all-features -- -D warnings          PASS
git diff --check                                        PASS
```

## 状态

阶段通过。未读取真实 Safari 数据、未修改 TCC/SIP、未执行现场配置写入。
