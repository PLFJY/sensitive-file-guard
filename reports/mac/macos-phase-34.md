# macOS 阶段 34：安全日志布局回归

## BASE HEAD

`2155ed0`

## 目标

修复 Security Log 页面中来自进程路径、资源路径和审计元数据的长文本把窗口无限向右撑大的问题。日志内容现在在列表行内部换行，并限制标题和副标题的可见行数；详细信息仍通过现有事件详情入口查看。

## 实现

- 统一历史日志和实时日志的行渲染逻辑。
- 标题使用按单词/字符换行，最多两行。
- 路径等副标题使用有限宽度、有限行数和中间省略。
- 日志元数据被视为不可信输入，不能改变顶层窗口尺寸。
- 增加 log 页面 UI layout smoke 覆盖，使用合成的超长路径，不读取真实敏感数据。

## 测试

通过：

```text
cargo fmt --check
cargo test -p guard-ui --all-features                 # 19 passed
cargo clippy -p guard-ui --all-targets --all-features -- -D warnings
git diff --check
BUILD_PROFILE=release SKIP_SIGNING=1 \
  MACOS_BUILD_ROOT="$PWD/build/macos-ui-test" \
  scripts/macos/build-dev-app.sh
scripts/macos/test-ui-layout.sh build/macos-ui-test/Guard.app
```

UI layout smoke 通过：Overview、Protection、Security Log 均保持 `800x560`，未出现横向无限扩展。

## 结论

安全日志布局修复通过 macOS UI 回归，可进入下一阶段的一键构建部署脚本和中文文档整理。
