# macOS 阶段 46：审计日志 1000 条轮转

## 变更

- 在跨平台 `guard-audit` SQLite 写入器中加入全局保留上限 `MAX_PERSISTED_EVENTS = 1000`。
- 每次批量提交与插入在同一事务内清理旧事件，只保留最新 1000 条。
- 服务打开已有数据库时也立即执行一次清理，不必等待下一条事件写入。
- Linux 与 macOS 后端共用该实现，无平台特判。
- 写入队列满载时的 `audit_dropped` 语义不变：只丢弃新事件，不删除已保存的旧事件。

## 测试

```text
cargo fmt --check                                      PASS
cargo test -p guard-audit --all-features               PASS
cargo test -p guard-es -p platform-macos --all-features PASS
cargo clippy -p guard-audit -p guard-es -p platform-macos \
  --all-targets --all-features -- -D warnings          PASS
git diff --check                                        PASS
```

## 保留范围

轮转按整个审计数据库计算，不按 UID 分桶。SQLite 文件的逻辑记录数最多为 1000；删除记录后文件可能暂时保留已分配的磁盘页，不代表仍能查询到旧事件。没有读取真实浏览器数据或 SSH 私钥。

## 状态

阶段通过。Linux/macOS 共享审计保留逻辑已提交。
