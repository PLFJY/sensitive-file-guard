# Credential Scope Refactor 验证报告

日期：2026-08-31

基线提交：`1a3c3f6e538abe68510d8f4ec739cc1dddef0a81`

## 当前产品范围

| 资源 | Common | Strict |
| --- | --- | --- |
| Browser Cookies 与必要 sidecar | 保护 | 保护 |
| Saved Credentials | 保护 | 保护 |
| Credential-decryption Key Material | 保护 | 保护 |
| 支持的网站 origin storage | 不保护 | 保护 |
| 已登记 SSH 私钥 | 独立保护 | 独立保护 |

Open Tabs、Cloud Tabs、Tab Groups、Recently Closed Tabs、tab/session restore、History、Bookmarks、Reading List、普通浏览器 UI/导航状态和仅因属于扩展而存在的扩展状态不属于 File Shield 资源集合。

## 浏览器路径矩阵

- Chromium Common：profile-root `Cookies*`、`Network/Cookies*`、`Login Data*`，以及 user-data-root `Local State`。
- Chromium Strict：Common 加 `Session Storage/`、`Local Storage/`、`IndexedDB/`。
- Firefox/Zen Common：`cookies.sqlite*`、`logins.json`、`key4.db`。
- Firefox/Zen Strict：Common 加 `storage/`、`webappsstore.sqlite*`。
- Safari Common：默认与命名 profile 的 `Cookies.binarycookies`；Safari 密码由系统 Keychain 管理，不创建文件型密码资源。
- Safari Strict：Common 加 `WebKit/WebsiteData/Default/` 与 `WebKit/WebsiteDataStore/<profile>/Origins/`。

Safari `HTTPStorages` 与 WebKit website-data directory 是独立的路径类别；WebKit 公共 API 将 Local Storage、Session Storage 与 IndexedDB 明确定义为 website data 类型。因此 Strict 选择 WebKit website-origin storage，不选择 `HTTPStorages` 或 `WebExtensions`。依据：[WebKit NetworkProcess](https://github.com/WebKit/WebKit/blob/main/Source/WebKit/NetworkProcess/NetworkProcess.cpp)、[WKWebsiteDataRecord](https://github.com/WebKit/WebKit/blob/main/Source/WebKit/UIProcess/API/Cocoa/WKWebsiteDataRecord.h)。

## 平台机制

- Linux 只有 Scoped resource enforcement。Common/Strict 仅改变 classifier、registry 与 fanotify mark 的资源集合；fanotify、进程身份、inode/object identity、连续性、lease、topology watcher 与 Process Shield 算法未改。
- macOS 继续使用 Endpoint Security `AUTH_OPEN`/`AUTH_LINK`/`AUTH_RENAME`、target-path selection、资源身份、pending authorization、migration、SSH 与 Process Shield。变更仅收敛资源索引与选择范围。
- SSH read/load/confirmation 独立于浏览器保护等级，语义未改。

## 配置与界面

- portable config 提供 `browser_protection_level: common|strict`，字段缺失时为 `common`。
- macOS authoritative config schema 版本为 2；版本 1 输入在独立解析边界迁移为 Common，当前顶层、portable policy 与 allowlist 对象拒绝未知字段。
- Linux 配置只表达 Scoped 资源范围，顶层与 portable policy 的未知字段拒绝。
- GUI 提供 `Common (Recommended)` 与 `Strict`，并把 SSH 私钥作为独立区域显示。
- CLI/configuration metadata 显示当前 browser protection level。

## 验证结果

在 macOS host 上通过：

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
git diff --check
bash -n（本次修改的 shell harness）
python3 -m json.tool deploy/guardd-config.example.json
```

语义测试覆盖三套浏览器 classifier 的 Common/Strict 正向与负向矩阵、portable 默认值、macOS Safari target selection、动态 profile Cookie、配置迁移、未知审计类型隔离以及 `SavedCredentials` criticality。

Linux live/privileged verification **NOT RUN**：当前 host 是 macOS，无法执行 fanotify、systemd、polkit、CAP_SYS_ADMIN 或 Linux Process Shield 的原生验收。此状态不是 PASS 或 FAIL；Linux harness 只完成静态语法检查。

所有自动化验证只使用合成 profile 与临时 fixture，没有读取真实浏览器秘密或 SSH 私钥。
