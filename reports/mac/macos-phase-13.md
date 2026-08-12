# macOS Phase 13 — End-user activation guide

## Outcome

Added [macOS protection enablement guide](../../docs/macOS保护启用指南.md).
It gives a GUI-only path for normal users:

1. install the formal `Guard.app` in `/Applications`;
2. click **安装防护扩展** in Guard;
3. approve the ordinary macOS prompt;
4. click **授予完全磁盘访问权限** and enable Guard in System Settings;
5. optionally enable the plainly named confirmation login item; and
6. configure reviewed resources, then enable the policy.

The guide makes the key boundary unambiguous: a grey install button that says
the bundle is a local test build means missing Apple provisioning, not a user
permission mistake. No local command, TCC edit, or SIP change can convert that
artifact into a live Endpoint Security product.

`INSTALL_MACOS.md` and the Chinese packaging/deployment guide now refer users
to this GUI flow and no longer direct normal activation through CLI lifecycle
commands.

## Tests

| Check | Result |
|---|---|
| `cargo fmt --check` | PASS |
| `cargo clippy -p guard-ui -p platform-macos --all-targets --all-features -- -D warnings` | PASS |
| `cargo test -p platform-macos -p guard-ui` | PASS — 75 tests |
| Local release build (`LOCAL_SIGNING_ONLY=1`) | PASS |
| Local bundle verification | PASS — `self-contained local-signed Guard.app verified for arm64` |
| Isolated GTK runtime smoke | PASS — `Guard bundled GTK runtime initialized` |
| `git diff --check` | PASS |
| Linux tests | NOT RUN — explicitly outside scope |
| Docker | NOT STARTED — explicitly prohibited |

## Scope boundary

The local package used for the runtime smoke is intentionally entitlement-free.
It proves the UI/package can launch, but cannot install or activate the system
extension. Live authorization remains blocked until a separately provisioned
Apple Endpoint Security release is available. No real browser data, cookies,
saved passwords, or SSH private keys were read.
