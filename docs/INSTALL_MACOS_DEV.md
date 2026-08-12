# macOS 开发构建（历史参考）

> 当前构建和部署请先阅读[中文构建与部署手册](构建与部署手册.md)；本文件不是安装入口。

The development `Guard.app` contains the Endpoint Security extension, GTK
control center, authenticated XPC clients, pending helper, and browser/SSH
policy runtime. It is not distributable packaging. Live enforcement requires
either explicit SIP-off self-use certificate mode or optional formally
provisioned Apple mode, plus Full Disk Access.
It intentionally may retain Homebrew GTK dependencies and is not the release
artifact. See [the macOS release guide](INSTALL_MACOS_RELEASE.md) for the
self-contained hardened-runtime/notarization path.

Requirements:

- macOS 13 or newer;
- the active Xcode command-line toolchain and macOS SDK;
- Rust stable;
- GTK4 4.14+ and libadwaita 1.4+ development packages (Homebrew packages are
  acceptable for this development bundle).

Build an ad-hoc development bundle:

```sh
scripts/macos/build-dev-app.sh
scripts/macos/inspect-signing.sh
```

The result is `build/macos/Guard.app`. The development bundle may reference
Homebrew GTK dylibs. Runtime relocation belongs to the packaging phase. The
ad-hoc development bundle carries restricted entitlement templates but has no
certificate identity; do not treat it as a launchable SIP-on GUI smoke package.
Use the entitlement-free `LOCAL_SIGNING_ONLY=1` release mode for that purpose.

For a live self-use development candidate, keep SIP enabled while building and
use a certificate (never `SIGNING_IDENTITY=-`):

```sh
SELF_USE_SIP_OFF=1 \
SELF_USE_SIGNING_IDENTITY='Guard Local Development Certificate' \
SELF_USE_SIGNING_KEYCHAIN="$HOME/Library/Keychains/GuardSelfUse.keychain-db" \
scripts/macos/build-dev-app.sh
```

This runs the self-use safety gate and retains both restricted entitlements
without provisioning. Do not activate it until offline review and removal of
any previous Guard extension are complete. While SIP is enabled, inspect this
candidate with signing tools rather than launching it.

Bundle and signing inputs are external:

```sh
APP_BUNDLE_ID=com.example.Guard \
SYSTEM_EXTENSION_BUNDLE_ID=com.example.Guard.guard-es \
DEVELOPMENT_TEAM=ABCDE12345 \
SIGNING_IDENTITY='Developer ID Application: Example (ABCDE12345)' \
HOST_PROVISIONING_PROFILE='/secure/path/Guard.provisionprofile' \
EXTENSION_PROVISIONING_PROFILE='/secure/path/GuardES.provisionprofile' \
BUILD_PROFILE=release \
scripts/macos/build-dev-app.sh
```

No Team ID, certificate, or provisioning profile is stored in the repository.
When profiles are supplied, both are required and are copied only into the
generated bundle before inside-out signing.
The host entitlement template contains
`com.apple.developer.system-extension.install`; the extension template alone
contains `com.apple.developer.endpoint-security.client`.

Lifecycle diagnostics are exposed by the bundled GTK host executable:

```sh
build/macos/Guard.app/Contents/MacOS/Guard --system-extension-status
build/macos/Guard.app/Contents/MacOS/Guard --activate-system-extension
build/macos/Guard.app/Contents/MacOS/Guard --deactivate-system-extension
```

The product uses `OSSystemExtensionRequest`; it does not shell out to
`systemextensionsctl`. Self-use activation requires SIP off, developer mode,
the local certificate, correct placement, both final entitlements, user
approval, and Full Disk Access. Formal SIP-on activation instead requires Apple
provisioning. `codesign` output is only a prerequisite; neither path is an
enforcement pass until the live synthetic kernel tests succeed. An ad-hoc
bundle remains suitable for layout and diagnostics only.

Phase 03's real synthetic AUTH_OPEN allow/deny acceptance script is
`scripts/macos/run-es-poc.sh`. In self-use mode it requires the local signing
identity and explicit risk acknowledgement, but not provisioning profiles.
It creates only a temporary synthetic canary and never accesses browser or SSH
data.

Process identity, verified browser discovery, and the distinct macOS config
format are described in [the macOS identity/config guide](MACOS_IDENTITY_AND_CONFIG.md).
Authenticated XPC, its explicit Endpoint Security Mach service, exact signing
requirements, and the LocalAuthentication Allow gate are described in
[the macOS XPC/authorization guide](MACOS_XPC_AND_AUTHORIZATION.md).
The GTK status model, policy-switch semantics, SMAppService LaunchAgent, and
pending-only lifecycle are described in
[the macOS UI/user-agent guide](MACOS_UI_AND_USER_AGENT.md).
The browser AUTH_OPEN classifier, interactive migration runtime, audit events,
and FREAD-only lease behavior are described in
[the macOS browser-protection guide](MACOS_BROWSER_PROTECTION.md).
SSH private-key enrollment, manual read approval, short process-tree leases,
and the deliberately unsupported specialized agent shortcut are described in
[the macOS SSH-protection guide](MACOS_SSH_PROTECTION.md).
Hardlink/rename mediation, bounded alias repair, ES sequence-gap handling, and
semantic health counters are described in
[the macOS namespace/health guide](MACOS_NAMESPACE_AND_HEALTH.md).

Entitlement-independent SSH fixture validation uses a newly generated key only:

```sh
cargo build -p guardctl
scripts/macos/test-ephemeral-ssh-key.sh target/debug/guardctl
```

On an installed and activated self-use or provisioned test host, run
`scripts/macos/run-ssh-policy-acceptance.sh build/macos/Guard.app` for the real
Block/Allow/process-tree flow. The script refuses to continue when authenticated
XPC/Endpoint Security is unavailable and never selects a key from `~/.ssh`.

Run `scripts/macos/run-namespace-health-acceptance.sh` for disposable Chrome
hardlink, symlink, rename-out, parent-rename, status-counter, and real-browser
atomic-update regression checks. It has the same live-backend prerequisite
and exits 77 before fixture creation when that prerequisite is absent.
