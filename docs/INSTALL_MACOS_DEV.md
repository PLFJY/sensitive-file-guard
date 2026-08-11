# macOS development build

The development `Guard.app` contains the Endpoint Security extension, GTK
control center, authenticated XPC clients, pending helper, and browser policy
runtime. It is not distributable packaging. Live enforcement still requires
Apple-approved Endpoint Security provisioning and Full Disk Access.

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
Homebrew GTK dylibs. Runtime relocation belongs to the packaging phase.

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
`systemextensionsctl`. Activation normally requires an Apple-approved Endpoint
Security entitlement, matching provisioning, proper signing, placement of the
app in an allowed location, user approval, and Full Disk Access. Direct
`codesign` output proves only that an entitlement claim was embedded; it does
not prove that Apple authorized that restricted entitlement. An ad-hoc bundle
is suitable for layout and diagnostics only and must not be reported as an
enforcement pass.

Phase 03's real synthetic AUTH_OPEN allow/deny acceptance script is
`scripts/macos/run-es-poc.sh`. It requires approved bundle IDs, matching host
and Endpoint Security provisioning profiles, and an explicit signing identity.
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
