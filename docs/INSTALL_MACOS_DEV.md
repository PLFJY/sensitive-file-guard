# macOS development build

Phase 02 provides a development `Guard.app` and Endpoint Security system
extension skeleton. It is not distributable packaging and does not yet enforce
file access.

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
BUILD_PROFILE=release \
scripts/macos/build-dev-app.sh
```

No Team ID, certificate, or provisioning profile is stored in the repository.
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
