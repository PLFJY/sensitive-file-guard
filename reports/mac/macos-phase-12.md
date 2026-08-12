# macOS Phase 12 — GUI-guided protection setup

## Outcome

The macOS GUI now owns the first-run protection setup flow instead of exposing
internal lifecycle terms as configuration. The Protection page presents, in
order:

1. the state of the protection system extension;
2. the state of Full Disk Access;
3. a GUI action to request extension installation from macOS;
4. a GUI action that opens the Full Disk Access settings pane; and
5. an optional, plainly named login item that opens Guard only when an
   authorization confirmation must be shown.

`Pending authorization helper` is no longer user-facing vocabulary. It is now
called `遇到确认请求时自动打开 Guard`; its description makes clear that it does
not install the extension or grant permissions.

The GUI checks the host app's `com.apple.developer.system-extension.install`
entitlement before enabling the installation action. A local-only build is
therefore told, in Chinese, that it can open the UI but cannot install the
Endpoint Security extension because it lacks Apple's provisioning authorization.
This is an explicit product limitation, not a user permission problem.

## Safety and behavior

- The app never attempts to modify TCC, SIP, or system-extension state behind
  the user's back.
- A provisioned release requests installation through Apple's
  `OSSystemExtensionManager`; macOS retains approval control.
- Opening Full Disk Access settings uses the standard System Settings URL and
  does not grant access automatically.
- No browser profile, cookie, saved password, or SSH private key was read.

## Tests

| Check | Result |
|---|---|
| `cargo fmt --check` | PASS |
| `cargo clippy -p guard-ui -p platform-macos --all-targets --all-features -- -D warnings` | PASS |
| `cargo test -p platform-macos -p guard-ui` | PASS — 75 tests |
| Objective-C bridge syntax (`clang -fsyntax-only -Wall -Wextra -Werror`) | PASS |
| `git diff --check` | PASS |
| Linux tests | NOT RUN — explicitly outside scope |
| Docker | NOT STARTED — explicitly prohibited |

## Host limitation observed

The available local signing identity is an Apple Development identity without
the Apple-approved Endpoint Security/system-extension provisioning profiles.
The currently produced `LOCAL_SIGNING_ONLY=1` app intentionally omits the
restricted entitlements, so it cannot install or activate the extension. The
new GUI makes that fact visible before the user attempts setup.
