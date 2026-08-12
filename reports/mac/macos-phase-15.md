# macOS Phase 15 — Local certificate self-use candidate

## BASE HEAD

`79a3536`

## PRODUCT TARGET

SIP-off self-use Endpoint Security candidate on the owner's arm64 Mac; no
Apple-managed Endpoint Security capability, provisioning profile, notarization,
or consumer-distribution claim.

## SELF-USE SIGNING MODEL

A dedicated local code-signing identity was created in the owner's private
Keychain:

```text
Guard Local Development Certificate
keychain: /Users/plfjy/Library/Keychains/GuardSelfUse.keychain-db
```

The identity's private key was not read, exported, committed, or bundled. The
dedicated keychain is in the current user's search list so `codesign` can use
it, and its random unlock password is stored only as a user login-keychain
item. This is not a system-wide trust installation.

The final self-use app and nested extension were signed by that exact local
certificate. Both report `TeamIdentifier=not set`, as expected for a local
self-signed identity. The XPC requirement chooses the new leaf certificate
SHA-1 + exact expected binary identifiers path, rather than Team ID or UID.

## EMBEDDED ENTITLEMENTS

System `codesign` inspection on the final artifact confirmed:

```text
Guard.app: com.apple.developer.system-extension.install = true
guard-es.systemextension: com.apple.developer.endpoint-security.client = true
```

`VERIFY_SIGNING_MODE=self-use scripts/macos/verify-bundle.sh` passed after the
local-certificate signing. The GTK smoke also passed with an isolated HOME.

## SIP PREFLIGHT

Observed:

```text
System Integrity Protection status: disabled.
```

The preflight passed artifact and SIP checks. System Extension developer mode
was requested with `sudo systemextensionsctl developer on`; the command is
waiting for the owner's administrator-password entry. No password was read or
recorded.

## SYSTEM EXTENSION ACTIVATION

An earlier entitlement-bearing artifact signed with the available Apple
Development identity was killed before Guard's lifecycle bridge ran
(`exit=137`). This is captured as a failed pre-developer-mode experiment, not
an activation success. The local-certificate candidate was built afterward and
awaits the developer-mode command before the real activation retry.

## Tests

| Check | Result |
|---|---|
| `cargo fmt --check` | PASS |
| macOS-target Clippy (`guard-es`, `guardctl`, `guard-notify`, `guard-test-probe`, `guard-ui`, `platform-macos`) | PASS |
| macOS-target tests | PASS — 106 tests before the final requirement syntax test; platform-macos rerun PASS — 62 tests including it |
| Release build of macOS binaries | PASS |
| self-use local-certificate Release build | PASS |
| final self-use bundle verification | PASS |
| isolated GTK smoke | PASS |
| Security.framework local-certificate requirement syntax test | PASS |
| full workspace Linux-target test/build on macOS | BLOCKED by unsupported fanotify/inotify APIs; Linux excluded from requested scope |
| Docker | NOT STARTED |

## Next gate

After the sudo developer-mode command completes, retry
`OSSystemExtensionRequest` with the final local-certificate candidate. Record
lifecycle API, `systemextensionsctl list`, XPC health, and only then run the
synthetic AUTH_OPEN deny/allow PoC.
