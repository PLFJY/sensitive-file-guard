# macOS Phase 18 — Self-use safety gate and offline signed candidate

## BASE HEAD

`5bda6ae`

## PRODUCT TARGET

Prevent an unreviewed or pre-incident self-use artifact from reaching System
Extension activation, while retaining the local-certificate SIP-off path.

## SAFETY GATE

`scripts/macos/self-use-safety-gate.sh` now runs automatically for every
`SELF_USE_SIP_OFF=1` development or release build. It executes the relevant
macOS application/platform tests and clippy with warnings denied.

Only after the gate passes may a bundle contain:

```text
SAFETY_GATE=mac-auth-scope-v1
```

`verify-bundle.sh` requires the exact line. The GUI reads the signed marker and
disables “安装防护扩展” for an old or incomplete self-use bundle.

## BUILD MODES

- `LOCAL_SIGNING_ONLY=1`: entitlement-free packaging smoke, unchanged.
- `SELF_USE_SIP_OFF=1`: local certificate, restricted entitlements retained,
  safety gate mandatory.
- neither flag: formal provisioning/profile path, unchanged.

The release builder explicitly invokes its inner unsigned assembly with
`SELF_USE_SIP_OFF=0`; final self-use entitlements, marker and signing remain the
outer release builder's responsibility.

## DEVELOPMENT BUILD

The development builder now has an explicit self-use branch. It rejects ad-hoc
identity and `SKIP_SIGNING=1`, supports the dedicated local keychain, embeds the
current safety marker before signing, and signs nested code inside-out.

Offline artifact:

```text
build/macos-dev-safety-review/Guard.app
```

Deep signature, host entitlement, extension entitlement, marker and signing
inspection all passed. It was not copied into `/Applications` or activated.

## RELEASE BUILD

Offline self-contained artifact:

```text
build/macos-safety-review/Guard.app
build/macos-safety-review/Guard-0.1.0-arm64.zip
```

The final artifact passed recursive GTK dependency bundling, inside-out code
signing, `codesign --verify --deep --strict`, architecture/runtime checks and
packaging smoke. It was not copied into `/Applications` or activated.

## FINAL SIGNATURE EVIDENCE

```text
Host Identifier=io.github.plfjy.SensitiveFileGuard
Host Authority=Guard Local Development Certificate
Host TeamIdentifier=not set
Host entitlement=com.apple.developer.system-extension.install

Extension Identifier=io.github.plfjy.SensitiveFileGuard.guard-es
Extension Authority=Guard Local Development Certificate
Extension TeamIdentifier=not set
Extension entitlement=com.apple.developer.endpoint-security.client

Marker=SAFETY_GATE=mac-auth-scope-v1
```

No provisioning profile, local certificate, or private key was embedded.

## LIVE POC INTERLOCK

The live PoC refuses to proceed without an explicit typed acknowledgement:

```text
LIVE_ES_ACCEPTANCE=I_ACCEPT_SYSTEM_EXTENSION_RISK
```

Observed without acknowledgement:

```text
exit 2
refusing live Endpoint Security activation
```

Observed with acknowledgement while SIP is enabled:

```text
exit 77
System Integrity Protection status: enabled.
BLOCKED: self-use live ES acceptance requires SIP disabled
```

Both exits happen before fixture build, app installation or extension
activation.

## SYSTEM STATE

SIP remains enabled. `guard-es` is absent. Guard remains `terminated waiting to
uninstall on reboot`; reboot is required before a future live test.

## TEST RESULTS

```text
scripts/macos/self-use-safety-gate.sh
PASS: 115 tests (8 guard-es + 3 guard-notify + 4 probe + 16 UI +
                 15 guardctl + 69 platform-macos)

clippy for guard-es/guardctl/guard-notify/probe/UI/platform-macos
PASS with -D warnings

cargo fmt --check
PASS

sh -n on modified macOS scripts
PASS

git diff --check
PASS

self-contained release build and verification
PASS

development self-use build and signing inspection
PASS

Docker
NOT STARTED
```

## FINAL STATUS

`OFFLINE SELF-USE CANDIDATE VERIFIED; LIVE ACTIVATION REQUIRES OWNER REBOOT AND SIP-OFF`

No real browser data, session material or SSH private key was accessed.
