# Install and validate Sensitive Data Firewall on macOS

## Current self-use target

macOS support is currently **self-use / experimental**. Its primary path is an
owner-controlled Mac with System Integrity Protection (SIP) disabled, a local
Guard signing certificate, System Extension developer mode, normal Full Disk
Access approval, and synthetic acceptance fixtures. This is an intentional
tradeoff: it is not a notarized, SIP-on, zero-configuration consumer product.

SIP is disabled only manually from macOS Recovery. Guard never changes SIP,
TCC, or Secure Boot. Disabling SIP reduces macOS global protection, so use this
mode only on a Mac you control and do not treat it as a distributable release.

## Self-use SIP-off setup

Run these commands from the repository root. Do not use real browser profiles,
cookies, passwords, sessions, or SSH keys for acceptance.

1. In macOS Recovery, run `csrutil disable`, then reboot. Guard cannot do this
   step for you. Verify after login:

   ```sh
   csrutil status
   ```

2. Enable System Extension developer mode once (this requires your macOS
   administrator password):

   ```sh
   sudo systemextensionsctl developer on
   ```

3. Create a private local signing identity. It creates no repository file and
   stores the certificate/private key only in your user Keychain:

   ```sh
   scripts/macos/create-self-use-signing-identity.sh
   ```

4. Build the entitlement-bearing self-use app:

   ```sh
   SELF_USE_SIP_OFF=1 \
   SELF_USE_SIGNING_IDENTITY='Guard Local Development Certificate' \
   SELF_USE_SIGNING_KEYCHAIN="$HOME/Library/Keychains/GuardSelfUse.keychain-db" \
   CODESIGN_TIMESTAMP=none \
   scripts/macos/build-release-app.sh
   ```

5. Verify the final signed artifact and platform preconditions, then open it:

   ```sh
   scripts/macos/self-use-preflight.sh build/macos-release/Guard.app
   open build/macos-release/Guard.app
   ```

6. In Guard's Protection page, click **安装防护扩展**, approve the normal
   macOS prompt, grant **完全磁盘访问**, optionally enable the confirmation
   login item, configure synthetic resources first, and finally enable policy.

The self-use build keeps `com.apple.developer.system-extension.install` on the
host and `com.apple.developer.endpoint-security.client` on the nested extension.
Its authenticated XPC path pins the exact local signing certificate plus the
expected Guard client identifiers; same-UID processes cannot self-approve.

## 先在本机打开

如果目标只是打开 macOS 界面，在仓库根目录复制执行：

```sh
SIGNING_IDENTITY='Apple Development: zero_plfjy@icloud.com (ZN9S86U87M)' \
DEVELOPMENT_TEAM='YSGFZUQGW6' \
LOCAL_SIGNING_ONLY=1 CODESIGN_TIMESTAMP=none \
scripts/macos/build-release-app.sh

open build/macos-release/Guard.app
```

如果提示无法打开，运行：

```sh
VERIFY_SIGNING_MODE=local \
scripts/macos/verify-bundle.sh build/macos-release/Guard.app
```

必须看到 `PASS: self-contained local-signed Guard.app verified`。请打开
`build/macos-release/Guard.app`，不要直接打开 zip。这个本地包只验证 GTK/UI
启动，不能激活 Endpoint Security 或代表正式安全验收。

## Choose the build path

- [Development build](INSTALL_MACOS_DEV.md): may resolve GTK from Homebrew and
  is suitable for compile, layout, transport, and UI development. It is not a
  distributable or security-accepted artifact.
- [Release build](INSTALL_MACOS_RELEASE.md): self-contained GTK/libadwaita,
  hardened runtime, explicit nested signing, scoped profiles/entitlements,
  update/recovery tooling, and external-credential notarization.

The locally generated test artifact is:

```text
build/macos-release/Guard.app
build/macos-release/Guard-0.1.0-arm64.zip
```

`LOCAL_SIGNING_ONLY=1` output is deliberately entitlement-free so AMFI can run
it without provisioning profiles. It tests packaging, not Endpoint Security.
Use `SELF_USE_SIP_OFF=1` above for the entitlement-bearing self-use candidate.

## Optional future formal release

For an eventual SIP-on distributable sequence, follow the Chinese
[macOS protection guide](macOS保护启用指南.md). The GUI now requests
system-extension installation, opens the Full Disk Access pane, and explains
whether a local test build lacks the Apple authorization required to continue.

Future release publishers must build with a Developer ID Application identity,
matching host/Endpoint Security provisioning profiles, then notarize and staple
before distributing `Guard.app`. An end user cannot repair a missing restricted
entitlement by granting more local permissions.

Guard never edits TCC, disables SIP/Secure Boot, shells out to
`systemextensionsctl`, or silently modifies shell profiles. The CLI remains at
`/Applications/Guard.app/Contents/MacOS/guardctl`.

## Safe final acceptance

Keep normal security enabled and run the preflight before creating any
fixtures:

```sh
scripts/macos/preflight-final-acceptance.sh /Applications/Guard.app
```

The preflight creates a dedicated disposable root, verifies the bundle and GTK
runtime, records SIP/lifecycle/XPC/helper evidence, and exits 77 if the real
platform boundary is unavailable. Only after it passes, run the printed
interactive scripts. Those scripts use temporary browser profiles and a newly
generated ephemeral SSH key. Never enroll a normal profile under
`~/Library/Application Support` or a real key under `~/.ssh` for acceptance.

The authoritative executed matrix and blockers are in
[the Phase 11 report](../reports/mac/macos-phase-11.md).

## Diagnostics, update, and removal

Use metadata-only diagnostics:

```sh
scripts/macos/diagnose.sh /Applications/Guard.app
```

Updates replace the app/extension while preserving the root-owned product
configuration and audit database. Pending operations, process ancestry, and
temporary leases are memory-only and do not survive extension replacement.
Protocol mismatches fail explicitly.

Before removal, disable policy and inspect the recoverable plan:

```sh
GUARD_APP=/Applications/Guard.app \
scripts/macos/uninstall-recovery.sh \
  --dry-run --preserve-data --remove-app --confirm
```

The normal path unregisters the user helper, requests extension deactivation,
and moves the app to Trash. Product config/audit data is preserved by default.
The explicit removal option targets only exact product state paths; browser
profiles and SSH keys are never deletion targets.
