# Install and validate Sensitive Data Firewall on macOS

## Current status

The macOS implementation is **FUNCTIONALLY COMPLETE / SECURITY ACCEPTANCE
BLOCKED** on the recorded Mac16,12 arm64 host running macOS 26.6.1. Do not call
this build security-accepted until a provisioned release app passes the real
Endpoint Security, Full Disk Access, browser, SSH, namespace, and performance
matrix with System Integrity Protection enabled.

The current host can build and launch a self-contained arm64 app, verify its
nested signatures, run authenticated-XPC/self-approval tests, and test local
updates/recovery. It cannot complete release acceptance because it has only an
Apple Development identity, lacks matching Apple Endpoint Security provisioning
profiles/notary credentials, has no active FDA-authorized extension, and SIP is
currently disabled.

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

## Release installation

1. Build with a Developer ID Application identity and separate matching host
   and Endpoint Security provisioning profiles as documented in the release
   guide.
2. Notarize and staple with the external Keychain-profile flow.
3. Place the stapled `Guard.app` in `/Applications`.
4. Launch Guard and request system-extension activation through the UI.
5. Complete ordinary System Settings approval if requested.
6. Grant Full Disk Access through System Settings when Guard reports
   `REQUIRES_FULL_DISK_ACCESS`.
7. Register the pending helper with its separate SMAppService switch.
8. Enroll only reviewed profiles/keys, then enable policy after authenticated
   product health reports active enforcement.

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
