# macOS Phase 16 — Self-use activation and GUI readiness

## BASE HEAD

`aa8d84e`

## SIP STATUS

```text
System Integrity Protection status: disabled.
```

## SELF-USE APP INSTALLATION

The existing `/Applications/Guard.app` was an older Apple Development test
bundle and was preserved. The final local-certificate candidate was copied to:

```text
/Applications/Guard Self-Use.app
```

`codesign --verify --deep --strict` passed there. The app and nested extension
both show `Authority=Guard Local Development Certificate` and no Team ID.

## SYSTEM EXTENSION ACTIVATION

The first real activation request from the build directory failed with the
exact native diagnostic:

```text
App containing System Extension to be activated must be in /Applications folder.
```

No provisioning error was reported. After installing the separate self-use app
in `/Applications`, the same `OSSystemExtensionRequest` returned:

```text
system-extension state=UserApprovalRequired
diagnostic=system extension activation is awaiting user approval
```

Independent system evidence agrees:

```text
io.github.plfjy.SensitiveFileGuard.guard-es (0.1.0/1)
Guard Endpoint Security [activated waiting for user]
```

The Endpoint Security extension is not claimed active. It still needs ordinary
user approval in System Settings > General > Login Items & Extensions >
Endpoint Security Extensions. The settings pane was opened. System Extension
developer mode was also requested with the explicit privileged command; the
terminal is awaiting the owner's password entry.

## XPC IDENTITY

The self-signed GUI reached authenticated XPC transport and failed only because
no server is active:

```text
authenticated XPC request failed: Couldn’t communicate with a helper application.
```

It did not report the former no-Team-ID failure. This verifies the local
certificate XPC selection path is used before any live ES service exists.

## GUI ACTIVATION

The Protection page now shows the following self-use readiness facts:

- SIP status, with SIP disabled described as expected for self-use;
- developer-mode command/status guidance;
- extension and Full Disk Access state;
- a clear requirement that self-use extension installation starts from
  `/Applications`, not `build/`;
- the existing optional confirmation login item, distinct from protection.

The install action remains enabled for a SIP-off self-use app only when the
actual host entitlement is present and the bundle starts from `/Applications`.

## Tests

| Check | Result |
|---|---|
| `cargo fmt --check` | PASS |
| `cargo clippy -p guard-ui -p platform-macos --all-targets --all-features -- -D warnings` | PASS |
| `cargo test -p guard-ui -p platform-macos --all-features` | PASS — 77 tests |
| final local-certificate self-use build/verification | PASS |
| local-certificate GTK smoke | PASS |
| `/Applications` nested signature verification | PASS |
| live SystemExtensions request | PASS to `UserApprovalRequired`; approval pending |
| Docker | NOT STARTED |
| Linux tests | NOT RUN — outside scope |

## Next gate

Once the owner approves **Guard Endpoint Security** and completes
`sudo systemextensionsctl developer on`, verify active lifecycle, authenticated
XPC, and `es_new_client`. Only then run the synthetic AUTH_OPEN deny/allow
acceptance. No browser/SSH data has been accessed.
