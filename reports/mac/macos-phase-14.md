# macOS Phase 14 — SIP-off self-use signing foundation

## BASE HEAD

`4fb218ed4dff553ad1501942501964ab83c728bb`

## PRODUCT TARGET

Self-use / experimental macOS Endpoint Security on an owner-controlled Mac with
SIP disabled. This phase does not claim notarization, SIP-on distribution, or
Apple-managed Endpoint Security approval.

## Build modes

`build-release-app.sh` now has three explicit, mutually exclusive modes:

| Mode | Entitlements | Profiles | Purpose |
|---|---|---|---|
| `LOCAL_SIGNING_ONLY=1` | omitted | none | UI/runtime packaging smoke only |
| `SELF_USE_SIP_OFF=1` | host + ES retained | none | local live-ES candidate |
| neither | scoped host + ES retained | required | future formal release |

`SELF_USE_SIP_OFF=1` requires `SELF_USE_SIGNING_IDENTITY`; it produces a
self-contained app with a sealed `SELF_USE_SIP_OFF.txt` marker and does not
silently reuse the entitlement-free smoke semantics.

## Embedded entitlements

The final self-use artifact was built with the available local Apple Development
identity and no provisioning profiles. System `codesign` inspection of the
final signed binaries showed:

```text
Guard.app: com.apple.developer.system-extension.install = true
guard-es.systemextension: com.apple.developer.endpoint-security.client = true
```

`VERIFY_SIGNING_MODE=self-use scripts/macos/verify-bundle.sh` passed and
confirmed that profiles are absent, helper binaries have neither restricted
entitlement, and the runtime is self-contained arm64.

## XPC identity

The Security.framework signature inspector now retrieves the leaf certificate
SHA-1 from the signed executable. Authenticated XPC accepts either:

- the existing Apple Team + expected signing identifiers; or
- one exact local leaf certificate SHA-1 + the exact expected Guard,
  `guardctl`, and `guard-notify` identifiers.

The local mode does not trust UID alone, an identifier alone, a cdhash, or a
different local certificate. A rebuild signed by the same certificate remains
the same local product identity even though its cdhash changes.

`scripts/macos/create-self-use-signing-identity.sh` creates a minimal local
`Guard Local Development Certificate` identity in the login keychain when one
is needed. Its key is not committed, exported by the build, or bundled.

## SIP and developer mode

Observed host evidence:

```text
System Integrity Protection status: disabled.
```

The new self-use preflight validates the final artifact and SIP state. Current
macOS exposes no read-only `systemextensionsctl developer status` form; it
therefore prints the exact manual command rather than guessing state:

```text
sudo systemextensionsctl developer on
```

## Tests

| Check | Result |
|---|---|
| `cargo fmt --check` | PASS |
| `cargo clippy -p guard-ui -p platform-macos --all-targets --all-features -- -D warnings` | PASS |
| `cargo test -p platform-macos -p guard-ui` | PASS — 76 tests |
| native Security bridge (`clang -fsyntax-only -Wall -Wextra -Werror`) | PASS |
| shell syntax for self-use scripts | PASS |
| self-use Release build | PASS |
| final self-use bundle verification | PASS |
| `git diff --check` | PASS |
| Docker | NOT STARTED |
| Linux commands | NOT RUN — outside requested scope |

## Next gate

Enable System Extension developer mode with the explicit privileged command,
run self-use preflight, then submit a real activation request. The result must
be recorded from both Guard lifecycle state and `systemextensionsctl list`
before any synthetic AUTH_OPEN acceptance is claimed.
