# MPS7 — Hardened Runtime / Entitlement Admission

## Status

PASS (code + offline mapping tests + native smoke against the deployed
guard-es binary).

## Repository

- HEAD: bc26dd03b8fb9e7d6540b4569f2ee256d4f743a3 (working tree changes only)

## Goal

Measure whether an enrolled browser executable's code-signing/runtime posture
materially weakens Process Shield.

## Changes

### Native bridge (`native/macos/code_signature_bridge.m/.h`)

- `guard_code_signature_runtime_inspect`: reads `kSecCodeInfoEntitlementsDict`
  from `SecCodeCopySigningInformation` (no shell/codesign parsing) and returns
  six boolean facts:
  - com.apple.security.get-task-allow
  - com.apple.security.cs.allow-dyld-environment-variables
  - com.apple.security.cs.disable-library-validation
  - com.apple.security.cs.disable-executable-page-protection
  - com.apple.security.cs.allow-unsigned-executable-memory
  - com.apple.security.cs.allow-jit

### `crates/platform-macos/src/code_signature.rs`

- `RuntimeEntitlementFacts` + `RuntimePosture` (Strong | Reduced |
  Unverifiable) + pure `posture_from_facts`:
  - Strong: verified entitlements, no security-relevant exception;
  - Reduced: any of the five security-relevant exceptions;
  - Unverifiable: no entitlements dictionary (unsigned/ad-hoc/inspection
    failure) — never silently trusted;
  - `allow-jit` alone is recognized as narrow/legitimate browser JIT and does
    NOT reduce posture.
- `RuntimePostureInspector` trait + `NativeCodeSignatureInspector` impl.
- `runtime_posture_of(path)` convenience.
- `guard_self_runtime_posture()`: inspects the running guard-es + the
  deployed Guard.app binaries for retained debug/task exceptions.

### `crates/platform-macos/src/config.rs`

- `MacBackendConfig::runtime_posture_report()`: enrolled browser executables
  + Guard self binaries. Metadata only; browsers with a documented required
  exception are REPORTED Reduced, never silently rejected.

## Security invariant added

```text
runtime posture (Strong | Reduced | Unverifiable):
    browser identity semantics unchanged
    Reduced/Unverifiable reported for health/diagnostics
    allow-jit != generic unsigned-executable-memory
    deployed Guard binaries must not retain get-task-allow etc.
```

## Tests

```text
cargo test -p platform-macos --lib code_signature (2 tests) PASS
cargo clippy --workspace --all-targets --all-features -- -D warnings PASS
```

New tests:
- `posture_mapping_is_deterministic` (Strong / Reduced per-exception /
  Unverifiable / allow-jit-is-not-reduced).
- `present_reasons_label_allow_jit_as_narrow`.

## Native security evidence

- Live smoke on this host:
  - `/usr/bin/true`, `/bin/ls` => Unverifiable (no entitlements dict) —
    correct semantics, never silently trusted.
  - deployed `guard-es` (running extension binary)
    => Strong (no get-task-allow / DYLD / library-validation exceptions
    retained) — the protection build is clean.
- Bridge uses Security.framework only; no `codesign` shell output in
  authoritative decisions.

## Compatibility evidence

- No browser was rejected for a Reduced posture; the model only reports.
  Real-browser observation happens in MPS11.

## Blockers

None.

## Security claims NOT made

- No claim that any real browser's posture was classified from live ES data
  yet (MPS11 metadata observation).

## Next phase readiness

- Posture facts are available for MPS8 health/UI surfacing.
