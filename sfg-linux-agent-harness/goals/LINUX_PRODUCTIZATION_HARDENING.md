# Goal: LINUX_PRODUCTIZATION_HARDENING

## Invariants

- Do not rewrite Linux Platform Freeze evidence.
- Reassess freeze impact for every runtime or security-behavior change.
- Keep File Shield independent of optional Process Shield capability.
- Never widen an unsupported browser/kernel/platform scope through product
  wording. Process Shield is a narrow access-control boundary, not an EDR.

## Required outcomes

1. A normal-user Linux release build produces a checksum-verified artifact
   with all four product binaries, systemd/polkit/desktop integration, fixed
   permissions, and tested install/upgrade/downgrade/config/uninstall behavior.
2. Human `guardctl status`, browser enrollment/status, and events output use
   product-level language; JSON retains stable machine-readable diagnostics.
3. Only evidence-proven exact Firefox enrollment may request Process Shield or
   claim a live authentication-state authority admission.
4. Browser expansion remains a written per-family acceptance contract until
   each family has fresh File Shield and Process Shield evidence.
5. The macOS design reuses portable policy/audit/enrollment seams while keeping
   Endpoint Security, TCC, signing, and system-extension mechanisms in the
   macOS platform adapter.

Evidence and the current completion state are recorded in
`reports/linux/linux-productization-hardening.md`.
