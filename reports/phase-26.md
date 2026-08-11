# Phase 26 — interactive SSH private-key authorization

## Delivered

- Replaced the SSH read-then-network observation path with pre-read fanotify
  confirmation for ordinary protected SSH private-key reads.
- Added protocol v5 SSH pending request DTOs and Allow/Block resolution. Allow
  is protected by the non-cached `org.guardd.ssh-read-resolve` Polkit action.
- Added a bounded 60-second in-memory pending queue keyed by key, UID, and
  stable process root. Repeated reads join a request; block, close, timeout,
  reader exit, queue saturation, and suppression deny the held read.
- Added a ten-minute `SshReadAccessLease`, restricted to the exact key, UID,
  stable reader root, and its verified descendants. It is revocable and is
  revoked when its root exits.
- Kept the existing one-shot verified `ssh-add` / `ssh-agent` load lease as a
  separate exception.
- Removed active BPF/network incident/quarantine integration, its IPC/UI
  surface, configuration output, BPF build dependency, service capabilities,
  legacy docs, and the old privileged acceptance script. Legacy JSON with
  `ssh_behavior_window_secs` remains harmlessly ignored by serde.

## Verification

- `cargo fmt --check`
- `cargo test --workspace --no-fail-fast -q`
- `cargo clippy --all-targets --all-features -- -D warnings`

All completed successfully using repository synthetic fixtures only. The old
root-required BPF acceptance is intentionally removed; live fanotify/Polkit
desktop acceptance remains environment-dependent and was not claimed as run.
