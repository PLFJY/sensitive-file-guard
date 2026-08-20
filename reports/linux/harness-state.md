# Linux Harness State

## Goal and current phase

`LINUX_PLATFORM_FREEZE` is the active goal. The first sub-goal,
`RE-CLOSE LINUX_FILE_SHIELD_FREEZE`, is **restored at commit
`77dcd75edc3a10b95e4aa3051cd48fe29654e407`**. Process Shield work has not
started; Linux Platform Freeze is therefore not complete.

## Current File Shield verdict

**Linux File Shield implementation freeze: RESTORED.**

This verdict is based on a fresh physical-host run, not reconstructed or
back-filled evidence:

- host kernel: `Linux plfjy-arch 7.1.8-arch1-3 #1 SMP PREEMPT_DYNAMIC Tue,
  11 Aug 2026 09:16:08 +0000 x86_64 GNU/Linux`
- commit: `77dcd75edc3a10b95e4aa3051cd48fe29654e407`
- one-shot formal manifest:
  `/tmp/sfg-host-formal-77dcd75-20260820-210000/summary-oneshot.txt`
- result: **23 mandatory PASS, 0 FAIL, 0 BLOCKED**; native-browser observation:
  **1 PASS, 0 PARTIAL/FAIL/BLOCKED**.
- systemd current-head evidence:
  `/tmp/sfg-systemd-77dcd75-20260820-211000.log`, **13 PASS, 0 FAIL, 0 BLOCKED**.

The formal manifest derives its count from `scripts/linux/run-all-root-gates.sh`.
It includes P0 SSH mmap (configured strict, configured conservative, runtime
enrollment), topology overflow fail-closed, autonomous required-mark loss,
object-identity/zero-settle, and the earlier File Shield gates. The physical
host run used only synthetic profiles, loop-backed ext4 fixtures, and ephemeral
SSH keys; strict filesystem marks never targeted the root mount or tmpfs.

## Review closure evidence

- Status truthfulness: topology uncertainty or handle-index exhaustion makes
  File Shield `REDUCED` and prevents top-level `ACTIVE`; deterministic unit
  coverage is in `apps/guardd/src/ipc.rs`.
- Topology lifecycle: deleted/recreated protected directories are reconciled by
  live object identity; old removed marks do not permanently poison topology,
  while unexpected live mark loss remains sticky and fails closed.
- SSH pre-open boundary: `FAN_OPEN_PERM` is the authorization boundary. The
  three P0 cases prove Guard OFF same-UID mmap/read can recover the synthetic
  canary, and Guard ON denies before a readable fd is obtained, records target
  plus requester PID/UID/event, and recovers zero canary bytes.
- Capability handle parsing uses the aligned `ObjectHandle` representation;
  no typed dereference of a `Vec<u8>` buffer remains.
- `O_PATH` executable identity changes require re-enrollment where rehashing is
  unavailable; this is the safe documented contract, not a claimed rehash.

## Browser and capability scope

Firefox is the only accepted native browser family: the disposable-profile
host observation passed 8 checks with zero unexpected File Shield denials.
`firefox-esr`, Chromium, Google Chrome, and Zen were not installed and are
**NOT ACCEPTED**. This does not infer acceptance for Flatpak, Snap, network
filesystems, or untested browser variants.

## Residual limitations

- **LFH4 crash continuity is PARTIAL / REDUCED.** The current systemd gate
  proves service restart, mark reconstruction, stale-socket recovery, and
  fail-open after stop. The fdstore experiment's stored-group recovery works,
  but a permission event read before a daemon crash cannot be recovered through
  public UAPI. Do not describe this as accepted crash continuity.
- Process Shield is optional and still inventory-only. Its unsupported or
  disabled state must never weaken File Shield; its LPS0 probe is the next
  phase.
- Capsule fanotify results remain container-scoped evidence. The prior capsule
  formal run could not be used as final full evidence because nspawn exposes
  only loop0--2; later synthetic loop allocation selected an invisible loop3.
  The capsule boot path also blocked in `systemd-firstboot`. Those limitations
  are reported rather than treated as host-equivalent PASS.

## Release artifacts staged and tested

The release artifacts used by the physical-host run were built by the normal
user and staged separately. SHA-256:

| Artifact | SHA-256 |
|---|---|
| `guardd` | `71562e764802aa406adb7446f6dcb6a8a818857aa948ee8ba16eb8c1720b03e0` |
| `guardctl` | `8a7bfffb7f5af5595fa370931b4b34144703a7038751a1342030b1b80e3e196e` |
| `guard-test-probe` | `37a850e7c0b67a6ba037299d63fee4ced1f28dff49979296c2c74452db8b256c` |
| `guard-notify` | `a9a2cda718ae5e04acb282465bbbe7d7c8f9b0de72799e8384a90e523c1811c1` |
| `guard-fdstore` | `7fbe5968ae5aa4b6b77eacb87186199fc73919f55887aa81b722b9e48094ee0e` |
| `rename-burst` | `52d51f887f753a38f31eaa576145a799883cad8067a03ee490e67be2449a17e4` |

## Next action

Start `LINUX_PROCESS_SHIELD_FREEZE` at LPS0: probe actual host and capsule BPF
LSM capabilities and report supported, disabled, reduced, or blocked status
without degrading File Shield.
