# Linux Harness State

## Goal and current phase

`LINUX_PLATFORM_FREEZE` is **accepted for the documented REDUCED capability
scope**. Fresh physical-host evidence on implementation commit
`9673f6fcd6380447af307b8f7ecc13679d5fbc8d` re-closes File Shield and runs the
complete Process Shield 5-gate manifest. Process Shield remains truthfully
REDUCED/optional; this never weakens File Shield.

## Current File Shield verdict

**Linux File Shield implementation freeze: RESTORED.**

This verdict is based on a fresh physical-host run, not reconstructed or
back-filled evidence:

- host kernel: `Linux plfjy-arch 7.1.8-arch1-3 #1 SMP PREEMPT_DYNAMIC Tue,
  11 Aug 2026 09:16:08 +0000 x86_64 GNU/Linux`
- commit: `9673f6fcd6380447af307b8f7ecc13679d5fbc8d`
- one-shot formal manifest:
  `/tmp/sfg-platform-file-oneshot-9673f6fcd638/summary-oneshot.txt`
- result: **23 mandatory PASS, 0 FAIL, 0 BLOCKED**; native-browser observation:
  **1 PASS, 0 PARTIAL/FAIL/BLOCKED**.
- systemd current-head evidence:
  `/tmp/sfg-platform-file-systemd-9673f6fcd638/summary-systemd.txt`, **1
  mandatory PASS, 0 FAIL, 0 BLOCKED**, plus fdstore observation PARTIAL.

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
- Process Shield is optional. With `process_shield_enabled: true`, LPS3
  attaches a `ptrace_access_check` BPF LSM policy and admits an exact Firefox
  Main only from a pre-response File Shield WebStorage event. The current-head
  daemon-integrated oracle proves this full admission path for ptrace,
  `process_vm_readv`, `process_vm_writev`, and `/proc/PID/mem`; other paths
  remain NOT ACCEPTED. Its unsupported or disabled state never weakens File
  Shield. See `reports/linux/lps5-adversarial.md`.
- Capsule fanotify results remain container-scoped evidence. The prior capsule
  formal run could not be used as final full evidence because nspawn exposes
  only loop0--2; later synthetic loop allocation selected an invisible loop3.
  The capsule boot path also blocked in `systemd-firstboot`. Those limitations
  are reported rather than treated as host-equivalent PASS.

## Release artifacts built and tested

The release artifacts used by the physical-host run were built by the normal
user. The complete formal manifests also record `guard-es` and `guard-ui`.
SHA-256:

| Artifact | SHA-256 |
|---|---|
| `guardd` | `a8a69e9b53ca194767e4d172c83dde21d7b20f8c96ac809649405685dfc510c9` |
| `guardctl` | `b897232aa8435aab3dc47375830a0839a5601861ba6e0abf5d6737eecd66679b` |
| `guard-test-probe` | `182abd41d92cbe9fd6c1812b426bf3e7ac16abea939c45c17375f69918ad1569` |
| `guard-notify` | `5ea90bda7c024e5b5995a2f8f4c65c45ed96018424fbc3931880c604adfeab93` |
| `guard-fdstore` | `7fbe5968ae5aa4b6b77eacb87186199fc73919f55887aa81b722b9e48094ee0e` |
| `rename-burst` | `52d51f887f753a38f31eaa576145a799883cad8067a03ee490e67be2449a17e4` |

## Final cross-layer result

The current-head Process Shield manifest at
`/tmp/sfg-process-shield-final-9673f6fcd638/summary.txt` is **5 mandatory
PASS, 0 FAIL, 0 BLOCKED**. It includes Firefox/File Shield compatibility and
the daemon-integrated four-primitive causality gate. See
`linux-platform-freeze-final.md` for the exact accepted scope and residual
limits.
