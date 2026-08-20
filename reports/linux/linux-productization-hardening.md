# Linux Productization & Hardening

Date: 2026-08-21  
Freeze baseline: `9de6629c4d1d163b703dcc732bd1ce249cbbf530`  
Status: release engineering and the requested P1/P2 productization scope are implemented and verified.

This report is new productization evidence. It does not amend, replace, or
back-fill any Linux Platform Freeze report.

## Release engineering

- `.github/workflows/linux-release.yml` runs formatting, workspace clippy,
  workspace tests, desktop/AppStream validation, a clean-tree release build,
  and the complete offline install lifecycle before uploading the artifact.
- `packaging/linux/build-release.sh` produces a reproducible, per-file
  checksum-verified `tar.gz` containing `guardd`, `guardctl`, `guard-ui`, and
  `guard-notify`. The fixed payload targets `/usr/bin`, `/usr/lib`, and
  `/usr/share`; release builds run as a normal user.
- The artifact records the source commit and refuses either a dirty formal
  build or a release label that differs from the version embedded by Cargo.
- `install.sh` verifies the bundle before acting, validates an existing config
  with the candidate `guardctl` before the first destination write, preserves
  `/etc/guardd` and `/var/lib/guardd`, refuses implicit downgrade, and verifies
  installed content plus permissions.
- `tests/check_linux_packaging.sh` passed install, permission/layout checks,
  content/mode tamper detection, upgrade, config/audit preservation, downgrade
  refusal, explicit compatible downgrade, incompatible-future-config refusal,
  verification, and uninstall preservation.

## User-facing security model

- Human `guardctl status` reports only product states for File Shield, Process
  Shield, browser authority, and enabled SSH keys. Kernel-specific details stay
  in the JSON diagnostic contract.
- Process Shield remains optional and narrow: an attached shield is reported
  `REDUCED`, never as a complete process security/EDR boundary. Definitively
  missing BTF/BPF LSM is `UNSUPPORTED`; unreadable capability state is not
  falsely promoted to `UNSUPPORTED`.
- Only exact native Firefox is shown as accepted. Firefox ESR, Chromium,
  Chrome, Zen, sandboxed packages, and untested layouts remain NOT ACCEPTED.

## Enrollment and audit experience

- `guardctl setup --process-shield` requires a reviewed native Firefox
  enrollment. After the user confirms the generated configuration, the first
  real allowed File Shield authentication-state access admits only that exact
  live Firefox instance.
- `guardctl browser status` reports that exact-instance lifecycle and uses the
  product wording: “This Firefox instance is trusted for authentication state
  access.” A stale PID/start-time event cannot claim a live admission.
- The admission is persisted as a metadata-only,
  `process_shield_authority_admitted` audit event through the existing bounded,
  non-blocking audit queue. No secret content is recorded.
- Human `guardctl events` classifies protected-file denials, admitted browser
  authorities, Process Shield blocks, topology degradation, and continuity
  loss. `guardctl --json events` retains the stable machine-readable event
  contract.

## Freeze-impact assessment

The authorization policy, fanotify decision boundary, BPF hook/program/map
contents, protected-resource classification, and allow/deny ordering were not
changed. The runtime change is a post-admission metadata audit record plus
truthful status derivation; its queue is non-blocking. File Shield status is
still derived independently of optional Process Shield support.

Because admission-path code changed, the daemon-integrated LPS5 gate was rerun:

- Capsule: Guard OFF succeeded for ptrace, `process_vm_readv`,
  `process_vm_writev`, and `/proc/PID/mem`; Guard ON was **BLOCKED** at libbpf's
  trivial program probe with `EPERM`. This is recorded only as a container
  limitation, never as host-equivalent evidence.
- Physical host, explicitly user-authorized polkit command:

  ```sh
  pkexec env TEST_USER=plfjy \
    BIN_DIR=/home/plfjy/sensitive-file-guard/target/release \
    LPS5_DAEMON_ORACLE=/home/plfjy/sensitive-file-guard/target/lps5/lps5-daemon-oracle \
    bash /home/plfjy/sensitive-file-guard/scripts/linux/test-lps5-daemon-integrated-root.sh
  ```

  The script used an isolated loop-backed ext4 fixture (`st_dev=1792`) while
  `/` was `st_dev=66314`. All four Guard OFF canary recovery baselines passed;
  all four Guard ON operations were denied with zero canary recovery; each
  denial and its exact authority admission had persisted requester/target
  attribution. Final result:
  `LPS5_DAEMON_INTEGRATED_ADMISSION_AND_ADVERSARIAL_MATRIX=PASS`.

No real browser profile, credential, cookie, token, password, or SSH private key
was read or copied.

## Other acceptance evidence

- `cargo fmt --all -- --check`: PASS
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`: PASS
- `cargo test --workspace --all-features`: PASS
- `git diff --check`: PASS
- `tests/check_linux_packaging.sh`: `LINUX_RELEASE_LIFECYCLE=PASS`
- `desktop-file-validate`: PASS
- `appstreamcli validate --no-net`: PASS

The browser-family expansion plan is
`docs/linux-browser-acceptance-contract.md`; it does not implement or accept a
new browser. The portable/non-portable seams, Endpoint Security authorization
boundary, TCC/system-extension lifecycle, and signing model for a future macOS
backend are documented in `docs/macos-architecture.md` without copying Linux
fanotify/BPF architecture.
