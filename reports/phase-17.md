# Phase 17 — Defensive Browser Adversarial Harness

## Status

**IMPLEMENTED; NON-PRIVILEGED GATES PASS; PRIVILEGED AND DESKTOP ACCEPTANCE
PENDING.**

The implementation follows `00_GLOBAL_CONTRACT.md` and
`01_ARCHITECTURE_CONTEXT.md` from the user-supplied harness directory. No real
browser profile, password, Cookie, token, or SSH key was accessed. No test uses
IP networking.

## What was added

- `guard-test-probe` now provides transparent `read`, `mmap`, `sqlite`,
  `copy-read`, `child-read`, `proc-fd`, and authorized fd-holder probes.
- The only data-transfer probes use an AF_UNIX socket. They extract and send at
  most one `SDF_CANARY_*` token; they never send the whole source file or DB.
- `scripts/test-browser-adversarial-root.sh` creates unique disposable
  Chromium and Firefox profiles under `/tmp` with valid synthetic SQLite cookie
  DBs and session files.
- The root suite covers direct reads, mmap, SQLite, copy-then-read, symlink,
  hardlink, a real rename of the protected inode, child access,
  `/proc/PID/fd`, local-sink transmission, replacement Cookie inodes, and new
  nested session data.
- Copied and hash-enrolled synthetic browser executables provide the positive
  control: each browser can recover its own canary and can send it to the local
  sink.
- Every unauthorized PASS requires probe failure, absence of the canary, and a
  newly persisted audit DENY. A plain OS error with no audit event is not
  accepted as firewall enforcement.
- Audit/daemon output is scanned to ensure it contains no canary contents.
- `guard-notify` now logs a safe event-ID acknowledgement after `notify-send`
  succeeds. The harness uses it to distinguish desktop delivery from the
  already-proven kernel denial.
- The presenter starts before adversarial probes, baselines an empty audit log
  at event ID zero, and must deliver every audited DENY. `notify-send` stderr is
  preserved so a missing/broken desktop notification service is diagnosable.
- Topology refresh retains marked inode aliases, so a protected Cookie renamed
  to an undiscoverable filename still produces a classified audit DENY rather
  than only an unclassified fail-closed decision.
- `BrowserFamily` accepts the lowercase names used by the documented config
  and existing root suites (`chromium`, `firefox`, `zen`) while retaining its
  prior serialization format. A regression test parses the documented
  lowercase form; the new harness emits canonical enum names.

## Safety boundary

The suite refuses to run without root and `CAP_SYS_ADMIN`. It never discovers
standard browser locations and constructs its config exclusively from paths in
its unique `/tmp/guard-browser-adversarial.*` directory. Cleanup validates both
that prefix and a marker file before recursively deleting anything. The test
sink is an AF_UNIX socket in the same disposable directory. `KEEP_WORK=1` is an
explicit opt-in for retaining synthetic diagnostics.

## Run on the Arch acceptance host

Run from the active graphical user's shell so `SUDO_USER` identifies the user
whose D-Bus notification session should receive the popup:

```sh
sudo bash scripts/test-browser-adversarial-root.sh
```

Expected final output has `FAIL=0`. A complete desktop environment also has
`BLOCKED=0` and includes both:

```text
PASS: ordinary read: open denied, canary absent, audit DENY recorded
PASS: desktop notification delivered for a proven firewall DENY
```

If `/run/user/$UID/bus` or `notify-send` is unavailable, only the notification
row is BLOCKED; enforcement does not inherit a PASS from that result.

## Quality gates

Executed in this environment:

```text
bash -n scripts/test-browser-adversarial-root.sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test -p guard-test-probe
cargo test -p guard-notify
cargo test --workspace --all-features
```

Formatting and clippy passed. The full workspace ran **185 tests, 0 failed**;
that total includes 3 probe tests (including a valid synthetic SQLite DB) and
1 notifier test.

## BLOCKED privileged acceptance

Observed environment:

```text
id -u => 1000
/proc/self/status CapEff => 0000000000000000
bash scripts/test-browser-adversarial-root.sh
=> ERROR: root/CAP_SYS_ADMIN is required for FAN_OPEN_PERM enforcement.
```

Therefore no adversarial enforcement or desktop-notification row is claimed
as PASS in this report.
