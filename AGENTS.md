# AGENTS.md — Sensitive Data Firewall

## Mission
Prevent unauthorized local processes from reading protected local secrets
(browser session/auth data + SSH private keys) **before** the protected file is
successfully opened. This is an access firewall, not an antivirus/EDR/DLP.

## Engineering style (KISS)
- No speculative framework architecture. No ManagerFactoryStrategy chains.
- No microservices. No custom crypto. No custom database engine.
- No pointless unit-test explosion. Every abstraction must remove real
  duplication or isolate an OS boundary.
- Plain Rust enums/structs/traits. `thiserror`/`anyhow` at boundaries.
- `serde` + JSON for low-volume local IPC/config. SQLite only when queryable
  persisted state is actually useful.
- No `unsafe` outside OS/FFI boundaries unless justified in a SAFETY comment.
- Comments explain non-obvious invariants, not obvious syntax.

## Security & testing rules
- NEVER use, read, or export the developer's real browser cookies, saved
  passwords, session tokens, or SSH private keys.
- Integration tests MUST use only synthetic browser-profile fixtures and
  ephemeral test SSH keys (see `guard-test-fixtures`).
- No test may upload secrets to a remote server. No "stealer" test may contain
  network exfiltration. Probes only attempt local open/read/copy on fixtures.
- Do not weaken system security globally to make a test pass. Do not silently
  disable Secure Boot/SIP/SELinux/AppArmor.
- Audit logs must NEVER contain secret contents (no cookie values, passwords,
  key bytes, browser DB rows, or private-key material).

## PRIVILEGED LIVE-TEST ENVIRONMENT — systemd-nspawn CAPSULE (use this for root)

A dedicated unattended privileged `systemd-nspawn` test capsule runs on the
host. It is the default privileged/live Linux test environment. The narrowly
scoped, explicitly user-authorized polkit fallback below is the only exception.

- **Default to the capsule for every privileged live test.** A physical-host
  privileged test is permitted only when the user explicitly authorizes it
  because a capsule namespace/seccomp/capability difference prevents a final
  conclusion. Use `pkexec`/polkit for that one reviewed command; never ask for,
  receive, cache, or pipe a password, and never use `sudo -S`. Record the exact
  host command, the capsule limitation that required it, and keep host and
  capsule evidence separate. The normal host-side privileged entrypoint remains
  `sudo -n /usr/local/sbin/sfg-test-capsule`.
- **Development stays on the host as the normal user**: source editing, `cargo
  build`, normal unit tests, and repository operations never move into the
  capsule.
- Discover paths / status with `sudo -n /usr/local/sbin/sfg-test-capsule paths`
  and `sudo -n /usr/local/sbin/sfg-test-capsule status`.
- One-shot privileged tests: `sudo -n /usr/local/sbin/sfg-test-capsule run CMD
  [ARGS...]`. Tests needing a real systemd PID 1: `... boot`, then
  `... exec CMD [ARGS...]`; shut down with `... stop`; reset the writable
  synthetic filesystem with `... reset-work`.
- The staging directory is writable by the normal host user: build artifacts on
  the host, then copy ONLY runtime artifacts, test scripts, configs, synthetic
  fixtures/templates, and service files into staging. **Never bind or copy the
  real user browser profile, SSH private keys, password stores, tokens,
  cookies, or other real secrets.**
- Inside the capsule: `/stage` is a read-only view of staged artifacts;
  `/testfs` is the writable synthetic test filesystem — ALL destructive and
  adversarial filesystem tests operate there unless a test explicitly proves
  another location is technically required.
- The capsule uses the HOST Linux kernel (real `CAP_SYS_ADMIN`, permission
  events, filesystem marks, pidfd, object handles). The capsule's nspawn
  seccomp allow-list is `--system-call-filter=fanotify_init fanotify_mark
  pidfd_getfd` (installed 2026-08-20; fanotify was previously EPERM-blocked).
  Do NOT automatically treat a capsule result as equivalent to every host
  deployment: if a result may depend on PID/mount namespaces, nspawn
  restrictions, nspawn seccomp/kernel-interface restrictions, BPF LSM
  availability, or another container-specific difference, explicitly
  investigate it and downgrade to REDUCED / NOT ACCEPTED / BLOCKED rather
  than inventing host acceptance. A passing capsule test is evidence only for
  exactly what the test proves.

## LIVE-TEST SAFETY — HARD RULES (two real system-wide lockups)
The root cause of BOTH observed system-wide lockups was a `FAN_MARK_FILESYSTEM`
mark on the ROOT filesystem: strict mode then gates EVERY open on the whole
machine through guardd, and a busy/slow daemon stalls every process. (This is
not claimed to be the only possible cause of a total lock — rule 4 below notes
that gating any shared critical filesystem such as `/tmp` can also wedge the
desktop if the daemon stalls. These rules are mandatory, not advisory:

1. **NEVER perform `FAN_MARK_FILESYSTEM` on the root mount** (any path whose
   `st_dev` equals `/`'s). Verify with `stat -c %d`, not by pathname: `/home`,
   `/var/tmp`, `$REPO`, `/root` are ALL on the root mount.
2. **Every strict-filesystem live test MUST place its fixtures (profile, WORK,
   benchmark data) on an ISOLATED loop-backed ext4** (the `select_test_fs`
   pattern in `scripts/linux/test-object-identity-root.sh`), or on an explicit
   non-root, non-tmpfs filesystem passed via `TEST_FS_ROOT`. NEVER inside the
   repo (`$REPO/target/...`), `/home`, `/var/tmp`, or any root-mount path.
3. **Every root test script MUST assert non-root before starting guardd**:
   compare `stat -c %d "$FIXTURE_DIR"` with `stat -c %d /`; on equality, print a
   loud error and `exit 2` (BLOCKED). No fixture, no guardd start, no exception.
4. A `FAN_MARK_FILESYSTEM` mark on tmpfs is also dangerous: if guardd stalls
   under load, every `/tmp` open blocks and the desktop (wofi, terminals,
   firefox, waybar) wedges. Prefer the isolated loop fs for load/benchmark
   tests too; never SIGSTOP or flood a daemon whose fs mark is shared with the
   desktop's filesystems.
5. **The permission hot path must stay bounded**: per-open work (e.g. the R1
   topology drain) must be O(1)-amortized (a zero-timeout poll, only draining
   when events are actually pending). Any change that adds per-open cost must
   be benchmarked on an isolated loop fs before a real-host run.
6. Before ANY real-host live batch, list every script in the batch and verify
   its fixture filesystem in code — the review checklist must include the
   `st_dev` of every strict-mode fixture.
7. `guardd` REFUSES to start when strict-filesystem would mark the root mount
   (exit with a loud error; `GUARDD_ALLOW_ROOT_FS_MARK=1` keeps the legacy
   warn-only behavior for operators who explicitly accept the whole-machine
   gate). Tests must treat the refusal as the default and never set the env
   var.

## Authorization hot path
- Deterministic decisions MUST return immediately; the platform callback
  thread MUST NOT wait for a human UI.
- A typed browser-migration or SSH-read confirmation may retain an opaque OS
  authorization operation asynchronously, but only until its bounded platform
  deadline. Drop, timeout, identity change, process exit, and queue pressure
  fail closed.
- Decision model: `Allow | Deny(reason) | AllowByLease(lease_id) |
  RequireMigrationConfirmation(candidate) | RequireSshKeyConfirmation`. No
  risk scores. No ML.
- Deny immediately when policy says deny, then audit, then notify out-of-band.

## Process identity
- Never trust process name alone. Use PID + start token/time + canonical exe
  path + exe file identity (st_dev + st_ino). Missing fields are not permission
  to allow.

## Platform boundary
- Portable domain/runtime/UI-client logic must not import `platform-linux`
  directly. OS mechanisms belong behind `guard-platform` contracts and
  platform adapters. Add a cross-platform seam only where implementations
  genuinely differ.

## Quality gate for every phase
1. inspect existing code, preserve working behavior
2. implement
3. `cargo fmt --check`
4. `cargo clippy --all-targets --all-features -- -D warnings`
5. relevant unit/integration tests
6. fix failures (do not merely describe them)
7. update docs for new user-visible behavior

If a test needs root/kernel/entitlement that is genuinely unavailable: complete
everything possible, give the exact blocked command/error, provide a deterministic
script for a human to run later, and mark that test BLOCKED. Never claim a
blocked test passed.
