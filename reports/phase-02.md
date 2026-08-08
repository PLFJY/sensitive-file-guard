# Phase 02 — fanotify Permission Interception PoC

## Objective

Prove that `guardd` can stop a process **before** it successfully opens a
protected synthetic file, using `FAN_OPEN_PERM` permission interception.

## Implemented behavior

### `platform-linux` crate

- [`fanotify.rs`](../crates/platform-linux/src/fanotify.rs): wraps the Linux
  fanotify UAPI.
  - `FanotifyGroup::new_content()` — `fanotify_init(FAN_CLASS_CONTENT | FAN_CLOEXEC, ...)`.
    Requires `CAP_SYS_ADMIN`.
  - `mark_file(FAN_OPEN_PERM, path)` — `fanotify_mark(FAN_MARK_ADD, ...)`.
  - `read(buf)` — blocking read of one or more events; handles `EINTR`/`EAGAIN`
    in the caller.
  - `respond(fd, allow)` — writes `fanotify_response` (`FAN_ALLOW`/`FAN_DENY`).
  - `close_event_fd(fd)` — closes each event fd exactly once; no-op for
    `FAN_NOFD` overflow events.
  - `parse_events(buf)` — **pure** parser (unit-testable without root):
    parses multiple `fanotify_event_metadata` records from one buffer,
    detects `FAN_Q_OVERFLOW`, detects metadata version mismatch, and drops
    trailing partial records.
- [`capability.rs`](../crates/platform-linux/src/capability.rs): parses
  `/proc/self/status` `CapEff` and tests the `CAP_SYS_ADMIN` (21) bit.
- [`proc.rs`](../crates/platform-linux/src/proc.rs): resolves
  `/proc/<pid>/exe` for the PoC allow decision (full identity in Phase 04).
- [`signal.rs`](../crates/platform-linux/src/signal.rs): installs SIGINT/SIGTERM
  handlers **without** `SA_RESTART` so a blocking `read` returns `EINTR` and the
  daemon shuts down promptly (important: if the fanotify fd closes, outstanding
  permission events become allowed).

### `guardd` dev mode

`guardd --protect-test-file PATH [--allow-exe EXE...] [--print-decisions] [--exit-after N]`

- Fails fast with a precise message and exit code 2 if `CAP_SYS_ADMIN` is
  missing; **never** silently falls back to notification-only.
- Marks `PATH` with `FAN_OPEN_PERM`.
- Allow-list = canonicalized `--allow-exe` paths; decision per event: resolve
  opener's `/proc/<pid>/exe`, allow if in allow-list, else **deny**.
  Unresolvable identity => deny (safer).
- Responds and closes every event fd exactly once.
- Detects `FAN_Q_OVERFLOW` and emits a critical diagnostic.
- Clean shutdown on SIGTERM/SIGINT.

### `guard-test-probe`

Tiny test binary (`apps/guard-test-probe`): `guard-test-probe read PATH` opens,
reads, and writes bytes to stdout; reports OS error on failure. **No network
code, no dependencies.** Used as the enrolled (allowed) opener; `cat` serves as
the unauthorized (denied) opener.

## Privilege behavior (verified non-root)

Running `guardd --protect-test-file …` without `CAP_SYS_ADMIN` produces:

```
guardd: ERROR: CAP_SYS_ADMIN is required for fanotify permission-event enforcement (FAN_CLASS_CONTENT).
guardd: Current process effective capabilities lack CAP_SYS_ADMIN (CapEff=0x0000000000000000).
guardd: Run as root, or grant the capability, e.g.: `sudo setcap cap_sys_admin+ep <guardd>`.
guardd: Refusing to start in enforcement mode. Not falling back to notification-only.
```
Exit code: **2**. This is the one part of Phase 02 exercisable without root and
it passes.

## Exact commands run

```sh
id                                   # uid=1000(plfjy), not root
grep CapEff /proc/self/status        # CapEff: 0000000000000000  (no CAP_SYS_ADMIN)
sudo -n true                         # fails: "sudo: a password is required"
cargo build --all-targets            # OK
cargo fmt && cargo fmt --check       # clean
cargo clippy --all-targets --all-features -- -D warnings   # clean
cargo test --all                     # 20 tests pass
./target/debug/guardd --protect-test-file /tmp/x --print-decisions   # exits 2 with precise message (verified)
bash -n scripts/test-fanotify-root.sh  # syntax OK
```

## Test results

### Non-root unit tests (PASS)
```
platform-linux unittests: 9 passed
  capability::tests::parses_cap_eff_line
  capability::tests::detects_sys_admin_bit
  capability::tests::missing_line_is_none
  fanotify::tests::parses_multiple_events
  fanotify::tests::detects_overflow_event
  fanotify::tests::version_mismatch_is_error
  fanotify::tests::trailing_partial_event_is_dropped_not_errored
  fanotify::tests::empty_buffer_yields_no_events
  fanotify::tests::has_fd_helper
(plus 11 carried-over tests from Phase 01; total workspace 20 passed)
```
fmt: clean. clippy `-D warnings`: clean.

Privilege-refusal (non-root, PASS): `guardd` exits 2 with a precise
`CAP_SYS_ADMIN`-required message and does not fall back to notification-only.

### Privileged integration tests (BLOCKED in this environment)

The six required PoC tests all require `CAP_SYS_ADMIN`:

1. unprotected file opens normally
2. protected synthetic file from unauthorized probe is denied
3. an explicitly enrolled test process is allowed
4. repeated denied opens do not leak file descriptors
5. daemon clean shutdown releases resources
6. burst test (1000 opens) with latency/overflow observations

**Blocker (exact):** the build agent runs as `uid=1000` with
`CapEff=0000000000000000` (no `CAP_SYS_ADMIN`), and `sudo -n true` fails with
`sudo: a password is required`. `fanotify_init(FAN_CLASS_CONTENT, …)` therefore
returns `EPERM`. The agent cannot obtain the capability non-interactively.

**Provided for a human to run as root:**
[`scripts/test-fanotify-root.sh`](../scripts/test-fanotify-root.sh)

```sh
sudo bash scripts/test-fanotify-root.sh
```

The script builds the release binaries, creates a synthetic marker file, starts
`guardd --protect-test-file`, and exercises all six tests with PASS/FAIL output
and an fd-leak check (`/proc/<guardd-pid>/fd` before/after 200 denied opens) and
a 1000-open burst latency measurement. It uses only synthetic data and contains
no network code.

These six tests are marked **BLOCKED** (not PASS) until a human runs the script
as root. The implementation is complete and the non-root logic (event parsing,
capability detection, privilege refusal, signal handling) is unit-tested.

## Known limitations

- Phase 02 identity is by canonical exe path only (PID + `/proc/<pid>/exe`).
  Stable start-time identity, exe file identity, trust tiers, and parent chain
  arrive in Phase 04. PID-reuse confusion is therefore possible in this PoC and
  is addressed in Phase 04.
- Blocking `read` on the fanotify fd; a nonblocking + `poll`/`io-uring`-style
  loop is deferred until measured need (Phase 13 benchmarks).
- If the fanotify group fd closes, outstanding permission events become allowed
  (kernel fail-open). Phase 14 mitigates with prompt `Restart=always`.
- `parse_events` drops a trailing partial record rather than retaining it for
  the next read; acceptable because fanotify `read` returns whole events.
- Single-file mark only (PoC). Recursive/mount marks arrive in Phase 05/06.

## Security assumptions

- Enforcement is deterministic and local; no human prompt in the hot path.
- Deny is the default for any unresolvable opener identity.
- No real secrets are used; the protected file is a synthetic marker string.
- The test probe and root script contain no network exfiltration code.

## Quality gate

- [x] `cargo fmt --check`
- [x] `cargo clippy --all-targets --all-features -- -D warnings`
- [x] non-privileged unit tests pass (event parsing, version check, capability parsing, signal handler cast)
- [x] privilege-refusal behavior verified non-root (exits 2, no silent fallback)
- [x] `scripts/test-fanotify-root.sh` provided for the privileged integration tests
- [x] `reports/phase-02.md` written
- [ ] privileged integration tests run as root — **BLOCKED** (no non-interactive `CAP_SYS_ADMIN`)
