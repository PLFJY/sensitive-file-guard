# Linux File Shield — Implementation Freeze Restored

## Verdict

At commit `77dcd75edc3a10b95e4aa3051cd48fe29654e407`, **Linux File Shield is
restored to IMPLEMENTATION FREEZE**.

This replaces the previously reopened review state. It does not claim that
Process Shield or Linux Platform Freeze is complete.

## Fresh acceptance evidence

The final privileged run was an explicitly authorized polkit physical-host
fallback, because the capsule's nspawn loop-device visibility and PID1 boot
limitations prevent it from being represented as host-equivalent full-suite
evidence.

| Evidence | Result |
|---|---|
| `/tmp/sfg-host-formal-77dcd75-20260820-210000/summary-oneshot.txt` | 23 mandatory PASS, 0 FAIL, 0 BLOCKED; 1 observation PASS |
| `/tmp/sfg-systemd-77dcd75-20260820-211000.log` | systemd gate: 13 PASS, 0 FAIL, 0 BLOCKED |
| `/tmp/sfg-broker-bb37537-20260820-203000.log` | SSH broker adversarial: 30 PASS, 0 FAIL, 0 BLOCKED (the runtime binaries are unchanged at `77dcd75`) |

Host kernel: `7.1.8-arch1-3`, x86_64. All privileged fixtures were synthetic;
strict filesystems used isolated loop-backed ext4. No real browser profile,
cookie, token, password store, or SSH key was read or copied.

The formal manifest now counts its actual gates rather than the historical
“21/21”: it contains 23 mandatory one-shot gates, including the three P0 SSH
mmap cases and P1 topology/continuity gates.

## Security findings closed

- P0 SSH mmap: Guard OFF same-user mmap/read baseline succeeds; Guard ON
  denies before readable-fd acquisition in strict configured, conservative
  configured, and runtime enrollment flows. Each case has requester/target
  audit attribution and zero synthetic-canary recovery.
- P1 status health: topology uncertainty and handle-index exhaustion reduce
  File Shield and cannot coexist with top-level `ACTIVE`.
- P1 topology lifecycle: desired live directories are reconciled against marks
  by object identity; removal/recreation at the same pathname is covered, and
  unexpected live mark loss remains sticky fail-closed.
- P1 capability parsing: safe aligned `ObjectHandle` parsing replaces unsafe
  byte-vector typed dereference.
- P1 privileged-test contract: capsule is the normal path; the user-authorized
  physical-host exception is polkit only, never interactive sudo/password
  forwarding. Formal evidence is written outside read-only staging.
- P2 executable identity: an `O_PATH` identity change requires re-enrollment
  when rehashing is impossible.

Firefox is accepted by a disposable-profile host observation (8 PASS). Other
browser families are **NOT ACCEPTED**, not inferred from Firefox.

## Deliberate non-claims

1. **Crash continuity remains REDUCED.** LFH4 fdstore is PARTIAL: a
   read-but-unanswered fanotify permission event cannot be resumed through the
   public fdstore UAPI. Service restart evidence does not change that verdict.
2. A capsule PASS proves only its nspawn environment. Its loop0--2 visibility
   and `systemd-firstboot` restriction blocked a meaningful full capsule run;
   this report therefore relies on physical-host evidence for final acceptance.
3. File Shield protects new opens. FDs opened before protection, agent signing
   after a key is loaded, and untested filesystem/sandbox/browser variants are
   documented boundaries, not prevention claims.

## Quality and handoff

Before the final privileged run, formatting, clippy with warnings denied,
workspace tests with all features, and `git diff --check` were clean. The next
phase is LPS0 Process Shield capability probing; File Shield remains
independent if Process Shield is unsupported or disabled.
