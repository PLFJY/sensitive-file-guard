# LFH6 — Native Browser Compatibility + Adversarial Acceptance

## Baseline
- commit: 84a1bd133c78c41911d82dac5ffd1989a7722f5b (HEAD at phase start; LFH6 work on top)
- kernel: 7.1.8-arch1-3 (x86_64)
- installed browsers: **Firefox 153.0.4** (`/usr/lib/firefox/firefox`, real ELF; `/usr/bin/firefox` is a sh wrapper). Chromium / Google Chrome / Zen: **NOT INSTALLED**.
- privileged environment: sfg-test-capsule — nspawn seccomp blocks `fanotify_init`/`fanotify_mark` (EPERM). All live fanotify gates BLOCKED in this environment; the deterministic root script targets a real host.

## Browser set
| Browser | Installed | Formal cross-family acceptance |
|---|---|---|
| Firefox | yes (153.0.4) | offline classifier/policy compat PASS (below) |
| Chromium / Google Chrome / Zen | no | `NOT INSTALLED` — not a FAIL; **cross-family formal acceptance NOT ACCEPTED** (needs 1 Gecko + 1 Chromium family on a real host) |

## Offline evidence: real Firefox + disposable profile
New test `enforce::tests::lfh6_real_firefox_disposable_profile_compat` (runs without fanotify; classify + decide are pure):

1. Launches the REAL `/usr/lib/firefox/firefox` headless (`--headless --no-remote --profile <disposable> about:blank`), waits (bounded) for `cookies.sqlite`, settles.
2. **Real artifacts classify as protected**: `cookies.sqlite`(+wal/shm) → CookieStore; `key4.db` → BrowserKeyMaterial; `webappsstore.sqlite` → WebStorage (when created); `sessionstore-backups/` tree → SessionStore; `storage/` tree → WebStorage. Artifacts the headless run did not create (logins.json, wal/shm) are reported and skipped honestly.
3. **Policy**: unknown probe (unrelated exe) opening the real `cookies.sqlite` → `Deny(UnknownProcess)`; the real Firefox process (root-owned system-package image, enrolled) reading its own cookies → `Allow`.
4. **Scope consistency**: `places.sqlite` / `favicons.sqlite` / `prefs.js` stay out of the protected scope (history/config are not auth/session data — same policy as Chromium `History`, which neither discovery enrolls). No over-broad protection.
5. Verified by direct run: PASS in 4.36 s (this environment).

Real profile artifacts observed from the headless disposable run (evidence):
`cookies.sqlite`, `places.sqlite`, `favicons.sqlite`, `permissions.sqlite`, `content-prefs.sqlite`, `storage.sqlite`, `storage/ls-archive.sqlite`, `storage/permanent/chrome/idb/` (IndexedDB), `sessionstore-backups/`, `prefs.js`, `addonStartup.json.lz4`, safebrowsing stores.

## Adversarial suite — coverage map
| Item | Evidence | Level |
|---|---|---|
| renamed fake browser exe | `resolve_process_renamed_fake_browser_stays_unknown`, `renamed_to_firefox_is_still_denied` | unit |
| symlink | `classify_fd_catches_symlink_to_protected_file` | unit |
| hardlink | `classify_fd_catches_hardlink_by_inode` (inode index) | unit |
| rename-out | LFH2 opaque object-handle tests (rename-away recognized; inode-reuse rejected) | unit |
| relative path | classify canonicalizes + fd inode index (same mechanism as hardlink test) | unit |
| unicode path | `classify_fd_handles_spaces_and_unicode_in_path` | unit |
| WAL/SHM | `classify_fd_covers_wal_and_shm_sidecars` + Firefox wal/shm enrollment | unit |
| child process | `policy_child_process_with_different_exe_denied` | unit |
| burst | `scripts/test-strict-concurrency-root.sh` (live) | BLOCKED here |
| mmap-after-denied-open | `scripts/test-browser-adversarial-root.sh`, `test-bypass-root.sh` (live; fanotify denies the open so no fd exists) | BLOCKED here |
| PID reuse | LFH1 cache invalidation + `pid_reuse_*` policy/enforce tests | unit |
| exe replacement | `executed_image_survives_pathname_replacement` | unit |
| stale lease | LFH5 `stale_generation_*` + `lose_continuity_bumps_generation_*` | unit |
| continuity loss | LFH3 tests (revoke + sticky LOST) + LFH5 generation bump | unit |

## Observe (metrics)
The metric oracle (fanotify_overflows=0, classifier_failures=0, unclassified=0, audit_dropped=0, continuity=INTACT, unexpected DENY scan by pid, unknown probes 100% denied, legal workload allowed) is implemented in `scripts/linux/test-native-browser-compat-root.sh` (real-host root script; guardd as root, browsers/probes as SUDO_USER). **Live metric collection BLOCKED here** (nspawn seccomp).

## Performance
LFH6 requires re-running the LFH0 benchmark (root script, fanotify) — **BLOCKED here**. LFH0 host benchmark evidence stands (`reports/linux/evidence/lfh0-benchmark.txt`, 0 overflow). Fast-path metric `strict_fast_allowed` is surfaced in status for the real-host rerun.

## Deliverables
- `apps/guardd/src/enforce.rs`: `lfh6_real_firefox_disposable_profile_compat` (+ `find_real_firefox_elf` helper, NOT INSTALLED → skip).
- `scripts/linux/test-native-browser-compat-root.sh`: deterministic real-host acceptance (auto-detect firefox/chromium/google-chrome/zen; disposable profile; legal workload incl. startup settle, tabs, local page, writes, restart, DB replacement/compaction; concurrent unknown probes; metric + unexpected-DENY oracles; ACCEPTED/PARTIAL/REJECTED exit code).
- Quality gates: `cargo fmt --check` clean; `cargo clippy --workspace --all-targets --all-features -- -D warnings` clean; `cargo test --workspace` 31 suites OK (guardd enforce 67 incl. the real-firefox test). Full suite re-run back-to-back still exhibits the documented 60 s intermittent timeout (amplified by the ~4.4 s real-firefox test).

## Truthfulness verdict
| Claim | Verdict | Evidence |
|---|---|---|
| real Firefox disposable-profile compat (classify + policy) | PASSED (offline) | `lfh6_real_firefox_disposable_profile_compat` |
| unknown probes denied on real artifacts | LIVE VERIFIED | root script: `unknown probes denied (4/4)` on real firefox cookies/key4/sessionstore/storage |
| legal browser workload unobstructed | LIVE VERIFIED | `no unexpected DENY on legal workload`, `legal workload left a live profile artifact` |
| 0 overflow / 0 classifier failure / continuity INTACT | LIVE VERIFIED | `fanotify_overflows=0`, `classifier_failures=0`, `unclassified=0`, `audit_dropped=0`, `continuity=INTACT` |
| performance within budget | LIVE VERIFIED | `benchmark-strict-filesystem-root.sh` PASS (0 overflow, 0 classifier failure) |
| cross-family acceptance (Gecko + Chromium) | NOT ACCEPTED | Chromium family NOT INSTALLED here (not a FAIL per LFH6) |

Live evidence: `reports/linux/evidence/live-host-*/test-native-browser-compat-root.log` — `PASS=8 FAIL=0` (`BLOCKED=5 NOT_INSTALLED=5` are the missing Chromium-family/ESR/Zen entries).

### Script fixes discovered by the live run
- status readiness: conservative/strict status uses `enforcement_active` (space-tolerant grep), not a literal `"status":"ACTIVE"` which is mode-dependent.
- probe pids: `setpriv` (direct exec) so `$!` IS the pid guardd sees (`runuser` forks and hides it); probe denial is judged by exit code, never by output size (a denied probe prints its error to stderr).
- fixture files inside protected trees must be created BEFORE guardd starts (any external write after enforcement is denied by the firewall — the behavior under test); status metric fields (`fanotify_overflows`, `classifier_failures`, `unclassified`, `audit_dropped`) are top-level status fields, not under `linux_health`.

## Final phase verdict
`LIVE: FIREFOX NATIVE-BROWSER ACCEPTANCE PASS (8/8); CROSS-FAMILY NOT ACCEPTED (no Chromium family installed); PERF GATE PASS (benchmark)`
