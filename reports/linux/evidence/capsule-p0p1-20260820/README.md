# Capsule P0/P1 live verification — 2026-08-20

Capsule: `sudo -n /usr/local/sbin/sfg-test-capsule run ...` (systemd-nspawn, HOST kernel,
nspawn seccomp allows fanotify + pidfd_getfd via `--system-call-filter=fanotify_init
fanotify_mark pidfd_getfd`). All strict marks placed ONLY on fresh capsule-internal tmpfs
instances (independent super_block, st_dev=92); `/testfs` (host root bind, st_dev=66314) and `/`
never marked (AGENTS.md LIVE-TEST SAFETY).

Re-run each with the staged binaries/scripts (see scripts/linux/capsule/ and the stage dir):
- `p0-capsule-run.sh`  — P0 SSH private-key OPEN_PERM boundary (mmap/read denied at open)
- `p1c-capsule-run.sh` — P1-c autonomous required-mark-loss detection (no status query)
- `p1b-capsule-run.sh` — P1-b topology queue overflow -> topology_uncertain -> fail-closed
- `test-pidfd-root.sh` — P1-a pidfd group live (enrolled allowed / unknown denied / 0 missing)

Results recorded below are transcripts captured from the capsule runs on this date.

Capsule caveat (AGENTS.md): a capsule result is evidence only for exactly what it proves;
nspawn PID/mount namespace and seccomp differences are downgraded where relevant. P1-d
(zero-settle / object-identity under fsid keys) requires name_to_handle_at (ext4) and is
therefore NOT testable on capsule tmpfs — host isolated loop ext4 rerun pending (BLOCKED in
capsule, never counted as PASS).
