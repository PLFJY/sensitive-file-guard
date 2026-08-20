# P1-d — filesystem-scoped topology identity, loop-ext4 capsule rerun

Date: 2026-08-20. The ordinary capsule tmpfs does not support
`name_to_handle_at`, so this live verification used the capsule's bound
`/dev/loop1` to create and mount a fresh ext4 instance. Its strict filesystem
mark was therefore isolated from `/`, `/testfs`, and every host filesystem.

Current staged `guardd` was built from the reviewed workspace and matched the
staged binary by SHA-256 before the run.

Results:

- `test-object-identity-root.sh`: `PASS=8 FAIL=0 BLOCKED=0`.
- `test-step3-zero-settle-root.sh`: `PASS=8 FAIL=0 BLOCKED=0`.
- Fast rename-in → immediate rename-out → immediate open: 10,000 iterations,
  0 recovered bytes / 10,000 denied / 0 other errors.
- Settled variant: 1,000 iterations, 0 recovered bytes.
- Runtime-created subdirectory variant: 200 iterations, 0 recovered bytes.

This is evidence for `TopologyKey = (fsid, handle_type, handle_bytes)` on a
handle-supporting filesystem. It does not claim equivalence to every host
namespace or deployment configuration.
