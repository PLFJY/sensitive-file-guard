#!/bin/bash
# Capsule P0 live test wrapper.
# Marks ONLY a fresh capsule-internal tmpfs (independent super_block).
# NEVER marks /testfs (host root bind) or /.
set -euo pipefail

mkdir -p /p0fs
mount -t tmpfs p0-fs /p0fs || { echo "BLOCKED: tmpfs mount failed"; exit 2; }

ROOT_DEV=$(stat -c %d /)
TESTFS_DEV=$(stat -c %d /testfs)
P0_DEV=$(stat -c %d /p0fs)
echo "== super_block identities =="
echo "root  st_dev=$ROOT_DEV"
echo "testfs st_dev=$TESTFS_DEV"
echo "p0fs  st_dev=$P0_DEV"
if [ "$P0_DEV" = "$ROOT_DEV" ] || [ "$P0_DEV" = "$TESTFS_DEV" ]; then
    echo "REFUSING: p0fs shares a super_block with root or testfs"
    umount /p0fs; exit 3
fi

echo "== P0 test =="
set +e
TEST_FS_ROOT=/p0fs \
PRESET_SSH_KEY=/stage/fixtures/synthetic-test-key \
BIN_DIR=/stage/bin \
ENFORCEMENT_MODE="${ENFORCEMENT_MODE:-strict-filesystem}" \
/stage/scripts/test-p0-ssh-mmap-root.sh
RC=$?
set -e
umount /p0fs 2>/dev/null || true
echo "P0 wrapper exit=$RC"
exit $RC
