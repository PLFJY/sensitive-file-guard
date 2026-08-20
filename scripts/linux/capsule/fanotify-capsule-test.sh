#!/bin/bash
# Capsule fanotify seccomp verification — marks ONLY a fresh capsule-internal
# tmpfs (independent super_block). NEVER marks /testfs (host root bind) or /.
set -u
echo "== super_block identities =="
stat -c 'root  st_dev=%d' /
stat -c 'testfs st_dev=%d' /testfs
mkdir -p /probe-mnt
mount -t tmpfs probe-fs /probe-mnt || { echo "tmpfs mount FAILED"; exit 2; }
stat -c 'probe-mnt st_dev=%d' /probe-mnt
ROOT_DEV=$(stat -c %d /)
TESTFS_DEV=$(stat -c %d /testfs)
PROBE_DEV=$(stat -c %d /probe-mnt)
if [ "$PROBE_DEV" = "$ROOT_DEV" ] || [ "$PROBE_DEV" = "$TESTFS_DEV" ]; then
    echo "REFUSING: probe-mnt shares a super_block with root or testfs"; umount /probe-mnt; exit 3
fi
echo "== fanotify probe on fresh tmpfs =="
MOUNT=/probe-mnt /stage/bin/fanotify-probe
rc=$?
umount /probe-mnt 2>/dev/null
echo "probe exit=$rc"
exit $rc
