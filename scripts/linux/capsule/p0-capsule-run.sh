#!/usr/bin/env bash
# Capsule P0 wrapper. The strict mark is confined to an isolated loop-backed
# ext4 filesystem; /, /testfs, and tmpfs are never marked.
set -euo pipefail

IMG="/testfs/p0-ssh-$$.img"
MNT="/testfs/p0-ssh-mnt-$$"
LOOP=""
cleanup() {
  if mountpoint -q "$MNT" 2>/dev/null; then umount "$MNT" || true; fi
  if [ -n "$LOOP" ]; then losetup -d "$LOOP" || true; fi
  rm -f -- "$IMG"
  rmdir "$MNT" 2>/dev/null || true
}
trap cleanup EXIT

truncate -s 256M "$IMG"
LOOP="$(losetup --find --show "$IMG")"
mkfs.ext4 -q -F "$LOOP"
mkdir -p "$MNT"
mount "$LOOP" "$MNT"
ROOT_DEV="$(stat -c %d /)"; TESTFS_DEV="$(stat -c %d /testfs)"; P0_DEV="$(stat -c %d "$MNT")"
echo "root=$ROOT_DEV testfs=$TESTFS_DEV p0fs=$P0_DEV loop=$LOOP"
if [ "$P0_DEV" = "$ROOT_DEV" ] || [ "$P0_DEV" = "$TESTFS_DEV" ]; then
  echo "BLOCKED: loop ext4 does not have an isolated superblock"
  exit 2
fi

TEST_FS_ROOT="$MNT" BIN_DIR=/stage/bin \
  ENFORCEMENT_MODE="${ENFORCEMENT_MODE:-strict-filesystem}" \
  P0_CASE="${P0_CASE:-configured}" \
  /stage/scripts/linux/test-p0-ssh-mmap-root.sh
