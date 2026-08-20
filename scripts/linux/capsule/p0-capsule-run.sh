#!/usr/bin/env bash
# P0 wrapper. The strict mark is confined to an isolated loop-backed
# ext4 filesystem; /, /testfs, and tmpfs are never marked.
set -euo pipefail

BIN_DIR="${BIN_DIR:-/stage/bin}"
P0_ARTIFACT_ROOT="${P0_ARTIFACT_ROOT:-${TEST_ARTIFACT_ROOT:-}}"
if [ -z "$P0_ARTIFACT_ROOT" ]; then
  if [ -d /testfs ]; then P0_ARTIFACT_ROOT=/testfs; else P0_ARTIFACT_ROOT=/tmp; fi
fi
[ -d "$P0_ARTIFACT_ROOT" ] || { echo "BLOCKED: artifact root missing: $P0_ARTIFACT_ROOT"; exit 2; }
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
P0_TEST_SCRIPT="${P0_TEST_SCRIPT:-$SCRIPT_DIR/../test-p0-ssh-mmap-root.sh}"
IMG="$P0_ARTIFACT_ROOT/p0-ssh-$$.img"
MNT="$P0_ARTIFACT_ROOT/p0-ssh-mnt-$$"
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
ROOT_DEV="$(stat -c %d /)"; ARTIFACT_DEV="$(stat -c %d "$P0_ARTIFACT_ROOT")"; P0_DEV="$(stat -c %d "$MNT")"
echo "root=$ROOT_DEV artifact_root=$ARTIFACT_DEV p0fs=$P0_DEV loop=$LOOP"
if [ "$P0_DEV" = "$ROOT_DEV" ] || [ "$P0_DEV" = "$ARTIFACT_DEV" ]; then
  echo "BLOCKED: loop ext4 does not have an isolated superblock"
  exit 2
fi

TEST_FS_ROOT="$MNT" BIN_DIR="$BIN_DIR" \
  ENFORCEMENT_MODE="${ENFORCEMENT_MODE:-strict-filesystem}" \
  P0_CASE="${P0_CASE:-configured}" \
  "$P0_TEST_SCRIPT"
