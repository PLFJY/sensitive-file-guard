#!/usr/bin/env bash
# scripts/linux/rerun-review-batch.sh
# One-polkit batch: re-verify the review-affected live gates on the real host.
# Each script is a standalone gate; results are aggregated by exit code
# (0=PASS, 1=FAIL, 2=BLOCKED).
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT="$REPO/reports/linux/evidence/live-host-review-batch-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUT"
PASS=0; FAIL=0; BLOCKED=0
: > "$OUT/summary.txt"

# --- pre-flight: drop leftover loop mounts from interrupted runs ---
# (a killed pkexec batch can leave a debug loop ext4 mounted; a fresh batch
# must start clean so losetup -f picks a free device)
for m in /tmp/guard-objectid-mnt-* /tmp/fdn-mnt /tmp/objid-debug-*/mnt; do
  if mountpoint -q "$m" 2>/dev/null; then
    echo "pre-flight: unmounting leftover $m" | tee -a "$OUT/summary.txt"
    umount "$m" 2>/dev/null || true
  fi
done
for img in /tmp/guard-objectid-img-*.img /tmp/objid-debug-*/img.img; do
  [ -e "$img" ] || continue
  dev="$(losetup -j "$img" -O NAME -n 2>/dev/null | head -1 || true)"
  if [ -n "$dev" ]; then
    echo "pre-flight: detaching leftover $dev ($img)" | tee -a "$OUT/summary.txt"
    losetup -d "$dev" 2>/dev/null || true
  fi
  rm -f "$img" 2>/dev/null || true
done

for s in \
  "scripts/linux/experiment-fdstore-root.sh" \
  "scripts/linux/test-continuity-root.sh" \
  "scripts/test-bypass-root.sh" \
  "scripts/linux/test-object-identity-root.sh" \
  "scripts/test-topology-race-stress-root.sh"
do
  name="$(basename "$s" .sh)"
  echo "=== [$name] $(date +%H:%M:%S) START ===" | tee -a "$OUT/summary.txt"
  set +e
  if [ "$name" = "test-topology-race-stress-root" ]; then
    # F10: rerun the topology race under STRICT mode (zero unauthorized reads).
    SKIP_BUILD=1 ENFORCEMENT_MODE=strict-filesystem SUDO_USER="${SUDO_USER:-}" bash "$REPO/$s" > "$OUT/$name.log" 2>&1
  else
    SKIP_BUILD=1 SUDO_USER="${SUDO_USER:-}" bash "$REPO/$s" > "$OUT/$name.log" 2>&1
  fi
  rc=$?
  set -e
  case "$rc" in
    0) echo "=== [$name] PASS ===" | tee -a "$OUT/summary.txt"; PASS=$((PASS+1));;
    1) echo "=== [$name] FAIL rc=1 ===" | tee -a "$OUT/summary.txt"; FAIL=$((FAIL+1));;
    2) echo "=== [$name] BLOCKED rc=2 ===" | tee -a "$OUT/summary.txt"; BLOCKED=$((BLOCKED+1));;
    *) echo "=== [$name] ABORT rc=$rc ===" | tee -a "$OUT/summary.txt"; FAIL=$((FAIL+1));;
  esac
  tail -2 "$OUT/$name.log" >> "$OUT/summary.txt"
done
echo
echo "=== REVIEW BATCH SUMMARY: PASS=$PASS FAIL=$FAIL BLOCKED=$BLOCKED ===" | tee -a "$OUT/summary.txt"
echo "evidence dir: $OUT"
if [ "$FAIL" -gt 0 ]; then exit 1; elif [ "$BLOCKED" -gt 0 ]; then exit 2; else exit 0; fi
