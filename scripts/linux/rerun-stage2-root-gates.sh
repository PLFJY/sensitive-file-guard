#!/usr/bin/env bash
# scripts/linux/rerun-stage2-root-gates.sh
# Stage-2 re-run: scripts fixed after the stage-1 re-run diagnostics.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TS="$(date +%Y%m%d-%H%M%S)"
OUT="$REPO/reports/linux/evidence/live-host-stage2-$TS"
mkdir -p "$OUT"

declare -a SCRIPTS=(
  "scripts/linux/test-pidfd-root.sh"
  "scripts/linux/experiment-fdstore-root.sh"
  "scripts/test-ssh-broker-adversarial-root.sh"
  "scripts/test-systemd-root.sh"
  "scripts/linux/test-native-browser-compat-root.sh"
)

PASS=0
FAIL=0
: > "$OUT/summary.txt"
for s in "${SCRIPTS[@]}"; do
  name="$(basename "$s" .sh)"
  echo "=== [$name] $(date +%H:%M:%S) START ===" | tee -a "$OUT/summary.txt"
  if SKIP_BUILD=1 SUDO_USER="${SUDO_USER:-}" bash "$REPO/$s" > "$OUT/$name.log" 2>&1; then
    echo "=== [$name] PASS ===" | tee -a "$OUT/summary.txt"
    PASS=$((PASS + 1))
  else
    rc=$?
    echo "=== [$name] FAIL rc=$rc ===" | tee -a "$OUT/summary.txt"
    FAIL=$((FAIL + 1))
  fi
  tail -3 "$OUT/$name.log" >> "$OUT/summary.txt"
done

echo
echo "=== STAGE-2 SUMMARY: PASS=$PASS FAIL=$FAIL ===" | tee -a "$OUT/summary.txt"
echo "evidence dir: $OUT"
exit $FAIL
