#!/usr/bin/env bash
# scripts/linux/rerun-fixed-root-gates.sh
# Re-runs the 5 scripts that failed in the first live-host gate run, after
# their fixes. One polkit authorization.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TS="$(date +%Y%m%d-%H%M%S)"
OUT="$REPO/reports/linux/evidence/live-host-fixed-$TS"
mkdir -p "$OUT"

declare -a SCRIPTS=(
  "scripts/linux/test-pidfd-root.sh"
  "scripts/linux/experiment-fdstore-root.sh"
  "scripts/test-ssh-broker-adversarial-root.sh"
  "scripts/test-systemd-root.sh"
  "scripts/test-installed-auth-root.sh"
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
echo "=== FIXED-GATE SUMMARY: PASS=$PASS FAIL=$FAIL ===" | tee -a "$OUT/summary.txt"
echo "evidence dir: $OUT"
exit $FAIL
