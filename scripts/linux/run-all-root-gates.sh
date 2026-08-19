#!/usr/bin/env bash
# scripts/linux/run-all-root-gates.sh
#
# LFH7 freeze gate driver: runs every formal privileged acceptance script for
# LINUX_FILE_SHIELD_FREEZE on a REAL host, one polkit authorization.
#
#   pkexec env SKIP_BUILD=1 SUDO_USER=plfjy /usr/bin/bash \
#     scripts/linux/run-all-root-gates.sh
#
# Exit code = number of FAILED scripts (fail>0 within a script => script failed).
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TS="$(date +%Y%m%d-%H%M%S)"
OUT="$REPO/reports/linux/evidence/live-host-$TS"
mkdir -p "$OUT"

declare -a SCRIPTS=(
  "scripts/linux/test-pidfd-root.sh"                       # LFH1
  "scripts/linux/test-object-identity-root.sh"             # LFH2
  "scripts/linux/test-continuity-root.sh"                  # LFH3
  "scripts/linux/experiment-fdstore-root.sh"               # LFH4
  "scripts/test-browser-enforcement-root.sh"
  "scripts/test-ssh-enforcement-root.sh"
  "scripts/test-fanotify-root.sh"
  "scripts/test-bypass-root.sh"
  "scripts/test-hardening-root.sh"
  "scripts/test-agent-compat-root.sh"
  "scripts/test-ssh-broker-adversarial-root.sh"
  "scripts/test-ssh-load-root.sh"
  "scripts/test-strict-concurrency-root.sh"
  "scripts/test-topology-race-stress-root.sh"
  "scripts/test-systemd-root.sh"
  "scripts/test-installed-auth-root.sh"
  "scripts/test-browser-adversarial-root.sh"
  "scripts/test-strict-filesystem-root.sh"
  "scripts/linux/test-native-browser-compat-root.sh"       # LFH6
  "scripts/benchmark-strict-filesystem-root.sh"            # LFH0 benchmark
)

# Standardized exit codes (review finding 1):
#   0 = PASS, 1 = FAIL, 2 = BLOCKED (a mandatory gate could not run).
# A script whose exit code is 2 must NEVER be aggregated as PASS.
PASS=0
FAIL=0
BLOCKED=0
: > "$OUT/summary.txt"
for s in "${SCRIPTS[@]}"; do
  name="$(basename "$s" .sh)"
  echo "=== [$name] $(date +%H:%M:%S) START ===" | tee -a "$OUT/summary.txt"
  set +e
  SKIP_BUILD=1 SUDO_USER="${SUDO_USER:-}" bash "$REPO/$s" > "$OUT/$name.log" 2>&1
  rc=$?
  set -e
  case "$rc" in
    0) echo "=== [$name] PASS ===" | tee -a "$OUT/summary.txt"; PASS=$((PASS + 1)) ;;
    1) echo "=== [$name] FAIL rc=1 ===" | tee -a "$OUT/summary.txt"; FAIL=$((FAIL + 1)) ;;
    2) echo "=== [$name] BLOCKED rc=2 (mandatory gate could not run) ===" | tee -a "$OUT/summary.txt"; BLOCKED=$((BLOCKED + 1)) ;;
    *) echo "=== [$name] ABORT rc=$rc ===" | tee -a "$OUT/summary.txt"; FAIL=$((FAIL + 1)) ;;
  esac
  tail -3 "$OUT/$name.log" >> "$OUT/summary.txt"
done

echo
echo "=== LIVE HOST GATE SUMMARY: PASS=$PASS FAIL=$FAIL BLOCKED=$BLOCKED ===" | tee -a "$OUT/summary.txt"
echo "    (a mandatory BLOCKED gate prevents GOAL COMPLETE)"
echo "evidence dir: $OUT"
if [ "$FAIL" -gt 0 ]; then exit 1; elif [ "$BLOCKED" -gt 0 ]; then exit 2; else exit 0; fi
