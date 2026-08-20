#!/usr/bin/env bash
# LPS3 product-BPF causality oracle. It loads the exact BPF object embedded in
# guardd, but uses only a synthetic same-UID parent/child canary target so
# Yama permits the Guard-OFF baseline. It never starts a real browser.
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "BLOCKED: run through explicitly authorized polkit host fallback"
  exit 2
fi

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN_DIR="${BIN_DIR:-$REPO/target/debug}"
PROBE="${PROBE:-$BIN_DIR/guard-test-probe}"
ORACLE="${LPS1_ORACLE:-$REPO/target/lps1/lps1-ptrace-oracle}"
OBJECT="${PROCESS_SHIELD_BPF_OBJECT:-}"
TEST_UID="${TEST_UID:-${PKEXEC_UID:-}}"
TEST_GID="${TEST_GID:-}"

if [ -z "$OBJECT" ]; then
  OBJECT="$(find "$REPO/target" -path '*/out/guardd-process-shield.bpf.o' -type f -printf '%T@ %p\n' 2>/dev/null | sort -nr | head -1 | cut -d' ' -f2-)"
fi
for artifact in "$PROBE" "$ORACLE" "$OBJECT"; do
  [ -r "$artifact" ] || { echo "BLOCKED: missing prebuilt artifact $artifact"; exit 2; }
done
[ -x "$PROBE" ] && [ -x "$ORACLE" ] || { echo "BLOCKED: probe and oracle must be executable"; exit 2; }
if [ -z "$TEST_UID" ] || ! getent passwd "$TEST_UID" >/dev/null; then
  echo "BLOCKED: TEST_UID (or PKEXEC_UID) must identify a local non-root user"
  exit 2
fi
if [ "$(id -u "$TEST_UID")" -eq 0 ]; then echo "BLOCKED: TEST_UID must not be root"; exit 2; fi
TEST_UID="$(id -u "$TEST_UID")"
if [ -z "$TEST_GID" ]; then TEST_GID="$(id -g "$TEST_UID")"; fi

READY="$(mktemp /tmp/sfg-lps3-product-ready.XXXXXX)"
cleanup() { rm -f -- "$READY"; }
trap cleanup EXIT

LOG="$(mktemp /tmp/sfg-lps3-product.XXXXXX)"
LPS_BPF_PROGRAM=guardd_process_shield_ptrace TEST_UID="$TEST_UID" TEST_GID="$TEST_GID" \
  "$ORACLE" off "$PROBE" "$READY" "$OBJECT" >"$LOG" 2>&1
cat "$LOG"
grep -Fqx 'LPS1_OFF_SAME_UID_PTRACE_CANARY_RECOVERED=PASS' "$LOG" || { rm -f -- "$LOG"; echo "FAIL: product-BPF OFF baseline failed"; exit 1; }
LPS_BPF_PROGRAM=guardd_process_shield_ptrace TEST_UID="$TEST_UID" TEST_GID="$TEST_GID" \
  "$ORACLE" on "$PROBE" "$READY" "$OBJECT" >"$LOG" 2>&1
cat "$LOG"
grep -Fqx 'LPS1_ON_SAME_UID_PTRACE_DENIED_AUDITED_CANARY_RECOVERY=0 PASS' "$LOG" || { rm -f -- "$LOG"; echo "FAIL: product-BPF ON attribution/canary oracle failed"; exit 1; }
if grep -Eq '[[:space:]][0-9a-f]{128}([[:space:]]|$)' "$LOG"; then rm -f -- "$LOG"; echo "FAIL: synthetic canary exposed"; exit 1; fi
rm -f -- "$LOG"
echo 'LPS3_PRODUCT_BPF_PTRACE_CAUSALITY=PASS'
