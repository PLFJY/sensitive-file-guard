#!/usr/bin/env bash
# LPS5 product-BPF adversarial matrix.  Each protected-target operation uses a
# disposable same-UID parent/child pair, so Yama permits Guard OFF.  The exact
# BPF object embedded in guardd is loaded only for the ON half.
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "BLOCKED: run through the authorized privileged test entrypoint"
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

READY="$(mktemp /tmp/sfg-lps5-ready.XXXXXX)"
LOG="$(mktemp /tmp/sfg-lps5.XXXXXX)"
cleanup() { rm -f -- "$READY" "$LOG"; }
trap cleanup EXIT

run_case() {
  local operation="$1" off_line="$2" on_line="$3"
  LPS_OPERATION="$operation" LPS_BPF_PROGRAM=guardd_process_shield_ptrace TEST_UID="$TEST_UID" TEST_GID="$TEST_GID" \
    "$ORACLE" off "$PROBE" "$READY" "$OBJECT" >"$LOG" 2>&1
  cat "$LOG"
  grep -Fqx "$off_line" "$LOG" || { echo "FAIL: $operation Guard-OFF baseline was not a successful primitive"; exit 1; }
  LPS_OPERATION="$operation" LPS_BPF_PROGRAM=guardd_process_shield_ptrace TEST_UID="$TEST_UID" TEST_GID="$TEST_GID" \
    "$ORACLE" on "$PROBE" "$READY" "$OBJECT" >"$LOG" 2>&1
  cat "$LOG"
  grep -Fqx "$on_line" "$LOG" || { echo "FAIL: $operation Guard-ON denial/audit/canary oracle failed"; exit 1; }
  if grep -Eq '[[:space:]][0-9a-f]{128}([[:space:]]|$)' "$LOG"; then
    echo "FAIL: synthetic canary exposed"; exit 1
  fi
}

run_case ptrace \
  'LPS1_OFF_SAME_UID_PTRACE_CANARY_RECOVERED=PASS' \
  'LPS1_ON_SAME_UID_PTRACE_DENIED_AUDITED_CANARY_RECOVERY=0 PASS'
run_case process_vm_readv \
  'LPS5_PROCESS_VM_READV_OFF_CANARY_RECOVERED=PASS' \
  'LPS5_PROCESS_VM_READV_ON_DENIED_AUDITED_CANARY_RECOVERY=0 PASS'
run_case process_vm_writev \
  'LPS5_PROCESS_VM_WRITEV_OFF_SYNTHETIC_WRITE_SUCCEEDED=PASS' \
  'LPS5_PROCESS_VM_WRITEV_ON_DENIED_AUDITED_CANARY_RECOVERY=0 PASS'
run_case proc_mem \
  'LPS5_PROC_MEM_OFF_CANARY_RECOVERED=PASS' \
  'LPS5_PROC_MEM_ON_DENIED_AUDITED_CANARY_RECOVERY=0 PASS'
run_case unrelated_ptrace \
  'LPS5_UNRELATED_NORMAL_PROCESS_OFF_UNCHANGED=PASS' \
  'LPS5_UNRELATED_NORMAL_PROCESS_ON_UNCHANGED=PASS'

echo 'LPS5_PRODUCT_BPF_ADVERSARIAL_MATRIX=PASS'
