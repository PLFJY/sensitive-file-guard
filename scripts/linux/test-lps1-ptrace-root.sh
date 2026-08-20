#!/usr/bin/env bash
# LPS1 physical-host oracle. Root is used only to attach a short-lived BPF LSM
# test program; attacker and target are a disposable same non-root UID pair.
# Run through explicitly authorized polkit when the capsule's BPF restriction
# prevents meaningful execution. It never accesses a browser profile or key.
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "BLOCKED: run through explicitly authorized polkit host fallback"
  exit 2
fi

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN_DIR="${BIN_DIR:-$REPO/target/release}"
LPS1_DIR="${LPS1_DIR:-$REPO/target/lps1}"
PROBE="${PROBE:-$BIN_DIR/guard-test-probe}"
ORACLE="${LPS1_ORACLE:-$LPS1_DIR/lps1-ptrace-oracle}"
BPF_OBJECT="${LPS1_BPF_OBJECT:-$LPS1_DIR/lps1-ptrace-guard.bpf.o}"
TEST_UID="${TEST_UID:-${PKEXEC_UID:-}}"
TEST_GID="${TEST_GID:-}"

for artifact in "$PROBE" "$ORACLE" "$BPF_OBJECT"; do
  [ -r "$artifact" ] || { echo "BLOCKED: missing prebuilt artifact $artifact"; exit 2; }
done
[ -x "$PROBE" ] && [ -x "$ORACLE" ] || { echo "BLOCKED: probe and oracle must be executable"; exit 2; }
if [ -z "$TEST_UID" ] || ! getent passwd "$TEST_UID" >/dev/null; then
  echo "BLOCKED: TEST_UID (or PKEXEC_UID) must identify a local non-root user"
  exit 2
fi
if [ "$(id -u "$TEST_UID")" -eq 0 ]; then
  echo "BLOCKED: TEST_UID must not be root"
  exit 2
fi
if [ -z "$TEST_GID" ]; then TEST_GID="$(id -g "$TEST_UID")"; fi

ready_file="$(mktemp /tmp/sfg-lps1-ready.XXXXXX)"
cleanup() { rm -f -- "$ready_file"; }
trap cleanup EXIT

run_case() {
  local mode="$1" expected="$2" log
  log="$(mktemp /tmp/sfg-lps1-${mode}.XXXXXX)"
  TEST_UID="$TEST_UID" TEST_GID="$TEST_GID" "$ORACLE" "$mode" "$PROBE" "$ready_file" "$BPF_OBJECT" >"$log" 2>&1
  cat "$log"
  if ! grep -Fqx "$expected" "$log"; then
    echo "FAIL: $mode result did not satisfy LPS1 oracle"
    rm -f -- "$log"
    return 1
  fi
  if grep -Eq '[[:space:]][0-9a-f]{128}([[:space:]]|$)' "$log"; then
    echo "FAIL: $mode log exposed the synthetic canary"
    rm -f -- "$log"
    return 1
  fi
  rm -f -- "$log"
}

run_case off 'LPS1_OFF_SAME_UID_PTRACE_CANARY_RECOVERED=PASS'
run_case on 'LPS1_ON_SAME_UID_PTRACE_DENIED_AUDITED_CANARY_RECOVERY=0 PASS'
echo 'LPS1_SAME_NONROOT_UID_PTRACE_ORACLE=PASS'
