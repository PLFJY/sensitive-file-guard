#!/usr/bin/env bash
# LPS6 product-object lifecycle and non-target performance checks. This is a
# physical-host fallback only when capsule BPF load is unavailable.
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "BLOCKED: run through the explicitly authorized polkit host fallback"
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
  echo "BLOCKED: TEST_UID (or PKEXEC_UID) must identify a local non-root user"; exit 2
fi
if [ "$(id -u "$TEST_UID")" -eq 0 ]; then echo "BLOCKED: TEST_UID must not be root"; exit 2; fi
TEST_UID="$(id -u "$TEST_UID")"
if [ -z "$TEST_GID" ]; then TEST_GID="$(id -g "$TEST_UID")"; fi

READY="$(mktemp /tmp/sfg-lps6-ready.XXXXXX)"
LOG="$(mktemp /tmp/sfg-lps6.XXXXXX)"
cleanup() { rm -f -- "$READY" "$LOG"; }
trap cleanup EXIT

run_case() {
  local expected="$1"; shift
  "$@" >"$LOG" 2>&1
  cat "$LOG"
  grep -Fqx "$expected" "$LOG" || { echo "FAIL: missing $expected"; exit 1; }
  if grep -Eq '[[:space:]][0-9a-f]{128}([[:space:]]|$)' "$LOG"; then
    echo "FAIL: synthetic canary exposed"; exit 1
  fi
}

base=(env LPS_BPF_PROGRAM=guardd_process_shield_ptrace TEST_UID="$TEST_UID" TEST_GID="$TEST_GID")
run_case 'LPS6_STALE_INSTANCE_ENTRY_DOES_NOT_BIND_NEW_TARGET=PASS' \
  "${base[@]}" LPS_FORCE_STALE_TARGET=1 LPS_OPERATION=ptrace \
  "$ORACLE" on "$PROBE" "$READY" "$OBJECT"

benchmark() {
  local mode="$1" expected="$2" value
  local -a samples=()
  for _ in $(seq 1 5); do
    run_case "$expected" "${base[@]}" LPS_OPERATION=unrelated_ptrace_benchmark \
      "$ORACLE" "$mode" "$PROBE" "$READY" "$OBJECT" >&2
    value="$(sed -n 's/^LPS6_UNRELATED_PTRACE_BENCH_100_NS=//p' "$LOG" | tail -1)"
    [[ "$value" =~ ^[0-9]+$ ]] || { echo "FAIL: $mode benchmark did not emit elapsed ns"; exit 1; }
    samples+=("$value")
  done
  printf '%s\n' "${samples[@]}" | sort -n | sed -n '3p'
}

off_ns="$(benchmark off 'LPS6_UNRELATED_PTRACE_BENCHMARK_OFF=PASS')"
on_ns="$(benchmark on 'LPS6_UNRELATED_PTRACE_BENCHMARK_ON=PASS')"
# This is a deliberately loose catastrophic-regression guard, not a latency
# promise: ptrace stop/resume is scheduler-noisy. Both samples exercise an
# unprotected child while the product BPF link is attached in the ON case.
if [ "$on_ns" -gt $((off_ns * 5 + 1000000)) ]; then
  echo "FAIL: Process Shield unprotected ptrace median regressed beyond 5x + 1ms (off=$off_ns on=$on_ns)"
  exit 1
fi
printf 'LPS6_UNRELATED_PTRACE_BENCH_100_MEDIAN_NS_OFF=%s ON=%s\n' "$off_ns" "$on_ns"
echo 'LPS6_PRODUCT_OBJECT_LIFECYCLE_AND_PERFORMANCE=PASS'
