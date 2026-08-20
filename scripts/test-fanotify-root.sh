#!/usr/bin/env bash
# scripts/test-fanotify-root.sh
#
# Phase 02 privileged integration test for the fanotify FAN_OPEN_PERM PoC.
#
# RUN AS ROOT only inside `sudo -n /usr/local/sbin/sfg-test-capsule run ...`.
#
# Why root: fanotify permission-event enforcement (FAN_CLASS_CONTENT) requires
# CAP_SYS_ADMIN. The non-interactive build agent cannot obtain it, so the
# privileged tests are provided here for a human to run.
#
# This script uses ONLY synthetic data (a marker file). It contains NO network
# exfiltration code. It does not touch any real browser profile or real SSH key.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_DIR="${BIN_DIR:-$REPO/target/release}"
GUARDD="${GUARDD:-$BIN_DIR/guardd}"
PROBE="${PROBE:-$BIN_DIR/guard-test-probe}"

PASS=0
FAIL=0
BLOCKED=0
note_pass() { echo "PASS: $1"; PASS=$((PASS+1)); }
note_fail() { echo "FAIL: $1"; FAIL=$((FAIL+1)); }

if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: this script must be run as root (needs CAP_SYS_ADMIN for fanotify)."
  echo "       run this script through sfg-test-capsule; never host sudo"
  exit 2
fi

if [ -z "${SKIP_BUILD:-}" ]; then
  echo "==> Building release binaries"
  cd "$REPO"
  cargo build --release 2>&1 | grep -E '(Compiling guardd|Compiling guard-test-probe|Finished|error)' || true
fi
test -x "$GUARDD" || { echo "guardd binary missing"; exit 1; }
test -x "$PROBE" || { echo "guard-test-probe binary missing"; exit 1; }

WORK="$(mktemp -d -t guard-fanotify-XXXXXX)"
cleanup() {
  if [ -n "${GUARDD_PID:-}" ] && kill -0 "$GUARDD_PID" 2>/dev/null; then
    kill -TERM "$GUARDD_PID" 2>/dev/null || true
    wait "$GUARDD_PID" 2>/dev/null || true
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

PROTECTED="$WORK/protected"
UNPROTECTED="$WORK/unprotected"
echo "GUARD_SYNTHETIC_COOKIE_FIXTURE" > "$PROTECTED"
echo "ordinary unprotected content" > "$UNPROTECTED"

echo "==> Starting guardd (dev mode) protecting $PROTECTED"
"$GUARDD" --protect-test-file "$PROTECTED" --allow-exe "$PROBE" --print-decisions \
  > "$WORK/guardd.log" 2>&1 &
GUARDD_PID=$!

# Wait for enforcement to become active.
for _ in $(seq 1 50); do
  if grep -q "enforcement ACTIVE" "$WORK/guardd.log" 2>/dev/null; then break; fi
  kill -0 "$GUARDD_PID" 2>/dev/null || { echo "guardd exited early"; cat "$WORK/guardd.log"; exit 1; }
  sleep 0.1
done
grep -q "enforcement ACTIVE" "$WORK/guardd.log" || { echo "guardd did not become active"; cat "$WORK/guardd.log"; exit 1; }
echo "guardd active (pid=$GUARDD_PID)"

count_fds() { ls -1 "/proc/$GUARDD_PID/fd" 2>/dev/null | wc -l; }

echo "==> Test 1: unprotected file opens normally"
if "$PROBE" read "$UNPROTECTED" > "$WORK/t1.out" 2>/dev/null; then
  note_pass "unprotected file opened by probe"
else
  note_fail "unprotected file open failed"
fi

echo "==> Test 2: protected synthetic file denied for unauthorized opener (cat)"
if cat "$PROTECTED" > "$WORK/t2.out" 2>/dev/null; then
  note_fail "cat unexpectedly read protected file"
else
  note_pass "cat denied (open failed before read)"
fi

echo "==> Test 3: enrolled probe allowed to read protected file"
if "$PROBE" read "$PROTECTED" > "$WORK/t3.out" 2>/dev/null; then
  if grep -q "GUARD_SYNTHETIC_COOKIE_FIXTURE" "$WORK/t3.out"; then
    note_pass "enrolled probe read protected marker"
  else
    note_fail "probe read protected file but content mismatch"
  fi
else
  note_fail "enrolled probe was denied"
fi

echo "==> Test 4: repeated denied opens do not leak file descriptors"
FD_BEFORE="$(count_fds)"
for _ in $(seq 1 200); do
  cat "$PROTECTED" > /dev/null 2>&1 || true
done
FD_AFTER="$(count_fds)"
echo "    guardd fds: before=$FD_BEFORE after=$FD_AFTER"
# Allow a small margin (the kernel may keep a few transient fds); a leak would
# grow roughly with the number of opens.
if [ "$FD_AFTER" -le $((FD_BEFORE + 5)) ]; then
  note_pass "no fd leak (before=$FD_BEFORE after=$FD_AFTER)"
else
  note_fail "fd leak detected (before=$FD_BEFORE after=$FD_AFTER)"
fi

echo "==> Test 6: burst load (1000 denied opens) and latency"
START_NS="$(date +%s%N)"
for _ in $(seq 1 1000); do
  cat "$PROTECTED" > /dev/null 2>&1 || true
done
END_NS="$(date +%s%N)"
ELAPSED_MS=$(( (END_NS - START_NS) / 1000000 ))
PER_OPEN_US=$(( (END_NS - START_NS) / 1000 ))
echo "    1000 denied opens in ${ELAPSED_MS} ms (~${PER_OPEN_US} us/op incl. process spawn)"
# Daemon survived the burst without crashing?
if kill -0 "$GUARDD_PID" 2>/dev/null; then
  note_pass "burst completed without daemon crash"
else
  note_fail "daemon crashed during burst"
  GUARDD_PID=""
fi

echo "==> Test 5: daemon clean shutdown releases resources"
kill -TERM "$GUARDD_PID" 2>/dev/null || true
for _ in $(seq 1 50); do
  if ! kill -0 "$GUARDD_PID" 2>/dev/null; then break; fi
  sleep 0.1
done
if kill -0 "$GUARDD_PID" 2>/dev/null; then
  note_fail "guardd did not exit on SIGTERM"
  kill -KILL "$GUARDD_PID" 2>/dev/null || true
  GUARDD_PID=""
else
  note_pass "guardd exited on SIGTERM"
  GUARDD_PID=""
fi

echo
echo "==> Phase 02 root integration summary: PASS=$PASS FAIL=$FAIL BLOCKED=$BLOCKED"
echo "    (see $WORK/guardd.log for daemon decision log)"
if [ "$FAIL" -gt 0 ]; then exit 1; elif [ "$BLOCKED" -gt 0 ]; then exit 2; else exit 0; fi
