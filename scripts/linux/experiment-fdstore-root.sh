#!/usr/bin/env bash
# scripts/linux/experiment-fdstore-root.sh
#
# LFH4 experiment: can systemd fdstore preserve a fanotify group across a
# daemon crash+restart, shrinking the fail-open window?
#
# Verdict is ACCEPTED / PARTIAL / REJECTED — decided by the evidence produced,
# never presumed.
#
# Requirements (NOT satisfied inside systemd-nspawn, whose seccomp blocks
# fanotify): a real host with root, systemd >= 233, fanotify permission events
# (FAN_CLASS_CONTENT needs CAP_SYS_ADMIN).
#
# Build as the normal user first:
#   cargo build --release -p guard-fdstore -p guard-test-probe
# Then run as root:
#   SKIP_BUILD=1 bash scripts/linux/experiment-fdstore-root.sh
#
# guard-fdstore auto-detects its role: with LISTEN_FDS set (systemd passed a
# stored fd on restart) it CLAIMS that group; otherwise it STORES a new one.
# One ExecStart therefore serves both, which is the production pattern.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HELPER="$REPO/target/release/guard-fdstore"
PROBE="$REPO/target/release/guard-test-probe"

PASS=0
FAIL=0
BLOCKED=0
note_pass() { echo "PASS: $1"; PASS=$((PASS + 1)); }
note_fail() { echo "FAIL: $1"; FAIL=$((FAIL + 1)); }
note_blocked() { echo "BLOCKED: $1"; BLOCKED=$((BLOCKED + 1)); }

if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: run as root"
  exit 2
fi
command -v systemd-run >/dev/null 2>&1 || { echo "ERROR: systemd-run missing"; exit 2; }
for bin in "$HELPER" "$PROBE"; do
  test -x "$bin" || { echo "ERROR: missing $bin; build as the normal user first"; exit 2; }
done

UNIT="guard-fdstore-exp"
WORK="$(mktemp -d -t guard-fdstore-XXXXXX)"
PROTECTED="$WORK/protected"
printf 'GUARD_FDSTORE_CANARY' > "$PROTECTED"

cleanup() {
  systemctl stop "$UNIT.service" 2>/dev/null || true
  rm -f "/etc/systemd/system/$UNIT.service"
  rm -rf "/etc/systemd/system/$UNIT.service.d" "/run/systemd/system/$UNIT.service"
  rm -rf -- "$WORK"
}
trap cleanup EXIT

# Clean a previous run's unit artifacts.
systemctl stop "$UNIT.service" 2>/dev/null || true
rm -f "/etc/systemd/system/$UNIT.service"
rm -rf "/etc/systemd/system/$UNIT.service.d" "/run/systemd/system/$UNIT.service"

# The base unit must exist — a drop-in alone cannot create a unit.
cat > "/etc/systemd/system/$UNIT.service" <<EOF
[Unit]
Description=guard fdstore crash-continuity experiment (synthetic fixture)
[Service]
Type=notify
ExecStart=$HELPER $PROTECTED
FileDescriptorStoreMax=1
FileDescriptorStorePreserve=restart
Restart=always
RestartSec=1
EOF
systemctl daemon-reload

echo "==> First start: store a new group + fdstore upload"
systemctl start "$UNIT.service"
for _ in $(seq 1 100); do
  if systemctl is-active "$UNIT.service" >/dev/null 2>&1; then break; fi
  sleep 0.05
done
systemctl is-active "$UNIT.service" >/dev/null 2>&1 || {
  echo "ERROR: unit did not become active"
  journalctl -u "$UNIT.service" -n 20 --no-pager
  exit 1
}
echo "    active; MainPID=$(systemctl show "$UNIT.service" -p MainPID --value)"

echo "==> Probe 1: unknown process opens protected file (blocked while alive)"
timeout 5 "$PROBE" read "$PROTECTED" >/dev/null 2>&1 && {
  note_fail "probe succeeded while listener alive"
} || {
  note_pass "probe denied while listener alive"
}

echo "==> SIGKILL the helper"
HELPER_PID="$(systemctl show "$UNIT.service" -p MainPID --value)"
kill -KILL "$HELPER_PID" 2>/dev/null || true

echo "==> Probe 2: is the opener STILL blocked right after SIGKILL?"
( "$PROBE" read "$PROTECTED" > "$WORK/probe2.out" 2>&1; echo $? > "$WORK/probe2.rc" ) &
PROBE2_PID=$!
# Check BEFORE RestartSec=1 brings the claim helper back: with the fdstore
# duplicate alive, the group survives the crash and the opener must stay
# blocked (no fail-open). A restart that resolves the event inside this
# window would make the opener exit with a DENY — also acceptable, but the
# 0.5s probe proves the dead-window hold.
sleep 0.5
if kill -0 "$PROBE2_PID" 2>/dev/null; then
  note_pass "probe still blocked 0.5s after SIGKILL (fdstore holds the group)"
else
  note_fail "probe exited before restart (fail-open window observed)"
fi

echo "==> systemd restarts the unit; helper claims the stored group"
for _ in $(seq 1 100); do
  if systemctl is-active "$UNIT.service" >/dev/null 2>&1; then break; fi
  sleep 0.05
done
systemctl is-active "$UNIT.service" >/dev/null 2>&1 || {
  echo "ERROR: unit did not restart"
  journalctl -u "$UNIT.service" -n 30 --no-pager
  exit 1
}
NEW_PID="$(systemctl show "$UNIT.service" -p MainPID --value)"
echo "    restarted; MainPID=$NEW_PID"

echo "==> Probe 2 outcome: did the opener unblock with a DENY?"
sleep 1
if kill -0 "$PROBE2_PID" 2>/dev/null; then
  note_fail "probe still blocked after restart (no recovery)"
  kill -KILL "$PROBE2_PID" 2>/dev/null || true
else
  RC2="$(cat "$WORK/probe2.rc" 2>/dev/null || echo 124)"
  if [ "$RC2" -ne 0 ]; then
    note_pass "probe unblocked with denial after restart (rc=$RC2)"
  else
    note_fail "probe READ the protected file after restart (rc=$RC2) — fail open!"
  fi
fi

echo "==> Probe 3: fresh open is denied by the restarted (claimed) group"
timeout 5 "$PROBE" read "$PROTECTED" >/dev/null 2>&1 && {
  note_fail "probe succeeded against restarted group"
} || {
  note_pass "probe denied by restarted group (marks survived)"
}

systemctl stop "$UNIT.service" 2>/dev/null || true

echo
echo "==> LFH4 fdstore experiment summary: PASS=$PASS FAIL=$FAIL BLOCKED=$BLOCKED"
echo
if [ "$FAIL" -eq 0 ] && [ "$PASS" -ge 4 ]; then
  echo "VERDICT: ACCEPTED (fdstore preserved the fanotify group; queued event"
  echo "         processed after restart; marks still enforce)"
elif [ "$FAIL" -eq 0 ]; then
  echo "VERDICT: PARTIAL (no failure observed but not all oracle steps ran)"
else
  echo "VERDICT: REJECTED (fail-open or no recovery observed)"
fi
exit $FAIL
