#!/bin/bash
# Capsule P1-b live test: topology group overflow -> topology_uncertain ->
# persistent REDUCED health + ambiguous outside-path open fails closed.
# - Marks ONLY a fresh capsule-internal tmpfs (independent super_block).
# - NO host sysctl mutation (default topology queue = 16384; rename burst
#   exceeds it while the daemon is SIGSTOPped).
set -euo pipefail

PASS=0; FAIL=0; BLOCKED=0
note_pass() { echo "PASS: $1"; PASS=$((PASS + 1)); }
note_fail() { echo "FAIL: $1"; FAIL=$((FAIL + 1)); }
note_blocked() { echo "BLOCKED: $1"; BLOCKED=$((BLOCKED + 1)); }

mkdir -p /p1bfs
mount -t tmpfs p1b-fs /p1bfs || { echo "BLOCKED: tmpfs mount failed"; exit 2; }
ROOT_DEV=$(stat -c %d /); TESTFS_DEV=$(stat -c %d /testfs); P1B_DEV=$(stat -c %d /p1bfs)
echo "root=$ROOT_DEV testfs=$TESTFS_DEV p1bfs=$P1B_DEV"
if [ "$P1B_DEV" = "$ROOT_DEV" ] || [ "$P1B_DEV" = "$TESTFS_DEV" ]; then
  echo "REFUSING: p1bfs shares a super_block"; umount /p1bfs; exit 3
fi

PROFILE=/p1bfs/profile
mkdir -p "$PROFILE/Default/Network/burst"
printf 'P1B_FIXTURE' > "$PROFILE/Default/Network/Cookies"
printf '{}' > "$PROFILE/Default/Preferences"
printf '{}' > "$PROFILE/Local State"
printf 'P1B_OUTSIDE' > /p1bfs/outside.txt
cat > /p1bfs/config.json <<'CONF_END'
{
  "config_version": 1,
  "enforcement_mode": "strict-filesystem",
  "browsers": [
    { "id": "synthetic-chrome", "family": "Chromium",
      "profile_root": "/p1bfs/profile", "owner_uid": 0, "exe_paths": [] }
  ],
  "enrolled_exes": [],
  "ssh_keys": []
}
CONF_END

read_health() {
  /stage/bin/guardctl --socket /p1bfs/guardd.sock --json status 2>/dev/null | python3 -c '
import json,sys
d=json.load(sys.stdin); data=d.get("data") or {}
lh=data.get("linux_health") or {}
print(lh.get("file_shield","?")+"|"+lh.get("continuity","?")+"|"+str(lh.get("continuity_reason")))' 2>/dev/null \
  || echo "?|parse-error"
}

DAEMON_PID=""
cleanup() {
  if [ -n "$DAEMON_PID" ] && kill -0 "$DAEMON_PID" 2>/dev/null; then
    kill -KILL "$DAEMON_PID" 2>/dev/null || true
    wait "$DAEMON_PID" 2>/dev/null || true
  fi
  umount /p1bfs 2>/dev/null || true
}
trap cleanup EXIT

/stage/bin/guardd --enforce-browser-config /p1bfs/config.json \
  --ipc-socket /p1bfs/guardd.sock --audit-db /p1bfs/audit.db --print-decisions \
  > /tmp/p1b-guardd.log 2>&1 &
DAEMON_PID=$!
for _ in $(seq 1 200); do
  [ -S /p1bfs/guardd.sock ] && break
  kill -0 "$DAEMON_PID" 2>/dev/null || { echo "guardd exited early"; sed -n '1,60p' /p1bfs/guardd.log; exit 1; }
  sleep 0.05
done
[ -S /p1bfs/guardd.sock ] || { echo "guardd not ready"; exit 1; }

echo "==> 1. ACTIVE at startup with topology healthy"
C="$(read_health)"
if echo "$C" | grep -q '^ACTIVE|INTACT'; then
  note_pass "file_shield ACTIVE, continuity INTACT ($C)"
else
  note_fail "startup health unexpected: $C"
fi

echo "==> 2. ambiguous outside-path open ALLOWED while topology healthy"
if /stage/bin/guard-test-probe read /p1bfs/outside.txt >/dev/null 2>&1; then
  note_pass "outside-path open allowed pre-overflow (Unrelated)"
else
  note_fail "outside-path open denied pre-overflow (unexpected)"
fi

echo "==> 3. pre-create 22000 burst files (opens while daemon runs)"
/stage/bin/rename-burst create "$PROFILE/Default/Network/burst" 22000 2>&1 | tail -1
echo "    burst files created"

echo "==> 4. SIGSTOP daemon; rename burst -> topology queue overflow (16384)"
kill -STOP "$DAEMON_PID"
# Each file renamed twice = 44000 FAN_MOVE events while the daemon is
# SIGSTOPped; the topology queue (default max_queued_events=16384) overflows.
# Renames never open files, so the PERMISSION queue stays empty.
/stage/bin/rename-burst rename "$PROFILE/Default/Network/burst" 22000 2>&1 | tail -1
kill -CONT "$DAEMON_PID"
echo "    SIGCONT; waiting for daemon to process overflow"

echo "==> 5. topology_uncertain -> file_shield REDUCED (persistent health)"
REDUCED=0
for _ in $(seq 1 100); do
  if read_health | grep -q '^REDUCED'; then REDUCED=1; break; fi
  sleep 0.1
done
if [ "$REDUCED" = 1 ]; then
  note_pass "file_shield REDUCED after topology overflow ($(read_health))"
else
  note_fail "file_shield did not become REDUCED: $(read_health)"
fi

echo "==> 6. ambiguous outside-path open DENIED while topology uncertain"
if /stage/bin/guard-test-probe read /p1bfs/outside.txt >/dev/null 2>&1; then
  note_fail "outside-path open ALLOWED while topology uncertain (fail-open!)"
else
  note_pass "outside-path open denied (fail-closed) while topology uncertain"
fi

echo "==> 7. guardd log records the topology overflow (truthfulness)"
# The log lives on UNMARKED /tmp: while topology_uncertain, every non-indexed
# open ON THE MARKED FS is denied (that is the fail-closed behavior under
# test), so reading the log from the marked fs would itself be denied.
if grep -q "topology group overflow" /tmp/p1b-guardd.log; then
  note_pass "daemon log: topology group overflow recorded"
else
  note_fail "daemon log lacks topology overflow record"
fi

echo
echo "==> P1-b summary: PASS=$PASS FAIL=$FAIL BLOCKED=$BLOCKED"
[ "$FAIL" -gt 0 ] && exit 1
[ "$BLOCKED" -gt 0 ] && exit 2
exit 0
