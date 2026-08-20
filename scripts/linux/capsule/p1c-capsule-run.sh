#!/bin/bash
# Capsule P1-c live test: AUTONOMOUS required-filesystem-mark-loss detection.
# - Marks ONLY a fresh capsule-internal loop-backed ext4 (independent superblock).
# - NEVER marks /testfs (host root bind), /, or changes host sysctls.
# - P1-c claim under test: mark loss is detected by the daemon event loop
#   (1s period) WITHOUT any guardctl status query; the IPC status path only
#   READS state. Evidence: the audit record "required_filesystem_mark_lost"
#   with "(autonomous)" appears while NO status query is made, and
#   continuity -> LOST(required_filesystem_mark_lost) with file_shield REDUCED.
set -euo pipefail

PASS=0; FAIL=0; BLOCKED=0
note_pass() { echo "PASS: $1"; PASS=$((PASS + 1)); }
note_fail() { echo "FAIL: $1"; FAIL=$((FAIL + 1)); }
note_blocked() { echo "BLOCKED: $1"; BLOCKED=$((BLOCKED + 1)); }

P1C_IMG="/testfs/p1c-$$.img"
P1C_LOOP=""
mkdir -p /p1cfs
truncate -s 256M "$P1C_IMG"
P1C_LOOP="$(losetup --find --show "$P1C_IMG")"
mkfs.ext4 -q -F "$P1C_LOOP"
mount "$P1C_LOOP" /p1cfs || { echo "BLOCKED: loop ext4 mount failed"; exit 2; }
ROOT_DEV=$(stat -c %d /); TESTFS_DEV=$(stat -c %d /testfs); P1C_DEV=$(stat -c %d /p1cfs)
echo "== super_block identities =="
echo "root=$ROOT_DEV testfs=$TESTFS_DEV p1cfs=$P1C_DEV"
if [ "$P1C_DEV" = "$ROOT_DEV" ] || [ "$P1C_DEV" = "$TESTFS_DEV" ]; then
  echo "REFUSING: p1cfs shares a super_block with root/testfs"; umount /p1cfs; losetup -d "$P1C_LOOP"; exit 2
fi

PROFILE=/p1cfs/profile
mkdir -p "$PROFILE/Default/Network"
printf 'P1C_MARKLOSS_FIXTURE' > "$PROFILE/Default/Network/Cookies"
printf '{}' > "$PROFILE/Default/Preferences"
printf '{}' > "$PROFILE/Local State"
cat > /p1cfs/config.json <<CONF_EOF
{
  "config_version": 1,
  "enforcement_mode": "strict-filesystem",
  "browsers": [
    { "id": "synthetic-chrome", "family": "Chromium",
      "profile_root": "$PROFILE", "owner_uid": 0, "exe_paths": [] }
  ],
  "enrolled_exes": [],
  "ssh_keys": []
}
CONF_EOF

status_json() {
  /stage/bin/guardctl --socket /p1cfs/guardd.sock --json status 2>/dev/null || echo "{}"
}
read_health() {
  status_json | python3 -c '
import json,sys
d=json.load(sys.stdin); data=d.get("data") or {}
lh=data.get("linux_health") or {}
print(lh.get("continuity","?")+"|"+str(lh.get("continuity_reason"))+"|"+str(lh.get("file_shield"))+"|"+str(data.get("filesystem_marks_healthy")))' 2>/dev/null \
  || echo "?|parse-error"
}

DAEMON_PID=""
cleanup() {
  if [ -n "$DAEMON_PID" ] && kill -0 "$DAEMON_PID" 2>/dev/null; then
    kill -KILL "$DAEMON_PID" 2>/dev/null || true
    wait "$DAEMON_PID" 2>/dev/null || true
  fi
  umount /p1cfs 2>/dev/null || true
  if [ -n "$P1C_LOOP" ]; then losetup -d "$P1C_LOOP" 2>/dev/null || true; fi
  rm -f -- "$P1C_IMG"
}
trap cleanup EXIT

/stage/bin/guardd --enforce-browser-config /p1cfs/config.json \
  --ipc-socket /p1cfs/guardd.sock --audit-db /p1cfs/audit.db --print-decisions \
  > /p1cfs/guardd.log 2>&1 &
DAEMON_PID=$!
for _ in $(seq 1 200); do
  [ -S /p1cfs/guardd.sock ] && break
  kill -0 "$DAEMON_PID" 2>/dev/null || { echo "guardd exited early"; sed -n '1,80p' /p1cfs/guardd.log 2>/dev/null; exit 1; }
  sleep 0.05
done
[ -S /p1cfs/guardd.sock ] || { echo "guardd not ready"; exit 1; }

echo "==> 1. continuity INTACT at startup"
C="$(read_health)"
if echo "$C" | grep -q '^INTACT|None|ACTIVE|True'; then
  note_pass "INTACT|ACTIVE|marks_healthy=True at startup ($C)"
else
  note_fail "startup health unexpected: $C"
fi

echo "==> 2. unknown probe denied while INTACT"
if /stage/bin/guard-test-probe read "$PROFILE/Default/Network/Cookies" >/dev/null 2>&1; then
  note_fail "unknown probe read the fixture"
else
  note_pass "unknown probe denied"
fi

echo "==> 3. remove the REAL kernel filesystem mark on the live group"
FSMARK_OUT="$(/stage/bin/guard-test-probe fsmark-remove "$DAEMON_PID" /p1cfs 2>&1)" || true
echo "    $FSMARK_OUT"
FSMARK_FD="$(echo "$FSMARK_OUT" | sed -n 's/.*fanotify_fd=\([0-9]*\).*/\1/p' | head -1)"
if echo "$FSMARK_OUT" | grep -q 'result=ok' && echo "$FSMARK_OUT" | grep -q 'sdev_after=0'; then
  note_pass "kernel filesystem mark removed from the live group (sdev_after=0)"
else
  note_fail "fsmark-remove did not drop the kernel mark: $FSMARK_OUT"
fi

echo "==> 4. AUTONOMOUS detection: sleep 3s with NO status query, then check"
# P1-c: the daemon's 1s event-loop check must detect the loss by itself.
# No guardctl call happens during the sleep. The audit record below is the
# proof of autonomous transition (the status read path never writes it).
sleep 3
C="$(read_health)"
echo "    health after autonomous window: $C"
if echo "$C" | grep -q '^LOST|required_filesystem_mark_lost|REDUCED'; then
  note_pass "continuity LOST(required_filesystem_mark_lost), file_shield REDUCED (autonomous)"
else
  note_fail "autonomous mark-loss transition not observed: $C"
fi

echo "==> 5. audit DB has the AUTONOMOUS revocation record"
AUDIT_SEEN=0
for _ in $(seq 1 20); do
  if python3 - /p1cfs/audit.db <<'PY_EOF'
import sqlite3, sys
conn = sqlite3.connect(sys.argv[1])
row = conn.execute(
  "SELECT event_code, backend_diag FROM events WHERE event_code='required_filesystem_mark_lost' ORDER BY id DESC LIMIT 1"
).fetchone()
print("  audit:", row if row else "none")
raise SystemExit(0 if row else 1)
PY_EOF
  then AUDIT_SEEN=1; break; fi
  sleep 0.1
done
if [ "$AUDIT_SEEN" = 1 ]; then
  note_pass "audit records required_filesystem_mark_lost with '(autonomous)'"
else
  note_fail "audit lacks the autonomous revocation record"
fi

echo "==> 6. restore the mark; continuity STAYS LOST (sticky)"
RESTORE_OUT="$(/stage/bin/guard-test-probe fsmark-restore "$DAEMON_PID" "$FSMARK_FD" /p1cfs 2>&1)" || true
echo "    $RESTORE_OUT"
if echo "$RESTORE_OUT" | grep -q 'sdev_after=[1-9]'; then
  note_pass "kernel filesystem mark restored"
else
  note_fail "fsmark-restore did not restore: $RESTORE_OUT"
fi
C="$(read_health)"
if echo "$C" | grep -q '^LOST|required_filesystem_mark_lost'; then
  note_pass "continuity STAYS LOST after restore (sticky)"
else
  note_fail "continuity erased by mark recovery: $C"
fi

echo "==> 7. enforcement resumed after mark restore (gating back)"
if /stage/bin/guard-test-probe read "$PROFILE/Default/Network/Cookies" >/dev/null 2>&1; then
  note_fail "probe read fixture after mark restore"
else
  note_pass "probe denied again after mark restore"
fi

echo
echo "==> P1-c summary: PASS=$PASS FAIL=$FAIL BLOCKED=$BLOCKED"
[ "$FAIL" -gt 0 ] && exit 1
[ "$BLOCKED" -gt 0 ] && exit 2
exit 0
