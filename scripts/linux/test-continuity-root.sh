#!/usr/bin/env bash
# scripts/linux/test-continuity-root.sh
#
# LFH3 privileged integration test: protection continuity semantics, LIVE.
#   - R3: deterministic kernel fanotify-queue overflow (temporarily lower
#     /proc/sys/fs/fanotify/max_queued_events, create the group under the low
#     limit, restore the sysctl, SIGSTOP the daemon, launch limit+margin
#     concurrent opens, SIGCONT) => fanotify_overflows increments, continuity
#     LOST(fanotify_queue_overflow). Dropped events are NEVER claimed denied.
#   - R4: REAL kernel mark loss — a test helper duplicates the exact live
#     permission-group fd via pidfd_open+pidfd_getfd and performs
#     FAN_MARK_REMOVE|FAN_MARK_FILESYSTEM; the daemon's fdinfo mark count
#     drops, status detects filesystem_marks_healthy=false, continuity becomes
#     LOST(required_filesystem_mark_lost) with the audit trail recording the
#     revocation; restoring the mark does NOT erase the sticky LOST.
#   - sticky semantics (recovery never erases historical loss).
#
# Everything runs on an isolated loop-backed ext4 (the fs-scoped permission
# mark can never gate the rest of the machine — including while the daemon is
# SIGSTOPped). Synthetic fixtures only. Exit codes: 0=PASS, 1=FAIL, 2=BLOCKED.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN_DIR="${BIN_DIR:-$REPO/target/release}"
GUARDD="${GUARDD:-$BIN_DIR/guardd}"
GUARDCTL="${GUARDCTL:-$BIN_DIR/guardctl}"
PROBE="${PROBE:-$BIN_DIR/guard-test-probe}"
SYSCTL="/proc/sys/fs/fanotify/max_queued_events"

PASS=0; FAIL=0; BLOCKED=0; MANDATORY_BLOCKED=0
note_pass() { echo "PASS: $1"; PASS=$((PASS + 1)); }
note_fail() { echo "FAIL: $1"; FAIL=$((FAIL + 1)); }
note_blocked() { echo "BLOCKED: $1"; BLOCKED=$((BLOCKED + 1)); }
note_mandatory_blocked() { echo "BLOCKED(mandatory): $1"; MANDATORY_BLOCKED=$((MANDATORY_BLOCKED + 1)); }

if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: run as root (fanotify FAN_CLASS_CONTENT requires CAP_SYS_ADMIN)"
  exit 2
fi
for bin in "$GUARDD" "$GUARDCTL" "$PROBE"; do
  test -x "$bin" || { echo "ERROR: missing $bin; build as the normal user first"; exit 2; }
done
[ -r "$SYSCTL" ] || { echo "ERROR: $SYSCTL not readable on this kernel"; exit 2; }

# --- isolated loop-backed ext4 (never touches the root fs) ---
LOOP_IMG=""; LOOP_DEV=""; LOOP_MNT=""; DAEMON_PID=""
SYSCTL_SAVED=""
cleanup() {
  if [ -n "$DAEMON_PID" ] && kill -0 "$DAEMON_PID" 2>/dev/null; then
    kill -KILL "$DAEMON_PID" 2>/dev/null || true
    wait "$DAEMON_PID" 2>/dev/null || true
  fi
  if [ -n "$SYSCTL_SAVED" ]; then
    echo "$SYSCTL_SAVED" > "$SYSCTL" 2>/dev/null || true
  fi
  if [ -n "$LOOP_DEV" ]; then
    umount "$LOOP_DEV" 2>/dev/null || true
    losetup -d "$LOOP_DEV" 2>/dev/null || true
    rm -f "$LOOP_IMG" 2>/dev/null || true
    rmdir "$LOOP_MNT" 2>/dev/null || true
  fi
}
trap cleanup EXIT
LOOP_IMG="$(mktemp /tmp/guard-continuity-img-XXXXXX.img)"
truncate -s 512M "$LOOP_IMG"
LOOP_DEV="$(losetup -f)"
losetup "$LOOP_DEV" "$LOOP_IMG"
mkfs.ext4 -q -F "$LOOP_DEV"
LOOP_MNT="$(mktemp -d /tmp/guard-continuity-mnt-XXXXXX)"
mount "$LOOP_DEV" "$LOOP_MNT"
echo "isolated loop-backed ext4: $LOOP_DEV at $LOOP_MNT"

PROFILE="$LOOP_MNT/profile"
CHROME_UDD="$PROFILE"
mkdir -p "$CHROME_UDD/Default/Network"
printf 'GUARD_CONTINUITY_FIXTURE' > "$CHROME_UDD/Default/Network/Cookies"
printf '{}' > "$CHROME_UDD/Default/Preferences"
printf '{}' > "$CHROME_UDD/Local State"

cat > "$LOOP_MNT/config.json" <<EOF
{
  "config_version": 1,
  "enforcement_mode": "strict-filesystem",
  "browsers": [
    {
      "id": "synthetic-chrome",
      "family": "Chromium",
      "profile_root": "$CHROME_UDD",
      "owner_uid": 0,
      "exe_paths": []
    }
  ],
  "enrolled_exes": [],
  "ssh_keys": []
}
EOF

status_linux() {
  "$GUARDCTL" --socket "$LOOP_MNT/guardd.sock" --json status 2>/dev/null \
    | python3 -c 'import json,sys; d=json.load(sys.stdin); lh=(d.get("data") or {}).get("linux_health") or {}; print(lh.get("continuity","?")+"|"+str(lh.get("continuity_reason")))' \
    || echo "?|parse-error"
}
# A freshly started guardd may not answer the IPC socket for a few ms; retry
# until the status JSON parses (a parse-error is NOT a continuity verdict).
wait_status_ok() {
  for _ in $(seq 1 50); do
    C="$(status_linux)"
    if ! echo "$C" | grep -q 'parse-error'; then
      echo "$C"
      return 0
    fi
    sleep 0.1
  done
  echo "?|parse-error"
  return 1
}
overflow_counter() {
  "$GUARDCTL" --socket "$LOOP_MNT/guardd.sock" --json status 2>/dev/null \
    | python3 -c 'import json,sys; d=json.load(sys.stdin); print((d.get("data") or {}).get("fanotify_overflows",-1))' \
    || echo "-1"
}

start_guardd() {
  "$GUARDD" --enforce-browser-config "$LOOP_MNT/config.json" \
    --ipc-socket "$LOOP_MNT/guardd.sock" --audit-db "$LOOP_MNT/audit.db" --print-decisions \
    > "$LOOP_MNT/guardd.log" 2>&1 &
  DAEMON_PID=$!
  for _ in $(seq 1 200); do
    [ -S "$LOOP_MNT/guardd.sock" ] && break
    kill -0 "$DAEMON_PID" 2>/dev/null || { echo "guardd exited early"; sed -n '1,120p' "$LOOP_MNT/guardd.log"; exit 1; }
    sleep 0.05
  done
  [ -S "$LOOP_MNT/guardd.sock" ] || { echo "guardd did not become ready"; sed -n '1,120p' "$LOOP_MNT/guardd.log"; exit 1; }
}

stop_guardd() {
  if [ -n "$DAEMON_PID" ] && kill -0 "$DAEMON_PID" 2>/dev/null; then
    kill -TERM "$DAEMON_PID" 2>/dev/null || true
    for _ in $(seq 1 50); do
      kill -0 "$DAEMON_PID" 2>/dev/null || break
      sleep 0.05
    done
    if kill -0 "$DAEMON_PID" 2>/dev/null; then
      note_fail "guardd did not exit on SIGTERM"
      kill -KILL "$DAEMON_PID" 2>/dev/null || true
      wait "$DAEMON_PID" 2>/dev/null || true
      DAEMON_PID=""
      return
    fi
    wait "$DAEMON_PID" 2>/dev/null || true
    note_pass "guardd exited on SIGTERM"
    DAEMON_PID=""
  fi
}

# ===========================================================================
echo "==> Test A: deterministic live kernel fanotify-queue overflow (R3)"
# ===========================================================================
SYSCTL_SAVED="$(cat "$SYSCTL")"
echo "    saved max_queued_events=$SYSCTL_SAVED"
echo 64 > "$SYSCTL"
start_guardd
# The group's queue limit is fixed at fanotify_init; the daemon has now
# initialized under the low limit (socket up happens after the group marks).
# Restore the host sysctl immediately so the rest of the test runs normally.
echo "$SYSCTL_SAVED" > "$SYSCTL"
SYSCTL_SAVED=""   # restored; cleanup must not clobber again
echo "    restored max_queued_events=$(cat "$SYSCTL") (group limit fixed at init: 64)"

echo "==> A.1 continuity starts INTACT"
C="$(wait_status_ok)"
if echo "$C" | grep -q '^INTACT|None'; then
  note_pass "continuity INTACT at startup"
else
  note_fail "continuity not INTACT at startup: $C"
fi

echo "==> A.2 unknown probe denied while INTACT"
if "$PROBE" read "$CHROME_UDD/Default/Network/Cookies" >/dev/null 2>&1; then
  note_fail "unknown probe read cookie fixture"
else
  note_pass "unknown probe denied"
fi

echo "==> A.3 SIGSTOP daemon, launch 80 concurrent opens on the loop fs (limit 64)"
kill -STOP "$DAEMON_PID"
OVERFLOW_PID=""
( seq 1 80 | xargs -P 80 -n1 -I{} "$PROBE" read "$CHROME_UDD/Default/Network/Cookies" >/dev/null 2>&1 ) &
OVERFLOW_PID=$!
# Let the opens reach the kernel; the first 64 queue, the rest overflow.
sleep 1
kill -CONT "$DAEMON_PID"

echo "==> A.4 poll for continuity LOST(fanotify_queue_overflow)"
LOST=0
for _ in $(seq 1 100); do
  if status_linux | grep -q '^LOST|fanotify_queue_overflow'; then LOST=1; break; fi
  sleep 0.1
done
if [ "$LOST" = 1 ]; then
  note_pass "overflow observed => continuity LOST (fanotify_queue_overflow)"
else
  note_fail "continuity did not become LOST after the overflow burst: $(status_linux)"
fi

OVFL="$(overflow_counter)"
if [ "$OVFL" -ge 1 ] 2>/dev/null; then
  note_pass "fanotify_overflows counter incremented ($OVFL)"
else
  note_fail "fanotify_overflows counter did not increment: $OVFL"
fi

echo "==> A.5 dropped events are NOT claimed denied (truthfulness wording)"
if grep -q "dropped events were NOT denied by Guard" "$LOOP_MNT/guardd.log"; then
  note_pass "daemon wording: dropped events NOT denied by Guard"
else
  note_fail "daemon log lacks the overflow truthfulness wording"
fi

# Reap the burst (bounded), then a fresh daemon for test B.
kill "$OVERFLOW_PID" 2>/dev/null || true
wait "$OVERFLOW_PID" 2>/dev/null || true
pkill -9 -f "guard-test-probe read $CHROME_UDD" 2>/dev/null || true
stop_guardd

# ===========================================================================
echo "==> Test B: REAL kernel mark loss via FAN_MARK_REMOVE on the live group (R4)"
# ===========================================================================
start_guardd
C="$(wait_status_ok)"
if echo "$C" | grep -q '^INTACT|None'; then
  note_pass "B: continuity INTACT at startup"
else
  note_fail "B: continuity not INTACT at startup: $C"
fi

echo "==> B.1 duplicate the exact permission-group fd and remove the fs mark"
FSMARK_OUT="$("$PROBE" fsmark-remove "$DAEMON_PID" "$CHROME_UDD" 2>&1)" || true
echo "    $FSMARK_OUT"
FSMARK_FD="$(echo "$FSMARK_OUT" | sed -n 's/.*fanotify_fd=\([0-9]*\).*/\1/p' | head -1)"
if echo "$FSMARK_OUT" | grep -q 'sdev_before=[1-9]' && echo "$FSMARK_OUT" | grep -q 'sdev_after=0'; then
  note_pass "kernel fdinfo filesystem-mark count dropped (before->after via FAN_MARK_REMOVE on the exact live group)"
else
  note_fail "fsmark-remove did not drop the kernel mark count: $FSMARK_OUT"
fi

echo "==> B.2 status detects the mark loss => continuity LOST(required_filesystem_mark_lost)"
MLOST=0
for _ in $(seq 1 50); do
  if status_linux | grep -q '^LOST|required_filesystem_mark_lost'; then MLOST=1; break; fi
  sleep 0.1
done
if [ "$MLOST" = 1 ]; then
  note_pass "required mark loss => continuity LOST (required_filesystem_mark_lost)"
else
  note_fail "mark loss not detected: $(status_linux)"
fi

echo "==> B.3 audit trail records the revocation"
AUDIT_SEEN=0
for _ in $(seq 1 30); do
  if python3 - "$LOOP_MNT/audit.db" <<'PY'
import sqlite3, sys
conn = sqlite3.connect(sys.argv[1])
row = conn.execute(
    "SELECT event_code, backend_diag FROM events WHERE event_code = 'required_filesystem_mark_lost' ORDER BY id DESC LIMIT 1"
).fetchone()
print("  audit:", row if row else "none")
raise SystemExit(0 if row else 1)
PY
  then
    AUDIT_SEEN=1
    break
  fi
  sleep 0.1
done
if [ "$AUDIT_SEEN" = 1 ]; then
  note_pass "audit DB records required_filesystem_mark_lost (revocation evidence)"
else
  note_fail "audit DB lacks the mark-loss revocation record"
fi

echo "==> B.4 restore the mark; continuity stays LOCKED/sticky"
if [ -n "$FSMARK_FD" ]; then
  RESTORE_OUT="$("$PROBE" fsmark-restore "$DAEMON_PID" "$FSMARK_FD" "$CHROME_UDD" 2>&1)" || true
else
  RESTORE_OUT="$("$PROBE" fsmark-restore "$DAEMON_PID" "$CHROME_UDD" 2>&1)" || true
fi
echo "    $RESTORE_OUT"
if echo "$RESTORE_OUT" | grep -q 'sdev_before=0' && echo "$RESTORE_OUT" | grep -q 'sdev_after=[1-9]'; then
  note_pass "kernel filesystem mark restored (FAN_MARK_ADD on the exact live group)"
else
  note_fail "fsmark-restore did not restore the kernel mark: $RESTORE_OUT"
fi
C="$(status_linux)"
if echo "$C" | grep -q '^LOST|required_filesystem_mark_lost'; then
  note_pass "continuity STAYS LOST after mark restore (sticky, never erased)"
else
  note_fail "continuity was erased by mark recovery: $C"
fi

echo "==> B.5 unknown probe denied again after the mark is restored"
if "$PROBE" read "$CHROME_UDD/Default/Network/Cookies" >/dev/null 2>&1; then
  note_fail "B.5: unknown probe read the fixture after mark restore"
else
  note_pass "B.5: enforcement resumed after mark restore (gating back)"
fi

stop_guardd

echo
echo "==> LFH3 continuity root summary: PASS=$PASS FAIL=$FAIL BLOCKED=$BLOCKED MANDATORY_BLOCKED=$MANDATORY_BLOCKED"
echo "    (see $LOOP_MNT/guardd.log for daemon decision log)"
if [ "$FAIL" -gt 0 ]; then exit 1; elif [ "$MANDATORY_BLOCKED" -gt 0 ]; then exit 2; else exit 0; fi
