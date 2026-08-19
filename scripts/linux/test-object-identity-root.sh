#!/usr/bin/env bash
# scripts/linux/test-object-identity-root.sh
#
# LFH2 privileged integration test: dynamic protected-object identity via
# opaque filesystem handles (name_to_handle_at on the event fd). Closes the
# rename-out gap (same object renamed outside the profile is still recognized
# by handle) while rejecting inode reuse (a different object reusing the inode
# is Unrelated). ALSO runs the LFH2 Step 3 scenario: a NEVER-OPENED dynamic
# object renamed out of a protected tree is learned by the SEPARATE
# FAN_CLASS_NOTIF|FAN_REPORT_FID topology group and the unknown reader is
# denied. Synthetic files only.
#
# REQUIRES a real handle-supporting filesystem (NOT tmpfs): point TEST_FS_ROOT
# at one, e.g. /var/tmp (root-fs ext4). The capability probe
# (`guardctl capabilities`) reports handle support per filesystem.
#
# Build as the normal user first, then run as root on a fanotify-capable host:
#   TEST_FS_ROOT=/var/tmp SKIP_BUILD=1 bash scripts/linux/test-object-identity-root.sh
#
# Exit codes (standardized): 0 = PASS, 1 = FAIL, 2 = BLOCKED (mandatory gate
# could not run; a mandatory BLOCKED gate must never be reported as PASS).
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
GUARDD="$REPO/target/release/guardd"
GUARDCTL="$REPO/target/release/guardctl"
PROBE="$REPO/target/release/guard-test-probe"

PASS=0
FAIL=0
BLOCKED=0
note_pass() { echo "PASS: $1"; PASS=$((PASS + 1)); }
note_fail() { echo "FAIL: $1"; FAIL=$((FAIL + 1)); }
note_blocked() { echo "BLOCKED: $1"; BLOCKED=$((BLOCKED + 1)); }

if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: run as root (fanotify FAN_CLASS_CONTENT requires CAP_SYS_ADMIN)"
  exit 2
fi
for bin in "$GUARDD" "$GUARDCTL" "$PROBE"; do
  test -x "$bin" || { echo "ERROR: missing $bin; build as the normal user first"; exit 2; }
done

# --- isolated REAL filesystem for the test fixtures ---
#
# Strict mode installs FAN_MARK_FILESYSTEM | FAN_OPEN_PERM on the filesystem
# containing the profile: EVERY open on that filesystem is gated by guardd.
# Marking the ROOT filesystem would gate the entire machine — any
# slowdown/overload in the daemon then blocks every process (a full system
# lock). The fixtures therefore live on a DEDICATED loop-backed ext4 image:
# a real handle-supporting filesystem whose marking can never affect the rest
# of the system. TEST_FS_ROOT may override with an explicit non-root,
# non-tmpfs filesystem.
LOOP_IMG=""
LOOP_DEV=""
LOOP_MNT=""
WORK=""
select_test_fs() {
  if [ -n "${TEST_FS_ROOT:-}" ]; then
    if [ "$(stat -c %d "$TEST_FS_ROOT")" = "$(stat -c %d /)" ]; then
      echo "BLOCKED: TEST_FS_ROOT=$TEST_FS_ROOT is on the ROOT filesystem; strict mode"
      echo "        would gate every open on the whole system. Leave TEST_FS_ROOT unset"
      echo "        to auto-create an isolated loop-backed ext4 image."
      exit 2
    fi
    if [ "$(stat -f -c %T "$TEST_FS_ROOT")" = "tmpfs" ]; then
      echo "BLOCKED: TEST_FS_ROOT=$TEST_FS_ROOT is tmpfs; object handles unsupported"
      exit 2
    fi
    WORK="$(mktemp -d "$TEST_FS_ROOT/guard-object-id-XXXXXX")"
    return
  fi
  LOOP_IMG="$(mktemp /tmp/guard-objectid-img-XXXXXX.img)"
  truncate -s 512M "$LOOP_IMG"
  LOOP_DEV="$(losetup -f)"
  losetup "$LOOP_DEV" "$LOOP_IMG"
  mkfs.ext4 -q -F "$LOOP_DEV"
  LOOP_MNT="$(mktemp -d /tmp/guard-objectid-mnt-XXXXXX)"
  mount "$LOOP_DEV" "$LOOP_MNT"
  WORK="$LOOP_MNT"
  echo "isolated loop-backed ext4: $LOOP_DEV at $LOOP_MNT (never touches the root fs)"
}
select_test_fs

DAEMON_PID=""
cleanup() {
  if [ -n "$DAEMON_PID" ] && kill -0 "$DAEMON_PID" 2>/dev/null; then
    kill -TERM "$DAEMON_PID" 2>/dev/null || true
    for _ in $(seq 1 50); do
      kill -0 "$DAEMON_PID" 2>/dev/null || break
      sleep 0.05
    done
    if kill -0 "$DAEMON_PID" 2>/dev/null; then
      kill -KILL "$DAEMON_PID" 2>/dev/null || true
      wait "$DAEMON_PID" 2>/dev/null || true
    fi
  fi
  if [ -n "$LOOP_DEV" ]; then
    umount "$LOOP_DEV" 2>/dev/null || true
    losetup -d "$LOOP_DEV" 2>/dev/null || true
    rm -f "$LOOP_IMG" 2>/dev/null || true
    rmdir "$LOOP_MNT" 2>/dev/null || true
  else
    rm -rf -- "$WORK" 2>/dev/null || true
  fi
}
trap cleanup EXIT

# --- synthetic Chromium profile (fixtures created BEFORE guardd starts, so
# they never open through the firewall — including the Step 3 never-opened
# object, which must be pre-existing and never opened under its protected
# path) ---
CHROME_UDD="$WORK/chrome-udd"
mkdir -p "$CHROME_UDD/Default/Local Storage/leveldb"
printf 'GUARD_OBJECTID_DYNAMIC_FIXTURE' > "$CHROME_UDD/Default/Local Storage/leveldb/000001.log"
printf 'GUARD_OBJECTID_NEVER_OPENED_FIXTURE' > "$CHROME_UDD/Default/Local Storage/leveldb/999999.log"
printf '{}' > "$CHROME_UDD/Default/Preferences"
printf '{}' > "$CHROME_UDD/Local State"

ENROLLED="$WORK/synthetic-chrome"
cp "$PROBE" "$ENROLLED"
chmod 0755 "$ENROLLED"

cat > "$WORK/config.json" <<EOF
{
  "config_version": 1,
  "enforcement_mode": "strict-filesystem",
  "browsers": [
    {
      "id": "synthetic-chrome",
      "family": "Chromium",
      "profile_root": "$CHROME_UDD",
      "owner_uid": 0,
      "exe_paths": ["$ENROLLED"]
    }
  ],
  "enrolled_exes": ["$ENROLLED"],
  "ssh_keys": []
}
EOF

echo "==> Starting guardd (strict-filesystem) on ${TEST_FS_ROOT:-$LOOP_MNT}"
# guardd's OWN operational files (socket, audit db, log) stay on the
# UNMARKED tmpfs: they must never sit on the filesystem strict mode gates,
# and the socket path is referenced below.
SOCK="/tmp/guard-objectid-sock-$$.sock"
AUDIT="/tmp/guard-objectid-audit-$$.db"
"$GUARDD" --enforce-browser-config "$WORK/config.json" \
  --ipc-socket "$SOCK" --audit-db "$AUDIT" --print-decisions \
  > "$WORK/guardd.log" 2>&1 &
DAEMON_PID=$!
for _ in $(seq 1 100); do
  [ -S "$SOCK" ] && break
  kill -0 "$DAEMON_PID" 2>/dev/null || { echo "guardd exited early"; cat "$WORK/guardd.log"; exit 2; }
  sleep 0.05
done
[ -S "$SOCK" ] || { echo "guardd did not become ready"; cat "$WORK/guardd.log"; exit 2; }
for _ in $(seq 1 50); do
  STATUS="$("$GUARDCTL" --socket "$SOCK" --json status 2>/dev/null || true)"
  [ -n "$STATUS" ] && echo "$STATUS" | grep -qE '"enforcement_active"[[:space:]]*:[[:space:]]*true' && break
  sleep 0.05
done
if ! echo "$STATUS" | grep -qE '"enforcement_active"[[:space:]]*:[[:space:]]*true'; then
  echo "BLOCKED: guardd did not reach enforcement (see $WORK/guardd.log)"
  exit 2
fi
note_pass "guardd enforcing (strict-filesystem)"

DYNAMIC="$CHROME_UDD/Default/Local Storage/leveldb/000001.log"
NEVER="$CHROME_UDD/Default/Local Storage/leveldb/999999.log"

# Run a probe expecting DENIAL; verifies Guard attribution in the daemon log.
probe_denied_with_attribution() { # path label
  local path="$1" label="$2"
  "$PROBE" read "$path" >/dev/null 2>&1 &
  local p=$!
  if wait "$p"; then
    note_fail "$label: probe READ the fixture (deny missed)"
    return 1
  fi
  if grep -q "pid=$p .*DENY(" "$WORK/guardd.log" 2>/dev/null; then
    note_pass "$label: probe denied with Guard attribution (pid=$p)"
  else
    note_fail "$label: probe denied but no Guard DENY attribution for pid=$p"
  fi
}

echo "==> 1. dynamic object under protected path => protected + attribution"
probe_denied_with_attribution "$DYNAMIC" "1. protected path"

echo "==> 2. rename dynamic object OUTSIDE the profile => still denied (handle identity)"
mv "$DYNAMIC" "$WORK/exfiltrated.log"
probe_denied_with_attribution "$WORK/exfiltrated.log" "2. renamed-out dynamic object"

echo "==> 3. (LFH2 Step 3) NEVER-OPENED dynamic object renamed out => denied"
# The pre-existing object's handle is learned by the STARTUP SNAPSHOT (and by
# any topology MOVED_TO event); the snapshot line proves the identity was
# captured before the rename. Settle so any event processing completes before
# the reader opens (deterministic acceptance; the residual sub-queue-latency
# race is documented as REDUCED, not claimed closed).
mv "$NEVER" "$WORK/never-exfil.log"
if grep -q "snapshot of pre-existing dynamic object handles" "$WORK/guardd.log" 2>/dev/null; then
  note_pass "3. startup snapshot learned pre-existing dynamic objects"
else
  note_fail "3. startup snapshot did not run (see guardd.log)"
fi
for _ in $(seq 1 100); do
  sleep 0.05
done
probe_denied_with_attribution "$WORK/never-exfil.log" "3. never-opened renamed-out object"

echo "==> 4. inode reuse / stale mapping => no false positive (replaced moved-out name)"
# Delete the moved-out object, then create an UNRELATED file at the same name
# OUTSIDE the protected tree. If the kernel reuses the learned inode number,
# the new object's handle differs => Unrelated (stale mapping dropped); a new
# inode has no candidate at all. Either way an unknown probe must open it
# normally (no over-broad denial from the stale learned mapping).
rm -f "$WORK/exfiltrated.log"
printf 'ordinary unrelated data' > "$WORK/exfiltrated.log"
if "$PROBE" read "$WORK/exfiltrated.log" >/dev/null 2>&1; then
  note_pass "4. unrelated file at the replaced moved-out name opens normally"
else
  note_fail "4. unrelated file denied (false positive from stale learned mapping)"
fi

echo "==> 5. audit/daemon log contains no fixture bytes"
if grep -rq "GUARD_OBJECTID_DYNAMIC_FIXTURE\|GUARD_OBJECTID_NEVER_OPENED_FIXTURE" "$WORK/guardd.log" 2>/dev/null; then
  note_fail "daemon log leaked fixture bytes"
else
  note_pass "no fixture bytes in daemon log"
fi

kill -TERM "$DAEMON_PID" 2>/dev/null || true
for _ in $(seq 1 50); do
  if ! kill -0 "$DAEMON_PID" 2>/dev/null; then break; fi
  sleep 0.05
done
if kill -0 "$DAEMON_PID" 2>/dev/null; then
  note_fail "guardd did not exit on SIGTERM"
  kill -KILL "$DAEMON_PID" 2>/dev/null || true
  DAEMON_PID=""
else
  note_pass "guardd exited on SIGTERM"
  DAEMON_PID=""
fi

echo
echo "==> LFH2 object-identity root summary: PASS=$PASS FAIL=$FAIL BLOCKED=$BLOCKED"
echo "    (see $WORK/guardd.log for daemon decision log)"
if [ "$FAIL" -gt 0 ]; then
  exit 1
elif [ "$BLOCKED" -gt 0 ]; then
  exit 2
fi
exit 0
