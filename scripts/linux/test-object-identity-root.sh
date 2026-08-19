#!/usr/bin/env bash
# scripts/linux/test-object-identity-root.sh
#
# LFH2 privileged integration test: dynamic protected-object identity via
# opaque filesystem handles (name_to_handle_at on the event fd). Closes the
# rename-out gap (same object renamed outside the profile is still recognized
# by handle) while rejecting inode reuse (a different object reusing the inode
# is Unrelated). Synthetic files only.
#
# Build as the normal user first, then run as root on a fanotify-capable host
# (NOT inside systemd-nspawn: its seccomp blocks fanotify):
#   SKIP_BUILD=1 bash scripts/linux/test-object-identity-root.sh
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

# Handle-supporting sandbox: must NOT be tmpfs (name_to_handle_at unsupported).
WORK="$(mktemp -d -t guard-object-id-XXXXXX)"
DAEMON_PID=""
cleanup() {
  if [ -n "$DAEMON_PID" ] && kill -0 "$DAEMON_PID" 2>/dev/null; then
    kill -TERM "$DAEMON_PID" 2>/dev/null || true
    wait "$DAEMON_PID" 2>/dev/null || true
  fi
  rm -rf -- "$WORK"
}
trap cleanup EXIT
if [ "$(stat -f -c %T "$WORK")" = "tmpfs" ]; then
  echo "BLOCKED: $WORK is on tmpfs; object handles unsupported (use a real filesystem)"
  exit 0
fi

# --- synthetic Chromium profile ---
CHROME_UDD="$WORK/chrome-udd"
mkdir -p "$CHROME_UDD/Default/Local Storage/leveldb"
printf 'GUARD_OBJECTID_DYNAMIC_FIXTURE' > "$CHROME_UDD/Default/Local Storage/leveldb/000001.log"
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

echo "==> Starting guardd (strict-filesystem)"
"$GUARDD" --enforce-browser-config "$WORK/config.json" \
  --ipc-socket "$WORK/guardd.sock" --audit-db "$WORK/audit.db" --print-decisions \
  > "$WORK/guardd.log" 2>&1 &
DAEMON_PID=$!
for _ in $(seq 1 100); do
  [ -S "$WORK/guardd.sock" ] && break
  kill -0 "$DAEMON_PID" 2>/dev/null || { echo "guardd exited early"; cat "$WORK/guardd.log"; exit 1; }
  sleep 0.05
done
[ -S "$WORK/guardd.sock" ] || { echo "guardd did not become ready"; cat "$WORK/guardd.log"; exit 1; }
for _ in $(seq 1 50); do
  if "$GUARDCTL" --socket "$WORK/guardd.sock" status >/dev/null 2>&1; then break; fi
  sleep 0.05
done

DYNAMIC="$CHROME_UDD/Default/Local Storage/leveldb/000001.log"

echo "==> 1. dynamic object under protected path => protected"
if "$PROBE" read "$DYNAMIC" >/dev/null 2>&1; then
  note_fail "unknown probe read the dynamic fixture"
else
  note_pass "unknown probe denied on dynamic fixture (protected path)"
fi

echo "==> 2. rename dynamic object OUTSIDE the profile => still denied (handle identity)"
mv "$DYNAMIC" "$WORK/exfiltrated.log"
if "$PROBE" read "$WORK/exfiltrated.log" >/dev/null 2>&1; then
  note_fail "renamed-out dynamic object was readable"
else
  note_pass "renamed-out dynamic object still denied (handle match)"
fi

echo "==> 3. replace the protected path with a NEW unrelated file => unrelated open allowed"
# The protected name now holds a different inode; an ordinary open of THAT
# file must NOT be denied by a stale learned mapping (inode reuse guard).
printf 'ordinary unrelated data' > "$DYNAMIC"
if "$PROBE" read "$DYNAMIC" >/dev/null 2>&1; then
  note_pass "reused protected name with unrelated content opens normally"
else
  note_fail "unrelated file at reused name was denied (false positive)"
fi

echo "==> 4. delete/recreate cycle on the protected path => no false positive"
rm -f "$DYNAMIC"
printf 'recreated unrelated' > "$DYNAMIC"
if "$PROBE" read "$DYNAMIC" >/dev/null 2>&1; then
  note_pass "recreated file opens normally (stale mapping dropped)"
else
  note_fail "recreated file denied (stale inode mapping survived)"
fi

echo "==> 5. audit/daemon log contains no fixture bytes"
if grep -rq "GUARD_OBJECTID_DYNAMIC_FIXTURE" "$WORK/guardd.log" 2>/dev/null; then
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
exit $FAIL
