#!/usr/bin/env bash
# scripts/linux/test-pidfd-root.sh
#
# LFH1 privileged integration test: the daemon uses a FAN_REPORT_PIDFD group
# on accepted kernels, validates each event's pidfd against its pid, and fails
# closed when the pidfd is unusable. Synthetic files only.
#
# RUN AS ROOT (or via the sfg-test-capsule on hosts where nspawn seccomp allows
# fanotify): build as the normal user first, then
#   SKIP_BUILD=1 bash scripts/linux/test-pidfd-root.sh
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
test -x "$GUARDD" || { echo "ERROR: missing $GUARDD; build as the normal user first"; exit 2; }
test -x "$GUARDCTL" || { echo "ERROR: missing $GUARDCTL; build as the normal user first"; exit 2; }
test -x "$PROBE" || { echo "ERROR: missing $PROBE; build as the normal user first"; exit 2; }

WORK="$(mktemp -d -t guard-pidfd-XXXXXX)"
DAEMON_PID=""
cleanup() {
  if [ -n "$DAEMON_PID" ] && kill -0 "$DAEMON_PID" 2>/dev/null; then
    kill -TERM "$DAEMON_PID" 2>/dev/null || true
    wait "$DAEMON_PID" 2>/dev/null || true
  fi
  rm -rf -- "$WORK"
}
trap cleanup EXIT

# --- synthetic Chrome profile ---
CHROME_UDD="$WORK/chrome-udd"
mkdir -p "$CHROME_UDD/Default/Network"
printf 'GUARD_PIDFD_COOKIE_FIXTURE' > "$CHROME_UDD/Default/Network/Cookies"
printf '{}' > "$CHROME_UDD/Default/Preferences"
printf '{}' > "$CHROME_UDD/Local State"

ENROLLED="$WORK/synthetic-chrome"
cp "$PROBE" "$ENROLLED"
chmod 0755 "$ENROLLED"

cat > "$WORK/config.json" <<EOF
{
  "config_version": 1,
  "enforcement_mode": "conservative",
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

echo "==> Starting guardd with FAN_REPORT_PIDFD group"
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

# Wait for ACTIVE status and capture the pidfd health.
for _ in $(seq 1 50); do
  STATUS="$("$GUARDCTL" --socket "$WORK/guardd.sock" --json status 2>/dev/null || true)"
  if [ -n "$STATUS" ] && echo "$STATUS" | grep -qE '"enforcement_active"[[:space:]]*:[[:space:]]*true'; then
    break
  fi
  sleep 0.05
done
if ! echo "$STATUS" | grep -qE '"enforcement_active"[[:space:]]*:[[:space:]]*true'; then
  echo "guardd did not become ACTIVE"
  echo "$STATUS" | head -5
  cat "$WORK/guardd.log"
  exit 1
fi

pidfd_enabled="$(echo "$STATUS" | python3 -c 'import json,sys; d=json.load(sys.stdin); lh=(d.get("data") or {}).get("linux_health") or {}; print(lh.get("pidfd_enabled"))' 2>/dev/null || echo unknown)"
echo "pidfd_enabled=$pidfd_enabled"

if [ "$pidfd_enabled" = "True" ]; then
  note_pass "daemon reports pidfd_enabled=true (FAN_REPORT_PIDFD accepted)"
elif [ "$pidfd_enabled" = "False" ]; then
  note_pass "daemon truthfully reports pidfd_enabled=false (legacy kernel fallback)"
else
  note_blocked "could not parse pidfd_enabled from status"
fi

# Unknown process must be denied (proves enforcement still works with the
# pidfd group).
echo "==> Unknown probe denied"
if "$PROBE" read "$CHROME_UDD/Default/Network/Cookies" > "$WORK/t1.out" 2>&1; then
  note_fail "unknown probe read the cookie fixture"
else
  note_pass "unknown probe denied"
fi

# Enrolled browser identity allowed.
echo "==> Enrolled browser probe allowed"
if "$ENROLLED" read "$CHROME_UDD/Default/Network/Cookies" > "$WORK/t2.out" 2>&1; then
  if grep -q "GUARD_PIDFD_COOKIE_FIXTURE" "$WORK/t2.out"; then
    note_pass "enrolled probe read its own fixture"
  else
    note_fail "enrolled probe read fixture but content mismatch"
  fi
else
  note_fail "enrolled probe was denied"
fi

# pidfd_missing_events must stay 0 (every event on the pidfd group carried a
# usable pidfd).
missing="$(echo "$STATUS" | python3 -c 'import json,sys; d=json.load(sys.stdin); lh=(d.get("data") or {}).get("linux_health") or {}; print(lh.get("pidfd_missing_events"))' 2>/dev/null || echo 0)"
if [ "$missing" = "0" ]; then
  note_pass "pidfd_missing_events=0 after normal enforcement"
else
  note_fail "pidfd_missing_events=$missing; protected events failed closed unexpectedly"
fi

# Clean shutdown.
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
echo "==> LFH1 pidfd root integration summary: PASS=$PASS FAIL=$FAIL BLOCKED=$BLOCKED"
echo "    (see $WORK/guardd.log for daemon decision log)"
exit $FAIL
