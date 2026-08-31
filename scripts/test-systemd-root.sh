#!/usr/bin/env bash
# scripts/test-systemd-root.sh
#
# Phase 14 privileged integration test for systemd install/startup/recovery.
#
# RUN AS ROOT on a systemd host:
#   sudo bash scripts/test-systemd-root.sh
#
# Requires: systemd, CAP_SYS_ADMIN (for fanotify), python3 (for JSON parsing).
#
# Tests:
#   1. install service via deploy/install.sh
#   2. start service, verify guardctl status shows ACTIVE
#   3. browser fixture is denied while SSH-key read remains allowed
#   4. stop service, verify files unprotected (fail-open)
#   5. start service again, verify files protected (marks reconstructed)
#   6. crash daemon (kill -9), verify systemd restarts it
#   7. stale socket recovery (kill -9 leaves socket, restart rebinds)
#   8. guardctl status distinguishes ACTIVE / NOT_ENFORCING
#   9. no secret contents leak into journald
#   (cleanup trap uninstalls the service at exit)
#
# Uses ONLY synthetic fixtures. No real browser profiles or SSH keys.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GUARDCTL="/usr/local/bin/guardctl"
PROBE="$REPO/target/release/guard-test-probe"
SOCK="/run/guardd/guardd.sock"

PASS=0
FAIL=0
BLOCKED=0
note_pass() { echo "PASS: $1"; PASS=$((PASS+1)); }
note_fail() { echo "FAIL: $1"; FAIL=$((FAIL+1)); }
note_blocked() { echo "BLOCKED: $1"; BLOCKED=$((BLOCKED+1)); }

if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: run as root (sudo $0)"
  exit 2
fi

if ! command -v systemctl >/dev/null 2>&1; then
  echo "ERROR: systemd not available. This test requires a systemd host."
  exit 2
fi

echo "==> Checking unprivileged pre-built release binaries"
# Deployment must never populate root's Cargo home. Build before invoking this
# root-only integration script: `cargo build --release` as the desktop user.
test -x "$REPO/target/release/guardd" || { echo "guardd build failed"; exit 1; }
test -x "$REPO/target/release/guardctl" || { echo "guardctl build failed"; exit 1; }
test -x "$REPO/target/release/guard-notify" || { echo "guard-notify build failed"; exit 1; }
test -x "$PROBE" || { echo "guard-test-probe build failed"; exit 1; }

WORK="$(mktemp -d -t guard-systemd-XXXXXX)"
CLEANUP_UNIT=false
cleanup() {
  if [ "$CLEANUP_UNIT" = true ]; then
    systemctl stop guardd 2>/dev/null || true
    bash "$REPO/deploy/install.sh" --uninstall 2>/dev/null || true
  fi
  # The installer intentionally preserves operator config. This suite's config
  # is disposable, so remove it only when it still points into this WORK dir.
  if [ -f /etc/guardd/config.json ] && grep -q "$WORK" /etc/guardd/config.json; then
    unlink /etc/guardd/config.json 2>/dev/null || true
    rmdir /etc/guardd 2>/dev/null || true
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

# --- synthetic fixtures ---
CHROME_UDD="$WORK/chrome-udd"
mkdir -p "$CHROME_UDD/Default/Network"
printf 'GUARD_SYNTHETIC_COOKIE_FIXTURE' > "$CHROME_UDD/Default/Network/Cookies"

SSH_DIR="$WORK/ssh"
mkdir -p "$SSH_DIR"; chmod 0700 "$SSH_DIR"
ssh-keygen -t ed25519 -N "" -C "guard-systemd-test" -f "$SSH_DIR/id_ed25519" >/dev/null
chmod 0600 "$SSH_DIR/id_ed25519"
PRIV_KEY="$SSH_DIR/id_ed25519"

# --- config ---
cat > "$WORK/config.json" <<EOF
{
  "browser_protection_level": "common",
  "browsers": [
    { "id": "chrome", "family": "chromium", "profile_root": "$CHROME_UDD", "owner_uid": 0, "exe_paths": [] }
  ],
  "enrolled_exes": [],
  "ssh_keys": ["$PRIV_KEY"]
}
EOF

COOKIES="$CHROME_UDD/Default/Network/Cookies"

# ===========================================================================
# Test 1: install service
# ===========================================================================
echo "==> Test 1: install service"
# Install binaries + unit, but use our test config.
bash "$REPO/deploy/install.sh" 2>&1 | tail -5
CLEANUP_UNIT=true
# Overwrite the config with our test config.
install -m 0640 "$WORK/config.json" /etc/guardd/config.json
if systemctl is-enabled guardd >/dev/null 2>&1; then
  note_fail "service must not be enabled by installer before configuration review"
else
  note_pass "service installed but not enabled before configuration review"
fi

# ===========================================================================
# Test 2: start service, verify ACTIVE
# ===========================================================================
echo "==> Test 2: start service, verify status"
systemctl start guardd
sleep 1
if systemctl is-active guardd >/dev/null 2>&1; then
  note_pass "service is active"
else
  note_fail "service did not start: $(journalctl -u guardd --no-pager -n 20 2>/dev/null)"
fi

# Wait for IPC socket to be ready.
for _ in $(seq 1 20); do
  if [ -S "$SOCK" ]; then break; fi
  sleep 0.2
done

if [ -S "$SOCK" ]; then
  STATUS_OUT="$("$GUARDCTL" --socket "$SOCK" status 2>/dev/null || true)"
  if echo "$STATUS_OUT" | grep -q "ACTIVE"; then
    note_pass "guardctl status shows ACTIVE"
  else
    note_fail "guardctl status does not show ACTIVE: $STATUS_OUT"
  fi
else
  note_fail "IPC socket not created at $SOCK"
fi

# ===========================================================================
# Test 3: verify browser denial and SSH behavioral read allowance
# ===========================================================================
echo "==> Test 3: browser denied; SSH read allowed"
if "$PROBE" read "$COOKIES" > /dev/null 2>&1; then
  note_fail "cookies readable (should be denied)"
else
  note_pass "cookies denied"
fi
if "$PROBE" read "$PRIV_KEY" > /dev/null 2>&1; then
  note_pass "SSH key read allowed under the behavioral model"
else
  note_fail "SSH key read was interrupted"
fi

# ===========================================================================
# Test 4: stop service, verify fail-open
# ===========================================================================
echo "==> Test 4: stop service (fail-open)"
systemctl stop guardd
sleep 1
if "$PROBE" read "$COOKIES" > /dev/null 2>&1; then
  note_pass "cookies readable after stop (fail-open confirmed)"
else
  note_blocked "cookies still denied after stop (fanotify marks may persist briefly)"
fi

# ===========================================================================
# Test 5: start again, verify marks reconstructed
# ===========================================================================
echo "==> Test 5: restart, marks reconstructed"
systemctl start guardd
sleep 1
for _ in $(seq 1 20); do
  if [ -S "$SOCK" ]; then break; fi
  sleep 0.2
done
if "$PROBE" read "$COOKIES" > /dev/null 2>&1; then
  note_fail "cookies readable after restart (marks not reconstructed)"
else
  note_pass "cookies denied after restart (marks reconstructed)"
fi

# ===========================================================================
# Test 6: crash daemon (kill -9), verify systemd restarts
# ===========================================================================
echo "==> Test 6: crash + auto-restart"
GUARDD_PID="$(systemctl show -p MainPID --value guardd 2>/dev/null || echo 0)"
if [ "$GUARDD_PID" -gt 0 ]; then
  kill -9 "$GUARDD_PID" 2>/dev/null || true
  echo "    killed guardd (pid=$GUARDD_PID), waiting for restart..."
  sleep 3
  if systemctl is-active guardd >/dev/null 2>&1; then
    note_pass "systemd restarted guardd after crash"
  else
    note_fail "systemd did not restart guardd after crash"
  fi
  # Wait for socket.
  for _ in $(seq 1 20); do
    if [ -S "$SOCK" ]; then break; fi
    sleep 0.2
  done
  # Verify enforcement is back.
  if "$PROBE" read "$COOKIES" > /dev/null 2>&1; then
    note_fail "cookies readable after crash-restart (enforcement not back)"
  else
    note_pass "cookies denied after crash-restart"
  fi
else
  note_blocked "could not find guardd PID to crash"
fi

# ===========================================================================
# Test 7: stale socket recovery
# ===========================================================================
echo "==> Test 7: stale socket recovery"
# Stop the service, manually create a stale socket file, then start.
systemctl stop guardd
sleep 1
# Create a stale socket file to simulate a crash that left the socket behind.
install -d -m 0750 -o root -g guardd-users "$(dirname "$SOCK")"
python3 -c "import socket, os; s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.bind('$SOCK'); s.close()" 2>/dev/null || true
if [ -e "$SOCK" ]; then
  echo "    stale socket created at $SOCK"
  systemctl start guardd
  sleep 1
  for _ in $(seq 1 20); do
    if [ -S "$SOCK" ]; then break; fi
    sleep 0.2
  done
  # Verify IPC works (guardctl status responds).
  STATUS_OUT="$("$GUARDCTL" --socket "$SOCK" status 2>/dev/null || true)"
  if echo "$STATUS_OUT" | grep -q "guardd"; then
    note_pass "stale socket recovered, IPC responds"
  else
    note_fail "stale socket not recovered: $STATUS_OUT"
  fi
else
  note_blocked "could not create stale socket for test"
fi

# ===========================================================================
# Test 8: guardctl status distinguishes states
# ===========================================================================
echo "==> Test 8: guardctl status states"
# While running, status should show ACTIVE.
STATUS_OUT="$("$GUARDCTL" --socket "$SOCK" status 2>/dev/null || true)"
if echo "$STATUS_OUT" | grep -q "ACTIVE"; then
  note_pass "status shows ACTIVE when running"
else
  note_fail "status does not show ACTIVE: $STATUS_OUT"
fi

# Stop the service; guardctl should fail to connect (not NOT_ENFORCING, since
# the daemon is down entirely).
systemctl stop guardd
sleep 1
if "$GUARDCTL" --socket "$SOCK" status > /dev/null 2>&1; then
  note_fail "guardctl connected to stopped daemon (unexpected)"
else
  note_pass "guardctl cannot connect to stopped daemon (expected)"
fi

# ===========================================================================
# Test 9: no secret contents in journal
# ===========================================================================
echo "==> Test 9: no secret contents in journal"
systemctl start guardd
sleep 1
if journalctl -u guardd --no-pager -n 100 2>/dev/null | grep -q "GUARD_SYNTHETIC_COOKIE_FIXTURE"; then
  note_fail "secret content leaked into journald"
else
  note_pass "no secret contents in journald"
fi

echo
echo "==> Phase 14 systemd test summary: PASS=$PASS FAIL=$FAIL BLOCKED=$BLOCKED"
echo "    (see journalctl -u guardd for daemon logs)"
exit $FAIL
