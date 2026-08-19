#!/usr/bin/env bash
# Installed-configuration acceptance for socket ACLs, per-UID audit filtering,
# real polkit decisions, and the user-session notification presenter.
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then echo "ERROR: run as root"; exit 2; fi
if [ -z "${SUDO_USER:-}" ] || [ "$SUDO_USER" = root ]; then
  echo "ERROR: SUDO_USER must identify the logged-in desktop test user"
  exit 2
fi

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_USER="$SUDO_USER"
TEST_UID="$(id -u "$TEST_USER")"
TEST_GID="$(id -g "$TEST_USER")"
WORK="$(mktemp -d -t guard-installed-auth-XXXXXX)"
KEEP_WORK="${KEEP_WORK:-0}"
# Use the distribution rules directory for the ephemeral rule: this Arch host
# loads it at daemon startup, while its /etc rules directory did not produce an
# evaluation even after restart. The file is removed before test cleanup ends.
RULE="/usr/share/polkit-1/rules.d/49-guardd-acceptance.rules"
PASS=0
FAIL=0
BLOCKED=0
INSTALLED=0

pass() { echo "PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "FAIL: $1"; FAIL=$((FAIL + 1)); }
blocked() { echo "BLOCKED: $1"; BLOCKED=$((BLOCKED + 1)); }
as_user() { runuser -u "$TEST_USER" -- "$@"; }
user_systemctl() {
  runuser -u "$TEST_USER" -- env \
    XDG_RUNTIME_DIR="/run/user/$TEST_UID" \
    DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$TEST_UID/bus" \
    systemctl --user "$@"
}
user_journal() {
  runuser -u "$TEST_USER" -- env \
    XDG_RUNTIME_DIR="/run/user/$TEST_UID" \
    DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$TEST_UID/bus" \
    journalctl --user "$@"
}
as_user_session() {
  runuser -u "$TEST_USER" -- env \
    XDG_RUNTIME_DIR="/run/user/$TEST_UID" \
    DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$TEST_UID/bus" \
    "$@"
}
cleanup() {
  if [ -e "$RULE" ]; then
    unlink "$RULE" || true
    systemctl restart polkit.service >/dev/null 2>&1 || true
  fi
  if [ "$INSTALLED" -eq 1 ]; then
    user_systemctl disable --now guard-notify >/dev/null 2>&1 || true
    systemctl stop guardd >/dev/null 2>&1 || true
    bash "$REPO/deploy/install.sh" --uninstall >/dev/null 2>&1 || true
  fi
  if [ -f /etc/guardd/config.json ] && grep -q "$WORK" /etc/guardd/config.json; then
    unlink /etc/guardd/config.json || true
  fi
  rmdir /etc/guardd 2>/dev/null || true
  if [ -f /var/lib/guardd/audit.db ]; then unlink /var/lib/guardd/audit.db || true; fi
  rmdir /var/lib/guardd 2>/dev/null || true
  if [ "$KEEP_WORK" = 1 ]; then
    echo "Synthetic installed-auth artifacts retained at: $WORK"
  else
    rm -rf -- "$WORK"
  fi
}
trap cleanup EXIT

if [ -e /etc/systemd/system/guardd.service ] || [ -e /etc/guardd/config.json ]; then
  echo "ERROR: refusing to overwrite an existing guardd installation/config"
  exit 2
fi
if [ ! -S "/run/user/$TEST_UID/bus" ]; then
  echo "ERROR: logged-in user's D-Bus session is unavailable"
  exit 2
fi
command -v setpriv >/dev/null || { echo "ERROR: setpriv is required"; exit 2; }

chmod 0755 "$WORK"
PROFILE="$WORK/disposable-chromium"
COOKIE="$PROFILE/Default/Network/Cookies"
mkdir -p "$(dirname "$COOKIE")"
printf '%s' 'synthetic-installed-preferences' > "$PROFILE/Default/Preferences"
printf '%s' 'SDF_CANARY_INSTALLED_COOKIE' > "$COOKIE"
KEY="$WORK/id_installed_ephemeral"
ssh-keygen -q -t ed25519 -N '' -C guard-installed-ephemeral -f "$KEY"
chmod 0600 "$KEY"
chown -R "$TEST_UID:$TEST_GID" "$PROFILE" "$KEY" "$KEY.pub"

echo "==> Installing real systemd/polkit configuration"
bash "$REPO/deploy/install.sh" >/dev/null
INSTALLED=1
mkdir -p /etc/guardd
install -m 0640 /dev/null /etc/guardd/config.json
printf '%s\n' \
  '{' \
  '  "config_version": 1,' \
  '  "enforcement_mode": "strict-filesystem",' \
  '  "browsers": [' \
  '    {' \
  '      "id": "installed-synthetic-chromium",' \
  '      "family": "Chromium",' \
  "      \"profile_root\": \"$PROFILE\"," \
  "      \"owner_uid\": $TEST_UID," \
  '      "exe_paths": []' \
  '    }' \
  '  ],' \
  '  "enrolled_exes": [],' \
  "  \"ssh_keys\": [\"$KEY\"]" \
  '}' > /etc/guardd/config.json
systemctl start guardd
for _ in $(seq 1 100); do [ -S /run/guardd/guardd.sock ] && break; sleep 0.05; done

SOCKET_STATE="$(stat -c '%U:%G %a' /run/guardd/guardd.sock 2>/dev/null || true)"
if [ "$SOCKET_STATE" = 'root:guardd-users 660' ]; then
  pass "installed socket is root:guardd-users mode 0660"
else
  fail "installed socket ACL is '$SOCKET_STATE'"
fi
if as_user /usr/local/bin/guardctl status > "$WORK/user-status.out" 2>&1 \
  && grep -q ACTIVE "$WORK/user-status.out"; then
  pass "ordinary guardd-users member can query ACTIVE status"
else
  fail "ordinary user cannot query installed daemon"
fi

echo "==> Per-UID event isolation"
if as_user "$REPO/target/release/guard-test-probe" read "$COOKIE" >/dev/null 2>&1; then
  fail "ordinary-user cookie probe was not denied"
else
  pass "ordinary-user installed probe denied"
fi
"$REPO/target/release/guard-test-probe" read "$KEY" >/dev/null 2>&1 || true
USER_EVENTS_OK=0
for _ in $(seq 1 100); do
  as_user /usr/local/bin/guardctl --json events --limit 100 > "$WORK/user-events.json"
  if python3 - "$WORK/user-events.json" "$TEST_UID" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1], encoding="utf-8"))
events = doc.get("data", [])
uid = int(sys.argv[2])
raise SystemExit(0 if events and all(e["uid"] == uid for e in events) else 1)
PY
  then USER_EVENTS_OK=1; break; fi
  sleep 0.02
done
if [ "$USER_EVENTS_OK" -eq 1 ]; then pass "ordinary user sees own events and no root events"; else
  fail "own-event UID filter failed"
  sed -n '1,120p' "$WORK/user-events.json"
fi

ACCESS_GID="$(getent group guardd-users | cut -d: -f3)"
NOBODY_UID="$(id -u nobody)"
NOBODY_GID="$(id -g nobody)"
setpriv --reuid="$NOBODY_UID" --regid="$NOBODY_GID" --groups="$ACCESS_GID" \
  /usr/local/bin/guardctl --json events --limit 100 > "$WORK/nobody-events.json"
if python3 - "$WORK/nobody-events.json" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1], encoding="utf-8"))
raise SystemExit(0 if doc.get("data", []) == [] else 1)
PY
then pass "another UID cannot query the test user's/root events"; else fail "cross-UID event query leaked metadata"; fi

echo "==> Real polkit denial and authorization"
USER_KEY="$WORK/id_user_runtime_synthetic"
printf '%s' 'synthetic-user-private-key-candidate' > "$USER_KEY"
chown "$TEST_UID:$TEST_GID" "$USER_KEY"
chmod 0600 "$USER_KEY"
printf '%s\n' \
  'polkit.addRule(function(action, subject) {' \
  '  if (action.id == "org.guardd.ssh-protect" ||' \
  '      action.id == "org.guardd.ssh-load") {' \
  '    return polkit.Result.NO;' \
  '  }' \
  '});' > "$RULE"
chmod 0644 "$RULE"
systemctl restart polkit.service
sleep 0.5
if as_user /usr/local/bin/guardctl ssh protect "$USER_KEY" > "$WORK/polkit-deny.out" 2>&1; then
  fail "explicit polkit denial did not prevent mutation"
else
  pass "explicit real polkit denial prevents owner-valid mutation"
fi

printf '%s\n' \
  'polkit.addRule(function(action, subject) {' \
  '  if (action.id == "org.guardd.ssh-protect" ||' \
  '      action.id == "org.guardd.ssh-load") {' \
  "    polkit.log(\"guardd acceptance allow for \" + subject.user);" \
  '    return polkit.Result.YES;' \
  '  }' \
  '});' > "$RULE"
chmod 0644 "$RULE"
# This host's long-running polkitd did not observe rules.d changes via inotify;
# restart the real authorization manager so the temporary acceptance rule is
# certainly loaded. Cleanup removes the rule and restarts polkit again.
systemctl restart polkit.service
sleep 0.5
setpriv --reuid="$TEST_UID" --regid="$TEST_GID" --init-groups /usr/bin/sleep 30 &
POLKIT_SUBJECT_PID=$!
POLKIT_SUBJECT_START="$(python3 - "$POLKIT_SUBJECT_PID" <<'PY'
import sys
raw = open(f"/proc/{sys.argv[1]}/stat", encoding="ascii").read()
print(raw[raw.rfind(")") + 1:].split()[19])
PY
)"
if pkcheck --action-id org.guardd.ssh-protect \
  --process "$POLKIT_SUBJECT_PID,$POLKIT_SUBJECT_START,$TEST_UID" \
  > "$WORK/polkit-direct.out" 2>&1; then
  pass "real polkit accepts a kernel-bound test-user process subject"
else
  fail "temporary polkit acceptance rule was not evaluated"
  sed -n '1,80p' "$WORK/polkit-direct.out"
fi
kill -TERM "$POLKIT_SUBJECT_PID" 2>/dev/null || true
wait "$POLKIT_SUBJECT_PID" 2>/dev/null || true
POLKIT_PEER_PID_FILE="$WORK/polkit-peer.pid"
POLKIT_ALLOW_JSON="$WORK/polkit-allow.json"
: > "$POLKIT_PEER_PID_FILE"
: > "$POLKIT_ALLOW_JSON"
chown "$TEST_UID:$TEST_GID" "$POLKIT_PEER_PID_FILE" "$POLKIT_ALLOW_JSON"
as_user python3 "$REPO/scripts/helpers/ipc-request.py" \
  --socket /run/guardd/guardd.sock \
  --operation-json "{\"kind\":\"ssh_protect\",\"path\":\"$USER_KEY\"}" \
  --output "$POLKIT_ALLOW_JSON" --pid-file "$POLKIT_PEER_PID_FILE" \
  --hold-seconds 30 &
POLKIT_RUNUSER_PID=$!
for _ in $(seq 1 100); do [ -s "$POLKIT_ALLOW_JSON" ] && break; sleep 0.02; done
if python3 - "$POLKIT_ALLOW_JSON" <<'PY'
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
raise SystemExit(0 if d.get("ok") else 1)
PY
then
  pass "real polkit authorization allows intended owner mutation"
else
  fail "polkit-authorized SSH protection failed"
  sed -n '1,80p' "$POLKIT_ALLOW_JSON"
  if [ -s "$POLKIT_PEER_PID_FILE" ]; then
    PEER_PID="$(cat "$POLKIT_PEER_PID_FILE")"
    PEER_START="$(python3 - "$PEER_PID" <<'PY'
import sys
raw = open(f"/proc/{sys.argv[1]}/stat", encoding="ascii").read()
print(raw[raw.rfind(")") + 1:].split()[19])
PY
)"
    pkcheck --action-id org.guardd.ssh-protect \
      --process "$PEER_PID,$PEER_START,$TEST_UID" \
      --allow-user-interaction -d path "$USER_KEY" \
      > "$WORK/polkit-peer-direct.out" 2>&1 || true
  fi
fi
if [ -s "$POLKIT_PEER_PID_FILE" ]; then
  kill -TERM "$(cat "$POLKIT_PEER_PID_FILE")" 2>/dev/null || true
fi
wait "$POLKIT_RUNUSER_PID" 2>/dev/null || true
if as_user "$REPO/target/release/guard-test-probe" read "$USER_KEY" >/dev/null 2>&1; then
  fail "polkit-authorized key did not become protected"
else
  pass "authorized mutation installed live FAN_OPEN_PERM protection"
fi

echo "==> Installed non-root SSH broker with real polkit authorization"
USER_AGENT_DIR="$WORK/user-agent"
mkdir -p "$USER_AGENT_DIR"
chown "$TEST_UID:$TEST_GID" "$USER_AGENT_DIR"
chmod 0700 "$USER_AGENT_DIR"
USER_AGENT_SOCKET="$USER_AGENT_DIR/agent.sock"
as_user /usr/bin/ssh-agent -D -a "$USER_AGENT_SOCKET" \
  > "$WORK/user-agent.log" 2>&1 &
USER_AGENT_RUNNER=$!
for _ in $(seq 1 100); do
  [ -S "$USER_AGENT_SOCKET" ] && break
  sleep 0.02
done
if [ ! -S "$USER_AGENT_SOCKET" ]; then
  fail "disposable user ssh-agent did not create its socket"
elif as_user env SSH_AUTH_SOCK="$USER_AGENT_SOCKET" \
  /usr/local/bin/guardctl ssh load "$KEY" > "$WORK/user-ssh-load.out" 2>&1; then
  pass "ordinary user completed polkit-authorized brokered SSH load"
else
  fail "installed non-root brokered SSH load failed"
  sed -n '1,100p' "$WORK/user-ssh-load.out"
fi
if as_user env SSH_AUTH_SOCK="$USER_AGENT_SOCKET" /usr/bin/ssh-add -l 2>/dev/null \
  | grep -q guard-installed-ephemeral; then
  pass "disposable trusted agent lists the brokered ephemeral key"
else
  fail "trusted agent does not contain the brokered ephemeral key"
fi
if as_user "$REPO/target/release/guard-test-probe" read "$KEY" >/dev/null 2>&1; then
  fail "private-key file became readable after brokered load"
else
  pass "private-key file remains denied after brokered agent load"
fi
pkill -TERM -P "$USER_AGENT_RUNNER" 2>/dev/null || true
kill -TERM "$USER_AGENT_RUNNER" 2>/dev/null || true
wait "$USER_AGENT_RUNNER" 2>/dev/null || true
unlink "$RULE"
systemctl restart polkit.service

echo "==> Installed user notification service"
user_systemctl daemon-reload
user_systemctl enable --now guard-notify >/dev/null
if user_systemctl is-active guard-notify >/dev/null; then
  pass "guard-notify user service is active"
else
  fail "guard-notify user service did not start"
fi
SINCE="$(date --iso-8601=seconds)"
for _ in $(seq 1 50); do
  user_journal -u guard-notify --since "$SINCE" --no-pager 2>/dev/null \
    | grep -q 'ready baseline_event_id=' && break
  sleep 0.1
done
as_user "$REPO/target/release/guard-test-probe" read "$COOKIE" >/dev/null 2>&1 || true
DELIVERED=0
for _ in $(seq 1 50); do
  if user_journal -u guard-notify \
    --since "$SINCE" --no-pager 2>/dev/null | grep -q 'delivered event_id='; then
    DELIVERED=1
    break
  fi
  sleep 0.1
done
if [ "$DELIVERED" -eq 1 ]; then
  pass "guard-notify delivered installed DENY event to the user session"
else
  UNIT_LOG="$WORK/guard-notify-unit.log"
  user_journal -u guard-notify --since "$SINCE" --no-pager > "$UNIT_LOG" 2>/dev/null || true
  if grep -q 'Permission denied' "$UNIT_LOG"; then
    blocked "logged-in systemd --user manager predates guardd-users membership; relogin required"
    user_systemctl stop guard-notify >/dev/null 2>&1 || true
    DIRECT_LOG="$WORK/guard-notify-direct.log"
    as_user_session /usr/local/bin/guard-notify --poll-ms 100 \
      >/dev/null 2> "$DIRECT_LOG" &
    DIRECT_PID=$!
    for _ in $(seq 1 50); do
      grep -q 'ready baseline_event_id=' "$DIRECT_LOG" 2>/dev/null && break
      sleep 0.1
    done
    as_user "$REPO/target/release/guard-test-probe" read "$COOKIE" >/dev/null 2>&1 || true
    DIRECT_DELIVERED=0
    for _ in $(seq 1 50); do
      if grep -q 'delivered event_id=' "$DIRECT_LOG" 2>/dev/null; then
        DIRECT_DELIVERED=1
        break
      fi
      sleep 0.1
    done
    kill -TERM "$DIRECT_PID" 2>/dev/null || true
    wait "$DIRECT_PID" 2>/dev/null || true
    if [ "$DIRECT_DELIVERED" -eq 1 ]; then
      pass "installed guard-notify binary delivered DENY to mako in fresh group context"
    else
      fail "installed notification presenter failed even with refreshed groups"
      sed -n '1,80p' "$DIRECT_LOG"
    fi
  else
    fail "installed guard-notify produced no successful delivery record"
    tail -40 "$UNIT_LOG" || true
  fi
fi

echo
echo "==> Installed authorization summary: PASS=$PASS FAIL=$FAIL BLOCKED=$BLOCKED"
exit "$FAIL"
