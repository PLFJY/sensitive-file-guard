#!/usr/bin/env bash
# Daemon-integrated LPS5 oracle: a synthetic root-owned Firefox-family Main is
# admitted by a real File Shield WebStorage OPEN_PERM before its same-UID parent
# attacks its in-memory canary. No real Firefox profile or secret is involved.
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "BLOCKED: requires authorized polkit host fallback"; exit 2; }
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN_DIR="${BIN_DIR:-$REPO/target/debug}"
GUARDD="$BIN_DIR/guardd"; GUARDCTL="$BIN_DIR/guardctl"; PROBE="$BIN_DIR/guard-test-probe"
ORACLE="${LPS5_DAEMON_ORACLE:-$REPO/target/lps5/lps5-daemon-oracle}"
TEST_USER="${TEST_USER:-${PKEXEC_UID:-}}"
for x in "$GUARDD" "$GUARDCTL" "$PROBE" "$ORACLE"; do [ -x "$x" ] || { echo "BLOCKED: missing $x"; exit 2; }; done
[ -n "$TEST_USER" ] && getent passwd "$TEST_USER" >/dev/null || { echo "BLOCKED: TEST_USER/PKEXEC_UID required"; exit 2; }
TEST_USER="$(getent passwd "$TEST_USER" | awk -F: 'NR==1{print $1}')"; TEST_UID="$(id -u "$TEST_USER")"; TEST_GID="$(id -g "$TEST_USER")"
[ "$TEST_UID" -ne 0 ] || { echo "BLOCKED: non-root test user required"; exit 2; }
LOOP_IMG=""; LOOP_DEV=""; LOOP_MNT=""; WORK=""; DAEMON=""
select_test_fs() {
  if [ -n "${TEST_FS_ROOT:-}" ]; then
    [ -d "$TEST_FS_ROOT" ] || { echo "BLOCKED: TEST_FS_ROOT is not a directory"; exit 2; }
    [ "$(stat -c %d "$TEST_FS_ROOT")" != "$(stat -c %d /)" ] || { echo "BLOCKED: TEST_FS_ROOT is on the root filesystem"; exit 2; }
    [ "$(stat -f -c %T "$TEST_FS_ROOT")" != "tmpfs" ] || { echo "BLOCKED: TEST_FS_ROOT must not be tmpfs"; exit 2; }
    WORK="$(mktemp -d "$TEST_FS_ROOT/sfg-lps5-daemon.XXXXXX")"
    return
  fi
  LOOP_IMG="$(mktemp /tmp/sfg-lps5-daemon-img.XXXXXX)"
  truncate -s 256M "$LOOP_IMG"
  LOOP_DEV="$(losetup -f)"
  losetup "$LOOP_DEV" "$LOOP_IMG"
  mkfs.ext4 -q -F "$LOOP_DEV"
  LOOP_MNT="$(mktemp -d /tmp/sfg-lps5-daemon-mnt.XXXXXX)"
  mount "$LOOP_DEV" "$LOOP_MNT"
  WORK="$LOOP_MNT/work"
  mkdir "$WORK"
}
select_test_fs
PROFILE="$WORK/profile"; STATE="$WORK/state"; READY="$STATE/ready"; STORAGE="$PROFILE/webappsstore.sqlite"; AUTHORITY="$WORK/synthetic-firefox-main"; SOCK="$WORK/guardd.sock"; AUDIT="$WORK/audit.db"
cleanup(){
  [ -n "$DAEMON" ] && kill -TERM "$DAEMON" 2>/dev/null || true
  [ -n "$DAEMON" ] && wait "$DAEMON" 2>/dev/null || true
  if [ -n "$LOOP_DEV" ]; then
    umount "$LOOP_MNT" 2>/dev/null || true
    losetup -d "$LOOP_DEV" 2>/dev/null || true
    rm -f -- "$LOOP_IMG" 2>/dev/null || true
    rmdir "$LOOP_MNT" 2>/dev/null || true
  elif [ "${KEEP_WORK:-0}" = 1 ]; then
    echo "KEEP_WORK: $WORK"
  else
    rm -rf -- "$WORK"
  fi
}
trap cleanup EXIT
mkdir -p "$PROFILE" "$STATE"; printf 'synthetic-cookie-db-marker' > "$PROFILE/cookies.sqlite"; printf 'synthetic-web-storage' > "$STORAGE"; chown -R "$TEST_UID:$TEST_GID" "$PROFILE" "$STATE"; chmod 0755 "$WORK"; install -m 0555 -o root -g root "$PROBE" "$AUTHORITY"
[ "$(stat -c %d "$PROFILE")" != "$(stat -c %d /)" ] || { echo "BLOCKED: fixture is on the root filesystem"; exit 2; }
echo "LPS5_FIXTURE_ST_DEV=$(stat -c %d "$PROFILE") ROOT_ST_DEV=$(stat -c %d /)"
start_guard(){
  local enabled="$1"; cat > "$WORK/config.json" <<EOF
{"config_version":1,"enforcement_mode":"conservative","browsers":[{"id":"synthetic-firefox","family":"Firefox","profile_root":"$PROFILE","owner_uid":$TEST_UID,"exe_paths":["$AUTHORITY"]}],"enrolled_exes":["$AUTHORITY"],"ssh_keys":[],"process_shield_enabled":$enabled}
EOF
  "$GUARDD" --enforce-browser-config "$WORK/config.json" --ipc-socket "$SOCK" --audit-db "$AUDIT" --print-decisions > "$WORK/guardd-$enabled.log" 2>&1 & DAEMON=$!
  for _ in $(seq 1 100); do [ -S "$SOCK" ] && "$GUARDCTL" --socket "$SOCK" status >/dev/null 2>&1 && return; sleep .05; done
  cat "$WORK/guardd-$enabled.log"; echo "FAIL: guardd did not start"; exit 1
}
stop_guard(){ kill -TERM "$DAEMON"; wait "$DAEMON" || true; DAEMON=""; rm -f "$SOCK"; }
run_case(){
  local mode="$1" op="$2"; rm -f "$READY" "$READY.admitted"; LPS_OPERATION="$op" TEST_UID="$TEST_UID" "$ORACLE" "$mode" "$AUTHORITY" "$READY" "$STORAGE" "$PROFILE" > "$WORK/$mode-$op.log" 2>&1
  cat "$WORK/$mode-$op.log"
  if [ "$mode" = off ]; then grep -Fqx 'LPS5_DAEMON_OFF_CANARY_RECOVERED=PASS' "$WORK/$mode-$op.log"; else grep -Fqx 'LPS5_DAEMON_ON_DENIED_CANARY_RECOVERY=0 PASS' "$WORK/$mode-$op.log"; fi
}
start_guard false
for op in ptrace process_vm_readv process_vm_writev proc_mem; do run_case off "$op"; done
stop_guard
start_guard true
for op in ptrace process_vm_readv process_vm_writev proc_mem; do
  run_case on "$op"; target="$(awk 'NR==1 {print $1}' "$READY")"
  audit_ok=0
  for _ in $(seq 1 20); do
    "$GUARDCTL" --socket "$SOCK" --json events --limit 100 > "$WORK/events-$op.json"
    if python3 - "$WORK/events-$op.json" "$target" <<'PY'
import json,sys
events=(json.load(open(sys.argv[1])).get('data') or [])
target=int(sys.argv[2])
denied=any(e.get('event_code')=='process_shield_ptrace_denied' and f'target_pid={target}' in e.get('backend_diag','') and e.get('pid',0)>0 for e in events)
admitted=any(e.get('event_code')=='process_shield_authority_admitted' and e.get('pid')==target and e.get('resource_browser')=='synthetic-firefox' and e.get('resource_kind_code')=='browser_web_storage' for e in events)
ok=denied and admitted
raise SystemExit(0 if ok else 1)
PY
    then audit_ok=1; break; fi
    sleep .1
  done
  [ "$audit_ok" = 1 ] || { echo "FAIL: missing persisted exact Process Shield denial/admission audit for $op"; exit 1; }
  echo "LPS5_DAEMON_${op^^}_ON_PERSISTED_EXACT_AUDIT=PASS"
done
grep -q 'Process Shield admitted exact Firefox Main from File Shield WebStorage allow' "$WORK/guardd-true.log" || { echo 'FAIL: no real daemon admission'; exit 1; }
echo 'LPS5_DAEMON_INTEGRATED_ADMISSION_AND_ADVERSARIAL_MATRIX=PASS'
