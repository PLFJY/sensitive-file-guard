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
WORK="$(mktemp -d /tmp/sfg-lps5-daemon.XXXXXX)"; PROFILE="$WORK/profile"; STATE="$WORK/state"; READY="$STATE/ready"; STORAGE="$PROFILE/webappsstore.sqlite"; AUTHORITY="$WORK/synthetic-firefox-main"; SOCK="$WORK/guardd.sock"; AUDIT="$WORK/audit.db"; DAEMON=""
cleanup(){ [ -n "$DAEMON" ] && kill -TERM "$DAEMON" 2>/dev/null || true; [ -n "$DAEMON" ] && wait "$DAEMON" 2>/dev/null || true; if [ "${KEEP_WORK:-0}" = 1 ]; then echo "KEEP_WORK: $WORK"; else rm -rf -- "$WORK"; fi; }
trap cleanup EXIT
mkdir -p "$PROFILE" "$STATE"; printf 'synthetic-cookie-db-marker' > "$PROFILE/cookies.sqlite"; printf 'synthetic-web-storage' > "$STORAGE"; chown -R "$TEST_UID:$TEST_GID" "$PROFILE" "$STATE"; chmod 0755 "$WORK"; install -m 0555 -o root -g root "$PROBE" "$AUTHORITY"
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
target=sys.argv[2]
ok=any(e.get('event_code')=='process_shield_ptrace_denied' and f'target_pid={target}' in e.get('backend_diag','') and e.get('pid',0)>0 for e in events)
raise SystemExit(0 if ok else 1)
PY
    then audit_ok=1; break; fi
    sleep .1
  done
  [ "$audit_ok" = 1 ] || { echo "FAIL: missing persisted exact Process Shield audit for $op"; exit 1; }
  echo "LPS5_DAEMON_${op^^}_ON_PERSISTED_EXACT_AUDIT=PASS"
done
grep -q 'Process Shield admitted exact Firefox Main from File Shield WebStorage allow' "$WORK/guardd-true.log" || { echo 'FAIL: no real daemon admission'; exit 1; }
echo 'LPS5_DAEMON_INTEGRATED_ADMISSION_AND_ADVERSARIAL_MATRIX=PASS'
