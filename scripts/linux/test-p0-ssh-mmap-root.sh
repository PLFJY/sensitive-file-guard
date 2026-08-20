#!/usr/bin/env bash
# P0 SSH mmap acceptance oracle. Root runs guardd, but the synthetic private
# key and attacker/probe both use the same non-root uid. Guard OFF proves the
# primitives are DAC-allowed; Guard ON must deny before a readable fd exists.
#
# Required: TEST_FS_ROOT=<isolated non-root, non-tmpfs filesystem>
# Optional: ENFORCEMENT_MODE=strict-filesystem|conservative
#           P0_CASE=configured|runtime
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: run as root through the capsule, or through an explicitly authorized polkit host fallback"
  exit 2
fi
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN_DIR="${BIN_DIR:-$REPO/target/release}"
GUARDD="${GUARDD:-$BIN_DIR/guardd}"
GUARDCTL="${GUARDCTL:-$BIN_DIR/guardctl}"
PROBE="${PROBE:-$BIN_DIR/guard-test-probe}"
IPC_HELPER="$REPO/scripts/helpers/ipc-request.py"
ENFORCEMENT_MODE="${ENFORCEMENT_MODE:-strict-filesystem}"
P0_CASE="${P0_CASE:-configured}"
# Use the capsule invoker's normal uid by default. Numeric UIDs without a
# passwd entry can be subject to nspawn's user-resolution restrictions, which
# would invalidate the same-UID Guard OFF causality baseline.
TEST_UID="${TEST_UID:-1000}"
TEST_GID="${TEST_GID:-1000}"
CANARY="SDF_CANARY_P0_SAME_UID_MMAP"
EVIDENCE_ROOT="${EVIDENCE_ROOT:-}"

PASS=0; FAIL=0; BLOCKED=0
note_pass() { echo "PASS: $1"; PASS=$((PASS + 1)); }
note_fail() { echo "FAIL: $1"; FAIL=$((FAIL + 1)); }
note_blocked() { echo "BLOCKED: $1"; BLOCKED=$((BLOCKED + 1)); }

if [ -z "${TEST_FS_ROOT:-}" ]; then
  echo "BLOCKED: TEST_FS_ROOT must be an isolated loop-backed ext4 filesystem"
  exit 2
fi
if [ "$(stat -c %d "$TEST_FS_ROOT")" = "$(stat -c %d /)" ]; then
  echo "BLOCKED: TEST_FS_ROOT=$TEST_FS_ROOT shares the root filesystem"
  exit 2
fi
if [ "$(stat -f -c %T "$TEST_FS_ROOT")" = "tmpfs" ]; then
  echo "BLOCKED: TEST_FS_ROOT must not be tmpfs"
  exit 2
fi
for bin in "$GUARDD" "$GUARDCTL" "$PROBE"; do
  test -x "$bin" || { echo "BLOCKED: missing staged binary $bin"; exit 2; }
done
test -f "$IPC_HELPER" || { echo "BLOCKED: missing staged IPC helper $IPC_HELPER"; exit 2; }
command -v python3 >/dev/null || { echo "BLOCKED: python3 is required"; exit 2; }
command -v setpriv >/dev/null || { echo "BLOCKED: setpriv is required"; exit 2; }
case "$ENFORCEMENT_MODE" in strict-filesystem|conservative) ;; *) echo "BLOCKED: bad ENFORCEMENT_MODE"; exit 2;; esac
case "$P0_CASE" in configured|runtime) ;; *) echo "BLOCKED: bad P0_CASE"; exit 2;; esac

WORK="$TEST_FS_ROOT/p0-ssh-${ENFORCEMENT_MODE}-${P0_CASE}-$$"
KEY="$WORK/ssh/id_ed25519"
SOCK="$WORK/guardd.sock"
DAEMON_PID=""
cleanup() {
  if [ -n "$DAEMON_PID" ] && kill -0 "$DAEMON_PID" 2>/dev/null; then
    kill -TERM "$DAEMON_PID" 2>/dev/null || true
    wait "$DAEMON_PID" 2>/dev/null || true
  fi
  # Preserve only metadata evidence; never copy the synthetic key or probe
  # output because those intentionally contain the baseline canary.
  if [ -n "$EVIDENCE_ROOT" ]; then
    mkdir -p "$EVIDENCE_ROOT"
    cp "$WORK/guardd.log" "$EVIDENCE_ROOT/p0-${ENFORCEMENT_MODE}-${P0_CASE}-guardd.log" 2>/dev/null || true
    cp "$WORK"/events-*.json "$EVIDENCE_ROOT/" 2>/dev/null || true
  fi
  rm -rf -- "$WORK"
}
trap cleanup EXIT

mkdir -p "$WORK/ssh" "$WORK/profile/Default"
# This deliberately is a local synthetic private-key-shaped fixture, not a
# developer key and not an authentication credential. The marker proves a
# readable fd reached mmap/read in the baseline and must never appear under
# Guard ON.
printf '%s\n%s\n%s\n' \
  '-----BEGIN OPENSSH PRIVATE KEY-----' "$CANARY" \
  '-----END OPENSSH PRIVATE KEY-----' > "$KEY"
chmod 0600 "$KEY"
chown -R "$TEST_UID:$TEST_GID" "$WORK/ssh"
printf '{}' > "$WORK/profile/Default/Preferences"
printf '{}' > "$WORK/profile/Local State"

as_attacker() {
  setpriv --reuid "$TEST_UID" --regid "$TEST_GID" --clear-groups "$@"
}

echo "==> Guard OFF baseline: same-UID mmap/read are genuinely readable"
BASE_MMAP="$WORK/baseline-mmap.out"
BASE_READ="$WORK/baseline-read.out"
if as_attacker "$PROBE" mmap "$KEY" >"$BASE_MMAP" 2>&1 && grep -Fqx "$CANARY" "$BASE_MMAP"; then
  note_pass "Guard OFF mmap recovered synthetic canary as uid $TEST_UID"
else
  note_fail "Guard OFF mmap baseline failed; denial could be DAC/container policy"
fi
if as_attacker "$PROBE" read "$KEY" >"$BASE_READ" 2>&1 && grep -Fqx "$CANARY" "$BASE_READ"; then
  note_pass "Guard OFF read recovered synthetic canary as uid $TEST_UID"
else
  note_fail "Guard OFF read baseline failed; denial could be DAC/container policy"
fi

SSH_KEYS='[]'
if [ "$P0_CASE" = configured ]; then SSH_KEYS="[\"$KEY\"]"; fi
cat > "$WORK/config.json" <<EOF
{
  "config_version": 1,
  "enforcement_mode": "$ENFORCEMENT_MODE",
  "browsers": [{
    "id": "synthetic-chromium", "family": "Chromium",
    "profile_root": "$WORK/profile", "owner_uid": $TEST_UID, "exe_paths": []
  }],
  "enrolled_exes": [],
  "ssh_keys": $SSH_KEYS
}
EOF

"$GUARDD" --enforce-browser-config "$WORK/config.json" --ipc-socket "$SOCK" \
  --audit-db "$WORK/audit.db" >"$WORK/guardd.log" 2>&1 &
DAEMON_PID=$!
for _ in $(seq 1 200); do
  if [ -S "$SOCK" ] && "$GUARDCTL" --socket "$SOCK" --json status >"$WORK/status.json" 2>/dev/null; then break; fi
  kill -0 "$DAEMON_PID" 2>/dev/null || { echo "FAIL: guardd exited"; sed -n '1,120p' "$WORK/guardd.log"; exit 1; }
  sleep 0.05
done
test -S "$SOCK" || { echo "FAIL: guardd did not become ready"; exit 1; }

if [ "$P0_CASE" = runtime ]; then
  echo "==> Runtime enrollment: key remains readable while guardd is ON but before protect"
  if as_attacker "$PROBE" mmap "$KEY" >"$WORK/runtime-pre-mmap.out" 2>&1 \
    && grep -Fqx "$CANARY" "$WORK/runtime-pre-mmap.out"; then
    note_pass "runtime pre-protect mmap recovered the synthetic canary"
  else
    note_fail "runtime pre-protect mmap did not prove readability"
  fi
  if as_attacker "$PROBE" read "$KEY" >"$WORK/runtime-pre-read.out" 2>&1 \
    && grep -Fqx "$CANARY" "$WORK/runtime-pre-read.out"; then
    note_pass "runtime pre-protect read recovered the synthetic canary"
  else
    note_fail "runtime pre-protect read did not prove readability"
  fi
  if "$GUARDCTL" --socket "$SOCK" ssh protect "$KEY" >"$WORK/protect.out" 2>&1; then
    note_pass "guardctl ssh protect installed open-time protection"
  else
    note_fail "runtime guardctl ssh protect failed"
  fi
fi

wait_for_denied_audit() {
  local pid="$1" label="$2"
  for _ in $(seq 1 150); do
    "$GUARDCTL" --socket "$SOCK" --json events --limit 50 >"$WORK/events-$pid.json" 2>/dev/null || true
    if python3 - "$WORK/events-$pid.json" "$KEY" "$pid" "$TEST_UID" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1], encoding="utf-8"))
body = doc.get("body") or doc.get("data") or {}
events = body.get("data", body) if isinstance(body, dict) else body
for event in events if isinstance(events, list) else []:
    if (event.get("path") == sys.argv[2] and str(event.get("pid")) == sys.argv[3]
            and str(event.get("uid")) == sys.argv[4]
            and event.get("event_code") == "ssh_key_access_blocked"
            and str(event.get("decision", "")).startswith("Deny(")):
        raise SystemExit(0)
raise SystemExit(1)
PY
    then
      note_pass "$label audit attributes target, requester PID/UID, and denied SSH event"
      return
    fi
    sleep 0.1
  done
  note_fail "$label has no exact denied SSH audit attribution"
}

resolve_pending_deny() {
  local attacker_pid="$1" pending_file="$WORK/pending-$attacker_pid.json"
  local pending_id=""
  for _ in $(seq 1 100); do
    timeout 5s python3 "$IPC_HELPER" --socket "$SOCK" \
      --operation-json '{"kind":"ssh_pending_list"}' --output "$pending_file" \
      --pid-file "$WORK/pending-helper.pid" >/dev/null 2>&1 || true
    pending_id="$(python3 - "$pending_file" "$attacker_pid" <<'PY'
import json, sys
try:
    document = json.load(open(sys.argv[1], encoding="utf-8"))
except (OSError, json.JSONDecodeError):
    raise SystemExit(0)
body = document.get("body") or {}
items = body.get("data", []) if body.get("kind") == "ssh_pending" else []
print(next((item["id"] for item in items if str(item.get("pid")) == sys.argv[2]), ""))
PY
)"
    [ -n "$pending_id" ] && break
    sleep 0.05
  done
  if [ -z "$pending_id" ]; then
    note_fail "attacker PID $attacker_pid never entered the SSH pending queue"
    return 1
  fi
  if timeout 5s python3 "$IPC_HELPER" --socket "$SOCK" \
    --operation-json "{\"kind\":\"ssh_read_resolve\",\"id\":\"$pending_id\",\"action\":\"block\"}" \
    --output "$WORK/resolve-$attacker_pid.json" \
    --pid-file "$WORK/resolve-helper.pid" >/dev/null 2>&1; then
    note_pass "root test authority explicitly denied pending SSH open for requester PID $attacker_pid"
  else
    note_fail "could not resolve pending SSH request as deny"
    return 1
  fi
}

run_guarded_primitive() {
  local primitive="$1" out="$WORK/on-$1.out"
  echo "==> Guard ON $primitive: same-UID attacker must not obtain a readable fd"
  local pid_file="$WORK/ssh/on-$primitive.pid"
  # `setpriv` may leave the shell's background PID one hop above the final
  # exec. Record the final non-root process PID immediately before exec so the
  # audit oracle binds the actual kernel requester.
  setpriv --reuid "$TEST_UID" --regid "$TEST_GID" --clear-groups \
    /bin/sh -c 'printf "%s\\n" "$$" > "$1"; shift; exec "$@"' sh "$pid_file" \
    "$PROBE" "$primitive" "$KEY" >"$out" 2>&1 &
  local wrapper_pid=$!
  local attacker_pid=""
  for _ in $(seq 1 100); do
    if [ -s "$pid_file" ]; then attacker_pid="$(cat "$pid_file")"; break; fi
    kill -0 "$wrapper_pid" 2>/dev/null || break
    sleep 0.01
  done
  if [ -z "$attacker_pid" ]; then
    note_fail "$primitive attacker failed before recording its PID"
    return
  fi
  # Wait until Guard owns the kernel permission request, then explicitly deny
  # it via the root test authority. This yields FAN_DENY promptly and is not a
  # kill, Yama, or DAC denial masquerading as Guard causality.
  resolve_pending_deny "$attacker_pid"
  if wait "$wrapper_pid"; then
    note_fail "$primitive unexpectedly succeeded under Guard ON"
  else
    note_pass "$primitive failed after Guard's bounded denial"
  fi
  if grep -Fq "$CANARY" "$out"; then
    note_fail "$primitive recovered the synthetic canary under Guard ON"
  else
    note_pass "$primitive synthetic canary recovery = 0 under Guard ON"
  fi
  wait_for_denied_audit "$attacker_pid" "$primitive"
}

run_guarded_primitive mmap
run_guarded_primitive read

echo "=== P0 SSH mmap ($ENFORCEMENT_MODE/$P0_CASE) SUMMARY pass=$PASS fail=$FAIL blocked=$BLOCKED ==="
if [ "$FAIL" -gt 0 ]; then exit 1; elif [ "$BLOCKED" -gt 0 ]; then exit 2; else exit 0; fi
