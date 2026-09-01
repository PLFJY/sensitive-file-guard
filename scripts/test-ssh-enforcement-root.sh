#!/usr/bin/env bash
# scripts/test-ssh-enforcement-root.sh
#
# Privileged regression test for interactive SSH private-key protection.
#
# RUN AS ROOT:   sudo bash scripts/test-ssh-enforcement-root.sh
#
# Why root: fanotify permission-event enforcement (FAN_CLASS_CONTENT) requires
# CAP_SYS_ADMIN. The non-interactive build agent cannot obtain it, so the
# privileged tests are provided here for a human to run.
#
# This script generates an EPHEMERAL test keypair under an isolated temp HOME
# via ssh-keygen. It NEVER touches the developer's real ~/.ssh. It contains NO
# network exfiltration code. The generated key is destroyed with the temp dir.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GUARDD="$REPO/target/release/guardd"
GUARDCTL="$REPO/target/release/guardctl"
PROBE="$REPO/target/release/guard-test-probe"
IPC_HELPER="$REPO/scripts/helpers/ipc-request.py"

PASS=0
FAIL=0
BLOCKED=0
note_pass() { echo "PASS: $1"; PASS=$((PASS+1)); }
note_fail() { echo "FAIL: $1"; FAIL=$((FAIL+1)); }
note_blocked() { echo "BLOCKED: $1"; BLOCKED=$((BLOCKED+1)); }

if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: this script must be run as root (needs CAP_SYS_ADMIN for fanotify)."
  echo "       try: sudo bash $0"
  exit 2
fi

echo "==> Checking pre-built release binaries"
# Build as the normal user before entering this root-only gate. The test must
# never populate root's Cargo home or produce root-owned build artifacts.
test -x "$GUARDD" || { echo "guardd binary missing"; exit 1; }
test -x "$GUARDCTL" || { echo "guardctl binary missing"; exit 1; }
test -x "$PROBE" || { echo "guard-test-probe binary missing"; exit 1; }
command -v python3 >/dev/null || { echo "python3 is required"; exit 1; }
command -v timeout >/dev/null || { echo "timeout is required"; exit 1; }

WORK="$(mktemp -d -t guard-ssh-enforce-XXXXXX)"
cleanup() {
  if [ -n "${GUARDD_PID:-}" ] && kill -0 "$GUARDD_PID" 2>/dev/null; then
    kill -TERM "$GUARDD_PID" 2>/dev/null || true
    wait "$GUARDD_PID" 2>/dev/null || true
  fi
  rm -rf -- "$WORK"
}
trap cleanup EXIT

# --- isolated temp HOME with a real ephemeral SSH keypair (NOT the dev's) ---
TEST_HOME="$WORK/home"
SSH_DIR="$TEST_HOME/.ssh"
mkdir -p "$SSH_DIR"
chmod 0700 "$SSH_DIR"

# Generate a real ephemeral ed25519 keypair. This key is NEVER used for auth
# and is destroyed with $WORK. It exists only so the protection tests operate
# on a real private-key file.
if ! command -v ssh-keygen >/dev/null 2>&1; then
  echo "ssh-keygen not found; using synthetic marker key instead"
  printf -- '-----BEGIN OPENSSH PRIVATE KEY-----\nGUARD_SYNTHETIC_SSH_PRIVATEKEY_FIXTURE\n-----END OPENSSH PRIVATE KEY-----\n' \
    > "$SSH_DIR/id_ed25519"
  printf 'ssh-ed25519 AAAA...fake GUARD_SYNTHETIC_SSH_PUBLICKEY_FIXTURE\n' \
    > "$SSH_DIR/id_ed25519.pub"
else
  ssh-keygen -t ed25519 -N "" -C "guard-ephemeral-test" -f "$SSH_DIR/id_ed25519" >/dev/null
fi
chmod 0600 "$SSH_DIR/id_ed25519"

# Non-private files that must remain readable.
printf '# synthetic ssh config\n' > "$SSH_DIR/config"
printf '# synthetic known_hosts\n' > "$SSH_DIR/known_hosts"
printf 'ordinary notes\n' > "$SSH_DIR/notes.txt"

PRIV_KEY="$SSH_DIR/id_ed25519"
PUB_KEY="$SSH_DIR/id_ed25519.pub"
CONFIG_FILE="$SSH_DIR/config"
KNOWN_HOSTS="$SSH_DIR/known_hosts"
NOTES="$SSH_DIR/notes.txt"

# --- enforcement config: protect the private key at startup ---
SOCK="$WORK/guardd.sock"
cat > "$WORK/config.json" <<EOF
{
  "browser_protection_level": "common",
  "browsers": [],
  "enrolled_exes": [],
  "ssh_keys": ["$PRIV_KEY"]
}
EOF

echo "==> Starting guardd SSH enforcement (config-enrolled key)"
"$GUARDD" --enforce-browser-config "$WORK/config.json" \
  --ipc-socket "$SOCK" --print-decisions \
  > "$WORK/guardd.log" 2>&1 &
GUARDD_PID=$!

for _ in $(seq 1 50); do
  if grep -q "enforcement ACTIVE" "$WORK/guardd.log" 2>/dev/null; then break; fi
  kill -0 "$GUARDD_PID" 2>/dev/null || { echo "guardd exited early"; cat "$WORK/guardd.log"; exit 1; }
  sleep 0.1
done
grep -q "enforcement ACTIVE" "$WORK/guardd.log" || { echo "guardd did not become active"; cat "$WORK/guardd.log"; exit 1; }
echo "guardd active (pid=$GUARDD_PID)"

IPC_SEQ=0
IPC_OUTPUT=""
ipc_request() {
  local operation="$1"
  IPC_SEQ=$((IPC_SEQ + 1))
  IPC_OUTPUT="$WORK/ipc-$IPC_SEQ.json"
  timeout 5s python3 "$IPC_HELPER" \
    --socket "$SOCK" \
    --operation-json "$operation" \
    --output "$IPC_OUTPUT" \
    --pid-file "$WORK/ipc-$IPC_SEQ.pid"
}

PENDING_ID=""
wait_for_pending() {
  local reader_pid="$1"
  PENDING_ID=""
  for _ in $(seq 1 50); do
    ipc_request '{"kind":"ssh_pending_list"}' || return 1
    PENDING_ID="$(python3 - "$IPC_OUTPUT" "$reader_pid" <<'PY'
import json, sys
document = json.load(open(sys.argv[1], encoding="utf-8"))
reader_pid = int(sys.argv[2])
body = document.get("body") or {}
items = body.get("data", []) if body.get("kind") == "ssh_pending" else []
print(next((item["id"] for item in items if item["pid"] == reader_pid), ""))
PY
)"
    if [ -n "$PENDING_ID" ]; then return 0; fi
    sleep 0.1
  done
  return 1
}

wait_for_process_exit() {
  local pid="$1"
  for _ in $(seq 1 50); do
    if ! kill -0 "$pid" 2>/dev/null; then return 0; fi
    sleep 0.1
  done
  return 1
}

run_read_resolution() {
  local label="$1"
  local path="$2"
  local action="$3"
  local expected_status="$4"
  local output="$WORK/$label.read"
  local error_output="$WORK/$label.err"

  "$PROBE" read "$path" > "$output" 2> "$error_output" &
  local reader_pid=$!
  if ! wait_for_pending "$reader_pid"; then
    note_fail "$label did not enter the pending SSH-read queue"
    kill -TERM "$reader_pid" 2>/dev/null || true
    wait "$reader_pid" 2>/dev/null || true
    return 1
  fi
  note_pass "$label entered pending before any key data was returned"

  if ! ipc_request "{\"kind\":\"ssh_read_resolve\",\"id\":\"$PENDING_ID\",\"action\":\"$action\"}"; then
    note_fail "$label resolution exceeded the five-second deadlock deadline"
    kill -KILL "$GUARDD_PID" 2>/dev/null || true
    GUARDD_PID=""
    kill -TERM "$reader_pid" 2>/dev/null || true
    wait "$reader_pid" 2>/dev/null || true
    return 1
  fi
  if ! python3 - "$IPC_OUTPUT" "$action" <<'PY'
import json, sys
document = json.load(open(sys.argv[1], encoding="utf-8"))
expected = "allowed" if sys.argv[2] == "allow" else "blocked"
body = document.get("body") or {}
ok = document.get("ok") and body.get("kind") == "ssh_read_resolved" and body.get("data") == expected
raise SystemExit(0 if ok else 1)
PY
  then
    note_fail "$label returned an invalid resolution response"
    kill -TERM "$reader_pid" 2>/dev/null || true
    wait "$reader_pid" 2>/dev/null || true
    return 1
  fi

  if ! wait_for_process_exit "$reader_pid"; then
    note_fail "$label reader remained blocked after resolution"
    kill -TERM "$reader_pid" 2>/dev/null || true
    wait "$reader_pid" 2>/dev/null || true
    return 1
  fi
  set +e
  wait "$reader_pid"
  local reader_status=$?
  set -e
  if [ "$expected_status" = success ] && [ "$reader_status" -eq 0 ] && [ -s "$output" ]; then
    note_pass "$label was allowed and completed"
  elif [ "$expected_status" = failure ] && [ "$reader_status" -ne 0 ] && [ ! -s "$output" ]; then
    note_pass "$label was blocked without returning key data"
  else
    note_fail "$label exited with unexpected status $reader_status"
    return 1
  fi

  if timeout 5s "$GUARDCTL" --socket "$SOCK" status >/dev/null 2>&1; then
    note_pass "daemon remained responsive after $label"
  else
    note_fail "daemon status hung after $label"
    return 1
  fi
  rm -f -- "$output" "$error_output"
}

run_reader_exit_resolution() {
  local output="$WORK/reader-exit.read"
  "$PROBE" read "$PRIV_KEY" > "$output" 2> "$WORK/reader-exit.err" &
  local reader_pid=$!
  if ! wait_for_pending "$reader_pid"; then
    note_fail "reader-exit case did not enter pending"
    kill -TERM "$reader_pid" 2>/dev/null || true
    wait "$reader_pid" 2>/dev/null || true
    return 1
  fi
  local pending_id="$PENDING_ID"
  kill -KILL "$reader_pid" 2>/dev/null || true
  wait "$reader_pid" 2>/dev/null || true
  for _ in $(seq 1 50); do
    ipc_request '{"kind":"ssh_pending_list"}' || return 1
    if python3 - "$IPC_OUTPUT" "$pending_id" <<'PY'
import json, sys
document = json.load(open(sys.argv[1], encoding="utf-8"))
items = (document.get("body") or {}).get("data", [])
raise SystemExit(0 if all(item["id"] != sys.argv[2] for item in items) else 1)
PY
    then
      if [ ! -s "$output" ]; then
        note_pass "exited reader was removed from pending without receiving key data"
        return 0
      fi
      note_fail "exited reader received key data"
      return 1
    fi
    sleep 0.1
  done
  note_fail "exited reader remained pending"
  return 1
}

run_pending_timeout_resolution() {
  local output="$WORK/pending-timeout.read"
  "$PROBE" read "$PRIV_KEY" > "$output" 2> "$WORK/pending-timeout.err" &
  local reader_pid=$!
  if ! wait_for_pending "$reader_pid"; then
    note_fail "timeout case did not enter pending"
    kill -TERM "$reader_pid" 2>/dev/null || true
    wait "$reader_pid" 2>/dev/null || true
    return 1
  fi
  for _ in $(seq 1 700); do
    if ! kill -0 "$reader_pid" 2>/dev/null; then break; fi
    sleep 0.1
  done
  if kill -0 "$reader_pid" 2>/dev/null; then
    note_fail "pending SSH read exceeded its 60-second daemon deadline"
    kill -TERM "$reader_pid" 2>/dev/null || true
    wait "$reader_pid" 2>/dev/null || true
    return 1
  fi
  set +e
  wait "$reader_pid"
  local reader_status=$?
  set -e
  if [ "$reader_status" -ne 0 ] && [ ! -s "$output" ]; then
    note_pass "pending timeout denied the read without returning key data"
  else
    note_fail "pending timeout produced unexpected reader status $reader_status"
    return 1
  fi
  timeout 5s "$GUARDCTL" --socket "$SOCK" status >/dev/null 2>&1 || {
    note_fail "daemon became unresponsive after pending timeout"
    return 1
  }
}

echo "==> Test 1: Allow resolves a held SSH read without deadlocking guardd"
run_read_resolution "allow-read" "$PRIV_KEY" allow success

echo "==> Test 2: Block denies a held SSH read without returning key data"
run_read_resolution "block-read" "$PRIV_KEY" block failure

echo "==> Test 3: reader exit cancels pending access without leaking data"
run_reader_exit_resolution

echo "==> Test 4: unanswered pending access times out closed"
run_pending_timeout_resolution

echo "==> Test 5: public key remains readable (not protected)"
if cat "$PUB_KEY" > "$WORK/t6.out" 2>/dev/null; then
  if [ -s "$WORK/t6.out" ]; then
    note_pass "public key remains readable"
  else
    note_fail "public key read but empty"
  fi
else
  note_fail "public key was blocked (over-blocking)"
fi

echo "==> Test 6: unrelated files under .ssh remain readable (config, known_hosts, notes)"
for f in "$CONFIG_FILE" "$KNOWN_HOSTS" "$NOTES"; do
  if cat "$f" > /dev/null 2>/dev/null; then
    note_pass "$(basename "$f") remains readable"
  else
    note_fail "$(basename "$f") was blocked (over-blocking)"
  fi
done

echo "==> Test 7: hardlink read follows the protected inode and can be allowed"
ln -f "$PRIV_KEY" "$WORK/hard-to-key" 2>/dev/null || {
  note_blocked "hardlink creation not supported on this filesystem ($WORK)"
}
if [ -e "$WORK/hard-to-key" ]; then
  run_read_resolution "hardlink-allow" "$WORK/hard-to-key" allow success
fi

echo "==> Test 8: symlink read follows the protected target and can be allowed"
ln -sf "$PRIV_KEY" "$WORK/sym-to-key"
run_read_resolution "symlink-allow" "$WORK/sym-to-key" allow success

echo "==> Test 9: runtime guardctl ssh protect on a NEW key => protects it"
# Generate a second ephemeral key not in the config and protect it at runtime.
if [ -x "$(command -v ssh-keygen)" ]; then
  ssh-keygen -t ed25519 -N "" -C "guard-runtime-test" -f "$SSH_DIR/id_runtime" >/dev/null
else
  printf -- '-----BEGIN OPENSSH PRIVATE KEY-----\nGUARD_SYNTHETIC_RUNTIME_KEY\n-----END OPENSSH PRIVATE KEY-----\n' \
    > "$SSH_DIR/id_runtime"
fi
chmod 0600 "$SSH_DIR/id_runtime"
RUNTIME_KEY="$SSH_DIR/id_runtime"
# Before protection: readable.
if ! cat "$RUNTIME_KEY" > /dev/null 2>&1; then
  note_fail "runtime key unexpectedly unreadable BEFORE protection"
fi
# Protect via guardctl IPC.
if "$GUARDCTL" --socket "$SOCK" ssh protect "$RUNTIME_KEY" > "$WORK/t10.out" 2>&1; then
  note_pass "guardctl ssh protect succeeded"
else
  note_fail "guardctl ssh protect failed: $(cat "$WORK/t10.out")"
fi
# After protection the same interactive mediation applies.
run_read_resolution "runtime-key-allow" "$RUNTIME_KEY" allow success

echo "==> Test 10: guardctl ssh protect rejects .pub file"
if "$GUARDCTL" --socket "$SOCK" ssh protect "$PUB_KEY" > "$WORK/t11.out" 2>&1; then
  note_fail "guardctl ssh protect accepted .pub file"
else
  note_pass "guardctl ssh protect rejected .pub file"
fi

echo "==> Test 11: guardctl ssh suggest lists conventional candidates"
# Run suggest against the temp .ssh dir; it should list id_ed25519 and id_runtime
# (not .pub, not known_hosts/config).
SUGGEST_OUT="$("$GUARDCTL" ssh suggest --dir "$SSH_DIR" 2>/dev/null || true)"
if echo "$SUGGEST_OUT" | grep -q "id_ed25519" && echo "$SUGGEST_OUT" | grep -q "id_runtime"; then
  if ! echo "$SUGGEST_OUT" | grep -q "\.pub"; then
    note_pass "ssh suggest lists private candidates, excludes .pub"
  else
    note_fail "ssh suggest listed a .pub file"
  fi
else
  note_fail "ssh suggest did not list expected candidates: $SUGGEST_OUT"
fi

echo "==> Test 12: protected key audit log has no key contents"
# Query events from the daemon; the audit JSON must not contain the private key
# header or any key bytes.
"$GUARDCTL" --socket "$SOCK" --json events --limit 20 > "$WORK/events.json" 2>/dev/null || true
if grep -q "BEGIN OPENSSH PRIVATE KEY" "$WORK/events.json" 2>/dev/null; then
  note_fail "audit events leaked private-key header"
else
  note_pass "audit events contain no private-key content"
fi
if grep -q "BEGIN OPENSSH PRIVATE KEY" "$WORK/guardd.log" 2>/dev/null; then
  note_fail "daemon log leaked private-key content"
else
  note_pass "daemon log contains no private-key content"
fi

echo "==> Test 13: clean daemon shutdown"
if [ -n "${GUARDD_PID:-}" ]; then
  kill -TERM "$GUARDD_PID" 2>/dev/null || true
  for _ in $(seq 1 50); do
    if ! kill -0 "$GUARDD_PID" 2>/dev/null; then break; fi
    sleep 0.1
  done
  if kill -0 "$GUARDD_PID" 2>/dev/null; then
    note_fail "guardd did not exit on SIGTERM"
    kill -KILL "$GUARDD_PID" 2>/dev/null || true
    GUARDD_PID=""
  else
    note_pass "guardd exited on SIGTERM"
    GUARDD_PID=""
  fi
fi

echo
echo "==> SSH interactive-read root integration summary: PASS=$PASS FAIL=$FAIL BLOCKED=$BLOCKED"
echo "    (see $WORK/guardd.log for daemon decision log)"
echo
echo "NOTE: rename gap — fanotify marks are inode-based; renaming a protected"
echo "      key moves the SAME inode so protection follows the rename. A key"
echo "      re-created at the original path after deletion is NOT protected until"
echo "      re-enrolled (documented in reports/phase-10.md)."
exit $FAIL
