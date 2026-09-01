#!/usr/bin/env bash
# Hardening Pass 2 SSH broker acceptance. Ephemeral key/agent only; no real
# HOME, ~/.ssh, agent, network, or key-content output.
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: run as root (fanotify FAN_OPEN_PERM requires CAP_SYS_ADMIN)"
  exit 2
fi

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GUARDD="$REPO/target/release/guardd"
GUARDCTL="$REPO/target/release/guardctl"
PROBE="$REPO/target/release/guard-test-probe"
SCENARIOS="$REPO/scripts/helpers/ssh-broker-scenarios.py"
WORK="$(mktemp -d -t guard-ssh-broker-adversarial-XXXXXX)"
GUARDD_PID=""
AGENT_PID=""
FAKE_AGENT_PID=""
PASS=0
FAIL=0
BLOCKED=0

pass() { echo "PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "FAIL: $1"; FAIL=$((FAIL + 1)); }
blocked() { echo "BLOCKED: $1"; BLOCKED=$((BLOCKED + 1)); }
cleanup() {
  for pid in "$FAKE_AGENT_PID" "$GUARDD_PID" "$AGENT_PID"; do
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
      kill -TERM "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    fi
  done
  rm -rf -- "$WORK"
}
trap cleanup EXIT

for tool in ssh-keygen ssh-add ssh-agent python3 cc; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "ERROR: required tool '$tool' is unavailable"
    exit 2
  fi
done

echo "==> Checking pre-built release binaries"
# Build as the normal user before entering this root-only gate. The test must
# never populate root's Cargo home or produce root-owned build artifacts.
for artifact in "$GUARDD" "$GUARDCTL" "$PROBE"; do
  [ -x "$artifact" ] || {
    echo "ERROR: missing $artifact; build it as the normal user first"
    exit 2
  }
done

HOME_FIXTURE="$WORK/home"
SSH_DIR="$HOME_FIXTURE/.ssh"
mkdir -p "$SSH_DIR"
chmod 0700 "$HOME_FIXTURE" "$SSH_DIR"
KEY="$SSH_DIR/id_ed25519"
PUB="$KEY.pub"
ssh-keygen -q -t ed25519 -N '' -C guard-hardening-pass-2-ephemeral -f "$KEY"
chmod 0600 "$KEY"

AGENT_SOCKET="$WORK/trusted-agent.sock"
"$(command -v ssh-agent)" -D -a "$AGENT_SOCKET" \
  > "$WORK/ssh-agent.log" 2>&1 &
AGENT_PID=$!
for _ in $(seq 1 200); do
  [ -S "$AGENT_SOCKET" ] && break
  kill -0 "$AGENT_PID" 2>/dev/null || {
    echo "ERROR: disposable system ssh-agent exited"
    exit 1
  }
  sleep 0.01
done
[ -S "$AGENT_SOCKET" ] || { echo "ERROR: disposable agent socket missing"; exit 1; }
export SSH_AUTH_SOCK="$AGENT_SOCKET"

CONFIG="$WORK/config.json"
printf '%s\n' \
  '{' \
  '  "browser_protection_level": "common",' \
  '  "browsers": [],' \
  '  "enrolled_exes": [],' \
  "  \"ssh_keys\": [\"$KEY\"]" \
  '}' > "$CONFIG"
SOCKET="$WORK/guardd.sock"
"$GUARDD" --enforce-browser-config "$CONFIG" --ipc-socket "$SOCKET" \
  --audit-db "$WORK/audit.db" --print-decisions \
  > "$WORK/guardd.log" 2>&1 &
GUARDD_PID=$!
for _ in $(seq 1 200); do
  grep -q 'enforcement ACTIVE' "$WORK/guardd.log" 2>/dev/null && break
  kill -0 "$GUARDD_PID" 2>/dev/null || {
    echo "ERROR: guardd exited before enforcement became active"
    sed -n '1,160p' "$WORK/guardd.log"
    exit 1
  }
  sleep 0.025
done
grep -q 'enforcement ACTIVE' "$WORK/guardd.log" || {
  echo "ERROR: guardd did not become active"
  sed -n '1,160p' "$WORK/guardd.log"
  exit 1
}

expect_rejected_response() {
  local description=$1
  local output=$2
  if python3 - "$output" <<'PY'
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
raise SystemExit(0 if not d["response"].get("ok", False) else 1)
PY
  then pass "$description"; else fail "$description"; fi
}

echo "==> Raw private-key access"
if cat "$KEY" >/dev/null 2>&1; then pass "direct private-key read allowed"; else fail "direct private-key read interrupted"; fi
if cp "$KEY" "$WORK/copied-key" 2>/dev/null; then
  pass "copy private key allowed"
  rm -f -- "$WORK/copied-key"
else
  fail "copy private key interrupted"
fi
if "$PROBE" read "$KEY" >/dev/null 2>&1; then pass "Rust probe read allowed"; else fail "Rust probe read interrupted"; fi
if python3 -c 'import sys; open(sys.argv[1], "rb").read()' "$KEY" 2>/dev/null; then
  pass "Python probe read allowed"
else
  fail "Python probe read interrupted"
fi
if [ -s "$PUB" ] && cat "$PUB" >/dev/null; then pass "public key remains readable"; else fail "public key was blocked"; fi

echo "==> Kernel-observed stopped-child validation"
python3 "$SCENARIOS" wrong-pid --socket "$SOCKET" --key "$KEY" \
  --agent "$AGENT_SOCKET" > "$WORK/wrong-pid.json"
expect_rejected_response "wrong child PID rejected" "$WORK/wrong-pid.json"
python3 "$SCENARIOS" non-child --socket "$SOCKET" --key "$KEY" \
  --agent "$AGENT_SOCKET" --other-pid "$AGENT_PID" > "$WORK/non-child.json"
expect_rejected_response "non-child PID rejected" "$WORK/non-child.json"
python3 "$SCENARIOS" running-child --socket "$SOCKET" --key "$KEY" \
  --agent "$AGENT_SOCKET" > "$WORK/running-child.json"
expect_rejected_response "running/not-stopped child rejected" "$WORK/running-child.json"
python3 "$SCENARIOS" fake-declared --socket "$SOCKET" --key "$KEY" \
  --agent "$AGENT_SOCKET" > "$WORK/fake-declared.json"
expect_rejected_response "client-declared fake identity rejected" "$WORK/fake-declared.json"
python3 "$SCENARIOS" disconnect-after-request --socket "$SOCKET" --key "$KEY" \
  --agent "$AGENT_SOCKET" > "$WORK/disconnect-after-request.json"
if python3 - "$WORK/disconnect-after-request.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
raise SystemExit(0 if all(lease.get("revoked") for lease in d["new_leases"]) else 1)
PY
then pass "IPC disconnect cannot leave a live SSH load capability"; else fail "IPC disconnect left a live SSH load capability"; fi

echo "==> Executable trust and lease identity"
cp /usr/bin/ssh-add "$WORK/user-writable-ssh-add"
chmod 0777 "$WORK/user-writable-ssh-add"
if "$GUARDCTL" --socket "$SOCKET" ssh load "$KEY" \
  --ssh-add "$WORK/user-writable-ssh-add" > "$WORK/user-writable.out" 2>&1; then
  fail "user-writable ssh-add was accepted"
else
  pass "fake/user-writable ssh-add rejected by guardctl"
fi
python3 "$SCENARIOS" fake-exec --socket "$SOCKET" --key "$KEY" \
  --agent "$AGENT_SOCKET" > "$WORK/fake-exec.json"
if python3 - "$WORK/fake-exec.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
# Authorization is issued for the future system ssh-add identity. /usr/bin/cat
# cannot consume that lease, but its ordinary read is intentionally allowed.
raise SystemExit(0 if d["response"].get("ok") and d["child_exit"] == 0 else 1)
PY
then pass "altered executable fell back to ordinary read allowance"; else fail "fake executable scenario failed"; fi

echo "==> Same-UID malicious agent endpoint"
FAKE_SOCKET="$WORK/fake-agent.sock"
FAKE_RECEIVED="$WORK/fake-agent-received"
python3 - "$FAKE_SOCKET" "$FAKE_RECEIVED" <<'PY' &
import os, socket, sys
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.bind(sys.argv[1]); sock.listen(2)
for _ in range(2):
    connection, _ = sock.accept()
    data = connection.recv(4096)
    with open(sys.argv[2], "ab") as output:
        output.write(data)
    connection.close()
PY
FAKE_AGENT_PID=$!
for _ in $(seq 1 100); do [ -S "$FAKE_SOCKET" ] && break; sleep 0.01; done
if SSH_AUTH_SOCK="$FAKE_SOCKET" "$GUARDCTL" --socket "$SOCKET" ssh load "$KEY" \
  > "$WORK/fake-agent.out" 2>&1; then
  fail "malicious same-UID fake agent endpoint was authorized"
else
  pass "malicious same-UID fake agent endpoint rejected"
fi
sleep 0.05
if [ ! -s "$FAKE_RECEIVED" ]; then pass "fake agent received zero private-key bytes"; else fail "fake agent received broker data"; fi
kill -TERM "$FAKE_AGENT_PID" 2>/dev/null || true
wait "$FAKE_AGENT_PID" 2>/dev/null || true
FAKE_AGENT_PID=""

echo "==> Minimal execve environment"
LOADER_LOG="$WORK/loader-invocations.log"
LOADER_C="$WORK/loader-probe.c"
printf '%s\n' \
  '#include <fcntl.h>' \
  '#include <unistd.h>' \
  '__attribute__((constructor)) static void loaded(void) {' \
  "  int fd = open(\"$LOADER_LOG\", O_WRONLY|O_CREAT|O_APPEND, 0600);" \
  '  if (fd >= 0) { write(fd, "loaded\n", 7); close(fd); }' \
  '}' > "$LOADER_C"
cc -shared -fPIC -o "$WORK/loader-probe.so" "$LOADER_C"
ssh-add -D >/dev/null 2>&1 || true
if LD_PRELOAD="$WORK/loader-probe.so" "$GUARDCTL" --socket "$SOCKET" ssh load "$KEY" \
  > "$WORK/loader-test.out" 2>&1; then
  if [ "$(wc -l < "$LOADER_LOG")" -eq 1 ]; then
    pass "hostile LD_PRELOAD reached guardctl only, not brokered ssh-add"
  else
    fail "loader injection appeared in brokered ssh-add"
  fi
else
  fail "brokered load failed during loader-environment test"
fi

echo "==> Trusted agent and one-shot lease"
if ssh-add -l 2>/dev/null | grep -q guard-hardening-pass-2-ephemeral; then
  pass "brokered trusted ssh-agent load is visible in ssh-add -l"
else
  fail "ssh-add -l cannot see the ephemeral loaded key"
fi
"$GUARDCTL" --socket "$SOCKET" --json events --limit 100 > "$WORK/after-load-events.json" 2>/dev/null || true
if grep -q 'AllowByLease' "$WORK/after-load-events.json"; then
  pass "first ssh-add private-key open recorded ALLOW_BY_LEASE"
else
  fail "successful broker load has no ALLOW_BY_LEASE audit evidence"
fi
if cat "$KEY" >/dev/null 2>&1; then pass "raw read remains allowed after ssh-add exit"; else fail "raw read interrupted after ssh-add exit"; fi

ssh-add -D >/dev/null 2>&1 || true
python3 "$SCENARIOS" double-open --socket "$SOCKET" --key "$KEY" \
  --agent "$AGENT_SOCKET" > "$WORK/double-open.json"
if python3 - "$WORK/double-open.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
raise SystemExit(0 if d["response"].get("ok") and d["child_exit"] == 0 else 1)
PY
then pass "double-open process completed; only first open can consume the lease"; else fail "double-open scenario failed"; fi
if ssh-add -l 2>/dev/null | grep -q guard-hardening-pass-2-ephemeral; then
  pass "first open in double-open scenario loaded the ephemeral key"
else
  fail "double-open scenario did not load on first open"
fi

echo "==> Lease expiration (31 seconds)"
ssh-add -D >/dev/null 2>&1 || true
python3 "$SCENARIOS" expired --socket "$SOCKET" --key "$KEY" \
  --agent "$AGENT_SOCKET" > "$WORK/expired.json"
if python3 - "$WORK/expired.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
raise SystemExit(0 if d["response"].get("ok") and d["child_exit"] == 0 else 1)
PY
then pass "expired lease fell back to ordinary read allowance"; else fail "expired-lease scenario failed"; fi
if ssh-add -l >/dev/null 2>&1; then pass "ordinary allowed read loaded the key after lease expiry"; else fail "ssh-add did not load after lease expiry"; fi

echo "==> Malicious client ignores daemon-pinned endpoint"
IGNORE_FAKE_SOCKET="$WORK/ignore-pin-fake-agent.sock"
IGNORE_FAKE_RECEIVED="$WORK/ignore-pin-fake-agent-received"
python3 - "$IGNORE_FAKE_SOCKET" "$IGNORE_FAKE_RECEIVED" <<'PY' &
import socket, sys
listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
listener.bind(sys.argv[1]); listener.listen(1); listener.settimeout(5)
data = b""
try:
    connection, _ = listener.accept()
    data = connection.recv(4096)
    connection.close()
except TimeoutError:
    pass
open(sys.argv[2], "wb").write(data)
PY
FAKE_AGENT_PID=$!
for _ in $(seq 1 100); do [ -S "$IGNORE_FAKE_SOCKET" ] && break; sleep 0.01; done
python3 "$SCENARIOS" ignore-pin-swap --socket "$SOCKET" --key "$KEY" \
  --agent "$AGENT_SOCKET" --replacement-socket "$IGNORE_FAKE_SOCKET" \
  > "$WORK/ignore-pin-swap.json"
IGNORE_PINNED_SOCKET="$(python3 - "$WORK/ignore-pin-swap.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
print(d["response"]["body"]["data"]["agent_socket"])
PY
)"
if python3 - "$WORK/ignore-pin-swap.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
raise SystemExit(0 if d["response"].get("ok") and d["child_exit"] != 0 else 1)
PY
then pass "real ssh-add cannot use a lease with an unpinned agent environment"; else fail "malicious client bypassed the pinned-agent lease binding"; fi
# Restore the trusted listener pathname from guardd's immutable hardlink so the
# following positive-control scenario starts from the same verified agent.
rm -f -- "$AGENT_SOCKET"
ln "$IGNORE_PINNED_SOCKET" "$AGENT_SOCKET"
wait "$FAKE_AGENT_PID" 2>/dev/null || true
FAKE_AGENT_PID=""
if [ ! -s "$IGNORE_FAKE_RECEIVED" ]; then
  pass "non-cooperative post-authorization fake agent received zero private-key bytes"
else
  fail "non-cooperative fake agent received broker data"
fi
if ssh-add -l >/dev/null 2>&1; then
  fail "non-cooperative agent swap loaded the key into the trusted agent"
else
  pass "trusted agent remained empty after the non-cooperative swap"
fi

echo "==> Post-authorization socket pathname replacement"
RACE_FAKE_SOCKET="$WORK/race-fake-agent.sock"
RACE_FAKE_RECEIVED="$WORK/race-fake-agent-received"
python3 - "$RACE_FAKE_SOCKET" "$RACE_FAKE_RECEIVED" <<'PY' &
import socket, sys
listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
listener.bind(sys.argv[1]); listener.listen(1); listener.settimeout(5)
data = b""
try:
    connection, _ = listener.accept()
    data = connection.recv(4096)
    connection.close()
except TimeoutError:
    pass
open(sys.argv[2], "wb").write(data)
PY
FAKE_AGENT_PID=$!
for _ in $(seq 1 100); do [ -S "$RACE_FAKE_SOCKET" ] && break; sleep 0.01; done
python3 "$SCENARIOS" swap-after-authorize --socket "$SOCKET" --key "$KEY" \
  --agent "$AGENT_SOCKET" --replacement-socket "$RACE_FAKE_SOCKET" \
  > "$WORK/swap-after-authorize.json"
PINNED_SOCKET="$(python3 - "$WORK/swap-after-authorize.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
print(d["response"]["body"]["data"]["agent_socket"])
PY
)"
if python3 - "$WORK/swap-after-authorize.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
raise SystemExit(0 if d["response"].get("ok") and d["child_exit"] == 0 else 1)
PY
then pass "root-pinned socket survives original pathname replacement"; else fail "pinned-agent load failed after pathname replacement"; fi
if SSH_AUTH_SOCK="$PINNED_SOCKET" ssh-add -l 2>/dev/null | grep -q guard-hardening-pass-2-ephemeral; then
  pass "post-swap key reached the preverified system ssh-agent"
else
  fail "post-swap key is absent from the preverified agent"
fi
wait "$FAKE_AGENT_PID" 2>/dev/null || true
FAKE_AGENT_PID=""
if [ ! -s "$RACE_FAKE_RECEIVED" ]; then
  pass "post-authorization fake socket received zero private-key bytes"
else
  fail "post-authorization fake socket received broker data"
fi

echo "==> Audit/log secret-content scan"
"$GUARDCTL" --socket "$SOCKET" --json events --limit 500 > "$WORK/events.json" 2>/dev/null || true
if grep -R -l --exclude='id_ed25519' --exclude='loader-probe.so' \
  'BEGIN OPENSSH PRIVATE KEY' "$WORK" > "$WORK/leaks.txt" 2>/dev/null; then
  fail "private-key content appeared outside the fixture"
else
  pass "daemon/audit/stdout artifacts contain no private-key bytes"
fi

echo
echo "==> SSH broker adversarial summary: PASS=$PASS FAIL=$FAIL BLOCKED=$BLOCKED"
exit "$FAIL"
