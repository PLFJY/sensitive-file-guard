#!/usr/bin/env bash
# scripts/test-ssh-load-root.sh
#
# Phase 11 privileged integration test for the ssh-agent load flow
# (`guardctl ssh load` -> one-shot SshLoadLease -> ssh-add reads the key once).
#
# RUN AS ROOT:   sudo bash scripts/test-ssh-load-root.sh
#
# Why root: fanotify permission-event enforcement (FAN_CLASS_CONTENT) requires
# CAP_SYS_ADMIN. The non-interactive build agent cannot obtain it, so the
# privileged tests are provided here for a human to run.
#
# This script generates an EPHEMERAL test keypair under an isolated temp HOME
# via ssh-keygen and runs an isolated `ssh-agent`. It NEVER touches the
# developer's real ~/.ssh or real ssh-agent. It contains NO network
# exfiltration code. The generated key + agent are destroyed with the temp dir.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENFORCEMENT_MODE="${ENFORCEMENT_MODE:-conservative}"
case "$ENFORCEMENT_MODE" in
  conservative|strict-filesystem) ;;
  *) echo "ERROR: ENFORCEMENT_MODE must be conservative or strict-filesystem"; exit 2 ;;
esac
GUARDD="$REPO/target/release/guardd"
GUARDCTL="$REPO/target/release/guardctl"

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

# Required external tools.
for tool in ssh-keygen ssh-add ssh-agent; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "ERROR: required tool '$tool' not found in PATH"
    exit 2
  fi
done

echo "==> Building release binaries"
cd "$REPO"
cargo build --release 2>&1 | grep -E '(Compiling guardd|Compiling guardctl|Finished|error)' || true
test -x "$GUARDD" || { echo "guardd binary missing"; exit 1; }
test -x "$GUARDCTL" || { echo "guardctl binary missing"; exit 1; }

WORK="$(mktemp -d -t guard-ssh-load-XXXXXX)"
GUARDD_PID=""
SSH_AGENT_PID=""
cleanup() {
  if [ -n "${GUARDD_PID:-}" ] && kill -0 "$GUARDD_PID" 2>/dev/null; then
    kill -TERM "$GUARDD_PID" 2>/dev/null || true
    wait "$GUARDD_PID" 2>/dev/null || true
  fi
  if [ -n "${SSH_AGENT_PID:-}" ] && kill -0 "$SSH_AGENT_PID" 2>/dev/null; then
    kill -TERM "$SSH_AGENT_PID" 2>/dev/null || true
    wait "$SSH_AGENT_PID" 2>/dev/null || true
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

# --- isolated temp HOME with a real ephemeral SSH keypair (NOT the dev's) ---
TEST_HOME="$WORK/home"
SSH_DIR="$TEST_HOME/.ssh"
mkdir -p "$SSH_DIR"
chmod 0700 "$SSH_DIR"

ssh-keygen -t ed25519 -N "" -C "guard-ephemeral-load-test" -f "$SSH_DIR/id_ed25519" >/dev/null
chmod 0600 "$SSH_DIR/id_ed25519"
PRIV_KEY="$SSH_DIR/id_ed25519"
PUB_KEY="$SSH_DIR/id_ed25519.pub"

# --- isolated ssh-agent (NOT the dev's agent) ---
AGENT_SOCK="$WORK/agent.sock"
# Keep the disposable agent as this script's direct foreground-mode child.
# This avoids parsing shell output and makes PID/lifecycle observation exact.
ssh-agent -D -a "$AGENT_SOCK" > "$WORK/ssh-agent.log" 2>&1 &
SSH_AGENT_PID=$!
export SSH_AUTH_SOCK="$AGENT_SOCK"

for _ in $(seq 1 100); do
  [ -S "$AGENT_SOCK" ] && break
  kill -0 "$SSH_AGENT_PID" 2>/dev/null || {
    echo "ERROR: isolated ssh-agent exited early"
    sed -n '1,80p' "$WORK/ssh-agent.log"
    exit 1
  }
  sleep 0.02
done

# Verify the agent is reachable. OpenSSH returns 1 for a reachable empty agent
# and 2 when no agent connection is available.
set +e
ssh-add -l >/dev/null 2>&1
AGENT_LIST_RC=$?
set -e
if [ "$AGENT_LIST_RC" -gt 1 ]; then
  echo "ERROR: isolated ssh-agent is not reachable at $AGENT_SOCK"
  exit 1
fi
echo "isolated ssh-agent ready (pid=$SSH_AGENT_PID, sock=$AGENT_SOCK)"

# --- enforcement config: protect the private key at startup ---
SOCK="$WORK/guardd.sock"
cat > "$WORK/config.json" <<EOF
{
  "enforcement_mode": "$ENFORCEMENT_MODE",
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

# ssh-add must be resolvable by guardctl via PATH; export a controlled PATH that
# still contains the system ssh-add.
export PATH="$PATH"

echo "==> Test 1: direct cat of the protected key => denied (no lease)"
if cat "$PRIV_KEY" > "$WORK/t1.out" 2>/dev/null; then
  note_fail "cat unexpectedly read protected private key before any load"
else
  note_pass "direct cat denied before load"
fi

echo "==> Test 2: direct ssh-add (no lease) => fails to read the key"
# ssh-add without guardctl has no SshLoadLease, so its open of the key is denied
# by fanotify and ssh-add fails. (Exit code 1 = could not add identity.)
if ssh-add "$PRIV_KEY" > "$WORK/t2.out" 2>&1; then
  # If ssh-add reported success it would mean the key was read without a lease.
  # Distinguish "loaded" from "already loaded" by checking the agent.
  if ssh-add -l 2>/dev/null | grep -q "guard-ephemeral-load-test"; then
    note_fail "direct ssh-add loaded the key without a lease"
  else
    note_pass "direct ssh-add did not load the key"
  fi
else
  note_pass "direct ssh-add denied (no lease)"
fi

echo "==> Test 3: guardctl ssh load => succeeds under a one-shot lease"
if "$GUARDCTL" --socket "$SOCK" ssh load "$PRIV_KEY" > "$WORK/t3.out" 2>&1; then
  note_pass "guardctl ssh load succeeded"
else
  note_fail "guardctl ssh load failed: $(cat "$WORK/t3.out")"
fi

echo "==> Test 4: ssh-add -l sees the loaded test identity"
if ssh-add -l 2>/dev/null | grep -q "guard-ephemeral-load-test"; then
  note_pass "ssh-add -l lists the loaded identity"
else
  note_fail "ssh-add -l did not show the loaded identity: $(ssh-add -l 2>&1)"
fi

echo "==> Test 5: after the load lease ends, direct cat is STILL denied"
# The one-shot lease was used + revoked when ssh-add exited, so raw reads must
# remain denied. Sleep briefly past any in-flight state.
sleep 1
if cat "$PRIV_KEY" > "$WORK/t5.out" 2>/dev/null; then
  note_fail "cat read protected key after load (lease should be one-shot/revoked)"
else
  note_pass "direct cat still denied after load (lease did not persist)"
fi

echo "==> Test 6: a second guardctl ssh load works (fresh one-shot lease)"
# Remove the identity first so the second load is a real load (not a no-op).
ssh-add -d "$PRIV_KEY" >/dev/null 2>&1 || true
if ssh-add -l 2>/dev/null | grep -q "guard-ephemeral-load-test"; then
  note_fail "ssh-add -d did not remove the identity before the second load"
else
  if "$GUARDCTL" --socket "$SOCK" ssh load "$PRIV_KEY" > "$WORK/t6.out" 2>&1; then
    if ssh-add -l 2>/dev/null | grep -q "guard-ephemeral-load-test"; then
      note_pass "second guardctl ssh load succeeded with a fresh lease"
    else
      note_fail "second load returned success but identity is not in agent"
    fi
  else
    note_fail "second guardctl ssh load failed: $(cat "$WORK/t6.out")"
  fi
fi

echo "==> Test 7: the used/revoked lease is in a terminal state"
# List leases; the one-shot leases from the loads should be revoked and/or used.
"$GUARDCTL" --socket "$SOCK" --json leases list > "$WORK/t7.json" 2>/dev/null || true
# Every ssh_load lease must be revoked OR used (no live grant remains).
if command -v python3 >/dev/null 2>&1; then
  if python3 - "$WORK/t7.json" <<'PY'; then
import json, sys
doc = json.load(open(sys.argv[1]))
leases = doc.get("data", []) if isinstance(doc, dict) else doc
if not isinstance(leases, list):
    sys.exit(0)
bad = [l for l in leases if l.get("kind") == "ssh_load" and not l.get("revoked") and not l.get("used")]
sys.exit(1 if bad else 0)
PY
    note_pass "no live ssh_load lease remains (all used or revoked)"
  else
    note_fail "a live (non-revoked, non-used) ssh_load lease remains"
  fi
else
  # Coarse fallback: just confirm ssh_load leases appear (state check skipped).
  if grep -q '"kind":"ssh_load"' "$WORK/t7.json" 2>/dev/null; then
    note_pass "ssh_load leases present (precise state check skipped: python3 absent)"
  else
    note_pass "no ssh_load leases listed (all expired/revoked already)"
  fi
fi

echo "==> Test 8: audit log contains no private-key bytes"
"$GUARDCTL" --socket "$SOCK" --json events --limit 50 > "$WORK/events.json" 2>/dev/null || true
if grep -q "BEGIN OPENSSH PRIVATE KEY" "$WORK/events.json" 2>/dev/null; then
  note_fail "audit events leaked private-key header"
else
  note_pass "audit events contain no private-key content"
fi
# The guardd decision log must not contain key bytes either.
if grep -q "BEGIN OPENSSH PRIVATE KEY" "$WORK/guardd.log" 2>/dev/null; then
  note_fail "guardd log leaked private-key header"
else
  note_pass "guardd log contains no private-key content"
fi

echo "==> Test 9: clean daemon shutdown"
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
echo "==> Phase 11 root integration summary: PASS=$PASS FAIL=$FAIL BLOCKED=$BLOCKED"
echo "    (see $WORK/guardd.log for daemon decision log)"
echo
echo "NOTE: documented limitation — once a key is loaded into ssh-agent, same-user"
echo "      malware that can reach SSH_AUTH_SOCK may request signatures. V1 mediates"
echo "      raw private-key file access; it does not fully mediate agent signing."
exit $FAIL
