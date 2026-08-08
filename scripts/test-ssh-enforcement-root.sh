#!/usr/bin/env bash
# scripts/test-ssh-enforcement-root.sh
#
# Phase 10 privileged integration test for SSH private-key protection.
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

echo "==> Building release binaries"
cd "$REPO"
cargo build --release 2>&1 | grep -E '(Compiling guardd|Compiling guardctl|Compiling guard-test-probe|Finished|error)' || true
test -x "$GUARDD" || { echo "guardd binary missing"; exit 1; }
test -x "$GUARDCTL" || { echo "guardctl binary missing"; exit 1; }
test -x "$PROBE" || { echo "guard-test-probe binary missing"; exit 1; }

WORK="$(mktemp -d -t guard-ssh-enforce-XXXXXX)"
cleanup() {
  if [ -n "${GUARDD_PID:-}" ] && kill -0 "$GUARDD_PID" 2>/dev/null; then
    kill -TERM "$GUARDD_PID" 2>/dev/null || true
    wait "$GUARDD_PID" 2>/dev/null || true
  fi
  rm -rf "$WORK"
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

echo "==> Test 1: cat the protected private key => denied"
if cat "$PRIV_KEY" > "$WORK/t1.out" 2>/dev/null; then
  note_fail "cat unexpectedly read protected private key"
else
  note_pass "cat denied before open completed"
fi

echo "==> Test 2: cp the protected private key => denied (source open fails)"
if cp "$PRIV_KEY" "$WORK/t2.copy" 2>/dev/null; then
  note_fail "cp unexpectedly copied protected private key"
  rm -f "$WORK/t2.copy"
else
  note_pass "cp denied because source open failed"
fi

echo "==> Test 3: guard-test-probe (Rust child) reads the protected key => denied"
if "$PROBE" read "$PRIV_KEY" > "$WORK/t3.out" 2>/dev/null; then
  note_fail "guard-test-probe unexpectedly read protected private key"
else
  note_pass "Rust child probe denied"
fi

echo "==> Test 4: Python reads the protected key => denied (if python3 available)"
if command -v python3 >/dev/null 2>&1; then
  if python3 -c "import sys; open(sys.argv[1]).read()" "$PRIV_KEY" 2>/dev/null; then
    note_fail "python3 unexpectedly read protected private key"
  else
    note_pass "Python child probe denied"
  fi
else
  note_blocked "python3 not available for probe test"
fi

echo "==> Test 5: shell script (sh -c cat) reads the protected key => denied"
if sh -c "cat '$PRIV_KEY'" > "$WORK/t5.out" 2>/dev/null; then
  note_fail "sh -c cat unexpectedly read protected private key"
else
  note_pass "shell script probe denied"
fi

echo "==> Test 6: public key remains readable (not protected)"
if cat "$PUB_KEY" > "$WORK/t6.out" 2>/dev/null; then
  if [ -s "$WORK/t6.out" ]; then
    note_pass "public key remains readable"
  else
    note_fail "public key read but empty"
  fi
else
  note_fail "public key was blocked (over-blocking)"
fi

echo "==> Test 7: unrelated files under .ssh remain readable (config, known_hosts, notes)"
for f in "$CONFIG_FILE" "$KNOWN_HOSTS" "$NOTES"; do
  if cat "$f" > /dev/null 2>/dev/null; then
    note_pass "$(basename "$f") remains readable"
  else
    note_fail "$(basename "$f") was blocked (over-blocking)"
  fi
done

echo "==> Test 8: hardlink to protected private key => denied by inode mark"
ln -f "$PRIV_KEY" "$WORK/hard-to-key" 2>/dev/null || {
  note_blocked "hardlink creation not supported on this filesystem ($WORK)"
}
if [ -e "$WORK/hard-to-key" ]; then
  if cat "$WORK/hard-to-key" > "$WORK/t8.out" 2>/dev/null; then
    note_fail "cat read protected key via hardlink"
  else
    note_pass "hardlink to protected key denied (inode mark + fd_index)"
  fi
fi

echo "==> Test 9: symlink to protected private key => denied"
ln -sf "$PRIV_KEY" "$WORK/sym-to-key"
if cat "$WORK/sym-to-key" > "$WORK/t9.out" 2>/dev/null; then
  note_fail "cat read protected key via symlink"
else
  note_pass "symlink to protected key denied"
fi

echo "==> Test 10: runtime guardctl ssh protect on a NEW key => protects it"
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
# After protection: denied.
if cat "$RUNTIME_KEY" > "$WORK/t10b.out" 2>/dev/null; then
  note_fail "runtime key readable AFTER guardctl ssh protect"
else
  note_pass "runtime key denied after guardctl ssh protect"
fi

echo "==> Test 11: guardctl ssh protect rejects .pub file"
if "$GUARDCTL" --socket "$SOCK" ssh protect "$PUB_KEY" > "$WORK/t11.out" 2>&1; then
  note_fail "guardctl ssh protect accepted .pub file"
else
  note_pass "guardctl ssh protect rejected .pub file"
fi

echo "==> Test 12: guardctl ssh suggest lists conventional candidates"
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

echo "==> Test 13: protected key audit log has no key contents"
# Query events from the daemon; the audit JSON must not contain the private key
# header or any key bytes.
"$GUARDCTL" --socket "$SOCK" --json events --limit 20 > "$WORK/events.json" 2>/dev/null || true
if grep -q "BEGIN OPENSSH PRIVATE KEY" "$WORK/events.json" 2>/dev/null; then
  note_fail "audit events leaked private-key header"
else
  note_pass "audit events contain no private-key content"
fi

echo "==> Test 14: clean daemon shutdown"
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
echo "==> Phase 10 root integration summary: PASS=$PASS FAIL=$FAIL BLOCKED=$BLOCKED"
echo "    (see $WORK/guardd.log for daemon decision log)"
echo
echo "NOTE: rename gap — fanotify marks are inode-based; renaming a protected"
echo "      key moves the SAME inode so protection follows the rename. A key"
echo "      re-created at the original path after deletion is NOT protected until"
echo "      re-enrolled (documented in reports/phase-10.md)."
exit $FAIL
