#!/usr/bin/env bash
# scripts/test-agent-compat-root.sh
#
# Phase 12 privileged integration test for AI/coding-agent compatibility.
#
# RUN AS ROOT:   sudo bash scripts/test-agent-compat-root.sh
#
# Why root: fanotify permission-event enforcement (FAN_CLASS_CONTENT) requires
# CAP_SYS_ADMIN. The non-interactive build agent cannot obtain it, so the
# privileged tests are provided here for a human to run.
#
# This script demonstrates that an ordinary coding agent (simulated by
# `guard-test-probe`, a generic read/open child process) does not require
# secret-file exemptions:
#   - agent reads normal project files  => unaffected
#   - agent reads browser fixture       => DENY
#   - agent reads SSH test key          => DENY
#   - guardctl explain --json           => stable reason_code
#   - git on a local temp repo          => unaffected
#
# It uses ONLY synthetic fixtures + an ephemeral ssh-keygen keypair. It contains
# NO network exfiltration code. It does not touch any real browser profile or
# real SSH key.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_DIR="${BIN_DIR:-$REPO/target/release}"
GUARDD="${GUARDD:-$BIN_DIR/guardd}"
GUARDCTL="${GUARDCTL:-$BIN_DIR/guardctl}"
PROBE="${PROBE:-$BIN_DIR/guard-test-probe}"

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

if [ -z "${SKIP_BUILD:-}" ]; then
  echo "==> Building release binaries"
  cd "$REPO"
  cargo build --release 2>&1 | grep -E '(Compiling guardd|Compiling guardctl|Compiling guard-test-probe|Finished|error)' || true
fi
test -x "$GUARDD"   || { echo "guardd binary missing"; exit 1; }
test -x "$GUARDCTL" || { echo "guardctl binary missing"; exit 1; }
test -x "$PROBE"    || { echo "guard-test-probe binary missing"; exit 1; }

WORK="$(mktemp -d -t guard-agent-compat-XXXXXX)"
GUARDD_PID=""
cleanup() {
  if [ -n "${GUARDD_PID:-}" ] && kill -0 "$GUARDD_PID" 2>/dev/null; then
    kill -TERM "$GUARDD_PID" 2>/dev/null || true
    wait "$GUARDD_PID" 2>/dev/null || true
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

# --- synthetic Chromium user_data_dir (Default profile) ---
CHROME_UDD="$WORK/chrome-udd"
mkdir -p "$CHROME_UDD/Default/Network"
printf 'GUARD_SYNTHETIC_COOKIE_FIXTURE' > "$CHROME_UDD/Default/Network/Cookies"
printf 'GUARD_SYNTHETIC_LOGIN_FIXTURE'  > "$CHROME_UDD/Default/Login Data"

# --- ephemeral SSH test keypair (NOT the dev's real key) ---
SSH_DIR="$WORK/ssh"
mkdir -p "$SSH_DIR"
chmod 0700 "$SSH_DIR"
ssh-keygen -t ed25519 -N "" -C "guard-agent-compat-test" -f "$SSH_DIR/id_ed25519" >/dev/null
chmod 0600 "$SSH_DIR/id_ed25519"
PRIV_KEY="$SSH_DIR/id_ed25519"

# --- a normal project file the agent should be able to read/edit ---
PROJECT_DIR="$WORK/project"
mkdir -p "$PROJECT_DIR/src"
printf 'fn main() { println!("hello"); }\n' > "$PROJECT_DIR/src/main.rs"
printf '# Project\n\nNormal files an agent edits.\n' > "$PROJECT_DIR/README.md"

# --- enforcement config: protect the browser profile + SSH key ---
SOCK="$WORK/guardd.sock"
cat > "$WORK/config.json" <<EOF
{
  "config_version": 1,
  "enforcement_mode": "conservative",
  "browsers": [
    {
      "id": "chrome",
      "family": "chromium",
      "profile_root": "$CHROME_UDD",
      "owner_uid": 0,
      "exe_paths": []
    }
  ],
  "enrolled_exes": [],
  "ssh_keys": ["$PRIV_KEY"]
}
EOF

echo "==> Starting guardd enforcement (browser + SSH)"
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

# ===========================================================================
# Test 1: agent reads a normal project file => unaffected (succeeds)
# ===========================================================================
echo "==> Test 1: agent reads normal project file => succeeds"
if "$PROBE" read "$PROJECT_DIR/src/main.rs" > "$WORK/t1.out" 2>&1; then
  if grep -q 'println!("hello")' "$WORK/t1.out"; then
    note_pass "agent read normal project file"
  else
    note_fail "agent read project file but content mismatch: $(cat "$WORK/t1.out")"
  fi
else
  note_fail "agent could not read normal project file: $(cat "$WORK/t1.out")"
fi

# ===========================================================================
# Test 2: agent edits (writes) a normal project file => unaffected
# ===========================================================================
echo "==> Test 2: agent writes normal project file => succeeds"
if printf 'fn main() { println!("edited by agent"); }\n' > "$PROJECT_DIR/src/main.rs" 2>/dev/null; then
  note_pass "agent wrote normal project file"
else
  note_fail "agent could not write normal project file"
fi

# ===========================================================================
# Test 3: agent reads browser fixture => DENY
# ===========================================================================
echo "==> Test 3: agent reads browser cookie fixture => denied"
if "$PROBE" read "$CHROME_UDD/Default/Network/Cookies" > "$WORK/t3.out" 2>&1; then
  note_fail "agent unexpectedly read browser cookie fixture"
else
  note_pass "agent denied reading browser cookie fixture"
fi

# ===========================================================================
# Test 4: agent reads SSH test key => gated by exact-reader confirmation
# ===========================================================================
# No SSH-read lease has been granted to this probe, so the read must fail
# closed (RequireSshKeyConfirmation with no approval in a headless harness).
echo "==> Test 4: agent reads SSH test key => denied without a lease"
if "$PROBE" read "$PRIV_KEY" > "$WORK/t4.out" 2>&1; then
  note_fail "agent SSH-key read succeeded without an exact-reader lease"
else
  note_pass "agent SSH-key read denied without an exact-reader lease"
fi

# ===========================================================================
# Test 5: guardctl explain --json explains a denial with a stable reason_code
# ===========================================================================
echo "==> Test 5: guardctl explain --json shows stable reason_code"
# Grab the most recent event id.
"$GUARDCTL" --socket "$SOCK" --json events --limit 5 > "$WORK/events.json" 2>/dev/null || true
EVENT_ID=""
if command -v python3 >/dev/null 2>&1; then
  EVENT_ID="$(python3 - "$WORK/events.json" <<'PY' || true
import json, sys
try:
    doc = json.load(open(sys.argv[1]))
    events = doc.get("data", []) if isinstance(doc, dict) else doc
    if isinstance(events, list) and events:
        print(events[0]["id"])
except Exception:
    pass
PY
)"
fi
# Fallback: parse with grep/sed if python3 is absent or returned nothing.
if [ -z "$EVENT_ID" ]; then
  EVENT_ID="$(grep -o '"id":[0-9]*' "$WORK/events.json" | head -n1 | grep -o '[0-9]*' || true)"
fi

if [ -n "$EVENT_ID" ]; then
  "$GUARDCTL" --socket "$SOCK" --json explain "$EVENT_ID" > "$WORK/explain.json" 2>/dev/null || true
  # Parse the pretty-printed JSON structurally; whitespace is not part of the
  # protocol and must not make the acceptance test report a false failure.
  CODE="$(python3 - "$WORK/explain.json" <<'PY' || true
import json, sys
doc = json.load(open(sys.argv[1], encoding="utf-8"))
data = doc.get("data", doc) if isinstance(doc, dict) else {}
if isinstance(data, dict):
    print(data.get("reason_code") or "")
PY
)"
  if [ -n "$CODE" ]; then
    note_pass "guardctl explain --json has reason_code=$CODE"
  else
    note_fail "guardctl explain --json missing/empty reason_code: $(cat "$WORK/explain.json")"
  fi
  # Also verify resource_kind_code is present.
  if grep -q '"resource_kind_code"' "$WORK/explain.json" 2>/dev/null; then
    note_pass "guardctl explain --json has resource_kind_code"
  else
    note_fail "guardctl explain --json missing resource_kind_code field"
  fi
else
  note_fail "could not find any event id to explain"
fi

# ===========================================================================
# Test 6: git operation on a local temp repo remains functional
# ===========================================================================
echo "==> Test 6: git on a local temp repo => unaffected"
GIT_REPO="$WORK/git-repo"
mkdir -p "$GIT_REPO"
cd "$GIT_REPO"
git init -q 2>/dev/null || true
git config user.email "agent@test.local" 2>/dev/null || true
git config user.name "agent" 2>/dev/null || true
printf '# Repo\n\nAgent edits here.\n' > "$GIT_REPO/README.md"
git add README.md 2>/dev/null
if git commit -q -m "agent commit" 2>/dev/null; then
  note_pass "git init + add + commit succeeded"
else
  note_fail "git operation failed (guardd should not interfere with ordinary repos)"
fi
cd "$REPO"

# ===========================================================================
# Test 7: audit log + explain JSON contain no secret contents
# ===========================================================================
echo "==> Test 7: no secret contents in audit/explain output"
if grep -q "GUARD_SYNTHETIC_COOKIE_FIXTURE" "$WORK/explain.json" 2>/dev/null \
  || grep -q "GUARD_SYNTHETIC_COOKIE_FIXTURE" "$WORK/events.json" 2>/dev/null \
  || grep -q "BEGIN OPENSSH PRIVATE KEY" "$WORK/explain.json" 2>/dev/null \
  || grep -q "BEGIN OPENSSH PRIVATE KEY" "$WORK/guardd.log" 2>/dev/null; then
  note_fail "secret content leaked into audit/explain/log output"
else
  note_pass "no secret contents in audit/explain/log output"
fi

# ===========================================================================
# Test 8: clean daemon shutdown
# ===========================================================================
echo "==> Test 8: clean daemon shutdown"
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
echo "==> Phase 12 root integration summary: PASS=$PASS FAIL=$FAIL BLOCKED=$BLOCKED"
echo "    (see $WORK/guardd.log for daemon decision log)"
echo
echo "NOTE: filesystem denial uses ordinary EPERM/EACCES from the OS. guardd does NOT"
echo "      inject custom text into open(2) errors. Tools use 'guardctl explain --json'"
echo "      + the stable 'reason_code' field to understand denials."
exit $FAIL
