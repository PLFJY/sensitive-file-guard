#!/usr/bin/env bash
# Privileged Hardening Pass 1 acceptance: replacement inode, new profile, and
# new nested tree coverage. Uses synthetic files only; no real profile paths.
#
# Fixture writes go through an ENROLLED browser identity (a copy of
# guard-test-probe mapped as the chrome executable) because new protected-tree
# content is protected immediately: the harness's own shell is an unknown
# process and is correctly denied. Denial probes use a separate unenrolled copy.
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: run as root (fanotify FAN_OPEN_PERM requires CAP_SYS_ADMIN)"
  exit 2
fi

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d -t guard-hardening-XXXXXX)"
DAEMON_PID=""
cleanup() {
  if [ -n "$DAEMON_PID" ]; then
    kill "$DAEMON_PID" 2>/dev/null || true
    wait "$DAEMON_PID" 2>/dev/null || true
  fi
  rm -rf -- "$WORK"
}
trap cleanup EXIT

if [ -z "${SKIP_BUILD:-}" ]; then
cargo build --manifest-path "$REPO/Cargo.toml" -p guardd -p guard-test-probe
fi
BIN_DIR="${BIN_DIR:-$REPO/target/debug}"
GUARDD="${GUARDD:-$BIN_DIR/guardd}"
PROBE="${PROBE:-$BIN_DIR/guard-test-probe}"
IPC_HELPER="$REPO/scripts/helpers/ipc-request.py"
# Enrolled browser identity: fixture writes use this binary (matches the
# config exe_paths) so the browser can create new profile content after
# startup.
BROWSER_PROBE="$WORK/synthetic-chrome"
cp "$PROBE" "$BROWSER_PROBE"
chmod 0755 "$BROWSER_PROBE"
# Unenrolled probe copy used for denial assertions.
EVIL_PROBE="$WORK/evil-probe"
cp "$PROBE" "$EVIL_PROBE"
chmod 0755 "$EVIL_PROBE"

ROOT="$WORK/chromium"
PROFILE="$ROOT/Default"
mkdir -p "$PROFILE/Network" "$PROFILE/Local Storage"
printf '%s' 'synthetic-preferences' > "$PROFILE/Preferences"
printf '%s' 'synthetic-cookie-v1' > "$PROFILE/Network/Cookies"
printf '%s' 'synthetic-state' > "$ROOT/Local State"
SSH_KEY="$WORK/id_synthetic"
printf '%s' 'synthetic-ephemeral-key-fixture' > "$SSH_KEY"
chmod 0600 "$SSH_KEY"

cat > "$WORK/config.json" <<EOF
{"config_version":1,"enforcement_mode":"conservative","browsers":[{"id":"chrome","family":"Chromium","profile_root":"$ROOT","owner_uid":0,"exe_paths":["$BROWSER_PROBE"]}],"enrolled_exes":[],"ssh_keys":["$SSH_KEY"]}
EOF

"$GUARDD" --enforce-browser-config "$WORK/config.json" \
  --ipc-socket "$WORK/guardd.sock" --audit-db "$WORK/audit.db" \
  >"$WORK/guardd.log" 2>&1 &
DAEMON_PID=$!
for _ in $(seq 1 100); do
  [ -S "$WORK/guardd.sock" ] && break
  sleep 0.05
done
[ -S "$WORK/guardd.sock" ] || { cat "$WORK/guardd.log"; exit 1; }
# Let the startup marking pass and topology watcher settle before mutating.
sleep 0.5

expect_denied_eventually() {
  local path=$1
  for _ in $(seq 1 100); do
    if ! "$EVIL_PROBE" read "$path" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.02
  done
  echo "FAIL: path did not become protected: $path"
  cat "$WORK/guardd.log"
  return 1
}

IPC_SEQ=0
IPC_OUTPUT=""
ipc_request() {
  local operation="$1"
  IPC_SEQ=$((IPC_SEQ + 1))
  IPC_OUTPUT="$WORK/ipc-$IPC_SEQ.json"
  timeout 5s python3 "$IPC_HELPER" \
    --socket "$WORK/guardd.sock" --operation-json "$operation" \
    --output "$IPC_OUTPUT" --pid-file "$WORK/ipc-$IPC_SEQ.pid"
}

expect_ssh_read_blocked() {
  # SSH readers are deliberately held for confirmation, even when the reader
  # is untrusted. A headless gate must resolve that exact pending operation to
  # BLOCK; treating its intentional wait as an immediate denial would hang and
  # would not prove that no key bytes were returned.
  local path="$1"
  local output="$WORK/ssh-replacement.out"
  "$EVIL_PROBE" read "$path" >"$output" 2>/dev/null &
  local reader_pid=$!
  local pending_id=""
  for _ in $(seq 1 50); do
    ipc_request '{"kind":"ssh_pending_list"}' || break
    pending_id="$(python3 - "$IPC_OUTPUT" "$reader_pid" <<'PY'
import json, sys
document = json.load(open(sys.argv[1], encoding="utf-8"))
body = document.get("body") or {}
items = body.get("data", []) if body.get("kind") == "ssh_pending" else []
pid = int(sys.argv[2])
print(next((item["id"] for item in items if item.get("pid") == pid), ""))
PY
)"
    [ -n "$pending_id" ] && break
    sleep 0.1
  done
  if [ -z "$pending_id" ]; then
    echo "FAIL: replacement SSH read did not enter the pending queue"
    kill -TERM "$reader_pid" 2>/dev/null || true
    wait "$reader_pid" 2>/dev/null || true
    return 1
  fi
  if ! ipc_request "{\"kind\":\"ssh_read_resolve\",\"id\":\"$pending_id\",\"action\":\"block\"}"; then
    echo "FAIL: replacement SSH read could not be explicitly blocked"
    kill -TERM "$reader_pid" 2>/dev/null || true
    wait "$reader_pid" 2>/dev/null || true
    return 1
  fi
  set +e
  wait "$reader_pid"
  local status=$?
  set -e
  if [ "$status" -ne 0 ] && [ ! -s "$output" ]; then
    return 0
  fi
  echo "FAIL: replacement SSH read returned data or was not denied"
  return 1
}

# New inode at an already-protected critical path. The enrolled browser
# replaces its own Cookies file; the unknown probe must still be denied.
rm -f "$PROFILE/Network/Cookies"
"$BROWSER_PROBE" write-file "$PROFILE/Network/Cookies" 'synthetic-cookie-v2'
expect_denied_eventually "$PROFILE/Network/Cookies"

# Directory created after startup below a protected tree.
mkdir -p "$PROFILE/Local Storage/new/nested"
"$BROWSER_PROBE" write-file "$PROFILE/Local Storage/new/nested/item" 'synthetic-session'
expect_denied_eventually "$PROFILE/Local Storage/new/nested/item"

# Entire profile created after startup.
NEW_PROFILE="$ROOT/Profile 2"
mkdir -p "$NEW_PROFILE/Network"
"$BROWSER_PROBE" write-file "$NEW_PROFILE/Preferences" 'synthetic-preferences'
"$BROWSER_PROBE" write-file "$NEW_PROFILE/Network/Cookies" 'synthetic-cookie-v3'
expect_denied_eventually "$NEW_PROFILE/Network/Cookies"

# Configured SSH key replaced with a new inode. SSH reads are gated by the
# exact-reader confirmation model (no lease is granted to any probe here), so
# the unknown probe must remain denied after the replacement.
rm -f "$SSH_KEY"
SSH_REPLACEMENT="$WORK/id_synthetic.replacement"
printf '%s' 'synthetic-ephemeral-key-fixture-v2' > "$SSH_REPLACEMENT"
chmod 0600 "$SSH_REPLACEMENT"
# The shell is an unknown reader/writer after enforcement starts, so creating
# directly at the protected pathname must be denied. Model a legitimate
# atomic key-file replacement without asking the firewall to allow that open.
mv -f "$SSH_REPLACEMENT" "$SSH_KEY"
expect_ssh_read_blocked "$SSH_KEY"

echo "PASS: browser replacements converge to denial; SSH replacement remains protected"
