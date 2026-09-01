#!/usr/bin/env bash
# Privileged Hardening Pass 1 acceptance: replacement inode, new profile, and
# new nested tree coverage. Uses synthetic files only; no real profile paths.
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

GUARDD="$REPO/target/debug/guardd"
PROBE="$REPO/target/debug/guard-test-probe"
echo "==> Checking pre-built debug binaries"
# Build as the normal user before entering this root-only gate. The test must
# never populate root's Cargo home or produce root-owned build artifacts.
for artifact in "$GUARDD" "$PROBE"; do
  [ -x "$artifact" ] || {
    echo "ERROR: missing $artifact; build it as the normal user first"
    exit 2
  }
done
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
{"browser_protection_level":"strict","browsers":[{"id":"chrome","family":"Chromium","profile_root":"$ROOT","owner_uid":0,"exe_paths":[]}],"enrolled_exes":[],"ssh_keys":["$SSH_KEY"]}
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

expect_denied_eventually() {
  local path=$1
  for _ in $(seq 1 100); do
    if ! "$PROBE" read "$path" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.02
  done
  echo "FAIL: path did not become protected: $path"
  cat "$WORK/guardd.log"
  return 1
}

expect_allowed_eventually() {
  local path=$1
  for _ in $(seq 1 100); do
    if "$PROBE" read "$path" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.02
  done
  echo "FAIL: SSH behavioral read remained interrupted: $path"
  cat "$WORK/guardd.log"
  return 1
}

# New inode at an already-protected critical path.
rm -f -- "$PROFILE/Network/Cookies"
printf '%s' 'synthetic-cookie-v2' > "$PROFILE/Network/Cookies"
expect_denied_eventually "$PROFILE/Network/Cookies"

# Directory created after startup below a protected tree.
mkdir -p "$PROFILE/Local Storage/new/nested"
printf '%s' 'synthetic-web-auth-storage' > "$PROFILE/Local Storage/new/nested/item"
expect_denied_eventually "$PROFILE/Local Storage/new/nested/item"

# Entire profile created after startup.
NEW_PROFILE="$ROOT/Profile 2"
mkdir -p "$NEW_PROFILE/Network"
printf '%s' 'synthetic-preferences' > "$NEW_PROFILE/Preferences"
printf '%s' 'synthetic-cookie-v3' > "$NEW_PROFILE/Network/Cookies"
expect_denied_eventually "$NEW_PROFILE/Network/Cookies"

# Configured SSH key replaced with a new inode.
rm -f -- "$SSH_KEY"
printf '%s' 'synthetic-ephemeral-key-fixture-v2' > "$SSH_KEY"
chmod 0600 "$SSH_KEY"
expect_allowed_eventually "$SSH_KEY"

echo "PASS: browser replacements converge to denial; SSH replacement read remains allowed"
