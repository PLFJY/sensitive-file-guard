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
printf '%s' 'synthetic-ephemeral-key-fixture-v2' > "$SSH_KEY"
chmod 0600 "$SSH_KEY"
expect_denied_eventually "$SSH_KEY"

echo "PASS: browser replacements converge to denial; SSH replacement remains protected"
