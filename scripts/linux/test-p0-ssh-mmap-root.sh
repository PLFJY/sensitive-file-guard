#!/usr/bin/env bash
# scripts/linux/test-p0-ssh-mmap-root.sh
#
# P0 (security review): SSH private-key authorization boundary.
#
# Attack: unknown same-UID malware -> open("~/.ssh/id_ed25519", O_RDONLY) ->
# FAN_OPEN_PERM previously ALLOWED (mediation deferred to FAN_ACCESS_PERM) ->
# mmap(PROT_READ) bypasses FAN_ACCESS_PERM (kernel v7.1 `fsnotify_mmap_perm()`
# emits only pre-content/HSM events, never a content-group access-perm event)
# -> private-key bytes read without any Guard interception.
#
# Fix under test: OPEN_PERM is now the SSH authorization boundary. The key is
# marked `FAN_OPEN_PERM | FAN_ACCESS_PERM`; an unauthorized open is DENIED
# before any readable fd exists, so mmap / read / splice / sendfile /
# copy_file_range / io_uring reads (all require a readable fd) cannot acquire
# the bytes.
#
# Requires a dedicated non-root filesystem (capsule tmpfs instance or host
# isolated fs). AGENTS.md: never mark the root mount.
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then echo "ERROR: run as root"; exit 2; fi
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN_DIR="${BIN_DIR:-$REPO/target/release}"
GUARDD="${GUARDD:-$BIN_DIR/guardd}"
GUARDCTL="${GUARDCTL:-$BIN_DIR/guardctl}"
PROBE="${PROBE:-$BIN_DIR/guard-test-probe}"

PASS=0; FAIL=0; BLOCKED=0
note_pass() { echo "PASS: $1"; PASS=$((PASS + 1)); }
note_fail() { echo "FAIL: $1"; FAIL=$((FAIL + 1)); }
note_blocked() { echo "BLOCKED: $1"; BLOCKED=$((BLOCKED + 1)); }

if [ -z "${TEST_FS_ROOT:-}" ]; then
  echo "BLOCKED: TEST_FS_ROOT required (isolated fs for the strict mark; a capsule tmpfs instance or host loop/ext4)"
  exit 2
fi
# AGENTS.md: never mark the root mount of THIS namespace.
if [ "$(stat -c %d "$TEST_FS_ROOT")" = "$(stat -c %d /)" ]; then
  echo "BLOCKED: TEST_FS_ROOT=$TEST_FS_ROOT is on the root mount of this namespace"
  exit 2
fi
for bin in "$GUARDD" "$GUARDCTL" "$PROBE"; do
  test -x "$bin" || { echo "ERROR: missing $bin"; exit 2; }
done

WORK="$TEST_FS_ROOT/p0-ssh-$$"
mkdir -p "$WORK/ssh" "$WORK/profile/Default"
if [ -n "${PRESET_SSH_KEY:-}" ]; then
  cp -f "$PRESET_SSH_KEY" "$WORK/ssh/id_ed25519"
  cp -f "$PRESET_SSH_KEY.pub" "$WORK/ssh/id_ed25519.pub"
else
  ssh-keygen -t ed25519 -N "" -f "$WORK/ssh/id_ed25519" >/dev/null 2>&1 \
    || { echo "BLOCKED: ssh-keygen unavailable and PRESET_SSH_KEY unset"; exit 2; }
fi
printf '{}' > "$WORK/profile/Default/Preferences"
printf '{}' > "$WORK/profile/Local State"

cat > "$WORK/config.json" <<EOF
{
  "config_version": 1,
  "enforcement_mode": "strict-filesystem",
  "browsers": [
    {
      "id": "synthetic-chromium",
      "family": "Chromium",
      "profile_root": "$WORK/profile",
      "owner_uid": 0,
      "exe_paths": []
    }
  ],
  "enrolled_exes": [],
  "ssh_keys": ["$WORK/ssh/id_ed25519"]
}
EOF

DAEMON_PID=""
cleanup() {
  if [ -n "$DAEMON_PID" ] && kill -0 "$DAEMON_PID" 2>/dev/null; then
    kill -TERM "$DAEMON_PID" 2>/dev/null || true
    wait "$DAEMON_PID" 2>/dev/null || true
  fi
  rm -rf -- "$WORK"
}
trap cleanup EXIT

"$GUARDD" --enforce-browser-config "$WORK/config.json" \
  --ipc-socket "$WORK/guardd.sock" --audit-db "$WORK/audit.db" \
  >"$WORK/guardd.log" 2>&1 &
DAEMON_PID=$!
for _ in $(seq 1 200); do
  [ -S "$WORK/guardd.sock" ] && "$GUARDCTL" --socket "$WORK/guardd.sock" --json status \
    >"$WORK/status.json" 2>/dev/null && break
  kill -0 "$DAEMON_PID" 2>/dev/null || { echo "guardd exited"; sed -n '1,120p' "$WORK/guardd.log"; exit 1; }
  sleep 0.05
done
[ -S "$WORK/guardd.sock" ] || { echo "guardd not ready"; exit 1; }

echo "==> P0: unknown process must NOT obtain a readable fd on the private key"
if "$PROBE" mmap "$WORK/ssh/id_ed25519" >/dev/null 2>&1; then
  note_fail "mmap of the private key succeeded (readable fd was granted)"
else
  note_pass "mmap denied at open (no readable fd granted)"
fi

if "$PROBE" read "$WORK/ssh/id_ed25519" >/dev/null 2>&1; then
  note_fail "plain read of the private key succeeded"
else
  note_pass "plain read denied at open"
fi

echo "==> audit records an SSH open denial with Guard attribution"
if "$GUARDCTL" --socket "$WORK/guardd.sock" --json events --limit 10 2>/dev/null \
  | grep -qE '"decision": "Deny'; then
  note_pass "audit records the denied SSH open"
else
  note_fail "no SSH denial in audit"
fi

kill -TERM "$DAEMON_PID"
wait "$DAEMON_PID" 2>/dev/null || true
DAEMON_PID=""

echo
echo "==> P0 SSH mmap summary: PASS=$PASS FAIL=$FAIL BLOCKED=$BLOCKED"
if [ "$FAIL" -gt 0 ]; then exit 1; elif [ "$BLOCKED" -gt 0 ]; then exit 2; else exit 0; fi
