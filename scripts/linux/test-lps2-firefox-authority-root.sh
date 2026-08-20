#!/usr/bin/env bash
# LPS2 metadata-only authority evidence. This intentionally runs guardd from a
# normal-user-built debug artifact because release audit persistence omits ALLOW
# records. It uses conservative marks and a disposable Firefox profile only.
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "BLOCKED: run through the capsule or explicitly authorized polkit host fallback"
  exit 2
fi

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN_DIR="${BIN_DIR:-$REPO/target/debug}"
GUARDD="${GUARDD:-$BIN_DIR/guardd}"
GUARDCTL="${GUARDCTL:-$BIN_DIR/guardctl}"
FIREFOX="${FIREFOX:-/usr/lib/firefox/firefox}"
TEST_USER="${TEST_USER:-${SUDO_USER:-${PKEXEC_UID:-}}}"
EVIDENCE_ROOT="${EVIDENCE_ROOT:-}"
PROCESS_SHIELD_ENABLED="${PROCESS_SHIELD_ENABLED:-false}"

for artifact in "$GUARDD" "$GUARDCTL" "$FIREFOX"; do
  [ -x "$artifact" ] || { echo "BLOCKED: required artifact unavailable: $artifact"; exit 2; }
done
if [ -z "$TEST_USER" ] || ! id -u "$TEST_USER" >/dev/null 2>&1; then
  echo "BLOCKED: TEST_USER/SUDO_USER/PKEXEC_UID must name a non-root local user"
  exit 2
fi
TEST_USER="$(getent passwd "$TEST_USER" | awk -F: 'NR == 1 { print $1 }')"
[ -n "$TEST_USER" ] || { echo "BLOCKED: test UID has no local passwd entry"; exit 2; }
TEST_UID="$(id -u "$TEST_USER")"
TEST_GID="$(id -g "$TEST_USER")"
if [ "$TEST_UID" -eq 0 ]; then echo "BLOCKED: Firefox test user must not be root"; exit 2; fi
case "$PROCESS_SHIELD_ENABLED" in true|false) ;; *) echo "BLOCKED: PROCESS_SHIELD_ENABLED must be true or false"; exit 2;; esac

WORK="$(mktemp -d /tmp/sfg-lps2-firefox.XXXXXX)"
PROFILE="$WORK/profile"
SOCK="$WORK/guardd.sock"
AUDIT_DB="$WORK/audit.db"
DAEMON_PID=""
BROWSER_PID=""
cleanup() {
  if [ -n "$BROWSER_PID" ] && kill -0 "$BROWSER_PID" 2>/dev/null; then kill -TERM "$BROWSER_PID" 2>/dev/null || true; fi
  # Firefox may fork descendants after runuser exits; the disposable profile
  # pathname is the exact fixture scope, never a real user profile.
  pkill -u "$TEST_USER" -f "$PROFILE" 2>/dev/null || true
  if [ -n "$DAEMON_PID" ] && kill -0 "$DAEMON_PID" 2>/dev/null; then kill -TERM "$DAEMON_PID" 2>/dev/null || true; fi
  wait "${BROWSER_PID:-}" 2>/dev/null || true
  wait "${DAEMON_PID:-}" 2>/dev/null || true
  rm -rf -- "$WORK"
}
trap cleanup EXIT

run_as_user() { runuser -u "$TEST_USER" -- "$@"; }
mkdir -p "$PROFILE"
chown -R "$TEST_UID:$TEST_GID" "$WORK"

# Populate only the disposable profile before guarding it. This creates the
# Firefox database structure but never supplies a cookie/login/session value.
run_as_user "$FIREFOX" --headless --no-remote --profile "$PROFILE" about:blank >"$WORK/populate.log" 2>&1 &
populate_pid=$!
for _ in $(seq 1 120); do [ -f "$PROFILE/cookies.sqlite" ] && break; sleep 0.25; done
kill -TERM "$populate_pid" 2>/dev/null || true
wait "$populate_pid" 2>/dev/null || true
[ -f "$PROFILE/cookies.sqlite" ] || { echo "FAIL: Firefox did not create disposable cookies.sqlite"; exit 1; }

cat > "$WORK/config.json" <<EOF
{
  "config_version": 1,
  "enforcement_mode": "conservative",
  "browsers": [{
    "id": "firefox-lps2", "family": "Firefox",
    "profile_root": "$PROFILE", "owner_uid": $TEST_UID,
    "exe_paths": ["$FIREFOX"]
  }],
  "enrolled_exes": ["$FIREFOX"],
  "ssh_keys": [],
  "process_shield_enabled": $PROCESS_SHIELD_ENABLED
}
EOF

"$GUARDD" --enforce-browser-config "$WORK/config.json" --ipc-socket "$SOCK" \
  --audit-db "$AUDIT_DB" --print-decisions >"$WORK/guardd.log" 2>&1 &
DAEMON_PID=$!
for _ in $(seq 1 160); do
  [ -S "$SOCK" ] && "$GUARDCTL" --socket "$SOCK" --json status >"$WORK/status.json" 2>/dev/null && break
  kill -0 "$DAEMON_PID" 2>/dev/null || { sed -n '1,120p' "$WORK/guardd.log"; echo "FAIL: guardd exited"; exit 1; }
  sleep 0.05
done
grep -q '"enforcement_active"[[:space:]]*:[[:space:]]*true' "$WORK/status.json" || { echo "FAIL: guardd did not become ACTIVE"; exit 1; }

# Keep Firefox alive while querying its true File Shield ALLOW events.
run_as_user "$FIREFOX" --headless --no-remote --profile "$PROFILE" about:blank >"$WORK/firefox.log" 2>&1 &
BROWSER_PID=$!
for _ in $(seq 1 160); do
  [ -f "$AUDIT_DB" ] && python3 - "$AUDIT_DB" <<'PY' >/dev/null 2>&1 && break
import sqlite3, sys
conn = sqlite3.connect(sys.argv[1])
raise SystemExit(0 if conn.execute("SELECT count(*) FROM events WHERE decision='allow'").fetchone()[0] else 1)
PY
  kill -0 "$BROWSER_PID" 2>/dev/null || break
  sleep 0.1
done

MATRIX="$WORK/matrix.json"
python3 - "$AUDIT_DB" "$TEST_UID" "$MATRIX" <<'PY'
import json, os, sqlite3, sys

database, uid, output = sys.argv[1], int(sys.argv[2]), sys.argv[3]
conn = sqlite3.connect(database)
rows = conn.execute("""
 SELECT pid,start_time,exe,resource_kind,path,parent_pid,parent_exe,decision
 FROM events WHERE uid=? AND decision='allow' ORDER BY id
""", (uid,)).fetchall()

def stat_fields(pid):
    text = open(f"/proc/{pid}/stat", encoding="utf-8").read()
    after = text.rsplit(")", 1)[1].split()
    return int(after[1]), int(after[19]) # ppid, starttime (fields 4, 22)

def role(argv):
    value = " ".join(argv)
    if "-contentproc" in value: return "Renderer"
    if "-gpu" in value: return "GPU"
    if "-utility" in value: return "Utility"
    if "-extension" in value: return "Extension"
    return "Main" if "firefox" in value else "Other"

accepted = []
seen = set()
for pid, start, exe, resource, path, parent_pid, parent_exe, decision in rows:
    key = (pid, start, exe, resource)
    if key in seen: continue
    seen.add(key)
    try:
        current_ppid, current_start = stat_fields(pid)
        if current_start != start: continue # exited or PID reuse: never infer authority
        argv = [part.decode("utf-8", "replace") for part in open(f"/proc/{pid}/cmdline", "rb").read().split(b"\0") if part]
        exe_stat = os.stat(f"/proc/{pid}/exe")
        pidfd = os.pidfd_open(pid)
        try:
            fdinfo = open(f"/proc/self/fdinfo/{pidfd}", encoding="utf-8").read()
            pidfd_matches = f"Pid:\t{pid}\n" in fdinfo or f"Pid:\t{pid}" in fdinfo
        finally:
            os.close(pidfd)
        ancestry = []
        ancestor = current_ppid
        for _ in range(8):
            if ancestor <= 1: break
            parent, parent_start = stat_fields(ancestor)
            ancestry.append({"pid": ancestor, "start_time": parent_start,
                             "exe": os.readlink(f"/proc/{ancestor}/exe")})
            ancestor = parent
        accepted.append({
            "pid": pid, "start_time": start, "pidfd_matches": pidfd_matches,
            "exe": exe, "exe_dev": exe_stat.st_dev, "exe_ino": exe_stat.st_ino,
            "exe_uid": exe_stat.st_uid, "exe_mode": oct(exe_stat.st_mode & 0o7777),
            "argv": argv, "role": role(argv), "resource_kind": resource,
            "parent_pid": parent_pid, "parent_exe": parent_exe,
            "ancestry": ancestry,
        })
    except (OSError, ValueError, IndexError):
        pass

if not accepted:
    raise SystemExit("FAIL: no live, start-time-verified Firefox ALLOW authority evidence")
if not any(item["exe"] == "/usr/lib/firefox/firefox" for item in accepted):
    raise SystemExit("FAIL: no ALLOW event belongs to the enrolled Firefox executable")
if not all(item["pidfd_matches"] for item in accepted):
    raise SystemExit("FAIL: a retained authority candidate lacks a matching pidfd")
with open(output, "w", encoding="utf-8") as file:
    json.dump(accepted, file, indent=2)
print("LPS2_FIREFOX_ALLOW_EVENTS_LIVE_INSTANCE_VERIFIED=PASS")
print("LPS2_SECRET_AUTHORITY_CANDIDATES=" + str(len(accepted)))
for item in accepted:
    print("LPS2_ROLE=" + item["role"] + " RESOURCE=" + item["resource_kind"])
PY

if [ "$PROCESS_SHIELD_ENABLED" = true ]; then
  LPS3_STATUS=""
  for _ in $(seq 1 30); do
    LPS3_STATUS="$("$GUARDCTL" --socket "$SOCK" --json status 2>/dev/null || true)"
    if printf '%s' "$LPS3_STATUS" | python3 -c 'import json,sys; d=json.load(sys.stdin); raise SystemExit(0 if ((d.get("data") or {}).get("linux_health") or {}).get("process_shield") == "REDUCED" else 1)' 2>/dev/null; then
      break
    fi
    sleep 0.1
  done
  if ! printf '%s' "$LPS3_STATUS" | python3 -c 'import json,sys; d=json.load(sys.stdin); raise SystemExit(0 if ((d.get("data") or {}).get("linux_health") or {}).get("process_shield") == "REDUCED" else 1)'; then
    echo "FAIL: requested LPS3 BPF link did not report REDUCED ptrace-only state"
    exit 1
  fi
  if ! grep -q 'Process Shield admitted exact Firefox Main from File Shield WebStorage allow' "$WORK/guardd.log"; then
    echo "FAIL: LPS3 did not admit Firefox from a pre-response File Shield WebStorage allow"
    exit 1
  fi
  echo "LPS3_FIREFOX_MAIN_BPF_ADMISSION_RUNTIME=PASS"
fi

if [ -n "$EVIDENCE_ROOT" ]; then
  mkdir -p "$EVIDENCE_ROOT"
  # Matrix carries process/resource metadata only; never copy profile, audit DB,
  # browser logs, or ready files which could contain unrelated local data.
  cp "$MATRIX" "$EVIDENCE_ROOT/lps2-firefox-authority-matrix.json"
fi
echo "LPS2_FIREFOX_SECRET_AUTHORITY_MATRIX=PASS"
