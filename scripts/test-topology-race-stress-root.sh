#!/usr/bin/env bash
# Measure the documented inotify -> rediscovery -> fanotify remark interval.
# Synthetic cookie canaries only; no real browser profile and no networking.
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: run as root (fanotify FAN_OPEN_PERM requires CAP_SYS_ADMIN)"
  exit 2
fi

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ITERATIONS="${ITERATIONS:-10000}"
KEEP_WORK="${KEEP_WORK:-0}"
WORK="$(mktemp -d -t guard-topology-race-XXXXXX)"
DAEMON_PID=""

cleanup() {
  if [ -n "$DAEMON_PID" ] && kill -0 "$DAEMON_PID" 2>/dev/null; then
    kill -TERM "$DAEMON_PID" 2>/dev/null || true
    wait "$DAEMON_PID" 2>/dev/null || true
  fi
  if [ "$KEEP_WORK" = 1 ]; then
    echo "Synthetic stress artifacts retained at: $WORK"
  else
    rm -rf -- "$WORK"
  fi
}
trap cleanup EXIT

case "$ITERATIONS" in
  ''|*[!0-9]*|0) echo "ERROR: ITERATIONS must be a positive integer"; exit 2 ;;
esac
GUARDD="$REPO/target/debug/guardd"
PROBE="$REPO/target/debug/guard-test-probe"
echo "==> Checking pre-built topology race probe and daemon"
for artifact in "$GUARDD" "$PROBE"; do
  [ -x "$artifact" ] || {
    echo "ERROR: missing $artifact; run cargo build -p guardd -p guard-test-probe as the normal user first"
    exit 2
  }
done

PROFILE_ROOT="$WORK/disposable-chromium"
COOKIE="$PROFILE_ROOT/Default/Network/Cookies"
STAGING="$WORK/staging"
mkdir -p "$(dirname "$COOKIE")" "$STAGING"
printf '%s' 'synthetic-preferences' > "$PROFILE_ROOT/Default/Preferences"
printf '%s' 'SDF_CANARY_TOPOLOGY_INITIAL' > "$COOKIE"

CONFIG="$WORK/config.json"
printf '%s\n' \
  '{' \
  '  "browsers": [' \
  '    {' \
  '      "id": "synthetic-chromium",' \
  '      "family": "Chromium",' \
  "      \"profile_root\": \"$PROFILE_ROOT\"," \
  '      "owner_uid": 0,' \
  '      "exe_paths": []' \
  '    }' \
  '  ],' \
  '  "enrolled_exes": [],' \
  '  "ssh_keys": []' \
  '}' > "$CONFIG"

SOCKET="$WORK/guardd.sock"
"$GUARDD" --enforce-browser-config "$CONFIG" \
  --ipc-socket "$SOCKET" --audit-db "$WORK/audit.db" \
  > "$WORK/guardd.log" 2>&1 &
DAEMON_PID=$!
for _ in $(seq 1 200); do
  grep -q 'enforcement ACTIVE' "$WORK/guardd.log" 2>/dev/null && break
  if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
    echo "ERROR: guardd exited before enforcement became active"
    sed -n '1,160p' "$WORK/guardd.log"
    exit 1
  fi
  sleep 0.025
done
if ! grep -q 'enforcement ACTIVE' "$WORK/guardd.log"; then
  echo "ERROR: guardd did not become active"
  sed -n '1,160p' "$WORK/guardd.log"
  exit 1
fi

echo "==> Running $ITERATIONS atomic-replacement/read iterations"
RESULT="$WORK/result.json"
if ! "$PROBE" topology-race "$COOKIE" "$STAGING" "$ITERATIONS" > "$RESULT"; then
  echo "FAIL: topology stress probe encountered non-policy errors"
  sed -n '1,20p' "$RESULT"
  exit 1
fi
python3 - "$RESULT" <<'PY'
import json, sys
r = json.load(open(sys.argv[1], encoding="utf-8"))
print("Topology race measurement:")
print(f"  iterations                    : {r['iterations']}")
print(f"  successful unauthorized reads : {r['successful_unauthorized_reads']}")
print(f"  denied reads                  : {r['denied_reads']}")
print(f"  other errors                  : {r['other_errors']}")
t = r['time_to_protection_us']
print(f"  time-to-protection samples    : {t['samples']}")
print(f"  time-to-protection p50/p95/p99/max (us): {t['p50']}/{t['p95']}/{t['p99']}/{t['max']}")
if r['iterations'] != r['successful_unauthorized_reads'] + r['denied_reads']:
    raise SystemExit("measurement accounting mismatch")
PY

# Scoped directory marks permit a bounded race, but must converge. The last
# inode must become denied within two seconds after the stress run.
CONVERGED=0
for _ in $(seq 1 200); do
  if ! "$PROBE" read "$COOKIE" >/dev/null 2>&1; then
    CONVERGED=1
    break
  fi
  sleep 0.01
done
if [ "$CONVERGED" -ne 1 ]; then
  echo "FAIL: final replacement inode did not converge to protection"
  exit 1
fi

echo "PASS: empirical topology-race measurement completed and final inode converged"
echo "NOTE: successful_unauthorized_reads measures the documented new-nested-directory race."
