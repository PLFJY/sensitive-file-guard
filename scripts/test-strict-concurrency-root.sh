#!/usr/bin/env bash
# Bounded strict-mode concurrency and queue-health stress. Synthetic/local only.
set -euo pipefail
if [ "$(id -u)" -ne 0 ]; then echo "ERROR: run as root"; exit 2; fi

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CARGO_BIN="$(command -v cargo)"
(cd "$REPO" && "$CARGO_BIN" build -p guardd -p guardctl -p guard-test-probe)
GUARDD="$REPO/target/debug/guardd"
GUARDCTL="$REPO/target/debug/guardctl"
PROBE="$REPO/target/debug/guard-test-probe"
WORK="$(mktemp -d -t guard-strict-concurrency-XXXXXX)"
DAEMON_PID=""
PIDS=()
cleanup() {
  for pid in "${PIDS[@]}"; do kill -TERM "$pid" 2>/dev/null || true; done
  if [ -n "$DAEMON_PID" ]; then kill -TERM "$DAEMON_PID" 2>/dev/null || true; wait "$DAEMON_PID" 2>/dev/null || true; fi
  rm -rf -- "$WORK"
}
trap cleanup EXIT

PROFILE="$WORK/chromium"
COOKIE="$PROFILE/Default/Network/Cookies"
ORDINARY="$WORK/ordinary"
STAGING="$WORK/staging"
mkdir -p "$(dirname "$COOKIE")" "$STAGING"
printf '%s' 'SDF_CANARY_CONCURRENT_SYNTHETIC' >"$COOKIE"
printf '%s' 'ordinary' >"$ORDINARY"
printf '%s' '{}' >"$PROFILE/Default/Preferences"
printf '%s' '{}' >"$PROFILE/Local State"
ENROLLED="$WORK/synthetic-chromium"
cp "$PROBE" "$ENROLLED"
chmod 0755 "$ENROLLED"

CONFIG="$WORK/config.json"
python3 - "$CONFIG" "$PROFILE" "$ENROLLED" <<'PY'
import json, sys
json.dump({"enforcement_mode":"strict-filesystem","browsers":[{
 "id":"synthetic-chromium","family":"Chromium","profile_root":sys.argv[2],
 "owner_uid":0,"exe_paths":[sys.argv[3]]}],"enrolled_exes":[sys.argv[3]],"ssh_keys":[]},
 open(sys.argv[1],"w",encoding="utf-8"))
PY

SOCKET="$WORK/guardd.sock"
"$GUARDD" --enforce-browser-config "$CONFIG" --ipc-socket "$SOCKET" \
  --audit-db "$WORK/audit.db" >"$WORK/guardd.log" 2>&1 &
DAEMON_PID=$!
for _ in $(seq 1 200); do
  [ -S "$SOCKET" ] && "$GUARDCTL" --socket "$SOCKET" --json status >"$WORK/status.json" 2>/dev/null && break
  kill -0 "$DAEMON_PID" 2>/dev/null || { sed -n '1,120p' "$WORK/guardd.log"; exit 1; }
  sleep 0.025
done

echo "==> Concurrent unrelated, allowed, denied, topology, and IPC traffic"
for i in $(seq 1 8); do
  "$PROBE" open-bench "$ORDINARY" 20000 >"$WORK/unprotected-$i.json" & PIDS+=("$!")
done
for i in $(seq 1 4); do
  "$ENROLLED" open-bench "$COOKIE" 5000 >"$WORK/allowed-$i.json" & PIDS+=("$!")
done
for i in $(seq 1 2); do
  "$PROBE" open-bench "$COOKIE" 100 >"$WORK/denied-$i.json" & PIDS+=("$!")
done
"$PROBE" topology-race "$COOKIE" "$STAGING" 100 >"$WORK/topology.json" & PIDS+=("$!")
(
  for _ in $(seq 1 200); do
    "$GUARDCTL" --socket "$SOCKET" --json status >/dev/null
    "$GUARDCTL" --socket "$SOCKET" --json events --limit 10 >/dev/null
  done
) >"$WORK/ipc.out" 2>"$WORK/ipc.err" & PIDS+=("$!")

failed=0
for pid in "${PIDS[@]}"; do wait "$pid" || failed=$((failed + 1)); done
PIDS=()
if [ "$failed" -ne 0 ]; then echo "FAIL: $failed concurrent workers failed"; exit 1; fi

"$GUARDCTL" --socket "$SOCKET" --json status >"$WORK/final-status.json"
python3 - "$WORK" <<'PY'
import json, pathlib, sys
w=pathlib.Path(sys.argv[1])
for path in w.glob("unprotected-*.json"):
    r=json.load(open(path, encoding="utf-8"))
    assert r["successful"] == r["iterations"] and r["other_errors"] == 0, path
for path in w.glob("allowed-*.json"):
    r=json.load(open(path, encoding="utf-8"))
    assert r["successful"] == r["iterations"] and r["other_errors"] == 0, path
for path in w.glob("denied-*.json"):
    r=json.load(open(path, encoding="utf-8"))
    assert r["denied"] == r["iterations"] and r["successful"] == 0, path
r=json.load(open(w/"topology.json", encoding="utf-8"))
assert r["denied_reads"] == r["iterations"] and r["successful_unauthorized_reads"] == 0
s=json.load(open(w/"final-status.json", encoding="utf-8"))["data"]
print("Concurrent strict health:")
for key in ("status","strict_events_total","strict_fast_allowed","protected_events",
            "allowed","denied","fanotify_overflows","audit_dropped",
            "classifier_failures","topology_degraded"):
    print(f"  {key}: {s[key]}")
assert s["status"] == "ACTIVE"
assert s["fanotify_overflows"] == 0
assert s["audit_dropped"] == 0
assert s["classifier_failures"] == 0
assert not s["topology_degraded"]
PY

kill -TERM "$DAEMON_PID"
wait "$DAEMON_PID"
DAEMON_PID=""
echo "PASS: bounded concurrent stress completed without deadlock, overflow, or audit loss"
