#!/usr/bin/env bash
# Linux scoped-enforcement benchmark. Synthetic files and binaries only.
# Timing is informational; permission-event counts are the correctness checks.
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: run as root (fanotify permission enforcement requires CAP_SYS_ADMIN)"
  exit 2
fi

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GUARDD="$REPO/target/debug/guardd"
GUARDCTL="$REPO/target/debug/guardctl"
PROBE="$REPO/target/debug/guard-test-probe"
for artifact in "$GUARDD" "$GUARDCTL" "$PROBE"; do
  [ -x "$artifact" ] || {
    echo "ERROR: missing $artifact; run cargo build -p guardd -p guardctl -p guard-test-probe first"
    exit 2
  }
done

WORK="$(mktemp -d "$REPO/target/guard-linux-benchmark.XXXXXX")"
DAEMON_PID=""
cleanup() {
  if [ -n "$DAEMON_PID" ]; then
    kill -TERM "$DAEMON_PID" 2>/dev/null || true
    wait "$DAEMON_PID" 2>/dev/null || true
  fi
  case "$WORK" in
    "$REPO"/target/guard-linux-benchmark.*) rm -rf -- "$WORK" ;;
  esac
}
trap cleanup EXIT

PROFILE="$WORK/chromium"
COOKIE="$PROFILE/Default/Network/Cookies"
ORDINARY="$WORK/ordinary.txt"
mkdir -p "$(dirname "$COOKIE")"
printf '%s' 'SDF_CANARY_BENCHMARK_COOKIE' > "$COOKIE"
printf '%s' 'ordinary-unprotected-data' > "$ORDINARY"
printf '%s' '{}' > "$PROFILE/Default/Preferences"
printf '%s' '{}' > "$PROFILE/Local State"
ENROLLED="$WORK/synthetic-chromium"
cp "$PROBE" "$ENROLLED"
chmod 0755 "$ENROLLED"

CONFIG="$WORK/config.json"
python3 - "$CONFIG" "$PROFILE" "$ENROLLED" <<'PY'
import json, sys
path, profile, executable = sys.argv[1:]
json.dump({
    "browser_protection_level": "common",
    "browsers": [{
        "id": "synthetic-chromium", "family": "Chromium",
        "profile_root": profile, "owner_uid": 0,
        "exe_paths": [executable],
    }],
    "enrolled_exes": [executable], "ssh_keys": [],
}, open(path, "w", encoding="utf-8"))
PY

SOCKET="$WORK/guardd.sock"
start_daemon() {
  "$GUARDD" --enforce-browser-config "$CONFIG" --ipc-socket "$SOCKET" \
    --audit-db "$WORK/audit.db" > "$WORK/guardd.log" 2>&1 &
  DAEMON_PID=$!
  for _ in $(seq 1 400); do
    if [ -S "$SOCKET" ] && "$GUARDCTL" --socket "$SOCKET" --json status \
      > "$WORK/ready-status.json" 2>/dev/null; then
      return
    fi
    kill -0 "$DAEMON_PID" 2>/dev/null || { cat "$WORK/guardd.log"; exit 1; }
    sleep 0.025
  done
  echo "ERROR: guardd did not become ready"
  cat "$WORK/guardd.log"
  exit 1
}

snapshot() {
  local label="$1"
  "$GUARDCTL" --socket "$SOCKET" --json status > "$WORK/$label-status.json"
}

timed_open_bench() {
  local label="$1" executable="$2" path="$3" iterations="$4"
  "$executable" open-bench "$path" "$iterations" > "$WORK/$label.json"
}

timed_exec() {
  local label="$1" iterations="$2" start end
  start="$(date +%s%N)"
  for _ in $(seq 1 "$iterations"); do "$PROBE" noop; done
  end="$(date +%s%N)"
  python3 - "$start" "$end" "$iterations" > "$WORK/$label-exec.json" <<'PY'
import json, sys
start, end, iterations = map(int, sys.argv[1:])
json.dump({"iterations": iterations, "elapsed_ns": end - start}, sys.stdout)
PY
}

OPEN_ITERATIONS="${OPEN_ITERATIONS:-10000}"
EXEC_ITERATIONS="${EXEC_ITERATIONS:-100}"
ALLOWED_ITERATIONS="${ALLOWED_ITERATIONS:-1000}"
DENIED_ITERATIONS="${DENIED_ITERATIONS:-100}"

echo "==> guardd absent"
timed_open_bench absent-open "$PROBE" "$ORDINARY" "$OPEN_ITERATIONS"
timed_exec absent "$EXEC_ITERATIONS"

echo "==> guardd active"
start_daemon
snapshot before-unrelated-open
timed_open_bench active-open "$PROBE" "$ORDINARY" "$OPEN_ITERATIONS"
snapshot after-unrelated-open
snapshot before-unrelated-exec
timed_exec active "$EXEC_ITERATIONS"
snapshot after-unrelated-exec
timed_open_bench active-allowed "$ENROLLED" "$COOKIE" "$ALLOWED_ITERATIONS"
timed_open_bench active-denied "$PROBE" "$COOKIE" "$DENIED_ITERATIONS"
snapshot final

python3 - "$WORK" <<'PY'
import json, pathlib, sys
w = pathlib.Path(sys.argv[1])
def status(name):
    return json.load(open(w / f"{name}-status.json", encoding="utf-8"))["data"]
def result(name):
    return json.load(open(w / f"{name}.json", encoding="utf-8"))

before_open = status("before-unrelated-open")
after_open = status("after-unrelated-open")
before_exec = status("before-unrelated-exec")
after_exec = status("after-unrelated-exec")
final = status("final")
open_delta = after_open["permission_events_total"] - before_open["permission_events_total"]
exec_delta = after_exec["permission_events_total"] - before_exec["permission_events_total"]
assert open_delta == 0, f"unrelated ordinary opens produced {open_delta} permission events"
assert exec_delta == 0, f"unrelated executable spawns produced {exec_delta} permission events"

allowed = result("active-allowed")
denied = result("active-denied")
assert allowed["successful"] == allowed["iterations"] and allowed["other_errors"] == 0
assert denied["denied"] == denied["iterations"] and denied["successful"] == 0
assert final["fanotify_overflows"] == 0
assert final["classifier_failures"] == 0
assert final["audit_dropped"] == 0
assert final["topology_degraded"] is False

print("Linux benchmark results (timing informational):")
for name in ("absent-open", "active-open", "active-allowed", "active-denied"):
    r = result(name)
    print(f"  {name}: {r['elapsed_ns'] / 1e6:.3f} ms, iterations={r['iterations']}")
for name in ("absent", "active"):
    r = json.load(open(w / f"{name}-exec.json", encoding="utf-8"))
    print(f"  {name} exec: {r['elapsed_ns'] / 1e6:.3f} ms, iterations={r['iterations']}")
print(f"  unrelated open permission-event delta: {open_delta}")
print(f"  unrelated exec permission-event delta: {exec_delta}")
print("PASS: active scoped enforcement preserved protected decisions and zero unrelated permission events")
PY

kill -TERM "$DAEMON_PID"
wait "$DAEMON_PID"
DAEMON_PID=""
