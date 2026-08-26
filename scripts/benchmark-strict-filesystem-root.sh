#!/usr/bin/env bash
# Reproducible fanotify mode comparison. Synthetic files and binaries only.
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then echo "ERROR: run as root"; exit 2; fi
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GUARDD="$REPO/target/debug/guardd"
GUARDCTL="$REPO/target/debug/guardctl"
PROBE="$REPO/target/debug/guard-test-probe"
for artifact in "$GUARDD" "$GUARDCTL" "$PROBE"; do
  [ -x "$artifact" ] || {
    echo "ERROR: missing $artifact; run cargo build -p guardd -p guardctl -p guard-test-probe as the normal user first"
    exit 2
  }
done
command -v ssh-keygen >/dev/null || { echo "ERROR: ssh-keygen is required"; exit 2; }

WORK="$(mktemp -d "$REPO/target/guard-strict-perf.XXXXXX")"
touch "$WORK/.synthetic-phase19-benchmark"
DAEMON_PID=""
cleanup() {
  if [ -n "$DAEMON_PID" ]; then kill -TERM "$DAEMON_PID" 2>/dev/null || true; wait "$DAEMON_PID" 2>/dev/null || true; fi
  case "$WORK" in "$REPO"/target/guard-strict-perf.*) rm -rf -- "$WORK" ;; esac
}
trap cleanup EXIT

PROFILE="$WORK/chromium"
COOKIE="$PROFILE/Default/Network/Cookies"
ORDINARY="$WORK/ordinary.txt"
mkdir -p "$(dirname "$COOKIE")"
printf '%s' 'SDF_CANARY_PERFORMANCE_SYNTHETIC' >"$COOKIE"
printf '%s' 'ordinary-unprotected-data' >"$ORDINARY"
printf '%s' '{"synthetic":true}' >"$PROFILE/Default/Preferences"
printf '%s' '{}' >"$PROFILE/Local State"
mkdir "$WORK/ssh"
SSH_KEY="$WORK/ssh/id_synthetic"
ssh-keygen -q -t ed25519 -N '' -f "$SSH_KEY"
ENROLLED="$WORK/synthetic-chromium"
cp "$PROBE" "$ENROLLED"
chmod 0755 "$ENROLLED"
UNRELATED_EXEC="$WORK/unrelated-exec"
cp "$PROBE" "$UNRELATED_EXEC"
chmod 0755 "$UNRELATED_EXEC"

make_config() {
  local mode="$1" output="$2"
  python3 - "$output" "$mode" "$PROFILE" "$ENROLLED" "$SSH_KEY" <<'PY'
import json, sys
path, mode, profile, exe, ssh_key = sys.argv[1:]
json.dump({"enforcement_mode":mode,"browsers":[{"id":"synthetic-chromium",
 "family":"Chromium","profile_root":profile,"owner_uid":0,"exe_paths":[exe]}],
 "enrolled_exes":[exe],"ssh_keys":[ssh_key]}, open(path,"w",encoding="utf-8"))
PY
}

start_daemon() {
  local mode="$1"
  local config="$WORK/$mode.json"
  make_config "$mode" "$config"
  "$GUARDD" --enforce-browser-config "$config" --ipc-socket "$WORK/guardd.sock" \
    --audit-db "$WORK/$mode-audit.db" >"$WORK/$mode.log" 2>&1 &
  DAEMON_PID=$!
  for _ in $(seq 1 400); do
    if [ -S "$WORK/guardd.sock" ] && "$GUARDCTL" --socket "$WORK/guardd.sock" --json status \
      >"$WORK/$mode-status.json" 2>/dev/null; then return; fi
    kill -0 "$DAEMON_PID" 2>/dev/null || { sed -n '1,160p' "$WORK/$mode.log"; exit 1; }
    sleep 0.025
  done
  echo "ERROR: $mode daemon did not become ready"; exit 1
}

stop_daemon() {
  kill -TERM "$DAEMON_PID"
  wait "$DAEMON_PID"
  DAEMON_PID=""
  rm -f "$WORK/guardd.sock"
}

bench() {
  local state="$1" workload="$2" executable="$3" path="$4" iterations="$5"
  "$executable" open-bench "$path" "$iterations" >"$WORK/$state-$workload.json"
}

snapshot() {
  local state="$1" point="$2"
  "$GUARDCTL" --socket "$WORK/guardd.sock" --json status \
    >"$WORK/$state-$point-status.json"
}

exec_wall() {
  local state="$1" iterations="$2" started finished
  started="$(date +%s%N)"
  for _ in $(seq 1 "$iterations"); do
    "$UNRELATED_EXEC" noop
  done
  finished="$(date +%s%N)"
  python3 - "$started" "$finished" "$iterations" >"$WORK/$state-exec.json" <<'PY'
import json
import sys
elapsed_ns=int(sys.argv[2])-int(sys.argv[1])
iterations=int(sys.argv[3])
json.dump({"iterations":iterations,"elapsed_ns":elapsed_ns}, sys.stdout)
PY
}

OPEN_ITERATIONS="${OPEN_ITERATIONS:-100000}"
ALLOWED_ITERATIONS="${ALLOWED_ITERATIONS:-10000}"
DENIED_ITERATIONS="${DENIED_ITERATIONS:-2000}"
EXEC_ITERATIONS="${EXEC_ITERATIONS:-200}"

echo "==> A. guardd absent"
bench absent unprotected "$PROBE" "$ORDINARY" "$OPEN_ITERATIONS"
bench absent browser "$ENROLLED" "$COOKIE" "$ALLOWED_ITERATIONS"
bench absent denied "$PROBE" "$COOKIE" "$DENIED_ITERATIONS"
exec_wall absent "$EXEC_ITERATIONS"

echo "==> B. scoped mode"
start_daemon scoped
snapshot scoped before-unprotected
bench scoped unprotected "$PROBE" "$ORDINARY" "$OPEN_ITERATIONS"
snapshot scoped after-unprotected
snapshot scoped before-exec
exec_wall scoped "$EXEC_ITERATIONS"
snapshot scoped after-exec
bench scoped browser "$ENROLLED" "$COOKIE" "$ALLOWED_ITERATIONS"
bench scoped denied "$PROBE" "$COOKIE" "$DENIED_ITERATIONS"
"$GUARDCTL" --socket "$WORK/guardd.sock" --json status >"$WORK/scoped-status.json"
stop_daemon

echo "==> C. strict-mount mode"
start_daemon strict-mount
snapshot strict-mount before-unprotected
bench strict-mount unprotected "$PROBE" "$ORDINARY" "$OPEN_ITERATIONS"
snapshot strict-mount after-unprotected
snapshot strict-mount before-exec
exec_wall strict-mount "$EXEC_ITERATIONS"
snapshot strict-mount after-exec
bench strict-mount browser "$ENROLLED" "$COOKIE" "$ALLOWED_ITERATIONS"
bench strict-mount denied "$PROBE" "$COOKIE" "$DENIED_ITERATIONS"
"$GUARDCTL" --socket "$WORK/guardd.sock" --json status >"$WORK/strict-mount-status.json"
stop_daemon

echo "==> D. strict-filesystem mode"
start_daemon strict-filesystem
snapshot strict-filesystem before-unprotected
bench strict-filesystem unprotected "$PROBE" "$ORDINARY" "$OPEN_ITERATIONS"
snapshot strict-filesystem after-unprotected
snapshot strict-filesystem before-exec
exec_wall strict-filesystem "$EXEC_ITERATIONS"
snapshot strict-filesystem after-exec
bench strict-filesystem browser "$ENROLLED" "$COOKIE" "$ALLOWED_ITERATIONS"
bench strict-filesystem denied "$PROBE" "$COOKIE" "$DENIED_ITERATIONS"
"$GUARDCTL" --socket "$WORK/guardd.sock" --json status >"$WORK/strict-filesystem-status.json"
stop_daemon

python3 - "$WORK" <<'PY'
import json, pathlib, sys
w=pathlib.Path(sys.argv[1])
def load(state, workload):
    d=json.load(open(w/f"{state}-{workload}.json", encoding="utf-8"))
    return d
rows=[]
for state in ("absent","scoped","strict-mount","strict-filesystem"):
    for workload in ("unprotected","browser","denied"):
        rows.append((state,workload,load(state,workload)))
baseline={(workload):d["elapsed_ns"] for state,workload,d in rows if state=="absent"}
print("Performance results:")
print("state | workload | iterations | wall_ms | opens/sec | p50/p95/p99/max_us | overhead")
for state,workload,d in rows:
    base=baseline.get(workload)
    overhead=(d["elapsed_ns"]/base) if base else 0
    overhead_text=f"{overhead:.2f}x" if base else "n/a"
    lat=d["latency_ns"]
    print(f"{state} | {workload} | {d['iterations']} | {d['elapsed_ns']/1e6:.3f} | "
          f"{d['opens_per_sec']} | "
          f"{lat['p50']/1e3:.1f}/{lat['p95']/1e3:.1f}/{lat['p99']/1e3:.1f}/{lat['max']/1e3:.1f} | "
          + overhead_text)
print("unrelated copied-executable spawn wall time:")
exec_baseline=None
for state in ("absent","scoped","strict-mount","strict-filesystem"):
    result=json.load(open(w/f"{state}-exec.json", encoding="utf-8"))
    if exec_baseline is None:
        exec_baseline=result["elapsed_ns"]
    ratio=result["elapsed_ns"]/exec_baseline
    print(f"  {state}: {result['elapsed_ns']/1e6:.3f} ms "
          f"({result['iterations']} spawns, {ratio:.2f}x absent)")
for state in ("scoped", "strict-mount", "strict-filesystem"):
    status=json.load(open(w/f"{state}-status.json", encoding="utf-8"))["data"]
    print(f"{state} queue health:")
    for key in ("strict_events_total","strict_fast_allowed","protected_events",
                "fanotify_overflows","audit_dropped","classifier_failures"):
        print(f"  {key}: {status[key]}")
    if status["fanotify_overflows"] or status["classifier_failures"] or status["topology_degraded"]:
        raise SystemExit(f"{state} benchmark degraded enforcement")
    if status["ssh_protected_keys"] != 1:
        raise SystemExit(f"{state} did not retain exact synthetic SSH-key enrollment")
    denied=json.load(open(w/f"{state}-denied.json", encoding="utf-8"))
    if denied["denied"] != denied["iterations"] or denied["successful"]:
        raise SystemExit(f"{state} denied benchmark did not deny every protected open")

def event_count(state, point):
    status=json.load(open(w/f"{state}-{point}-status.json", encoding="utf-8"))["data"]
    return status["strict_events_total"]

for workload in ("unprotected", "exec"):
    before=event_count("scoped", f"before-{workload}")
    after=event_count("scoped", f"after-{workload}")
    if after != before:
        raise SystemExit(
            f"scoped unrelated {workload} workload produced {after-before} permission events")

# The ordinary file and copied executable share the fixture mount/filesystem
# with the profile, so both broad modes must observe them. Status requests can
# add broad-mode events of their own, hence this assertion is deliberately > 0.
for state in ("strict-mount", "strict-filesystem"):
    for workload in ("unprotected", "exec"):
        before=event_count(state, f"before-{workload}")
        after=event_count(state, f"after-{workload}")
        if after <= before:
            raise SystemExit(f"{state} did not observe unrelated {workload} workload")
PY

echo "PASS: performance benchmark completed with no fanotify overflow or classifier failure"
