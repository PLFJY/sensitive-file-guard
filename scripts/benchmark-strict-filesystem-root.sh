#!/usr/bin/env bash
# Reproducible Phase 19 fanotify performance comparison. Synthetic files only.
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then echo "ERROR: run as root"; exit 2; fi
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CARGO_BIN="$(command -v cargo)"
(cd "$REPO" && "$CARGO_BIN" build -p guardd -p guardctl -p guard-test-probe)
GUARDD="$REPO/target/debug/guardd"
GUARDCTL="$REPO/target/debug/guardctl"
PROBE="$REPO/target/debug/guard-test-probe"

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
ENROLLED="$WORK/synthetic-chromium"
cp "$PROBE" "$ENROLLED"
chmod 0755 "$ENROLLED"

make_config() {
  local mode="$1" output="$2"
  python3 - "$output" "$mode" "$PROFILE" "$ENROLLED" <<'PY'
import json, sys
path, mode, profile, exe = sys.argv[1:]
json.dump({"enforcement_mode":mode,"browsers":[{"id":"synthetic-chromium",
 "family":"Chromium","profile_root":profile,"owner_uid":0,"exe_paths":[exe]}],
 "enrolled_exes":[exe],"ssh_keys":[]}, open(path,"w",encoding="utf-8"))
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

cargo_wall() {
  local state="$1" started finished
  started="$(date +%s%N)"
  "$CARGO_BIN" check --manifest-path "$REPO/Cargo.toml" --workspace --all-features -q
  finished="$(date +%s%N)"
  python3 - "$started" "$finished" >"$WORK/$state-cargo.time" <<'PY'
import sys
print(f"{(int(sys.argv[2])-int(sys.argv[1]))/1e9:.6f}")
PY
}

OPEN_ITERATIONS="${OPEN_ITERATIONS:-100000}"
ALLOWED_ITERATIONS="${ALLOWED_ITERATIONS:-10000}"
DENIED_ITERATIONS="${DENIED_ITERATIONS:-2000}"

echo "==> A. guardd absent"
bench absent unprotected "$PROBE" "$ORDINARY" "$OPEN_ITERATIONS"
bench absent browser "$ENROLLED" "$COOKIE" "$ALLOWED_ITERATIONS"
bench absent denied "$PROBE" "$COOKIE" "$DENIED_ITERATIONS"
cargo_wall absent

echo "==> B. scoped mode"
start_daemon scoped
bench scoped unprotected "$PROBE" "$ORDINARY" "$OPEN_ITERATIONS"
bench scoped browser "$ENROLLED" "$COOKIE" "$ALLOWED_ITERATIONS"
bench scoped denied "$PROBE" "$COOKIE" "$DENIED_ITERATIONS"
cargo_wall scoped
"$GUARDCTL" --socket "$WORK/guardd.sock" --json status >"$WORK/scoped-status.json"
stop_daemon

echo "==> C. strict-mount mode"
start_daemon strict-mount
bench strict-mount unprotected "$PROBE" "$ORDINARY" "$OPEN_ITERATIONS"
bench strict-mount browser "$ENROLLED" "$COOKIE" "$ALLOWED_ITERATIONS"
bench strict-mount denied "$PROBE" "$COOKIE" "$DENIED_ITERATIONS"
cargo_wall strict-mount
"$GUARDCTL" --socket "$WORK/guardd.sock" --json status >"$WORK/strict-mount-status.json"
stop_daemon

echo "==> D. strict-filesystem mode"
start_daemon strict-filesystem
bench strict-filesystem unprotected "$PROBE" "$ORDINARY" "$OPEN_ITERATIONS"
bench strict-filesystem browser "$ENROLLED" "$COOKIE" "$ALLOWED_ITERATIONS"
bench strict-filesystem denied "$PROBE" "$COOKIE" "$DENIED_ITERATIONS"
cargo_wall strict-filesystem
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
print("cargo check wall seconds:")
for state in ("absent","scoped","strict-mount","strict-filesystem"):
    print(f"  {state}: {(w/f'{state}-cargo.time').read_text().strip()}")
for state in ("scoped", "strict-mount", "strict-filesystem"):
    status=json.load(open(w/f"{state}-status.json", encoding="utf-8"))["data"]
    print(f"{state} queue health:")
    for key in ("strict_events_total","strict_fast_allowed","protected_events",
                "fanotify_overflows","audit_dropped","classifier_failures"):
        print(f"  {key}: {status[key]}")
    if status["fanotify_overflows"] or status["classifier_failures"] or status["topology_degraded"]:
        raise SystemExit(f"{state} benchmark degraded enforcement")
    denied=json.load(open(w/f"{state}-denied.json", encoding="utf-8"))
    if denied["denied"] != denied["iterations"] or denied["successful"]:
        raise SystemExit(f"{state} denied benchmark did not deny every protected open")

# `strict_events_total` is the stable status field for every permission event.
# It starts at zero at daemon launch; scoped's three protected workloads must
# account for all events, while the unrelated sibling workload contributes none.
scoped=json.load(open(w/"scoped-status.json", encoding="utf-8"))["data"]
if scoped["strict_events_total"] != scoped["protected_events"]:
    raise SystemExit("scoped unrelated workload produced a permission event")
PY

echo "PASS: performance benchmark completed with no fanotify overflow or classifier failure"
