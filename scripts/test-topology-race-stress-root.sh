#!/usr/bin/env bash
# Measure the documented inotify -> rediscovery -> fanotify remark interval.
# Synthetic cookie canaries only; no real browser profile and no networking.
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: run as root (fanotify FAN_OPEN_PERM requires CAP_SYS_ADMIN)"
  exit 2
fi

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# This gate measures the replacement/read race, not handle-index exhaustion.
# Stay below the bounded dynamic-handle capacity; P1-b separately proves the
# capacity-exhaustion fail-closed contract.
ITERATIONS="${ITERATIONS:-1000}"
ENFORCEMENT_MODE="${ENFORCEMENT_MODE:-conservative}"
KEEP_WORK="${KEEP_WORK:-0}"
# AGENTS.md LIVE-TEST SAFETY: strict-filesystem marks the fixture's
# filesystem. Pressure/load tests MUST use an ISOLATED loop-backed ext4
# (a root-fs mark -> total lockup; a tmpfs mark wedges /tmp when the daemon
# stalls under load). TEST_FS_ROOT may override with a non-root non-tmpfs fs.
LOOP_IMG=""; LOOP_DEV=""; LOOP_MNT=""; WORK=""; RESULT=""
select_test_fs() {
  if [ -n "${TEST_FS_ROOT:-}" ]; then
    if [ "$(stat -c %d "$TEST_FS_ROOT")" = "$(stat -c %d /)" ]; then
      echo "BLOCKED: TEST_FS_ROOT=$TEST_FS_ROOT is on the ROOT filesystem; strict mode"
      echo "        would gate every open on the whole machine (AGENTS.md)."
      exit 2
    fi
    if [ "$(stat -f -c %T "$TEST_FS_ROOT")" = "tmpfs" ]; then
      echo "BLOCKED: TEST_FS_ROOT=$TEST_FS_ROOT is tmpfs (AGENTS.md rule 4)."
      exit 2
    fi
    WORK="$(mktemp -d "$TEST_FS_ROOT/guard-XXXXXX")"
    return
  fi
  LOOP_IMG="$(mktemp /tmp/guard-img-XXXXXX.img)"
  truncate -s 512M "$LOOP_IMG"
  LOOP_DEV="$(losetup -f)"
  losetup "$LOOP_DEV" "$LOOP_IMG"
  mkfs.ext4 -q -F "$LOOP_DEV"
  LOOP_MNT="$(mktemp -d /tmp/guard-mnt-XXXXXX)"
  mount "$LOOP_DEV" "$LOOP_MNT"
  WORK="$LOOP_MNT"
  echo "isolated loop-backed ext4: $LOOP_DEV at $LOOP_MNT (never touches root/tmpfs)"
}
select_test_fs
DAEMON_PID=""

cleanup() {
  if [ -n "$DAEMON_PID" ] && kill -0 "$DAEMON_PID" 2>/dev/null; then
    kill -TERM "$DAEMON_PID" 2>/dev/null || true
    wait "$DAEMON_PID" 2>/dev/null || true
  fi
  if [ "$KEEP_WORK" = 1 ]; then
    echo "Synthetic stress artifacts retained at: $WORK"
  else
  if [ -n "$LOOP_DEV" ]; then
    umount "$LOOP_DEV" 2>/dev/null || true
    losetup -d "$LOOP_DEV" 2>/dev/null || true
    rm -f "$LOOP_IMG" 2>/dev/null || true
    rmdir "$LOOP_MNT" 2>/dev/null || true
  else
    rm -rf -- "$WORK"
  fi
  fi
  [ -z "$RESULT" ] || rm -f -- "$RESULT"
}
trap cleanup EXIT

case "$ITERATIONS" in
  ''|*[!0-9]*|0) echo "ERROR: ITERATIONS must be a positive integer"; exit 2 ;;
esac
case "$ENFORCEMENT_MODE" in
  conservative|strict-filesystem) ;;
  *) echo "ERROR: ENFORCEMENT_MODE must be conservative or strict-filesystem"; exit 2 ;;
esac

echo "==> Building topology race probe and daemon"
if [ -z "${SKIP_BUILD:-}" ]; then
cargo build --manifest-path "$REPO/Cargo.toml" -p guardd -p guard-test-probe
fi
BIN_DIR="${BIN_DIR:-$REPO/target/debug}"
GUARDD="${GUARDD:-$BIN_DIR/guardd}"
PROBE="${PROBE:-$BIN_DIR/guard-test-probe}"

PROFILE_ROOT="$WORK/disposable-chromium"
COOKIE="$PROFILE_ROOT/Default/Network/Cookies"
STAGING="$WORK/staging"
mkdir -p "$(dirname "$COOKIE")" "$STAGING"
printf '%s' 'synthetic-preferences' > "$PROFILE_ROOT/Default/Preferences"
printf '%s' 'SDF_CANARY_TOPOLOGY_INITIAL' > "$COOKIE"

CONFIG="$WORK/config.json"
printf '%s\n' \
  '{' \
  '  "config_version": 1,' \
  "  \"enforcement_mode\": \"$ENFORCEMENT_MODE\"," \
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
# The strict filesystem mark covers WORK's loop filesystem. Keep the harness
# result on the unmarked host/capsule root so an intentional P1-b-style
# fail-closed transition can never prevent the test from reporting diagnostics.
RESULT="$(mktemp /tmp/sfg-topology-race-result-XXXXXX.json)"
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

if [ "$ENFORCEMENT_MODE" = strict-filesystem ]; then
  if python3 - "$RESULT" <<'PY'
import json, sys
r = json.load(open(sys.argv[1], encoding="utf-8"))
raise SystemExit(0 if r["successful_unauthorized_reads"] == 0 and
                        r["denied_reads"] == r["iterations"] and
                        r["other_errors"] == 0 else 1)
PY
  then
    echo "PASS: strict mode denied every immediate replacement read"
  else
    echo "FAIL: strict mode allowed at least one immediate replacement read"
    exit 1
  fi
fi

# The conservative model permits a bounded race, but must converge. The last
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
if [ "$ENFORCEMENT_MODE" = conservative ]; then
  echo "NOTE: successful_unauthorized_reads is a measured known gap, not a test PASS claim."
else
  echo "NOTE: strict PASS requires zero successful unauthorized reads."
fi
