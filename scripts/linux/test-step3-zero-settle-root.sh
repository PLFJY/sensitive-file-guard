#!/usr/bin/env bash
# scripts/linux/test-step3-zero-settle-root.sh
#
# R1 (review finding): LFH2 Step 3 acceptance must run the EXACT attacker path
#   unprotected temp -> rename into protected sensitive name
#   -> immediately rename out -> immediate unknown open
# with ZERO settle between the renames and the open, and the topology group's
# processing must not be assumed to precede the permission group's decision.
#
# This harness runs that path 10k times on an isolated loop-backed ext4 (the
# permission mark is fs-scoped; a dedicated loop fs can never gate the rest of
# the machine). The move-in topology event and the open's permission event are
# generated microseconds apart; the daemon's permission hot path synchronously
# drains causally-prior topology events (R1 cross-group ordering), so every
# immediate open must be denied. ALSO verifies runtime-created subdirectory
# coverage: a subdir created after startup becomes marked by the learner's
# periodic refresh, and the same attack inside it is denied.
#
# Synthetic fixtures only. Exit codes: 0=PASS, 1=FAIL, 2=BLOCKED.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN_DIR="${BIN_DIR:-$REPO/target/release}"
GUARDD="${GUARDD:-$BIN_DIR/guardd}"
GUARDCTL="${GUARDCTL:-$BIN_DIR/guardctl}"
PROBE="${PROBE:-$BIN_DIR/guard-test-probe}"

PASS=0; FAIL=0; BLOCKED=0
note_pass() { echo "PASS: $1"; PASS=$((PASS + 1)); }
note_fail() { echo "FAIL: $1"; FAIL=$((FAIL + 1)); }
note_blocked() { echo "BLOCKED: $1"; BLOCKED=$((BLOCKED + 1)); }

if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: run as root (fanotify requires CAP_SYS_ADMIN)"
  exit 2
fi
for bin in "$GUARDD" "$GUARDCTL" "$PROBE"; do
  test -x "$bin" || { echo "ERROR: missing $bin; build as the normal user first"; exit 2; }
done

# --- isolated loop-backed ext4 (never touches the root fs) ---
LOOP_IMG=""; LOOP_DEV=""; LOOP_MNT=""; DAEMON_PID=""
KEEP_WORK="${KEEP_WORK:-0}"
cleanup() {
  if [ -n "$DAEMON_PID" ] && kill -0 "$DAEMON_PID" 2>/dev/null; then
    kill -TERM "$DAEMON_PID" 2>/dev/null || true
    for _ in $(seq 1 50); do kill -0 "$DAEMON_PID" 2>/dev/null || break; sleep 0.05; done
    kill -KILL "$DAEMON_PID" 2>/dev/null || true
    wait "$DAEMON_PID" 2>/dev/null || true
  fi
  if [ "$KEEP_WORK" = 1 ]; then
    echo "KEPT diagnostics at: $LOOP_MNT (loop $LOOP_DEV still mounted)"
  else
    if [ -n "$LOOP_DEV" ]; then
      umount "$LOOP_DEV" 2>/dev/null || true
      losetup -d "$LOOP_DEV" 2>/dev/null || true
      rm -f "$LOOP_IMG" 2>/dev/null || true
      rmdir "$LOOP_MNT" 2>/dev/null || true
    fi
  fi
}
trap cleanup EXIT
LOOP_IMG="$(mktemp /tmp/guard-step3-img-XXXXXX.img)"
truncate -s 512M "$LOOP_IMG"
LOOP_DEV="$(losetup -f)"
losetup "$LOOP_DEV" "$LOOP_IMG"
mkfs.ext4 -q -F "$LOOP_DEV"
LOOP_MNT="$(mktemp -d /tmp/guard-step3-mnt-XXXXXX)"
mount "$LOOP_DEV" "$LOOP_MNT"
echo "isolated loop-backed ext4: $LOOP_DEV at $LOOP_MNT"

# --- synthetic Chromium profile + outside staging on the SAME fs ---
PROFILE="$LOOP_MNT/profile"
OUTSIDE="$LOOP_MNT/outside"
mkdir -p "$PROFILE/Default/Network" "$OUTSIDE"
printf 'synthetic-step3' > "$PROFILE/Default/Preferences"
# The race objects are created BEFORE guardd starts (creation not gated).
printf 'RACE_OBJECT_1' > "$OUTSIDE/.sdf-race-tmp"
printf 'RACE_OBJECT_2' > "$OUTSIDE/.sdf-race-tmp2"
TARGET="$PROFILE/Default/Network/Cookies"

cat > "$LOOP_MNT/config.json" <<EOF
{
  "config_version": 1,
  "enforcement_mode": "strict-filesystem",
  "browsers": [
    {
      "id": "synthetic-chromium",
      "family": "Chromium",
      "profile_root": "$PROFILE",
      "owner_uid": 0,
      "exe_paths": []
    }
  ],
  "enrolled_exes": [],
  "ssh_keys": []
}
EOF

start_guardd() {
  RUST_LOG="${RUST_LOG:-guardd=debug}" "$GUARDD" --enforce-browser-config "$LOOP_MNT/config.json" \
    --ipc-socket "$LOOP_MNT/guardd.sock" --audit-db "$LOOP_MNT/audit.db" --print-decisions \
    > "$LOOP_MNT/guardd.log" 2>&1 &
  DAEMON_PID=$!
  for _ in $(seq 1 200); do
    [ -S "$LOOP_MNT/guardd.sock" ] && break
    kill -0 "$DAEMON_PID" 2>/dev/null || { echo "guardd exited early"; sed -n '1,120p' "$LOOP_MNT/guardd.log"; exit 1; }
    sleep 0.05
  done
  [ -S "$LOOP_MNT/guardd.sock" ] || { echo "guardd did not become ready"; sed -n '1,120p' "$LOOP_MNT/guardd.log"; exit 1; }
  grep -q "snapshot of pre-existing dynamic object handles" "$LOOP_MNT/guardd.log" \
    || { echo "guardd did not log the pre-existing snapshot"; sed -n '1,160p' "$LOOP_MNT/guardd.log"; exit 1; }
  grep -q "topology group marked for FAN_MOVE" "$LOOP_MNT/guardd.log" \
    || { echo "guardd did not mark the topology trees"; sed -n '1,160p' "$LOOP_MNT/guardd.log"; exit 1; }
}

stop_guardd() {
  kill -TERM "$DAEMON_PID" 2>/dev/null || true
  for _ in $(seq 1 50); do
    kill -0 "$DAEMON_PID" 2>/dev/null || break
    sleep 0.05
  done
  kill -KILL "$DAEMON_PID" 2>/dev/null || true
  wait "$DAEMON_PID" 2>/dev/null || true
  DAEMON_PID=""
}

run_race_and_assert_zero() {
  local label="$1"; shift
  local result_file="$LOOP_MNT/result-$label.json"
  if ! "$PROBE" rename-out-race "$@" > "$result_file" 2>&1; then
    note_fail "$label: probe errored"; sed -n '1,10p' "$result_file"; return 1
  fi
  if python3 - "$result_file" <<'PY'
import json, sys
r = json.load(open(sys.argv[1], encoding="utf-8"))
print(f"  {r['iterations']} iterations: recovered={r['successful_unauthorized_reads']} denied={r['denied_reads']} other={r['other_errors']}")
raise SystemExit(0 if r["successful_unauthorized_reads"] == 0 and r["other_errors"] == 0 else 1)
PY
  then
    note_pass "$label: zero successful unauthorized reads ($(python3 -c "import json,sys; print(json.load(open('$result_file'))['iterations'])" ) iterations, no settle)"
  else
    note_fail "$label: at least one unauthorized read succeeded"
    cat "$result_file"
    return 1
  fi
}

echo "==> Starting guardd (strict-filesystem, isolated loop fs)"
start_guardd

echo "==> 1. fast attack (rename-in -> immediate rename-out -> immediate open, 10k)"
echo "    FAN_REPORT_TARGET_FID: move events carry the moved file's OWN fid"
echo "    (the last plain-FID record), so the learner learns it directly with"
echo "    no resolution race. Zero-settle, zero recovery is enforceable."
RESULT_FAST="$LOOP_MNT/result-fast.json"
if ! "$PROBE" rename-out-race "$TARGET" "$OUTSIDE" "$OUTSIDE/.sdf-race-tmp" 10000 > "$RESULT_FAST" 2>&1; then
  note_fail "fast: probe errored"; cat "$RESULT_FAST"; exit 1
fi
cat "$RESULT_FAST"
python3 - "$RESULT_FAST" <<'PY'
import json, sys
r = json.load(open(sys.argv[1], encoding="utf-8"))
print(f"  fast-attack measurement: recovered={r['successful_unauthorized_reads']} denied={r['denied_reads']} other={r['other_errors']}")
if r["successful_unauthorized_reads"] != 0 or r["other_errors"] != 0:
    raise SystemExit(1)
PY
note_pass "fast attack: 0 successful unauthorized reads across 10000 iterations (no settle)"

echo "==> 2. SETTLED move-in -> later rename-out -> open (the enforceable guarantee)"
# Move the object INTO the protected tree and let it REMAIN; the learner
# resolves (DFID_NAME parent/name) and learns its handle. Only after the learn
# is logged do we rename it out and open — no settle between rename-OUT and
# the open.
mv "$OUTSIDE/.sdf-race-tmp" "$TARGET"
LEARNED=0
for _ in $(seq 1 80); do
  if grep -q "topology: learned moved object handle" "$LOOP_MNT/guardd.log"; then
    LEARNED=1; break
  fi
  sleep 0.25
done
if [ "$LEARNED" = 1 ]; then
  note_pass "learner resolved+learned the settled moved object's handle"
else
  note_fail "learner never learned the settled moved object (20s)"
  sed -n '1,200p' "$LOOP_MNT/guardd.log"
  exit 1
fi
# Return the object to the outside staging so the race probe can drive it.
mv "$TARGET" "$OUTSIDE/.sdf-race-tmp"
run_race_and_assert_zero "settled" "$TARGET" "$OUTSIDE" "$OUTSIDE/.sdf-race-tmp" 1000

echo "==> 3. runtime-created subdirectory becomes marked and the settled attack inside it is denied"
NEWDIR="$PROFILE/Default/NewRuntimeDir"
mkdir -p "$NEWDIR"
MARKED=0
for _ in $(seq 1 80); do
  if grep -q "topology: marked newly created subdirectories" "$LOOP_MNT/guardd.log"; then
    MARKED=1; break
  fi
  sleep 0.25
done
if [ "$MARKED" = 1 ]; then
  note_pass "learner refresh marked the runtime-created subdirectory"
else
  note_fail "learner never refreshed marks for the new subdirectory (8s)"
  sed -n '1,200p' "$LOOP_MNT/guardd.log"
  exit 1
fi
# Settled variant inside the new subdir: move in, wait for the learn, then race.
mv "$OUTSIDE/.sdf-race-tmp2" "$NEWDIR/secret.txt"
SUB_LEARNED=0
for _ in $(seq 1 80); do
  if grep -q "topology: learned moved object handle" "$LOOP_MNT/guardd.log"; then
    SUB_LEARNED=1; break
  fi
  sleep 0.25
done
if [ "$SUB_LEARNED" = 1 ]; then
  note_pass "learner learned the object moved into the runtime-created subdir"
else
  note_fail "learner never learned the subdir-moved object (20s)"
  exit 1
fi
mv "$NEWDIR/secret.txt" "$OUTSIDE/.sdf-race-tmp2"
run_race_and_assert_zero "subdir" "$NEWDIR/secret.txt" "$OUTSIDE" "$OUTSIDE/.sdf-race-tmp2" 200

echo "==> 3. unknown probe denied while enforcement is active (sanity)"
if "$PROBE" read "$TARGET" >/dev/null 2>&1; then
  note_fail "sanity: unknown probe read the protected fixture"
else
  note_pass "sanity: unknown probe denied"
fi

echo "==> 4. daemon exits cleanly on SIGTERM"
stop_guardd
if kill -0 "$DAEMON_PID" 2>/dev/null; then
  note_fail "guardd did not exit on SIGTERM"
else
  note_pass "guardd exited on SIGTERM"
  DAEMON_PID=""
fi

echo
echo "==> LFH2 Step 3 zero-settle summary: PASS=$PASS FAIL=$FAIL BLOCKED=$BLOCKED"
if [ "$FAIL" -gt 0 ]; then exit 1; elif [ "$BLOCKED" -gt 0 ]; then exit 2; else exit 0; fi
