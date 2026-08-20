#!/usr/bin/env bash
# Phase 19 strict-filesystem first-open and alias acceptance.
# Synthetic disposable profiles only; no real credentials and no networking.
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: root/CAP_SYS_ADMIN is required"
  exit 2
fi

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Build these debug artifacts as the normal user before this root-only test.
# The privileged assertion must not create a root Cargo cache.
BIN_DIR="${BIN_DIR:-$REPO/target/debug}"
GUARDD="${GUARDD:-$BIN_DIR/guardd}"
GUARDCTL="${GUARDCTL:-$BIN_DIR/guardctl}"
PROBE="${PROBE:-$BIN_DIR/guard-test-probe}"
for artifact in "$GUARDD" "$GUARDCTL" "$PROBE"; do
  [ -x "$artifact" ] || {
    echo "ERROR: missing $artifact; run cargo build -p guardd -p guardctl -p guard-test-probe as the normal user first"
    exit 2
  }
done

PASS=0
FAIL=0
BLOCKED=0
OBSERVED=0
pass() { echo "PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "FAIL: $1"; FAIL=$((FAIL + 1)); }
blocked() { echo "BLOCKED: $1"; BLOCKED=$((BLOCKED + 1)); }
observed() { echo "OBSERVED: $1"; OBSERVED=$((OBSERVED + 1)); }

# AGENTS.md LIVE-TEST SAFETY: strict-filesystem marks the fixture's
# filesystem. Fixtures MUST be on an ISOLATED loop-backed ext4 (root-fs mark
# -> total lockup; tmpfs mark wedges /tmp when the daemon stalls). TEST_FS_ROOT
# may override with a non-root non-tmpfs filesystem.
LOOP_IMG=""; LOOP_DEV=""; LOOP_MNT=""; WORK=""
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
HOLDER_PID=""
BIND_MOUNT=""
LIFECYCLE_MOUNT=""
cleanup() {
  if [ -n "$HOLDER_PID" ]; then kill -TERM "$HOLDER_PID" 2>/dev/null || true; fi
  if [ -n "$BIND_MOUNT" ]; then umount "$BIND_MOUNT" 2>/dev/null || true; fi
  if [ -n "$LIFECYCLE_MOUNT" ]; then umount "$LIFECYCLE_MOUNT" 2>/dev/null || true; fi
  if [ -n "$DAEMON_PID" ]; then
    kill -TERM "$DAEMON_PID" 2>/dev/null || true
    wait "$DAEMON_PID" 2>/dev/null || true
  fi
  if [ -n "$LOOP_DEV" ]; then
    umount "$LOOP_DEV" 2>/dev/null || true
    losetup -d "$LOOP_DEV" 2>/dev/null || true
    rm -f "$LOOP_IMG" 2>/dev/null || true
    rmdir "$LOOP_MNT" 2>/dev/null || true
  else
    rm -rf -- "$WORK"
  fi
}
trap cleanup EXIT

CHROME_ROOT="$WORK/chromium"
FIREFOX_ROOT="$WORK/firefox-profile"
STAGING="$WORK/staging"
RUNTIME="$WORK/runtime"
mkdir -p "$CHROME_ROOT/Default/Network" "$CHROME_ROOT/Default/Sessions" \
  "$FIREFOX_ROOT/storage/default/synthetic" \
  "$FIREFOX_ROOT/sessionstore-backups" "$STAGING" "$RUNTIME"

CANARY="SDF_CANARY_STRICT_$(tr -d '\n' </proc/sys/kernel/random/uuid)"
printf '%s' "$CANARY" > "$CHROME_ROOT/Default/Cookies"
printf '%s' "$CANARY" > "$CHROME_ROOT/Default/Network/Cookies"
printf '%s' "$CANARY" > "$CHROME_ROOT/Default/Sessions/Session_0"
printf '%s' "$CANARY" > "$FIREFOX_ROOT/cookies.sqlite"
printf '%s' '{"synthetic":true}' > "$CHROME_ROOT/Default/Preferences"
printf '%s' '{"synthetic":true}' > "$CHROME_ROOT/Local State"

CHROME_PROBE="$WORK/synthetic-chromium"
FIREFOX_PROBE="$WORK/synthetic-firefox"
cp "$PROBE" "$CHROME_PROBE"
cp "$PROBE" "$FIREFOX_PROBE"
chmod 0755 "$CHROME_PROBE" "$FIREFOX_PROBE"

CONFIG="$WORK/config.json"
python3 - "$CONFIG" "$CHROME_ROOT" "$FIREFOX_ROOT" "$CHROME_PROBE" "$FIREFOX_PROBE" <<'PY'
import json, sys
path, chromium, firefox, chromium_exe, firefox_exe = sys.argv[1:]
json.dump({
    "enforcement_mode": "strict-filesystem",
    "browsers": [
        {"id": "synthetic-chromium", "family": "Chromium",
         "profile_root": chromium, "owner_uid": 0, "exe_paths": [chromium_exe]},
        {"id": "synthetic-firefox", "family": "Firefox",
         "profile_root": firefox, "owner_uid": 0, "exe_paths": [firefox_exe]},
    ],
    "enrolled_exes": [chromium_exe, firefox_exe],
    "ssh_keys": [],
}, open(path, "w", encoding="utf-8"), indent=2)
PY

SOCKET="$WORK/guardd.sock"
AUDIT="$WORK/audit.db"
LOG="$WORK/guardd.log"
"$GUARDD" --enforce-browser-config "$CONFIG" --ipc-socket "$SOCKET" \
  --audit-db "$AUDIT" >"$LOG" 2>&1 &
DAEMON_PID=$!
for _ in $(seq 1 200); do
  [ -S "$SOCKET" ] && "$GUARDCTL" --socket "$SOCKET" --json status \
    >"$RUNTIME/status.json" 2>/dev/null && break
  kill -0 "$DAEMON_PID" 2>/dev/null || {
    echo "ERROR: guardd exited during strict startup"
    sed -n '1,160p' "$LOG"
    exit 1
  }
  sleep 0.025
done

if python3 - "$RUNTIME/status.json" <<'PY'
import json, sys
d=json.load(open(sys.argv[1], encoding="utf-8"))["data"]
raise SystemExit(0 if d["status"] == "ACTIVE" and
                      d["mode"] == "strict-filesystem" and
                      d["marked_filesystems"] == 1 and
                      d["required_filesystems"] == 1 and
                      d["filesystem_marks_healthy"] is True else 1)
PY
then pass "status exposes ACTIVE strict-filesystem with one deduplicated filesystem mark"
else fail "strict status/mode/filesystem count is incorrect"; fi

denied_count() {
  "$GUARDCTL" --socket "$SOCKET" --json status >"$RUNTIME/status.json"
  python3 - "$RUNTIME/status.json" <<'PY'
import json, sys
print(json.load(open(sys.argv[1], encoding="utf-8"))["data"]["denied"])
PY
}

assert_first_open_denied() {
  local label="$1" target="$2" stage="$STAGING/replacement-$PASS-$FAIL"
  mkdir -p "$(dirname "$target")"
  printf '%s' "$CANARY" > "$stage"
  local before rc
  before="$(denied_count)"
  mv -f -- "$stage" "$target"
  set +e
  "$PROBE" read "$target" >"$RUNTIME/probe.out" 2>&1
  rc=$?
  set -e
  local after
  after="$(denied_count)"
  if [ "$rc" -ne 0 ] && [ "$after" -gt "$before" ] \
    && ! grep -Fq -- "$CANARY" "$RUNTIME/probe.out"; then
    pass "$label denied on the first unauthorized open"
  else
    fail "$label was not proven denied on its first unauthorized open"
  fi
}

echo "==> Strict namespace first-open matrix (no convergence waits)"
assert_first_open_denied "Chromium Network/Cookies" "$CHROME_ROOT/Default/Network/Cookies"
assert_first_open_denied "Chromium Cookies-wal" "$CHROME_ROOT/Default/Network/Cookies-wal"
assert_first_open_denied "Chromium Cookies-shm" "$CHROME_ROOT/Default/Network/Cookies-shm"
assert_first_open_denied "Chromium Local State" "$CHROME_ROOT/Local State"
assert_first_open_denied "Chromium Session descendant" "$CHROME_ROOT/Default/Sessions/new/Session_1"
assert_first_open_denied "Chromium new-profile Cookies" "$CHROME_ROOT/Profile 2/Network/Cookies"
assert_first_open_denied "Firefox cookies.sqlite" "$FIREFOX_ROOT/cookies.sqlite"
assert_first_open_denied "Firefox storage descendant" "$FIREFOX_ROOT/storage/default/synthetic/data.sqlite"
assert_first_open_denied "Firefox sessionstore descendant" "$FIREFOX_ROOT/sessionstore-backups/recovery.jsonlz4"

echo "==> Existing-inode alias regressions"
KNOWN="$CHROME_ROOT/Default/Cookies"
ln -s "$KNOWN" "$RUNTIME/known-symlink"
before="$(denied_count)"; set +e; "$PROBE" read "$RUNTIME/known-symlink" >/dev/null 2>&1; rc=$?; set -e
after="$(denied_count)"
if [ "$rc" -ne 0 ] && [ "$after" -gt "$before" ]; then pass "symlink remains denied"; else fail "symlink regression"; fi

if ln "$KNOWN" "$RUNTIME/known-hardlink" 2>/dev/null; then
  before="$(denied_count)"; set +e; "$PROBE" read "$RUNTIME/known-hardlink" >/dev/null 2>&1; rc=$?; set -e
  after="$(denied_count)"
  if [ "$rc" -ne 0 ] && [ "$after" -gt "$before" ]; then pass "known-inode hardlink remains denied"; else fail "known-inode hardlink regression"; fi
else
  blocked "known-inode hardlink unsupported on fixture filesystem"
fi

mv "$KNOWN" "$CHROME_ROOT/Default/Cookies.renamed"
before="$(denied_count)"; set +e; "$PROBE" read "$CHROME_ROOT/Default/Cookies.renamed" >/dev/null 2>&1; rc=$?; set -e
after="$(denied_count)"
if [ "$rc" -ne 0 ] && [ "$after" -gt "$before" ]; then pass "renamed known inode remains denied"; else fail "renamed-inode regression"; fi
mv "$CHROME_ROOT/Default/Cookies.renamed" "$KNOWN"

READY="$RUNTIME/held.ready"
"$CHROME_PROBE" hold-fd "$KNOWN" "$READY" >/dev/null 2>&1 &
HOLDER_PID=$!
for _ in $(seq 1 100); do [ -s "$READY" ] && break; sleep 0.02; done
if [ -s "$READY" ]; then
  read -r held_pid held_fd <"$READY"
  before="$(denied_count)"; set +e; "$PROBE" proc-fd "$held_pid" "$held_fd" >/dev/null 2>&1; rc=$?; set -e
  after="$(denied_count)"
  if [ "$rc" -ne 0 ] && [ "$after" -gt "$before" ]; then pass "/proc/PID/fd reopen remains denied"; else fail "/proc/PID/fd reopen regression"; fi
else
  fail "authorized holder could not open its synthetic profile resource"
fi
kill -TERM "$HOLDER_PID" 2>/dev/null || true
wait "$HOLDER_PID" 2>/dev/null || true
HOLDER_PID=""

if "$CHROME_PROBE" open-bench "$CHROME_ROOT/Default/Network/Cookies" 1 \
  >"$RUNTIME/allowed.json" && python3 - "$RUNTIME/allowed.json" <<'PY'
import json, sys
r=json.load(open(sys.argv[1], encoding="utf-8"))
raise SystemExit(0 if r["successful"] == 1 and r["denied"] == 0 else 1)
PY
then pass "enrolled Chromium still opens its own protected data"
else fail "strict mode regressed owning-browser allow policy"; fi

echo "==> Structural-hit inode promotion and rename-away"
A_TARGET="$CHROME_ROOT/Profile A/Network/Cookies"
A_EXTERNAL="$RUNTIME/rename-away-authorized"
A_STAGE="$STAGING/rename-away-authorized"
mkdir -p "$(dirname "$A_TARGET")"
printf '%s' "$CANARY" >"$A_STAGE"
before="$(denied_count)"
if "$CHROME_PROBE" promote-rename "$A_STAGE" "$A_TARGET" "$A_EXTERNAL" \
  >"$RUNTIME/rename-away-a.json"; then
  set +e
  "$PROBE" read "$A_EXTERNAL" >"$RUNTIME/rename-away-a.out" 2>&1
  rc=$?
  set -e
  after="$(denied_count)"
  if [ "$rc" -ne 0 ] && [ "$after" -gt "$before" ] \
    && ! grep -Fq -- "$CANARY" "$RUNTIME/rename-away-a.out"; then
    pass "A: authorized first structural open promotes inode before rename-away"
  else
    fail "A: authorized new sensitive inode was readable after rename-away"
  fi
else
  fail "A: enrolled browser could not publish/open/rename the synthetic inode"
fi

B_TARGET="$CHROME_ROOT/Profile B/Network/Cookies"
B_EXTERNAL="$RUNTIME/rename-away-denied"
B_STAGE="$STAGING/rename-away-denied"
mkdir -p "$(dirname "$B_TARGET")"
printf '%s' "$CANARY" >"$B_STAGE"
mv "$B_STAGE" "$B_TARGET"
before="$(denied_count)"
if "$PROBE" deny-rename-retry "$B_TARGET" "$B_EXTERNAL" \
    >"$RUNTIME/rename-away-b.json" \
  && python3 - "$RUNTIME/rename-away-b.json" <<'PY'
import json, sys
r=json.load(open(sys.argv[1], encoding="utf-8"))
raise SystemExit(0 if r["first_denied"] is True and
                      r["second_denied"] is True and
                      r["successful_unauthorized_opens"] == 0 else 1)
PY
then
  after="$(denied_count)"
  if [ "$after" -ge $((before + 2)) ]; then
    pass "B: denied structural first open promotes inode before rename-away retry"
  else
    fail "B: both opens failed but two firewall DENY events were not recorded"
  fi
else
  fail "B: denied new sensitive inode became readable after rename-away"
fi

C_TARGET="$CHROME_ROOT/Profile C/Network/Cookies"
C_EXTERNAL="$RUNTIME/rename-away-without-open"
C_STAGE="$STAGING/rename-away-without-open"
mkdir -p "$(dirname "$C_TARGET")"
printf '%s' "$CANARY" >"$C_STAGE"
if "$PROBE" transit-rename "$C_STAGE" "$C_TARGET" "$C_EXTERNAL" \
    >"$RUNTIME/rename-away-c.json" \
  && python3 - "$RUNTIME/rename-away-c.json" <<'PY'
import json, sys
r=json.load(open(sys.argv[1], encoding="utf-8"))
raise SystemExit(0 if r["opened_while_protected"] is False and
                      r["outside_opened"] is True else 1)
PY
then
  observed "C: an inode moved through a sensitive name without an open is not labeled by FAN_OPEN_PERM"
else
  observed "C: no-open transit did not reproduce on this run; FAN_OPEN_PERM still cannot mediate rename"
fi

echo "==> Alias-scan amplification stress"
ALIAS_FLOOD_A="$RUNTIME/unprotected-nlink-file"
ALIAS_FLOOD_B="$RUNTIME/unprotected-nlink-alias"
printf '%s' 'synthetic-non-secret' >"$ALIAS_FLOOD_A"
ln "$ALIAS_FLOOD_A" "$ALIAS_FLOOD_B"
"$GUARDCTL" --socket "$SOCKET" --json status >"$RUNTIME/alias-flood-before.json"
flood_started="$(date +%s%N)"
flood_pids=()
flood_iterations="${ALIAS_FLOOD_ITERATIONS:-2000}"
for worker in $(seq 1 8); do
  "$PROBE" open-bench "$ALIAS_FLOOD_A" "$flood_iterations" \
    >"$RUNTIME/alias-flood-$worker.json" &
  flood_pids+=("$!")
done
flood_ok=1
for flood_pid in "${flood_pids[@]}"; do
  if ! wait "$flood_pid"; then flood_ok=0; fi
done
flood_elapsed_ms=$(( ( $(date +%s%N) - flood_started ) / 1000000 ))
"$GUARDCTL" --socket "$SOCKET" --json status >"$RUNTIME/alias-flood-after.json"
if [ "$flood_ok" -eq 1 ] && python3 - \
    "$RUNTIME/alias-flood-before.json" "$RUNTIME/alias-flood-after.json" \
    "$RUNTIME"/alias-flood-[0-9]*.json <<'PY'
import json, sys
before=json.load(open(sys.argv[1], encoding="utf-8"))["data"]
after=json.load(open(sys.argv[2], encoding="utf-8"))["data"]
workloads=[json.load(open(p, encoding="utf-8")) for p in sys.argv[3:]]
expected=sum(r["iterations"] for r in workloads)
ok=(all(r["successful"] == r["iterations"] and r["other_errors"] == 0 for r in workloads)
    and after["strict_alias_scans"] - before["strict_alias_scans"] >= expected
    and after["fanotify_overflows"] == before["fanotify_overflows"]
    and after["classifier_failures"] == before["classifier_failures"]
    and after["audit_dropped"] == before["audit_dropped"])
raise SystemExit(0 if ok else 1)
PY
then
  pass "alias-scan amplification completed $((8 * flood_iterations)) opens in ${flood_elapsed_ms} ms without overflow or audit loss"
else
  fail "alias-scan amplification caused errors, overflow, classifier failure, or audit loss"
fi

echo "==> New-inode external-hardlink investigation"
"$PROBE" alias-race "$CHROME_ROOT/Default/Network/Cookies" "$STAGING" \
  "$RUNTIME/external-cookie-alias" "${ALIAS_ITERATIONS:-1000}" >"$RUNTIME/alias.json"
python3 - "$RUNTIME/alias.json" <<'PY'
import json, sys
r=json.load(open(sys.argv[1], encoding="utf-8"))
print("Alias race measurement:")
for key in ("iterations", "successful_unauthorized_reads", "denied_reads", "other_errors"):
    print(f"  {key}: {r[key]}")
PY
if python3 - "$RUNTIME/alias.json" <<'PY'
import json, sys
r=json.load(open(sys.argv[1], encoding="utf-8"))
raise SystemExit(0 if r["successful_unauthorized_reads"] == 0 and r["other_errors"] == 0 else 1)
PY
then pass "new replacement inode external hardlink had zero recoveries"
else fail "new replacement inode external hardlink is a reproducible first-open bypass"; fi

echo "==> Optional bind-mount alias"
BIND_MOUNT="$WORK/bind-alias"
mkdir "$BIND_MOUNT"
if mount --bind "$CHROME_ROOT" "$BIND_MOUNT" 2>/dev/null; then
  before="$(denied_count)"; set +e; "$PROBE" read "$BIND_MOUNT/Default/Network/Cookies" >/dev/null 2>&1; rc=$?; set -e
  after="$(denied_count)"
  if [ "$rc" -ne 0 ] && [ "$after" -gt "$before" ]; then pass "bind-mount alias of indexed protected inode denied"; else fail "bind-mount alias bypassed indexed protection"; fi
  umount "$BIND_MOUNT"
  BIND_MOUNT=""
else
  blocked "bind mount is unavailable under current host policy"
  BIND_MOUNT=""
fi

"$GUARDCTL" --socket "$SOCKET" --json status >"$RUNTIME/final-status.json"
if python3 - "$RUNTIME/final-status.json" <<'PY'
import json, sys
d=json.load(open(sys.argv[1], encoding="utf-8"))["data"]
raise SystemExit(0 if d["fanotify_overflows"] == 0 and
                      d["classifier_failures"] == 0 and
                      not d["topology_degraded"] else 1)
PY
then pass "strict backend remained healthy with zero overflow/classifier/topology degradation"
else fail "strict backend reported degraded health"; fi

if grep -aFq -- "$CANARY" "$LOG" "$AUDIT"; then
  fail "synthetic canary content appeared in daemon log or audit DB"
else
  pass "daemon log and audit DB contain no synthetic secret content"
fi

kill -TERM "$DAEMON_PID"
wait "$DAEMON_PID"
DAEMON_PID=""
pass "strict daemon shut down without self-deadlock after topology and audit activity"

echo "==> Filesystem mark lifecycle"
LIFECYCLE_MOUNT="$WORK/lifecycle-mount"
mkdir "$LIFECYCLE_MOUNT"
if mount -t tmpfs -o size=8m guard-phase19-lifecycle "$LIFECYCLE_MOUNT" 2>/dev/null; then
  mkdir -p "$LIFECYCLE_MOUNT/Default/Network"
  printf '%s' '{}' >"$LIFECYCLE_MOUNT/Default/Preferences"
  printf '%s' "$CANARY" >"$LIFECYCLE_MOUNT/Default/Network/Cookies"
  LIFECYCLE_CONFIG="$WORK/lifecycle.json"
  python3 - "$LIFECYCLE_CONFIG" "$LIFECYCLE_MOUNT" <<'PY'
import json, sys
json.dump({"enforcement_mode":"strict-filesystem","browsers":[{
  "id":"lifecycle","family":"Chromium","profile_root":sys.argv[2],
  "owner_uid":0,"exe_paths":[]}],"enrolled_exes":[],"ssh_keys":[]},
  open(sys.argv[1], "w", encoding="utf-8"))
PY
  LIFECYCLE_SOCKET="$WORK/lifecycle.sock"
  "$GUARDD" --enforce-browser-config "$LIFECYCLE_CONFIG" \
    --ipc-socket "$LIFECYCLE_SOCKET" --audit-db "$WORK/lifecycle-audit.db" \
    >"$RUNTIME/lifecycle.log" 2>&1 &
  DAEMON_PID=$!
  for _ in $(seq 1 200); do
    [ -S "$LIFECYCLE_SOCKET" ] \
      && "$GUARDCTL" --socket "$LIFECYCLE_SOCKET" --json status \
        >"$RUNTIME/lifecycle-before.json" 2>/dev/null && break
    kill -0 "$DAEMON_PID" 2>/dev/null || break
    sleep 0.025
  done
  umount "$LIFECYCLE_MOUNT"
  mount -t tmpfs -o size=8m guard-phase19-lifecycle-reappeared "$LIFECYCLE_MOUNT"
  "$GUARDCTL" --socket "$LIFECYCLE_SOCKET" --json status \
    >"$RUNTIME/lifecycle-after.json"
  if python3 - "$RUNTIME/lifecycle-before.json" "$RUNTIME/lifecycle-after.json" <<'PY'
import json, sys
before=json.load(open(sys.argv[1], encoding="utf-8"))["data"]
after=json.load(open(sys.argv[2], encoding="utf-8"))["data"]
raise SystemExit(0 if before["status"] == "ACTIVE" and
                      before["filesystem_marks_healthy"] is True and
                      before["marked_filesystems"] == 1 and
                      after["status"] == "DEGRADED" and
                      after["filesystem_marks_healthy"] is False and
                      after["marked_filesystems"] == 0 and
                      after["required_filesystems"] == 1 else 1)
PY
  then
    pass "unmount/remount mark loss is observed and status becomes DEGRADED"
  else
    fail "filesystem mark loss was not reflected in strict status"
  fi
  kill -TERM "$DAEMON_PID"
  wait "$DAEMON_PID"
  DAEMON_PID=""
  umount "$LIFECYCLE_MOUNT"
  LIFECYCLE_MOUNT=""
else
  blocked "tmpfs lifecycle mount unavailable under current host policy"
  LIFECYCLE_MOUNT=""
fi

MISSING_CONFIG="$WORK/missing.json"
python3 - "$MISSING_CONFIG" "$WORK/does-not-exist" <<'PY'
import json, sys
json.dump({"enforcement_mode":"strict-filesystem","browsers":[{
  "id":"missing","family":"Chromium","profile_root":sys.argv[2],
  "owner_uid":0,"exe_paths":[]}],"enrolled_exes":[],"ssh_keys":[]},
  open(sys.argv[1], "w", encoding="utf-8"))
PY
set +e
timeout 3 "$GUARDD" --enforce-browser-config "$MISSING_CONFIG" \
  --audit-db "$WORK/missing-audit.db" >"$RUNTIME/missing.log" 2>&1
missing_rc=$?
set -e
if [ "$missing_rc" -ne 0 ] && [ "$missing_rc" -ne 124 ] \
  && ! grep -q 'enforcement ACTIVE' "$RUNTIME/missing.log"; then
  pass "strict startup fails closed when a required protected root cannot be marked"
else
  fail "strict startup did not fail closed for a missing required root"
fi

echo
echo "Strict filesystem summary: PASS=$PASS FAIL=$FAIL BLOCKED=$BLOCKED OBSERVED=$OBSERVED"
if [ "$FAIL" -gt 0 ]; then exit 1; elif [ "$BLOCKED" -gt 0 ]; then exit 2; else exit 0; fi
