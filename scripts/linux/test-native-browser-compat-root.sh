#!/usr/bin/env bash
# scripts/linux/test-native-browser-compat-root.sh
#
# LFH6 privileged integration: real installed browsers + DISPOSABLE synthetic
# profiles. Verifies the legal workload runs (own reads allowed), concurrent
# unknown probes are denied on every protected artifact, the daemon observes
# zero overflow / classifier failure / unexpected DENY, and continuity stays
# INTACT. Never touches a real profile.
#
#   sudo bash scripts/linux/test-native-browser-compat-root.sh
#
# guardd runs as root (fanotify FAN_CLASS_CONTENT needs CAP_SYS_ADMIN); the
# browsers and probes run as the invoking user (SUDO_USER) because Firefox
# refuses to run as root. Browsers that are not installed are reported as
# NOT INSTALLED (not FAIL). Exit code = number of FAILs.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
GUARDD="$REPO/target/release/guardd"
GUARDCTL="$REPO/target/release/guardctl"
PROBE="$REPO/target/release/guard-test-probe"

PASS=0
FAIL=0
BLOCKED=0
NOT_INSTALLED=0
note_pass() { echo "PASS: $1"; PASS=$((PASS + 1)); }
note_fail() { echo "FAIL: $1"; FAIL=$((FAIL + 1)); }
note_blocked() { echo "BLOCKED: $1"; BLOCKED=$((BLOCKED + 1)); }

if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: run as root (fanotify FAN_CLASS_CONTENT requires CAP_SYS_ADMIN)"
  echo "  sudo bash scripts/linux/test-native-browser-compat-root.sh"
  exit 2
fi
if [ -n "${SUDO_USER:-}" ]; then
  TEST_USER="$SUDO_USER"
else
  echo "ERROR: run via sudo so the browsers can run as a non-root user"
  echo "  (Firefox refuses to run as root)."
  exit 2
fi
for bin in "$GUARDD" "$GUARDCTL" "$PROBE"; do
  test -x "$bin" || { echo "ERROR: missing $bin; build as the normal user first"; exit 2; }
done
id -u "$TEST_USER" >/dev/null 2>&1 || { echo "ERROR: unknown user $TEST_USER"; exit 2; }
TEST_UID="$(id -u "$TEST_USER")"
TEST_GID="$(id -g "$TEST_USER")"

run_as() { runuser -u "$TEST_USER" -- "$@"; }

WORK="$(mktemp -d -t guard-lfh6-XXXXXX)"
DAEMON_PID=""
cleanup() {
  if [ -n "$DAEMON_PID" ] && kill -0 "$DAEMON_PID" 2>/dev/null; then
    kill -TERM "$DAEMON_PID" 2>/dev/null || true
    wait "$DAEMON_PID" 2>/dev/null || true
  fi
  pkill -u "$TEST_USER" -f "$WORK" 2>/dev/null || true
  rm -rf -- "$WORK"
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Browser detection (NOT INSTALLED is not a failure)
# ---------------------------------------------------------------------------
declare -a BROWSERS=()
detect_browser() { # id family elf
  local id="$1" family="$2" elf="$3"
  if [ -x "$elf" ]; then
    BROWSERS+=("$id|$family|$elf")
    echo "detected: $id ($family) at $elf"
  else
    note_blocked "$id NOT INSTALLED (not a failure)"
    NOT_INSTALLED=$((NOT_INSTALLED + 1))
  fi
}
detect_browser firefox Firefox /usr/lib/firefox/firefox
detect_browser firefox-esr Firefox /usr/lib/firefox-esr/firefox
detect_browser chromium Chromium /usr/bin/chromium
detect_browser google-chrome Chromium /usr/bin/google-chrome
detect_browser zen Firefox /usr/bin/zen
detect_browser zen Firefox /opt/zen/zen

if [ "${#BROWSERS[@]}" -eq 0 ]; then
  echo "ERROR: no supported browser detected"
  exit 2
fi

# ---------------------------------------------------------------------------
# Per-browser compat run
# ---------------------------------------------------------------------------
run_browser_compat() {
  local id="$1" family="$2" elf="$3"
  echo
  echo "==> LFH6 compat run: $id ($family) elf=$elf"
  local B="$WORK/$id"
  local PROFILE="$B/profile"
  mkdir -p "$PROFILE"
  # The whole WORK tree (not just $B) must be traversable by the browser user:
  # mktemp -d leaves a root-owned 0700 parent, which plfjy cannot cross.
  chown -R "$TEST_USER:$TEST_USER" "$WORK"

  local launch=()
  local artifact=""
  if [ "$family" = "Firefox" ]; then
    launch=(--headless --no-remote --profile "$PROFILE")
    artifact="$PROFILE/cookies.sqlite"
  else
    launch=(--headless --new --no-sandbox --no-first-run --no-default-browser-check \
      --user-data-dir="$PROFILE")
    artifact="$PROFILE/Default/Network/Cookies"
  fi

  # --- populate the disposable profile (legal workload part 1) ---
  echo "    launching $id headless to populate the disposable profile"
  run_as "$elf" "${launch[@]}" about:blank >"$B/populate.log" 2>&1 &
  local pop_pid=$!
  local waited=0
  while [ ! -f "$artifact" ] && [ "$waited" -lt 120 ]; do
    if ! kill -0 "$pop_pid" 2>/dev/null; then
      # The browser exited before creating the artifact — dump its stderr so
      # the failure is diagnosable instead of a silent timeout.
      echo "    $id exited early; stderr tail:"
      tail -5 "$B/populate.log" 2>/dev/null || true
      break
    fi
    sleep 0.5; waited=$((waited + 1))
  done
  if [ ! -f "$artifact" ]; then
    echo "    $id did not create $artifact (waited ${waited}x0.5s); see $B/populate.log"
    kill "$pop_pid" 2>/dev/null || true
    wait "$pop_pid" 2>/dev/null || true
    # An INSTALLED browser that cannot even populate a disposable profile is a
    # real compatibility failure, not a NOT INSTALLED skip.
    note_fail "$id disposable profile population (installed but no artifact)"
    return 1
  fi
  sleep 4   # settle: storage tree, sessionstore, sidecars
  kill "$pop_pid" 2>/dev/null || true
  wait "$pop_pid" 2>/dev/null || true
  sleep 1

  # Probe fixtures INSIDE protected trees must exist BEFORE guardd starts:
  # once enforcement is live, no external (unknown) process can create them —
  # the firewall denies the write, which is exactly the behavior under test.
  if [ "$family" = "Firefox" ]; then
    mkdir -p "$PROFILE/storage/default"
    chown -R "$TEST_USER:$TEST_USER" "$PROFILE/storage"
    run_as "$PROBE" write-file "$PROFILE/storage/default/probe-target.ls" fixture
  else
    mkdir -p "$PROFILE/Default/Sessions"
    chown -R "$TEST_USER:$TEST_USER" "$PROFILE/Default/Sessions"
    run_as "$PROBE" write-file "$PROFILE/Default/Sessions/probe-target.session" fixture
  fi

  # --- config + guardd ---
  cat > "$B/config.json" <<EOF
{
  "config_version": 1,
  "enforcement_mode": "conservative",
  "browsers": [
    {
      "id": "$id",
      "family": "$family",
      "profile_root": "$PROFILE",
      "owner_uid": $TEST_UID,
      "exe_paths": ["$elf"]
    }
  ],
  "enrolled_exes": ["$elf"],
  "ssh_keys": []
}
EOF
  echo "    starting guardd"
  "$GUARDD" --enforce-browser-config "$B/config.json" \
    --ipc-socket "$B/guardd.sock" --audit-db "$B/audit.db" --print-decisions \
    > "$B/guardd.log" 2>&1 &
  DAEMON_PID=$!
  local ready=0
  for _ in $(seq 1 100); do
    [ -S "$B/guardd.sock" ] && { ready=1; break; }
    kill -0 "$DAEMON_PID" 2>/dev/null || { echo "guardd exited early"; cat "$B/guardd.log"; return 1; }
    sleep 0.05
  done
  [ "$ready" = 1 ] || { echo "guardd did not become ready"; cat "$B/guardd.log"; return 1; }
  local STATUS=""
  for _ in $(seq 1 100); do
    STATUS="$("$GUARDCTL" --socket "$B/guardd.sock" --json status 2>/dev/null || true)"
    [ -n "$STATUS" ] && echo "$STATUS" | grep -qE '"enforcement_active"[[:space:]]*:[[:space:]]*true' && break
    sleep 0.05
  done
  if ! echo "$STATUS" | grep -qE '"enforcement_active"[[:space:]]*:[[:space:]]*true'; then
    echo "    guardd did not become ACTIVE"
    echo "$STATUS" | head -3
    cat "$B/guardd.log"
    return 1
  fi

  # --- concurrent unknown probes (background) ---
  local probe_pids=()
  probe_expect_denied() { # path
    if [ -e "$1" ]; then
      # setpriv EXECs the probe directly, so $! IS the pid guardd sees (an
      # unknown same-uid process). runuser would fork and hide the probe pid.
      setpriv --reuid="$TEST_UID" --regid="$TEST_GID" --clear-groups \
        "$PROBE" read "$1" >"$B/probe-$(basename "$1").out" 2>&1 &
      probe_pids+=("$!")
    else
      echo "    (probe target $1 absent; skipped)"
    fi
  }
  echo "    launching unknown probes (must all be denied)"
  if [ "$family" = "Firefox" ]; then
    probe_expect_denied "$PROFILE/cookies.sqlite"
    probe_expect_denied "$PROFILE/logins.json"
    probe_expect_denied "$PROFILE/key4.db"
    probe_expect_denied "$PROFILE/sessionstore-backups/recovery.jsonlz4"
    probe_expect_denied "$PROFILE/storage/default/probe-target.ls"
  else
    probe_expect_denied "$PROFILE/Default/Network/Cookies"
    probe_expect_denied "$PROFILE/Default/Login Data"
    probe_expect_denied "$PROFILE/Local State"
    probe_expect_denied "$PROFILE/Default/Sessions/probe-target.session"
  fi

  # --- legal workload part 2: relaunch the browser against the protected
  # --- disposable profile, settle, restart, and let the browser itself do DB
  # --- writes/compaction (an external process cannot replace a protected DB —
  # --- open(2) on it is denied by the firewall, which is the behavior under
  # --- test; only the browser's own access is the legal path).
  echo "    legal workload: $id relaunch (startup settle, tabs, writes, restart)"
  run_as "$elf" "${launch[@]}" about:blank "file://$B/harmless.html" >"$B/wl1.log" 2>&1 &
  local wl1=$!
  sleep 8
  kill "$wl1" 2>/dev/null || true
  wait "$wl1" 2>/dev/null || true
  sleep 1
  run_as "$elf" "${launch[@]}" about:blank >"$B/wl2.log" 2>&1 &
  local wl2=$!
  sleep 8
  # Wait for the probe decisions to settle, then collect.
  for p in "${probe_pids[@]}"; do wait "$p" 2>/dev/null || true; done
  kill "$wl2" 2>/dev/null || true
  wait "$wl2" 2>/dev/null || true
  sleep 1

  # --- oracles ---
  local json=""
  json="$("$GUARDCTL" --socket "$B/guardd.sock" --json status 2>/dev/null || true)"
  local continuity overflows classifier unclassified audit_dropped
  continuity="$(echo "$json" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(((d.get("data") or {}).get("linux_health") or {}).get("continuity","?"))' 2>/dev/null || echo "?")"
  overflows="$(echo "$json" | python3 -c 'import json,sys; d=json.load(sys.stdin); print((d.get("data") or {}).get("fanotify_overflows","?"))' 2>/dev/null || echo "?")"
  classifier="$(echo "$json" | python3 -c 'import json,sys; d=json.load(sys.stdin); print((d.get("data") or {}).get("classifier_failures","?"))' 2>/dev/null || echo "?")"
  unclassified="$(echo "$json" | python3 -c 'import json,sys; d=json.load(sys.stdin); print((d.get("data") or {}).get("unclassified","?"))' 2>/dev/null || echo "?")"
  audit_dropped="$(echo "$json" | python3 -c 'import json,sys; d=json.load(sys.stdin); print((d.get("data") or {}).get("audit_dropped","?"))' 2>/dev/null || echo "?")"

  [ "$continuity" = "INTACT" ] && note_pass "$id continuity=INTACT" \
    || note_fail "$id continuity=$continuity"
  [ "$overflows" = "0" ] && note_pass "$id fanotify_overflows=0" \
    || note_fail "$id fanotify_overflows=$overflows"
  [ "$classifier" = "0" ] && note_pass "$id classifier_failures=0" \
    || note_fail "$id classifier_failures=$classifier"
  [ "$unclassified" = "0" ] && note_pass "$id unclassified=0" \
    || note_fail "$id unclassified=$unclassified"
  [ "$audit_dropped" = "0" ] && note_pass "$id audit_dropped=0" \
    || note_fail "$id audit_dropped=$audit_dropped"

  # Unknown probes: every probe must have been DENIED (non-zero exit). A
  # denied probe prints its error to stderr only, so the exit code is the
  # oracle (never the output size).
  local nprobe=0 ndenied=0 probe_ok=1
  for p in "${probe_pids[@]}"; do
    nprobe=$((nprobe + 1))
    if wait "$p"; then
      note_fail "$id probe pid $p READ protected data (deny missed)"
      probe_ok=0
    else
      ndenied=$((ndenied + 1))
    fi
  done
  [ "$probe_ok" = 1 ] && note_pass "$id unknown probes denied ($ndenied/$nprobe)" \
    || note_fail "$id unknown probes: only $ndenied/$nprobe denied"

  # Unexpected DENY: every DENY in the daemon log whose pid is NOT a probe pid
  # means the legal browser workload was denied. Probe pids were recorded
  # before the workload relaunches; the probe binaries exited quickly, so a
  # late DENY with an unknown pid is treated as unexpected unless it is one of
  # the recorded probe pids.
  local unexpected=0
  while read -r line; do
    local pid
    pid="$(echo "$line" | sed -n 's/.*pid=\([0-9]*\).*/\1/p')"
    if [ -n "$pid" ] && ! printf '%s\n' "${probe_pids[@]}" | grep -qx "$pid"; then
      unexpected=$((unexpected + 1))
      echo "    UNEXPECTED DENY: $line"
    fi
  done < <(grep "DENY(" "$B/guardd.log" || true)
  [ "$unexpected" = 0 ] && note_pass "$id no unexpected DENY on legal workload" \
    || note_fail "$id $unexpected unexpected DENY on legal workload"

  # Legal workload itself must still function: the second run must have
  # produced a live profile (cookies recreated after replacement).
  if [ -f "$artifact" ]; then
    note_pass "$id legal workload left a live profile artifact"
  else
    note_fail "$id legal workload lost the profile artifact"
  fi

  kill -TERM "$DAEMON_PID" 2>/dev/null || true
  for _ in $(seq 1 50); do
    if ! kill -0 "$DAEMON_PID" 2>/dev/null; then break; fi
    sleep 0.05
  done
  DAEMON_PID=""
  echo "    $id compat run finished (see $B/guardd.log)"
}

echo "==> writing harmless local page"
printf '<html><body>lfh6 harmless local page</body></html>' > "$WORK/harmless.html"
chown "$TEST_USER:$TEST_USER" "$WORK/harmless.html"

for entry in "${BROWSERS[@]}"; do
  IFS='|' read -r id family elf <<< "$entry"
  run_browser_compat "$id" "$family" "$elf" || note_fail "$id compat run aborted"
done

echo
echo "==> LFH6 native browser compat summary: PASS=$PASS FAIL=$FAIL BLOCKED=$BLOCKED NOT_INSTALLED=$NOT_INSTALLED"
echo "    logs: $WORK"
exit $FAIL
