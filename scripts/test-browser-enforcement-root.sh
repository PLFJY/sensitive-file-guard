#!/usr/bin/env bash
# scripts/test-browser-enforcement-root.sh
#
# Phase 06 privileged integration test for browser enforcement.
#
# RUN AS ROOT:   sudo bash scripts/test-browser-enforcement-root.sh
#
# Why root: fanotify permission-event enforcement (FAN_CLASS_CONTENT) requires
# CAP_SYS_ADMIN. The non-interactive build agent cannot obtain it, so the
# privileged tests are provided here for a human to run.
#
# This script uses ONLY synthetic data (marker strings). It contains NO network
# exfiltration code. It does not touch any real browser profile or real SSH key.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GUARDD="$REPO/target/release/guardd"
PROBE="$REPO/target/release/guard-test-probe"

PASS=0
FAIL=0
BLOCKED=0
note_pass() { echo "PASS: $1"; PASS=$((PASS+1)); }
note_fail() { echo "FAIL: $1"; FAIL=$((FAIL+1)); }
note_blocked() { echo "BLOCKED: $1"; BLOCKED=$((BLOCKED+1)); }

if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: this script must be run as root (needs CAP_SYS_ADMIN for fanotify)."
  echo "       try: sudo bash $0"
  exit 2
fi

echo "==> Building release binaries"
cd "$REPO"
cargo build --release 2>&1 | grep -E '(Compiling guardd|Compiling guard-test-probe|Finished|error)' || true
test -x "$GUARDD" || { echo "guardd binary missing"; exit 1; }
test -x "$PROBE" || { echo "guard-test-probe binary missing"; exit 1; }

WORK="$(mktemp -d -t guard-browser-enforce-XXXXXX)"
cleanup() {
  if [ -n "${GUARDD_PID:-}" ] && kill -0 "$GUARDD_PID" 2>/dev/null; then
    kill -TERM "$GUARDD_PID" 2>/dev/null || true
    wait "$GUARDD_PID" 2>/dev/null || true
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

# --- synthetic Chromium user_data_dir (Default profile) ---
CHROME_UDD="$WORK/chrome-udd"
mkdir -p "$CHROME_UDD/Default/Network"
printf 'GUARD_SYNTHETIC_COOKIE_FIXTURE' > "$CHROME_UDD/Default/Network/Cookies"
printf 'GUARD_SYNTHETIC_COOKIE_FIXTURE' > "$CHROME_UDD/Default/Network/Cookies-wal"
printf 'GUARD_SYNTHETIC_COOKIE_FIXTURE' > "$CHROME_UDD/Default/Network/Cookies-shm"
printf 'GUARD_SYNTHETIC_LOGIN_FIXTURE'  > "$CHROME_UDD/Default/Login Data"
printf 'GUARD_SYNTHETIC_WEBSTORAGE_FIXTURE' > "$CHROME_UDD/Default/Web Data"
printf '{\n  "profile": "synthetic-chromium"\n}\n' > "$CHROME_UDD/Local State"
mkdir -p "$CHROME_UDD/Default/Local Storage"
printf 'GUARD_SYNTHETIC_WEBSTORAGE_FIXTURE' > "$CHROME_UDD/Default/Local Storage/https_example.com_0.localstorage"
mkdir -p "$CHROME_UDD/Default/Sessions"
printf 'GUARD_SYNTHETIC_SESSION_FIXTURE' > "$CHROME_UDD/Default/Sessions/Session_Tab_0"
# An unprotected file (must NOT be blocked).
printf 'ordinary bookmarks' > "$CHROME_UDD/Default/Bookmarks"

# --- synthetic Firefox profile dir ---
FF_PROFILE="$WORK/ff-profile"
mkdir -p "$FF_PROFILE"
printf 'GUARD_SYNTHETIC_FIREFOX_COOKIE_FIXTURE' > "$FF_PROFILE/cookies.sqlite"
printf 'GUARD_SYNTHETIC_FIREFOX_COOKIE_FIXTURE' > "$FF_PROFILE/cookies.sqlite-wal"
printf 'GUARD_SYNTHETIC_FIREFOX_LOGIN_FIXTURE' > "$FF_PROFILE/logins.json"
printf 'GUARD_SYNTHETIC_FIREFOX_KEY4_FIXTURE'  > "$FF_PROFILE/key4.db"
mkdir -p "$FF_PROFILE/storage/default"
printf 'GUARD_SYNTHETIC_WEBSTORAGE_FIXTURE' > "$FF_PROFILE/storage/default/https+++example.com.idb"

# --- two probe identities: copy guard-test-probe to chrome-probe / firefox-probe ---
CHROME_PROBE="$WORK/chrome-probe"
FIREFOX_PROBE="$WORK/firefox-probe"
cp "$PROBE" "$CHROME_PROBE"
cp "$PROBE" "$FIREFOX_PROBE"
chmod 0755 "$CHROME_PROBE" "$FIREFOX_PROBE"

# --- enforcement config (JSON) ---
# owner_uid=0 because the script runs as root and probes run as root.
# enrolled_exes hash-enrolls the user-writable probe copies so they reach
# EnrolledUserWritable trust; exe_paths maps each probe to a BrowserId.
cat > "$WORK/config.json" <<EOF
{
  "browser_protection_level": "common",
  "browsers": [
    {
      "id": "chrome",
      "family": "chromium",
      "profile_root": "$CHROME_UDD",
      "owner_uid": 0,
      "exe_paths": ["$CHROME_PROBE"]
    },
    {
      "id": "firefox",
      "family": "firefox",
      "profile_root": "$FF_PROFILE",
      "owner_uid": 0,
      "exe_paths": ["$FIREFOX_PROBE"]
    }
  ],
  "enrolled_exes": ["$CHROME_PROBE", "$FIREFOX_PROBE"]
}
EOF

echo "==> Starting guardd browser enforcement"
"$GUARDD" --enforce-browser-config "$WORK/config.json" --print-decisions \
  > "$WORK/guardd.log" 2>&1 &
GUARDD_PID=$!

# Wait for enforcement to become active.
for _ in $(seq 1 50); do
  if grep -q "enforcement ACTIVE" "$WORK/guardd.log" 2>/dev/null; then break; fi
  kill -0 "$GUARDD_PID" 2>/dev/null || { echo "guardd exited early"; cat "$WORK/guardd.log"; exit 1; }
  sleep 0.1
done
grep -q "enforcement ACTIVE" "$WORK/guardd.log" || { echo "guardd did not become active"; cat "$WORK/guardd.log"; exit 1; }
echo "guardd active (pid=$GUARDD_PID)"
grep "enforcement ACTIVE" "$WORK/guardd.log"

COOKIES="$CHROME_UDD/Default/Network/Cookies"
COOKIES_WAL="$CHROME_UDD/Default/Network/Cookies-wal"
COOKIES_SHM="$CHROME_UDD/Default/Network/Cookies-shm"
BOOKMARKS="$CHROME_UDD/Default/Bookmarks"
WEB_DATA="$CHROME_UDD/Default/Web Data"
LOCAL_STORAGE="$CHROME_UDD/Default/Local Storage/https_example.com_0.localstorage"
TAB_STATE="$CHROME_UDD/Default/Sessions/Session_Tab_0"

echo "==> Test 1: ordinary process (cat) reads fake Cookie => denied"
if cat "$COOKIES" > "$WORK/t1.out" 2>/dev/null; then
  note_fail "cat unexpectedly read protected Cookie"
else
  note_pass "cat denied before open completed"
fi

echo "==> Test 2: ordinary process copies fake Cookie => denied (source open fails)"
if cp "$COOKIES" "$WORK/t2.copy" 2>/dev/null; then
  note_fail "cp unexpectedly copied protected Cookie"
  rm -f "$WORK/t2.copy"
else
  note_pass "cp denied because source open failed"
fi

echo "==> Test 3: symlink path to protected file => denied"
ln -sf "$COOKIES" "$WORK/sym-to-cookies"
if cat "$WORK/sym-to-cookies" > "$WORK/t3.out" 2>/dev/null; then
  note_fail "cat read protected Cookie via symlink"
else
  note_pass "symlink to protected file denied"
fi

echo "==> Test 4: hardlink to protected critical file => denied by inode mark"
ln -f "$COOKIES" "$WORK/hard-to-cookies" 2>/dev/null || {
  note_blocked "hardlink creation not supported on this filesystem ($WORK)"
}
if [ -e "$WORK/hard-to-cookies" ]; then
  if cat "$WORK/hard-to-cookies" > "$WORK/t4.out" 2>/dev/null; then
    note_fail "cat read protected Cookie via hardlink"
  else
    note_pass "hardlink to protected Cookie denied (inode mark + fd_index)"
  fi
fi

echo "==> Test 5: trusted simulated Browser A (chrome-probe) -> own profile => allowed"
if "$CHROME_PROBE" read "$COOKIES" > "$WORK/t5.out" 2>/dev/null; then
  if grep -q "GUARD_SYNTHETIC_COOKIE_FIXTURE" "$WORK/t5.out"; then
    note_pass "chrome-probe read own Cookie (allowed)"
  else
    note_fail "chrome-probe allowed but content mismatch"
  fi
else
  note_fail "chrome-probe was denied own profile"
fi

echo "==> Test 6: Browser B (firefox-probe) -> Browser A profile => denied without lease"
if "$FIREFOX_PROBE" read "$COOKIES" > "$WORK/t6.out" 2>/dev/null; then
  note_fail "firefox-probe unexpectedly read chrome Cookie without lease"
else
  note_pass "firefox-probe denied chrome Cookie (cross-browser, no lease)"
fi

echo "==> Test 7: rapid repeated denied opens do not crash daemon (no prompt storm)"
FD_BEFORE="$(ls -1 "/proc/$GUARDD_PID/fd" 2>/dev/null | wc -l)"
for _ in $(seq 1 300); do
  cat "$COOKIES" > /dev/null 2>&1 || true
done
if kill -0 "$GUARDD_PID" 2>/dev/null; then
  FD_AFTER="$(ls -1 "/proc/$GUARDD_PID/fd" 2>/dev/null | wc -l)"
  if [ "$FD_AFTER" -le $((FD_BEFORE + 5)) ]; then
    note_pass "daemon survived 300 denied opens, no fd leak (before=$FD_BEFORE after=$FD_AFTER)"
  else
    note_fail "fd leak after burst (before=$FD_BEFORE after=$FD_AFTER)"
  fi
else
  note_fail "daemon crashed during burst"
  GUARDD_PID=""
fi

echo "==> Test 8: SQLite WAL/SHM sidecar paths are covered"
if cat "$COOKIES_WAL" > "$WORK/t8wal.out" 2>/dev/null; then
  note_fail "cat read protected Cookies-wal"
else
  note_pass "Cookies-wal denied"
fi
if cat "$COOKIES_SHM" > "$WORK/t8shm.out" 2>/dev/null; then
  note_fail "cat read protected Cookies-shm"
else
  note_pass "Cookies-shm denied"
fi

echo "==> Test 8b: firefox cookies.sqlite also protected"
if cat "$FF_PROFILE/cookies.sqlite" > "$WORK/t8ff.out" 2>/dev/null; then
  note_fail "cat read protected firefox cookies.sqlite"
else
  note_pass "firefox cookies.sqlite denied"
fi

echo "==> Test 9: unprotected file (Bookmarks) opens normally (no over-blocking)"
if cat "$BOOKMARKS" > "$WORK/t9.out" 2>/dev/null; then
  if grep -q "ordinary bookmarks" "$WORK/t9.out"; then
    note_pass "unprotected Bookmarks opened normally"
  else
    note_fail "Bookmarks opened but content mismatch"
  fi
else
  note_fail "unprotected Bookmarks was blocked (over-blocking)"
fi

echo "==> Test 9b: Common leaves autofill, website storage, and tab state outside File Shield"
for path in "$WEB_DATA" "$LOCAL_STORAGE" "$TAB_STATE"; do
  if cat "$path" > /dev/null 2>&1; then
    note_pass "Common allowed unprotected $(basename "$path")"
  else
    note_fail "Common over-blocked $(basename "$path")"
  fi
done

echo "==> Test 10: firefox-probe reading own firefox profile => allowed"
if "$FIREFOX_PROBE" read "$FF_PROFILE/cookies.sqlite" > "$WORK/t10.out" 2>/dev/null; then
  if grep -q "GUARD_SYNTHETIC_FIREFOX_COOKIE_FIXTURE" "$WORK/t10.out"; then
    note_pass "firefox-probe read own cookies.sqlite (allowed)"
  else
    note_fail "firefox-probe allowed but content mismatch"
  fi
else
  note_fail "firefox-probe was denied own profile"
fi

echo "==> Test 11: chrome-probe reading firefox profile => denied (cross-browser reverse)"
if "$CHROME_PROBE" read "$FF_PROFILE/cookies.sqlite" > "$WORK/t11.out" 2>/dev/null; then
  note_fail "chrome-probe unexpectedly read firefox Cookie without lease"
else
  note_pass "chrome-probe denied firefox Cookie (cross-browser, no lease)"
fi

echo "==> Test 12: clean daemon shutdown releases resources"
if [ -n "${GUARDD_PID:-}" ]; then
  kill -TERM "$GUARDD_PID" 2>/dev/null || true
  for _ in $(seq 1 50); do
    if ! kill -0 "$GUARDD_PID" 2>/dev/null; then break; fi
    sleep 0.1
  done
  if kill -0 "$GUARDD_PID" 2>/dev/null; then
    note_fail "guardd did not exit on SIGTERM"
    kill -KILL "$GUARDD_PID" 2>/dev/null || true
    GUARDD_PID=""
  else
    note_pass "guardd exited on SIGTERM"
    GUARDD_PID=""
  fi
fi

echo
echo "==> Phase 06 root integration summary: PASS=$PASS FAIL=$FAIL BLOCKED=$BLOCKED"
echo "    (see $WORK/guardd.log for daemon decision log)"
echo
echo "NOTE: open-before-daemon limitation is documented in reports/phase-06.md:"
echo "      an fd opened BEFORE guardd protection begins cannot be retroactively"
echo "      prevented; fanotify only gates new opens. This is a known V1 boundary."
exit $FAIL
