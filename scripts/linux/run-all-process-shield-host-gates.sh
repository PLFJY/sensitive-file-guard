#!/usr/bin/env bash
# Formal physical-host Process Shield manifest. It is intentionally separate
# from the capsule File Shield runner: nspawn currently blocks BPF program
# loading with EPERM, so capsule evidence cannot establish these BPF gates.
# Run only through the explicitly user-authorized polkit fallback. Exit 0 PASS,
# 1 FAIL, 2 BLOCKED. All artifacts must have been built by the normal user.
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "BLOCKED: run this formal host manifest through authorized polkit"
  exit 2
fi

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN_DIR="${BIN_DIR:-$REPO/target/release}"
EVIDENCE_ROOT="${EVIDENCE_ROOT:-/tmp/sfg-process-shield-formal-$(date +%Y%m%d-%H%M%S)}"
SFG_GIT_COMMIT="${SFG_GIT_COMMIT:-unknown}"
SFG_TEST_USER="${SFG_TEST_USER:-${PKEXEC_UID:-${SUDO_USER:-}}}"

[ -d "$BIN_DIR" ] || { echo "BLOCKED: missing BIN_DIR $BIN_DIR"; exit 2; }
if [ -z "$SFG_TEST_USER" ] || ! getent passwd "$SFG_TEST_USER" >/dev/null; then
  echo "BLOCKED: SFG_TEST_USER or PKEXEC_UID must identify a local non-root user"; exit 2
fi
if [ "$(id -u "$SFG_TEST_USER")" -eq 0 ]; then echo "BLOCKED: test user must be non-root"; exit 2; fi
SFG_TEST_UID="$(id -u "$SFG_TEST_USER")"
mkdir -p "$EVIDENCE_ROOT"

# name|script|environment assignments. The count comes from this manifest.
declare -a FORMAL_MANIFEST=(
  "authority-admission|scripts/linux/test-lps2-firefox-authority-root.sh|BIN_DIR=$REPO/target/debug PROCESS_SHIELD_ENABLED=true TEST_USER=$SFG_TEST_USER"
  "firefox-compatibility|scripts/linux/test-native-browser-compat-root.sh|PROCESS_SHIELD_ENABLED=true FIREFOX_ONLY=true PKEXEC_UID=$SFG_TEST_USER"
  "adversarial-primitives|scripts/linux/test-lps5-adversarial-root.sh|TEST_UID=$SFG_TEST_UID"
  "daemon-integrated-adversarial|scripts/linux/test-lps5-daemon-integrated-root.sh|TEST_USER=$SFG_TEST_USER"
  "lifecycle-and-performance|scripts/linux/test-lps6-lifecycle-root.sh|TEST_UID=$SFG_TEST_UID"
)

PASS=0; FAIL=0; BLOCKED=0; SELECTED=0
SUMMARY="$EVIDENCE_ROOT/summary.txt"
: > "$SUMMARY"
printf 'git_commit=%s\nkernel=%s\nbin_dir=%s\nartifacts:\n' "$SFG_GIT_COMMIT" "$(uname -a)" "$BIN_DIR" >> "$SUMMARY"
find "$BIN_DIR" -maxdepth 1 -type f -executable -print0 | sort -z | xargs -r -0 sha256sum >> "$SUMMARY"
printf 'authority_debug_artifacts:\n' >> "$SUMMARY"
find "$REPO/target/debug" -maxdepth 1 \( -name guardd -o -name guardctl \) -type f -executable -print0 \
  | sort -z | xargs -r -0 sha256sum >> "$SUMMARY"
printf 'manifest:\n' >> "$SUMMARY"
printf '  %s\n' "${FORMAL_MANIFEST[@]}" >> "$SUMMARY"

for entry in "${FORMAL_MANIFEST[@]}"; do
  IFS='|' read -r name script assignments <<< "$entry"
  SELECTED=$((SELECTED + 1))
  log="$EVIDENCE_ROOT/${name}.log"
  echo "=== [$name] START ===" | tee -a "$SUMMARY"
  set +e
  # shellcheck disable=SC2086
  env BIN_DIR="$BIN_DIR" EVIDENCE_ROOT="$EVIDENCE_ROOT" $assignments \
    bash "$REPO/$script" >"$log" 2>&1
  rc=$?
  set -e
  case "$rc" in
    0) PASS=$((PASS + 1)); verdict=PASS ;;
    2) BLOCKED=$((BLOCKED + 1)); verdict=BLOCKED ;;
    *) FAIL=$((FAIL + 1)); verdict="FAIL rc=$rc" ;;
  esac
  echo "=== [$name] $verdict ===" | tee -a "$SUMMARY"
  tail -5 "$log" >> "$SUMMARY" || true
done

echo "=== FORMAL LINUX PROCESS SHIELD SUMMARY: selected=$SELECTED pass=$PASS fail=$FAIL blocked=$BLOCKED ===" | tee -a "$SUMMARY"
echo "evidence_root=$EVIDENCE_ROOT" | tee -a "$SUMMARY"
if [ "$SELECTED" -eq 0 ] || [ "$BLOCKED" -gt 0 ]; then exit 2; fi
if [ "$FAIL" -gt 0 ]; then exit 1; fi
