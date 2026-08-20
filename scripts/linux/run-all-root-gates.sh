#!/usr/bin/env bash
# Formal Linux File Shield privileged manifest. The normal execution path is
# `sudo -n /usr/local/sbin/sfg-test-capsule`; /stage may be read-only, so
# evidence defaults to /testfs. An explicitly user-authorized physical-host
# fallback is a separate, narrowly reviewed command and must record its
# namespace/capability difference instead of being represented by this runner.
#
# FORMAL_MODE=oneshot runs capsule-safe gates; FORMAL_MODE=systemd runs only
# PID-1 gates after `sfg-test-capsule boot`. The capsule host wrapper combines
# both result sets. Exit: 0 PASS, 1 FAIL, 2 mandatory BLOCKED.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN_DIR="${BIN_DIR:-$REPO/bin}"
if [ ! -d "$BIN_DIR" ] && [ -d /stage/bin ]; then BIN_DIR=/stage/bin; fi
EVIDENCE_ROOT="${EVIDENCE_ROOT:-/testfs/sfg-formal-evidence/$(date +%Y%m%d-%H%M%S)}"
FORMAL_MODE="${FORMAL_MODE:-oneshot}"
SFG_GIT_COMMIT="${SFG_GIT_COMMIT:-unknown}"
mkdir -p "$EVIDENCE_ROOT"

# The volatile nspawn root can omit a passwd entry for uid 0. OpenSSH's
# ssh-keygen refuses to create an ephemeral fixture in that state before any
# Guard code runs. Supply only the capsule-local NSS records required by the
# synthetic fixtures; the capsule is discarded after the gate.
if ! getent passwd 0 >/dev/null 2>&1; then
  printf '%s\n' 'root:x:0:0:root:/root:/bin/sh' >> /etc/passwd
fi
if ! getent group 0 >/dev/null 2>&1; then
  printf '%s\n' 'root:x:0:' >> /etc/group
fi
if ! getent group 1000 >/dev/null 2>&1; then
  printf '%s\n' 'sfgtest:x:1000:' >> /etc/group
fi
if ! getent passwd 1000 >/dev/null 2>&1; then
  printf '%s\n' 'sfgtest:x:1000:1000:Synthetic capsule user:/home/sfgtest:/bin/sh' >> /etc/passwd
  mkdir -p /home/sfgtest
  chown 1000:1000 /home/sfgtest
fi
# Legacy compatibility gates key off SUDO_USER to choose the non-root browser
# fixture identity. It is not a host sudo contract inside the capsule.
export SUDO_USER="${SUDO_USER:-sfgtest}"

cleanup_stale_test_loops() {
  # nspawn exposes only loop0..2. Interrupted synthetic test gates can leave
  # one attached; detach only a known Guard test image after proving it is not
  # mounted. Never touch any other backing device.
  for loop in /dev/loop0 /dev/loop1 /dev/loop2; do
    [ -b "$loop" ] || continue
    backing="$(losetup "$loop" 2>/dev/null || true)"
    case "$backing" in
      *'/guard-'*|*'/p0-ssh-'*|*'/p1b-'*|*'/p1c-'*|*'/dac-'*) ;;
      *) continue ;;
    esac
    if findmnt -rn -S "$loop" >/dev/null 2>&1; then
      continue
    fi
    # A just-exited fanotify daemon can keep the synthetic loop transiently
    # busy while its final fd closes. nspawn exposes only loop0..2, so retry a
    # known, unmounted test loop before the next gate instead of letting
    # losetup select an invisible loop3 and misreport an environment failure.
    detached=0
    for _ in $(seq 1 20); do
      if losetup -d "$loop" 2>/dev/null; then
        detached=1
        break
      fi
      sleep 0.05
    done
    if [ "$detached" -ne 1 ]; then
      echo "ERROR: could not detach stale synthetic loop $loop: $backing" >&2
      return 1
    fi
  done
}

# name|execution-mode|script|environment assignments
# The summary count is derived from this manifest, never a historical number.
# LFH4 proves an explicitly PARTIAL crash-continuity contract; it remains a
# required observation but is not counted as a restored crash-continuity PASS.
# Native compatibility is scoped to browsers actually installed in the capsule.
declare -a FORMAL_MANIFEST=(
  "pidfd|oneshot|scripts/linux/test-pidfd-root.sh|"
  "object-identity|oneshot|scripts/linux/test-object-identity-root.sh|"
  "topology-zero-settle-and-lifecycle|oneshot|scripts/linux/test-step3-zero-settle-root.sh|"
  "topology-overflow-fail-closed|oneshot|scripts/linux/capsule/p1b-capsule-run.sh|"
  "continuity-autonomous-mark-loss|oneshot|scripts/linux/capsule/p1c-capsule-run.sh|"
  "fdstore-continuity|systemd|scripts/linux/experiment-fdstore-root.sh|"
  "browser-enforcement|oneshot|scripts/test-browser-enforcement-root.sh|"
  "ssh-read-authorized-flow|oneshot|scripts/test-ssh-enforcement-root.sh|"
  "fanotify|oneshot|scripts/test-fanotify-root.sh|"
  "bypass|oneshot|scripts/test-bypass-root.sh|"
  "hardening|oneshot|scripts/test-hardening-root.sh|"
  "agent-compat|oneshot|scripts/test-agent-compat-root.sh|"
  "ssh-broker-adversarial|oneshot|scripts/test-ssh-broker-adversarial-root.sh|"
  "ssh-load-authorized-flow-conservative|oneshot|scripts/test-ssh-load-root.sh|ENFORCEMENT_MODE=conservative"
  "ssh-load-authorized-flow-strict|oneshot|scripts/test-ssh-load-root.sh|ENFORCEMENT_MODE=strict-filesystem"
  "strict-concurrency|oneshot|scripts/test-strict-concurrency-root.sh|"
  "topology-race-stress|oneshot|scripts/test-topology-race-stress-root.sh|ENFORCEMENT_MODE=strict-filesystem"
  "installed-auth|oneshot|scripts/test-installed-auth-root.sh|"
  "browser-adversarial|oneshot|scripts/test-browser-adversarial-root.sh|"
  "strict-filesystem|oneshot|scripts/test-strict-filesystem-root.sh|"
  "native-browser-compat|oneshot|scripts/linux/test-native-browser-compat-root.sh|"
  "strict-filesystem-performance|oneshot|scripts/benchmark-strict-filesystem-root.sh|"
  "p0-ssh-mmap-configured-strict|oneshot|scripts/linux/capsule/p0-capsule-run.sh|ENFORCEMENT_MODE=strict-filesystem P0_CASE=configured"
  "p0-ssh-mmap-configured-conservative|oneshot|scripts/linux/capsule/p0-capsule-run.sh|ENFORCEMENT_MODE=conservative P0_CASE=configured"
  "p0-ssh-mmap-runtime-enrollment|oneshot|scripts/linux/capsule/p0-capsule-run.sh|ENFORCEMENT_MODE=strict-filesystem P0_CASE=runtime"
  "systemd|systemd|scripts/test-systemd-root.sh|"
)

MANDATORY_PASS=0; MANDATORY_FAIL=0; MANDATORY_BLOCKED=0; MANDATORY_SELECTED=0
OBSERVATION_PASS=0; OBSERVATION_PARTIAL=0; OBSERVATION_FAIL=0; OBSERVATION_BLOCKED=0
SUMMARY="$EVIDENCE_ROOT/summary-${FORMAL_MODE}.txt"
: > "$SUMMARY"
printf 'formal_mode=%s\nbin_dir=%s\n' "$FORMAL_MODE" "$BIN_DIR" >> "$SUMMARY"
printf 'git_commit=%s\nkernel=%s\nartifacts:\n' "$SFG_GIT_COMMIT" "$(uname -a)" >> "$SUMMARY"
for artifact in guardd guardctl guard-test-probe guard-notify guard-fdstore; do
  if [ -x "$BIN_DIR/$artifact" ]; then
    sha256sum "$BIN_DIR/$artifact" >> "$SUMMARY"
  else
    printf 'MISSING %s\n' "$artifact" >> "$SUMMARY"
  fi
done
printf 'manifest:\n' >> "$SUMMARY"
printf '  %s\n' "${FORMAL_MANIFEST[@]}" >> "$SUMMARY"

requirement_for() {
  case "$1" in
    fdstore-continuity|native-browser-compat) echo observation ;;
    *) echo mandatory ;;
  esac
}

for entry in "${FORMAL_MANIFEST[@]}"; do
  IFS='|' read -r name mode script assignments <<< "$entry"
  [ "$mode" = "$FORMAL_MODE" ] || continue
  requirement="$(requirement_for "$name")"
  if [ "$requirement" = mandatory ]; then
    MANDATORY_SELECTED=$((MANDATORY_SELECTED + 1))
  fi
  log="$EVIDENCE_ROOT/${name}.log"
  echo "=== [$name][$requirement] START ===" | tee -a "$SUMMARY"
  cleanup_stale_test_loops
  set +e
  # shellcheck disable=SC2086
  env SKIP_BUILD=1 BIN_DIR="$BIN_DIR" EVIDENCE_ROOT="$EVIDENCE_ROOT" $assignments \
    bash "$REPO/$script" >"$log" 2>&1
  rc=$?
  set -e
  if [ "$requirement" = observation ] && [ "$rc" -eq 0 ] && grep -q '^VERDICT: PARTIAL' "$log"; then
    OBSERVATION_PARTIAL=$((OBSERVATION_PARTIAL + 1)); verdict=PARTIAL
  elif [ "$requirement" = mandatory ]; then
    case "$rc" in
      0) MANDATORY_PASS=$((MANDATORY_PASS + 1)); verdict=PASS ;;
      2) MANDATORY_BLOCKED=$((MANDATORY_BLOCKED + 1)); verdict=BLOCKED ;;
      *) MANDATORY_FAIL=$((MANDATORY_FAIL + 1)); verdict="FAIL rc=$rc" ;;
    esac
  else
    case "$rc" in
      0) OBSERVATION_PASS=$((OBSERVATION_PASS + 1)); verdict=PASS ;;
      2) OBSERVATION_BLOCKED=$((OBSERVATION_BLOCKED + 1)); verdict=BLOCKED ;;
      *) OBSERVATION_FAIL=$((OBSERVATION_FAIL + 1)); verdict="FAIL rc=$rc" ;;
    esac
  fi
  echo "=== [$name] $verdict ===" | tee -a "$SUMMARY"
  tail -3 "$log" >> "$SUMMARY" || true
  cleanup_stale_test_loops
done

echo "=== FORMAL LINUX FILE SHIELD SUMMARY: mandatory_selected=$MANDATORY_SELECTED mandatory_pass=$MANDATORY_PASS mandatory_fail=$MANDATORY_FAIL mandatory_blocked=$MANDATORY_BLOCKED observation_pass=$OBSERVATION_PASS observation_partial=$OBSERVATION_PARTIAL observation_fail=$OBSERVATION_FAIL observation_blocked=$OBSERVATION_BLOCKED ===" | tee -a "$SUMMARY"
echo "evidence_root=$EVIDENCE_ROOT" | tee -a "$SUMMARY"
if [ "$MANDATORY_SELECTED" -eq 0 ]; then exit 2; fi
if [ "$MANDATORY_FAIL" -gt 0 ]; then exit 1; elif [ "$MANDATORY_BLOCKED" -gt 0 ]; then exit 2; else exit 0; fi
