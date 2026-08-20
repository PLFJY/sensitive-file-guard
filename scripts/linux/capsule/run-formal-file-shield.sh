#!/usr/bin/env bash
# Host-side formal-suite orchestrator. This is the only supported entrypoint
# for the privileged Linux File Shield suite: it uses the test capsule for
# both one-shot gates and the PID-1 systemd gate. Build/stage first as the
# normal host user; evidence remains below /testfs.
set -euo pipefail

CAPSULE=/usr/local/sbin/sfg-test-capsule
STAMP="$(date +%Y%m%d-%H%M%S)"
EVIDENCE_ROOT="${EVIDENCE_ROOT:-/testfs/sfg-formal-evidence/$STAMP}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SFG_GIT_COMMIT="$(git -C "$REPO" rev-parse HEAD)"

run_mode() {
  local mode="$1"
  sudo -n "$CAPSULE" "$2" env \
    FORMAL_MODE="$mode" EVIDENCE_ROOT="$EVIDENCE_ROOT" BIN_DIR=/stage/bin \
    SFG_GIT_COMMIT="$SFG_GIT_COMMIT" \
    /stage/scripts/linux/run-all-root-gates.sh
}

set +e
run_mode oneshot run
ONE_SHOT_RC=$?
set -e

sudo -n "$CAPSULE" boot
set +e
run_mode systemd exec
SYSTEMD_RC=$?
set -e
sudo -n "$CAPSULE" stop

echo "formal evidence (inside capsule): $EVIDENCE_ROOT"
if [ "$ONE_SHOT_RC" -eq 1 ] || [ "$SYSTEMD_RC" -eq 1 ]; then exit 1; fi
if [ "$ONE_SHOT_RC" -ne 0 ] || [ "$SYSTEMD_RC" -ne 0 ]; then exit 2; fi
