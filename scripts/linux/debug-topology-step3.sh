#!/usr/bin/env bash
# Debug harness for LFH2 Step 3 topology group (keeps logs).
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
GUARDD="$REPO/target/release/guardd"
GUARDCTL="$REPO/target/release/guardctl"
PROBE="$REPO/target/release/guard-test-probe"
OUT="/tmp/objid-debug-$$"
mkdir -p "$OUT"

LOOP_IMG="$OUT/img.img"; LOOP_MNT="$OUT/mnt"; LOOP_DEV=""
truncate -s 512M "$LOOP_IMG"
LOOP_DEV="$(losetup -f)"
losetup "$LOOP_DEV" "$LOOP_IMG"
mkfs.ext4 -q -F "$LOOP_DEV"
mkdir -p "$LOOP_MNT"
mount "$LOOP_DEV" "$LOOP_MNT"

CHROME_UDD="$LOOP_MNT/chrome-udd"
mkdir -p "$CHROME_UDD/Default/Local Storage/leveldb"
printf 'NEVER_OPENED_FIXTURE' > "$CHROME_UDD/Default/Local Storage/leveldb/999999.log"
printf '{}' > "$CHROME_UDD/Default/Preferences"
ENROLLED="$OUT/synthetic-chrome"
cp "$PROBE" "$ENROLLED"; chmod 0755 "$ENROLLED"
cat > "$OUT/cfg.json" <<EOF
{ "config_version": 1, "enforcement_mode": "strict-filesystem",
  "browsers": [ { "id": "synthetic-chrome", "family": "Chromium",
    "profile_root": "$CHROME_UDD", "owner_uid": 0, "exe_paths": ["$ENROLLED"] } ],
  "enrolled_exes": ["$ENROLLED"], "ssh_keys": [] }
EOF

"$GUARDD" --enforce-browser-config "$OUT/cfg.json" \
  --ipc-socket /tmp/objid-debug.sock --audit-db /tmp/objid-debug.db --print-decisions \
  > "$OUT/guardd.log" 2>&1 &
GPID=$!
sleep 1.5
echo "--- guardd.log after start ---"
cat "$OUT/guardd.log"

echo "=== topology group marks from fdinfo ==="
grep -m1 "topology" "$OUT/guardd.log" || echo "(no topology line)"

mv "$CHROME_UDD/Default/Local Storage/leveldb/999999.log" "$LOOP_MNT/never-exfil.log"
sleep 2
echo "--- guardd.log after mv ---"
cat "$OUT/guardd.log"
echo "=== probing the moved object ==="
"$PROBE" read "$LOOP_MNT/never-exfil.log" >/dev/null 2>&1; echo "probe rc=$?"
sleep 0.5
echo "--- guardd.log after probe ---"
tail -8 "$OUT/guardd.log"

kill -TERM "$GPID" 2>/dev/null || true
sleep 1
kill -KILL "$GPID" 2>/dev/null || true
umount "$LOOP_DEV" 2>/dev/null || true
losetup -d "$LOOP_DEV" 2>/dev/null || true
echo "=== preserved logs in $OUT ==="
