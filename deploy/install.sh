#!/usr/bin/env bash
# deploy/install.sh — install/uninstall guardd as a systemd service.
#
# Usage:
#   sudo deploy/install.sh              # install
#   sudo deploy/install.sh --uninstall  # uninstall
#
# This script copies the release binaries + systemd unit + config into
# conventional system locations and enables the service. It does NOT start
# the service automatically — run `systemctl start guardd` after verifying
# the config.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UNIT_SRC="$REPO/deploy/guardd.service"
UNIT_DST="/etc/systemd/system/guardd.service"
GUARDD_BIN="$REPO/target/release/guardd"
GUARDCTL_BIN="$REPO/target/release/guardctl"
GUARD_NOTIFY_BIN="$REPO/target/release/guard-notify"
GUARDD_DST="/usr/local/sbin/guardd"
GUARDCTL_DST="/usr/local/bin/guardctl"
GUARD_NOTIFY_DST="/usr/local/bin/guard-notify"
NOTIFY_UNIT_SRC="$REPO/deploy/guard-notify.service"
NOTIFY_UNIT_DST="/usr/local/lib/systemd/user/guard-notify.service"
CONFIG_DIR="/etc/guardd"
CONFIG_DST="$CONFIG_DIR/config.json"
CONFIG_EXAMPLE="$REPO/deploy/guardd-config.example.json"
STATE_DIR="/var/lib/guardd"
RUN_DIR="/run/guardd"
POLKIT_SRC="$REPO/deploy/org.guardd.policy"
POLKIT_DST="/usr/share/polkit-1/actions/org.guardd.policy"
ACCESS_GROUP="guardd-users"

UNINSTALL=false
if [ "${1:-}" = "--uninstall" ]; then
  UNINSTALL=true
fi

if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: run as root (sudo $0)"
  exit 2
fi

if [ "$UNINSTALL" = true ]; then
  echo "==> Uninstalling guardd service"
  systemctl stop guardd 2>/dev/null || true
  systemctl disable guardd 2>/dev/null || true
  rm -f "$UNIT_DST"
  rm -f "$NOTIFY_UNIT_DST"
  rm -f "$POLKIT_DST"
  systemctl daemon-reload
  rm -f "$GUARDD_DST" "$GUARDCTL_DST" "$GUARD_NOTIFY_DST"
  echo "    Removed: $UNIT_DST, $NOTIFY_UNIT_DST, $POLKIT_DST, $GUARDD_DST, $GUARDCTL_DST, $GUARD_NOTIFY_DST"
  echo "    Preserved: $CONFIG_DIR (edit to remove), $STATE_DIR (audit DB)"
  echo "==> Uninstall complete"
  exit 0
fi

echo "==> Installing guardd service"

if ! command -v pkcheck >/dev/null; then
  echo "ERROR: pkcheck is required for sensitive IPC authorization (install polkit)"
  exit 2
fi

# Transport access is separate from authorization: this group can connect to
# the socket, while migration/SSH mutations still require polkit.
if ! getent group "$ACCESS_GROUP" >/dev/null; then
  groupadd --system "$ACCESS_GROUP"
  echo "    Created system group: $ACCESS_GROUP"
fi
if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
  usermod -aG "$ACCESS_GROUP" "$SUDO_USER"
  echo "    Added $SUDO_USER to $ACCESS_GROUP (log out/in before using the socket)"
fi

# 1. Build the exact checked-out source; never install stale release binaries.
echo "    Building release binaries..."
cd "$REPO"
cargo build --release

# 2. Install binaries.
install -m 0755 "$GUARDD_BIN" "$GUARDD_DST"
install -m 0755 "$GUARDCTL_BIN" "$GUARDCTL_DST"
install -m 0755 "$GUARD_NOTIFY_BIN" "$GUARD_NOTIFY_DST"
echo "    Installed: $GUARDD_DST, $GUARDCTL_DST, $GUARD_NOTIFY_DST"

# 3. Install config (don't overwrite existing).
mkdir -p "$CONFIG_DIR"
if [ ! -f "$CONFIG_DST" ]; then
  install -m 0640 "$CONFIG_EXAMPLE" "$CONFIG_DST"
  echo "    Installed: $CONFIG_DST (example — edit before starting)"
else
  echo "    Preserved: $CONFIG_DST (already exists)"
fi

# 4. Create state directory.
mkdir -p "$STATE_DIR"
chmod 0700 "$STATE_DIR"
echo "    Ready: $STATE_DIR (audit DB)"

# 5. Install systemd unit.
install -m 0644 "$UNIT_SRC" "$UNIT_DST"
mkdir -p "$(dirname "$NOTIFY_UNIT_DST")"
install -m 0644 "$NOTIFY_UNIT_SRC" "$NOTIFY_UNIT_DST"
install -m 0644 "$POLKIT_SRC" "$POLKIT_DST"
systemctl daemon-reload
echo "    Installed: $UNIT_DST, $POLKIT_DST"

# 6. Enable (but don't start — let the user verify config first).
systemctl enable guardd
echo "    Enabled: guardd.service (not started yet)"

echo
echo "==> Install complete. Next steps:"
echo "    1. Edit $CONFIG_DST — set your browser profile_root + ssh_keys"
echo "    2. Start:  sudo systemctl start guardd"
echo "    3. Verify: guardctl status"
echo "    4. Logs:   journalctl -u guardd -f"
echo "    5. Desktop notifications (as your user): systemctl --user daemon-reload && systemctl --user enable --now guard-notify"
