#!/usr/bin/env bash
# deploy/install.sh — install/uninstall guardd as a systemd service.
#
# Usage:
#   sudo deploy/install.sh              # install
#   sudo deploy/install.sh --uninstall  # uninstall
#
# Build as an unprivileged user first with `cargo build --release`, then run
# this script with sudo.  It installs already-built artifacts and deliberately
# does not enable or start the daemon: an empty strict config must be completed
# for the intended desktop user first.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UNIT_SRC="$REPO/deploy/guardd.service"
UNIT_DST="/etc/systemd/system/guardd.service"
GUARDD_BIN="$REPO/target/release/guardd"
GUARDCTL_BIN="$REPO/target/release/guardctl"
GUARD_NOTIFY_BIN="$REPO/target/release/guard-notify"
BIN_DIR="/usr/local/bin"
GUARDD_DST="$BIN_DIR/guardd"
GUARDCTL_DST="/usr/local/bin/guardctl"
GUARD_TUI_BIN="$REPO/target/release/guard-tui"
GUARD_TUI_DST="$BIN_DIR/guard-tui"
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
  rm -f "$GUARDD_DST" "$GUARDCTL_DST" "$GUARD_TUI_DST" "$GUARD_NOTIFY_DST"
  echo "    Removed: $UNIT_DST, $NOTIFY_UNIT_DST, $POLKIT_DST, $GUARDD_DST, $GUARDCTL_DST, $GUARD_TUI_DST, $GUARD_NOTIFY_DST"
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

# Never compile as root: doing so pollutes root's Cargo home and makes the
# result depend on a privileged toolchain. Refuse stale/missing artifacts.
for artifact in "$GUARDD_BIN" "$GUARDCTL_BIN" "$GUARD_TUI_BIN" "$GUARD_NOTIFY_BIN"; do
  if [ ! -x "$artifact" ]; then
    echo "ERROR: missing release artifact: $artifact"
    echo "Build first as your normal user: cargo build --release"
    exit 2
  fi
done

# Install binaries.
mkdir -p "$BIN_DIR"
install -m 0755 "$GUARDD_BIN" "$GUARDD_DST"
install -m 0755 "$GUARDCTL_BIN" "$GUARDCTL_DST"
install -m 0755 "$GUARD_TUI_BIN" "$GUARD_TUI_DST"
install -m 0755 "$GUARD_NOTIFY_BIN" "$GUARD_NOTIFY_DST"
echo "    Installed: $GUARDD_DST, $GUARDCTL_DST, $GUARD_TUI_DST, $GUARD_NOTIFY_DST"

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

# Install one reviewed unit template with an installation-time absolute path.
# This is not a runtime shell indirection and keeps source/package hardening
# identical.
sed "s|@GUARDD_BINDIR@|$BIN_DIR|g" "$UNIT_SRC" > "$UNIT_DST"
chmod 0644 "$UNIT_DST"
mkdir -p "$(dirname "$NOTIFY_UNIT_DST")"
sed "s|@GUARDD_BINDIR@|$BIN_DIR|g" "$NOTIFY_UNIT_SRC" > "$NOTIFY_UNIT_DST"
chmod 0644 "$NOTIFY_UNIT_DST"
install -m 0644 "$POLKIT_SRC" "$POLKIT_DST"
systemctl daemon-reload
echo "    Installed: $UNIT_DST, $POLKIT_DST"

echo
echo "==> Install complete. Next steps:"
echo "    1. Inspect browser paths: guardctl browser discover"
echo "    2. Edit $CONFIG_DST with existing profile roots and emitted exe_paths"
echo "    3. Optionally choose an existing key: guardctl ssh suggest"
echo "    4. Start: sudo systemctl enable --now guardd"
echo "    5. Verify: guardctl status"
echo "    6. Desktop notifications (as your user): systemctl --user daemon-reload && systemctl --user enable --now guard-notify"
