#!/usr/bin/env bash
# deploy/install.sh — install guardd as a systemd service.
#
# Usage:
#   sudo deploy/install.sh
#
# Build as an unprivileged user first with `cargo build --release`, then run
# this script with sudo.  It installs already-built artifacts and deliberately
# does not enable or start the daemon: `guardctl setup` creates a reviewed,
# non-empty protection configuration for the intended desktop user first.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UNIT_SRC="$REPO/deploy/guardd.service"
UNIT_DST="/etc/systemd/system/guardd.service"
GUARDD_BIN="$REPO/target/release/guardd"
GUARDCTL_BIN="$REPO/target/release/guardctl"
GUARD_NOTIFY_BIN="$REPO/target/release/guard-notify"
GUARD_UI_BIN="$REPO/target/release/guard-ui"
BIN_DIR="/usr/local/bin"
GUARDD_DST="$BIN_DIR/guardd"
GUARDCTL_DST="/usr/local/bin/guardctl"
GUARD_NOTIFY_DST="/usr/local/bin/guard-notify"
GUARD_UI_DST="/usr/local/bin/guard-ui"
DESKTOP_SRC="$REPO/data/io.github.plfjy.SensitiveFileGuard.desktop"
METAINFO_SRC="$REPO/data/io.github.plfjy.SensitiveFileGuard.metainfo.xml"
ICON_SRC="$REPO/data/io.github.plfjy.SensitiveFileGuard.svg"
NOTIFY_UNIT_SRC="$REPO/deploy/guard-notify.service"
NOTIFY_UNIT_DST="/usr/local/lib/systemd/user/guard-notify.service"
CONFIG_DIR="/etc/guardd"
CONFIG_DST="$CONFIG_DIR/config.json"
CONFIG_EXAMPLE="$REPO/deploy/guardd-config.example.json"
CONFIG_EXAMPLE_DST="/usr/local/share/guardd/guardd-config.example.json"
STATE_DIR="/var/lib/guardd"
POLKIT_SRC="$REPO/deploy/org.guardd.policy"
POLKIT_DST="/usr/share/polkit-1/actions/org.guardd.policy"
ACCESS_GROUP="guardd-users"

usage() {
  echo "Usage: sudo $0"
}

if [ "$#" -ne 0 ]; then
  if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
    usage
    exit 0
  fi
  usage >&2
  exit 2
fi

if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: run as root (sudo $0)"
  exit 2
fi

echo "==> Installing guardd service"

if ! command -v systemctl >/dev/null; then
  echo "ERROR: systemctl is required to install the guardd service"
  exit 2
fi

if ! command -v pkcheck >/dev/null; then
  echo "ERROR: pkcheck is required for sensitive IPC authorization (install polkit)"
  exit 2
fi

# Validate every source artifact before changing host state. This avoids a
# partial installation such as a new group with no matching service binary.
for source in \
  "$UNIT_SRC" "$NOTIFY_UNIT_SRC" "$CONFIG_EXAMPLE" "$POLKIT_SRC" \
  "$DESKTOP_SRC" "$METAINFO_SRC" "$ICON_SRC"; do
  if [ ! -f "$source" ]; then
    echo "ERROR: missing installation asset: $source"
    exit 2
  fi
done

# Never compile as root: doing so pollutes root's Cargo home and makes the
# result depend on a privileged toolchain. Refuse stale/missing artifacts.
for artifact in "$GUARDD_BIN" "$GUARDCTL_BIN" "$GUARD_NOTIFY_BIN" "$GUARD_UI_BIN"; do
  if [ ! -x "$artifact" ]; then
    echo "ERROR: missing release artifact: $artifact"
    echo "Build first as your normal user: cargo build --release"
    exit 2
  fi
done

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

# Install binaries.
mkdir -p "$BIN_DIR"
install -m 0755 "$GUARDD_BIN" "$GUARDD_DST"
install -m 0755 "$GUARDCTL_BIN" "$GUARDCTL_DST"
install -m 0755 "$GUARD_NOTIFY_BIN" "$GUARD_NOTIFY_DST"
install -m 0755 "$GUARD_UI_BIN" "$GUARD_UI_DST"
# Remove the binary installed by releases that still shipped the terminal UI.
rm -f -- "$BIN_DIR/guard-tui"
install -Dm0644 "$DESKTOP_SRC" /usr/share/applications/io.github.plfjy.SensitiveFileGuard.desktop
install -Dm0644 "$METAINFO_SRC" /usr/share/metainfo/io.github.plfjy.SensitiveFileGuard.metainfo.xml
install -Dm0644 "$ICON_SRC" /usr/share/icons/hicolor/scalable/apps/io.github.plfjy.SensitiveFileGuard.svg
echo "    Installed: $GUARDD_DST, $GUARDCTL_DST, $GUARD_NOTIFY_DST, $GUARD_UI_DST"

# 3. Install a non-active example. Never create /etc/guardd/config.json here:
# an empty protection config would look configured while protecting no resources.
install -Dm0644 "$CONFIG_EXAMPLE" "$CONFIG_EXAMPLE_DST"
if [ -e "$CONFIG_DST" ]; then
  echo "    Preserved: $CONFIG_DST (already exists)"
else
  echo "    No active config created; run guardctl setup --home /home/USER"
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
if systemctl is-active --quiet guardd; then
  echo "    Restarting active guardd service to apply the upgrade"
  systemctl try-restart guardd
fi
echo "    Installed: $UNIT_DST, $POLKIT_DST"

echo
echo "==> Install complete. Next steps:"
echo "    1. Create reviewed protection config: sudo guardctl setup --home /home/USER"
echo "    2. Optionally choose an existing key: guardctl ssh suggest"
echo "    3. Start: sudo systemctl enable --now guardd"
echo "    4. Verify: guardctl status"
echo "    5. Desktop notifications (as your user): systemctl --user daemon-reload && systemctl --user enable guard-notify && systemctl --user restart guard-notify"
