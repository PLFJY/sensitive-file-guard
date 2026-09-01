#!/usr/bin/env bash
# deploy/uninstall.sh — remove a source-installed Sensitive Data Firewall.
#
# Usage:
#   sudo deploy/uninstall.sh
#   sudo deploy/uninstall.sh --purge
#
# The default keeps operator configuration and audit/state data. --purge
# removes only Guard's exact persistent directories; it never targets browser
# profiles, SSH keys, package dependencies, or the guardd-users group.
set -euo pipefail

BIN_DIR="/usr/local/bin"
UNIT_DST="/etc/systemd/system/guardd.service"
NOTIFY_UNIT_DST="/usr/local/lib/systemd/user/guard-notify.service"
POLKIT_DST="/usr/share/polkit-1/actions/org.guardd.policy"
CONFIG_EXAMPLE_DST="/usr/local/share/guardd/guardd-config.example.json"
EXAMPLE_DIR="/usr/local/share/guardd"
DESKTOP_DST="/usr/share/applications/io.github.plfjy.SensitiveFileGuard.desktop"
METAINFO_DST="/usr/share/metainfo/io.github.plfjy.SensitiveFileGuard.metainfo.xml"
ICON_DST="/usr/share/icons/hicolor/scalable/apps/io.github.plfjy.SensitiveFileGuard.svg"
RUN_DIR="/run/guardd"
CONFIG_DIR="/etc/guardd"
STATE_DIR="/var/lib/guardd"
LOG_DIR="/var/log/guardd"
PURGE=false

usage() {
  cat <<'EOF'
Usage: sudo deploy/uninstall.sh [--purge]

Default removal deletes source-installed binaries, units, policy, examples,
desktop assets, and transient runtime files. It preserves /etc/guardd and
/var/lib/guardd so reviewed configuration and audit records remain available.

--purge additionally removes /etc/guardd, /var/lib/guardd, and /var/log/guardd.
It never removes browser profiles, SSH keys, system dependencies, or accounts.
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --purge) PURGE=true ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
  shift
done

if [ "${EUID}" -ne 0 ]; then
  echo "ERROR: deploy/uninstall.sh must run as root; rerun it with sudo." >&2
  exit 2
fi

if ! command -v systemctl >/dev/null 2>&1; then
  echo "ERROR: systemctl is required to remove the guardd service." >&2
  exit 2
fi

remove_file() {
  case "$1" in
    "$UNIT_DST"|"$NOTIFY_UNIT_DST"|"$POLKIT_DST"|"$CONFIG_EXAMPLE_DST"|\
    "$DESKTOP_DST"|"$METAINFO_DST"|"$ICON_DST"|\
    "$BIN_DIR/guardd"|"$BIN_DIR/guardctl"|"$BIN_DIR/guard-notify"|\
    "$BIN_DIR/guard-ui"|"$BIN_DIR/guard-tui") ;;
    *) echo "ERROR: internal refusal to remove unexpected path: $1" >&2; exit 2 ;;
  esac
  rm -f -- "$1"
}

remove_empty_runtime_dir() {
  if [ -L "$RUN_DIR" ]; then
    echo "WARNING: refusing to remove symlinked runtime path: $RUN_DIR" >&2
    return
  fi
  if [ -d "$RUN_DIR" ]; then
    rm -f -- "$RUN_DIR/guardd.sock"
    if ! rmdir -- "$RUN_DIR" 2>/dev/null; then
      echo "WARNING: retained non-empty runtime directory: $RUN_DIR" >&2
    fi
  fi
}

remove_empty_example_dir() {
  if [ -L "$EXAMPLE_DIR" ]; then
    echo "WARNING: refusing to remove symlinked example directory: $EXAMPLE_DIR" >&2
    return
  fi
  if [ -d "$EXAMPLE_DIR" ] && ! rmdir -- "$EXAMPLE_DIR" 2>/dev/null; then
    echo "WARNING: retained non-empty example directory: $EXAMPLE_DIR" >&2
  fi
}

purge_directory() {
  local directory="$1"
  case "$directory" in
    "$CONFIG_DIR"|"$STATE_DIR"|"$LOG_DIR") ;;
    *) echo "ERROR: internal refusal to purge unexpected path: $directory" >&2; exit 2 ;;
  esac
  [ -e "$directory" ] || return 0
  if [ -L "$directory" ] || [ ! -d "$directory" ]; then
    echo "WARNING: refusing to recursively remove non-directory or symlink: $directory" >&2
    return 0
  fi
  rm -rf -- "$directory"
}

stop_invoking_user_notification_service() {
  local user="${SUDO_USER:-}" uid runtime_dir bus
  if [ -z "$user" ] || [ "$user" = root ] || ! command -v runuser >/dev/null 2>&1; then
    return 0
  fi
  uid="$(id -u -- "$user" 2>/dev/null || true)"
  [ -n "$uid" ] || return 0
  runtime_dir="/run/user/$uid"
  bus="$runtime_dir/bus"
  if [ -S "$bus" ]; then
    if runuser -u "$user" -- env \
      XDG_RUNTIME_DIR="$runtime_dir" \
      DBUS_SESSION_BUS_ADDRESS="unix:path=$bus" \
      systemctl --user disable --now guard-notify; then
      echo "    Stopped notification service for $user"
    else
      echo "WARNING: could not stop guard-notify for $user; removing its unit prevents a new executable from starting." >&2
    fi
  fi
}

echo "==> Removing Sensitive Data Firewall source installation"

# Stop and disable the system daemon before removing its unit or executable.
systemctl stop guardd 2>/dev/null || true
systemctl disable guardd 2>/dev/null || true
stop_invoking_user_notification_service
# Remove only a global activation symlink if an administrator created one.
# Per-user activation remains under that user's control and becomes inert once
# the unit and executable below are removed.
systemctl --global disable guard-notify 2>/dev/null || true

remove_file "$UNIT_DST"
remove_file "$NOTIFY_UNIT_DST"
remove_file "$POLKIT_DST"
systemctl daemon-reload
systemctl reset-failed guardd 2>/dev/null || true

remove_file "$CONFIG_EXAMPLE_DST"
remove_empty_example_dir
remove_file "$BIN_DIR/guardd"
remove_file "$BIN_DIR/guardctl"
remove_file "$BIN_DIR/guard-notify"
remove_file "$BIN_DIR/guard-ui"
remove_file "$BIN_DIR/guard-tui"
remove_file "$DESKTOP_DST"
remove_file "$METAINFO_DST"
remove_file "$ICON_DST"
remove_empty_runtime_dir

if [ "$PURGE" = true ]; then
  purge_directory "$CONFIG_DIR"
  purge_directory "$STATE_DIR"
  purge_directory "$LOG_DIR"
  echo "    Purged: $CONFIG_DIR, $STATE_DIR, $LOG_DIR"
else
  echo "    Preserved: $CONFIG_DIR (reviewed configuration)"
  echo "    Preserved: $STATE_DIR and $LOG_DIR (audit/state data)"
fi

echo "    Preserved: guardd-users group and its memberships"
echo "==> Uninstall complete"
