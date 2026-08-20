#!/usr/bin/env bash
# Install a verified Sensitive File Guard Linux release bundle.
set -euo pipefail

bundle_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
payload_dir="$bundle_dir/payload"
install_root="${SFG_INSTALL_ROOT:-/}"
action=install
allow_downgrade=0

usage() {
  cat <<'EOF'
Usage: ./install.sh [install|verify|uninstall] [--allow-downgrade]

The bundle installs under /usr, preserves /etc/guardd and /var/lib/guardd,
and never creates an empty active configuration. Downgrades require an
explicit flag and are refused if the installed configuration is incompatible
with the candidate guardd release.

SFG_INSTALL_ROOT=/path may be used only for an offline image/test root. No
systemd, group, or ownership changes are attempted outside the real root.
EOF
}

while (($#)); do
  case "$1" in
    install|verify|uninstall) action="$1" ;;
    --allow-downgrade) allow_downgrade=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "ERROR: unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

[[ "$install_root" = /* ]] || { echo "ERROR: SFG_INSTALL_ROOT must be absolute" >&2; exit 2; }
install_root="${install_root%/}"
if [[ -z "$install_root" && "$(id -u)" -ne 0 ]]; then
  echo "ERROR: installation to / requires root" >&2
  exit 2
fi

[[ -d "$payload_dir/usr" ]] || { echo "ERROR: bundle payload is missing" >&2; exit 2; }
[[ -s "$bundle_dir/manifest.sha256" ]] || { echo "ERROR: bundle manifest is missing" >&2; exit 2; }
(
  cd "$bundle_dir"
  sha256sum --quiet -c manifest.sha256
) || { echo "ERROR: release checksum verification failed" >&2; exit 2; }

candidate_version="$(<"$bundle_dir/VERSION")"
candidate_commit="$(<"$bundle_dir/SOURCE_COMMIT")"
release_dir="$install_root/usr/lib/sensitive-file-guard"
installed_version_file="$release_dir/VERSION"
config_path="$install_root/etc/guardd/config.json"
state_dir="$install_root/var/lib/guardd"

version_cmp() {
  if [[ "$1" == "$2" ]]; then
    printf 'equal\n'
  elif [[ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1)" == "$1" ]]; then
    printf 'older\n'
  else
    printf 'newer\n'
  fi
}

verify_installed() {
  local failed=0 relative source_path destination expected_mode actual_mode
  while IFS= read -r relative; do
    source_path="$payload_dir/$relative"
    destination="$install_root/$relative"
    expected_mode=644
    [[ "$relative" == usr/bin/* ]] && expected_mode=755
    if [[ ! -f "$destination" ]]; then
      echo "MISSING: /$relative" >&2
      failed=1
      continue
    fi
    if ! cmp --silent "$source_path" "$destination"; then
      echo "CONTENT MISMATCH: /$relative" >&2
      failed=1
    fi
    actual_mode="$(stat -c %a "$destination")"
    if [[ "$actual_mode" != "$expected_mode" ]]; then
      echo "MODE MISMATCH: /$relative is $actual_mode, expected $expected_mode" >&2
      failed=1
    fi
  done < <(cd "$payload_dir" && find usr -type f -print | sort)
  [[ "$failed" -eq 0 ]] || return 1
  echo "Sensitive File Guard ${candidate_version} installation content and permissions are verified."
}

if [[ "$action" == verify ]]; then
  verify_installed
  exit
fi

if [[ "$action" == uninstall ]]; then
  if [[ -z "$install_root" ]]; then
    systemctl stop guardd.service 2>/dev/null || true
    systemctl disable guardd.service 2>/dev/null || true
  fi
  installed_files="$release_dir/installed-files"
  if [[ -s "$installed_files" ]]; then
    mapfile -t removal_files < "$installed_files"
  else
    mapfile -t removal_files < <(cd "$payload_dir" && find usr -type f -print | sort)
  fi
  for relative in "${removal_files[@]}"; do
    [[ -n "$relative" ]] || continue
    rm -f -- "$install_root/$relative"
  done
  rm -f -- "$release_dir/VERSION" "$release_dir/SOURCE_COMMIT" "$release_dir/installed-files"
  rmdir --ignore-fail-on-non-empty "$release_dir" 2>/dev/null || true
  if [[ -z "$install_root" ]]; then
    systemctl daemon-reload
  fi
  echo "Uninstalled release files. Preserved /etc/guardd and /var/lib/guardd."
  exit
fi

if [[ -s "$installed_version_file" ]]; then
  installed_version="$(<"$installed_version_file")"
  if [[ "$(version_cmp "$candidate_version" "$installed_version")" == older && "$allow_downgrade" -ne 1 ]]; then
    echo "ERROR: refusing downgrade from $installed_version to $candidate_version without --allow-downgrade" >&2
    exit 2
  fi
fi

# This is deliberately before the first destination write. A downgrade whose
# guardctl cannot parse/validate the installed schema leaves the current
# binaries and service untouched.
if [[ -e "$config_path" ]]; then
  "$payload_dir/usr/bin/guardctl" config validate-file --path "$config_path" >/dev/null
fi

service_was_active=0
if [[ -z "$install_root" ]] && systemctl is-active --quiet guardd.service; then
  service_was_active=1
fi

while IFS= read -r relative; do
  source_path="$payload_dir/$relative"
  destination="$install_root/$relative"
  mode=0644
  [[ "$relative" == usr/bin/* ]] && mode=0755
  install -D -m "$mode" "$source_path" "$destination"
done < <(cd "$payload_dir" && find usr -type f -print | sort)

install -d -m 0755 "$release_dir"
printf '%s\n' "$candidate_version" > "$release_dir/VERSION"
printf '%s\n' "$candidate_commit" > "$release_dir/SOURCE_COMMIT"
(cd "$payload_dir" && find usr -type f -print | sort) > "$release_dir/installed-files"
install -d -m 0750 "$install_root/etc/guardd"
install -d -m 0700 "$state_dir"

if [[ -z "$install_root" ]]; then
  systemd-sysusers /usr/lib/sysusers.d/sensitive-file-guard.conf
  chown root:guardd-users "$install_root/etc/guardd"
  chmod 0750 "$install_root/etc/guardd"
  chown root:root "$release_dir/VERSION" "$release_dir/SOURCE_COMMIT" "$release_dir/installed-files"
  if [[ -e "$config_path" ]]; then
    chown root:guardd-users "$config_path"
    chmod 0640 "$config_path"
  fi
  systemctl daemon-reload
  if [[ "$service_was_active" -eq 1 ]]; then
    systemctl restart guardd.service
  fi
fi

verify_installed
echo "Installed Sensitive File Guard $candidate_version ($candidate_commit)."
if [[ ! -e "$config_path" ]]; then
  echo "No active configuration was created. Run: guardctl setup --home /home/USER"
fi
