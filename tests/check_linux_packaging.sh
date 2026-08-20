#!/usr/bin/env bash
# Normal-user release lifecycle: install, upgrade, downgrade, config guard, uninstall.
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/sfg-packaging-test.XXXXXX")"
trap 'rm -rf -- "$work_dir"' EXIT
dist_dir="$work_dir/dist"
root_dir="$work_dir/root"
mkdir -p "$dist_dir" "$root_dir"

if "$repo_dir/packaging/linux/build-release.sh" --output-dir "$dist_dir" --version 99.0.0 >/dev/null 2>&1; then
  echo "ERROR: formal build accepted a version that differs from the workspace" >&2
  exit 1
fi

build_bundle() {
  "$repo_dir/packaging/linux/build-release.sh" --no-build \
    --binary-dir "$repo_dir/target/release" --output-dir "$dist_dir" --version "$1" >/dev/null
  tar -xzf "$dist_dir/sensitive-file-guard-linux-$(uname -m)-$1.tar.gz" -C "$work_dir"
}

run_installer() {
  local version="$1"
  shift
  SFG_INSTALL_ROOT="$root_dir" \
    "$work_dir/sensitive-file-guard-linux-$(uname -m)-$version/install.sh" "$@"
}

build_bundle 0.0.9
build_bundle 0.1.0

run_installer 0.0.9 install >/dev/null
test -x "$root_dir/usr/bin/guardd"
test -x "$root_dir/usr/bin/guardctl"
test -x "$root_dir/usr/bin/guard-ui"
test -x "$root_dir/usr/bin/guard-notify"
test "$(stat -c %a "$root_dir/usr/bin/guardd")" = 755
test "$(stat -c %a "$root_dir/usr/lib/systemd/system/guardd.service")" = 644
grep -q '^ExecStart=/usr/bin/guardd ' "$root_dir/usr/lib/systemd/system/guardd.service"
grep -q '^Exec=guard-ui$' "$root_dir/usr/share/applications/io.github.plfjy.SensitiveFileGuard.desktop"

mkdir -p "$root_dir/etc/guardd" "$root_dir/var/lib/guardd"
config_path="$root_dir/etc/guardd/config.json"
printf '%s\n' \
  '{' \
  '  "config_version": 1,' \
  '  "enforcement_mode": "conservative",' \
  '  "browsers": [],' \
  '  "enrolled_exes": ["/usr/bin/true"],' \
  '  "ssh_keys": []' \
  '}' > "$config_path"
printf '%s\n' 'preserve-audit-state' > "$root_dir/var/lib/guardd/audit.sentinel"
config_hash="$(sha256sum "$config_path" | cut -d' ' -f1)"

run_installer 0.1.0 install >/dev/null
test "$(<"$root_dir/usr/lib/sensitive-file-guard/VERSION")" = 0.1.0
test "$(sha256sum "$config_path" | cut -d' ' -f1)" = "$config_hash"
grep -q preserve-audit-state "$root_dir/var/lib/guardd/audit.sentinel"

printf '\nTAMPERED\n' >> "$root_dir/usr/bin/guardctl"
if run_installer 0.1.0 verify >/dev/null 2>&1; then
  echo "ERROR: installed-content tampering was not detected" >&2
  exit 1
fi
run_installer 0.1.0 install >/dev/null
chmod 0700 "$root_dir/usr/bin/guardctl"
if run_installer 0.1.0 verify >/dev/null 2>&1; then
  echo "ERROR: installed permission drift was not detected" >&2
  exit 1
fi
run_installer 0.1.0 install >/dev/null

if run_installer 0.0.9 install >/dev/null 2>&1; then
  echo "ERROR: downgrade succeeded without --allow-downgrade" >&2
  exit 1
fi
test "$(<"$root_dir/usr/lib/sensitive-file-guard/VERSION")" = 0.1.0
run_installer 0.0.9 install --allow-downgrade >/dev/null
test "$(<"$root_dir/usr/lib/sensitive-file-guard/VERSION")" = 0.0.9
test "$(sha256sum "$config_path" | cut -d' ' -f1)" = "$config_hash"

sed -i 's/"config_version": 1/"config_version": 999/' "$config_path"
if run_installer 0.1.0 install >/dev/null 2>&1; then
  echo "ERROR: incompatible future config was accepted" >&2
  exit 1
fi
test "$(<"$root_dir/usr/lib/sensitive-file-guard/VERSION")" = 0.0.9
sed -i 's/"config_version": 999/"config_version": 1/' "$config_path"

run_installer 0.0.9 verify >/dev/null
run_installer 0.0.9 uninstall >/dev/null
test ! -e "$root_dir/usr/bin/guardd"
test -e "$config_path"
grep -q preserve-audit-state "$root_dir/var/lib/guardd/audit.sentinel"

echo "LINUX_RELEASE_LIFECYCLE=PASS"
