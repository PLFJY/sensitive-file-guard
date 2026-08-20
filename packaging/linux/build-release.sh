#!/usr/bin/env bash
# Build a reproducible, checksum-verified Linux release bundle as a normal user.
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
output_dir="$repo_dir/dist"
binary_dir="$repo_dir/target/release"
workspace_version="$(sed -n 's/^version = "\([^"]*\)"/\1/p' "$repo_dir/Cargo.toml" | head -n1)"
release_version="$workspace_version"
build=1

usage() {
  cat <<'EOF'
Usage: packaging/linux/build-release.sh [options]

  --output-dir PATH  Artifact destination (default: dist/)
  --binary-dir PATH  Prebuilt release binaries (default: target/release/)
  --version VERSION  Artifact version (default: workspace version)
  --no-build         Package existing normal-user-built binaries
  -h, --help         Show this help
EOF
}

while (($#)); do
  case "$1" in
    --output-dir) output_dir="$2"; shift ;;
    --binary-dir) binary_dir="$2"; shift ;;
    --version) release_version="$2"; shift ;;
    --no-build) build=0 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "ERROR: unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

[[ "$(id -u)" -ne 0 ]] || { echo "ERROR: build releases as a normal user" >&2; exit 2; }
[[ "$release_version" =~ ^[0-9A-Za-z][0-9A-Za-z.+_-]*$ ]] || { echo "ERROR: invalid release version" >&2; exit 2; }

cd "$repo_dir"
source_commit="$(git rev-parse HEAD)"
source_epoch="${SOURCE_DATE_EPOCH:-$(git show -s --format=%ct HEAD)}"
architecture="$(uname -m)"
case "$architecture" in
  x86_64|aarch64) ;;
  *) echo "ERROR: unsupported release architecture: $architecture" >&2; exit 2 ;;
esac

if [[ "$build" -eq 1 ]]; then
  if [[ "$release_version" != "$workspace_version" ]]; then
    echo "ERROR: release version $release_version does not match workspace version $workspace_version" >&2
    echo "Update [workspace.package].version before creating a tagged release." >&2
    exit 2
  fi
  if [[ -n "$(git status --porcelain --untracked-files=normal)" ]]; then
    echo "ERROR: refusing a formal release build from a dirty source tree" >&2
    echo "Commit or otherwise preserve the intended source state, then retry." >&2
    exit 2
  fi
  GUARDD_BUILD_ID="$source_commit" cargo build --locked --release \
    -p guardd -p guardctl -p guard-ui -p guard-notify
fi
for binary in guardd guardctl guard-ui guard-notify; do
  [[ -x "$binary_dir/$binary" ]] || { echo "ERROR: missing binary: $binary_dir/$binary" >&2; exit 2; }
done

work_dir="$(mktemp -d "${TMPDIR:-/tmp}/sfg-release.XXXXXX")"
trap 'rm -rf -- "$work_dir"' EXIT
bundle_name="sensitive-file-guard-linux-${architecture}-${release_version}"
bundle_dir="$work_dir/$bundle_name"
payload="$bundle_dir/payload"
mkdir -p "$payload/usr/bin" "$payload/usr/lib/systemd/system" \
  "$payload/usr/lib/systemd/user" "$payload/usr/lib/sysusers.d" \
  "$payload/usr/share/polkit-1/actions" "$payload/usr/share/applications" \
  "$payload/usr/share/metainfo" "$payload/usr/share/icons/hicolor/scalable/apps" \
  "$payload/usr/share/guardd" "$payload/usr/share/doc/sensitive-file-guard"
mkdir -p "$payload/usr/share/licenses/sensitive-file-guard"

for binary in guardd guardctl guard-ui guard-notify; do
  install -m 0755 "$binary_dir/$binary" "$payload/usr/bin/$binary"
done
sed 's|@GUARDD_BINDIR@|/usr/bin|g' deploy/guardd.service > "$payload/usr/lib/systemd/system/guardd.service"
sed 's|@GUARDD_BINDIR@|/usr/bin|g' deploy/guard-notify.service > "$payload/usr/lib/systemd/user/guard-notify.service"
install -m 0644 deploy/guardd-users.sysusers "$payload/usr/lib/sysusers.d/sensitive-file-guard.conf"
install -m 0644 deploy/org.guardd.policy "$payload/usr/share/polkit-1/actions/org.guardd.policy"
install -m 0644 deploy/guardd-config.example.json "$payload/usr/share/guardd/guardd-config.example.json"
install -m 0644 data/io.github.plfjy.SensitiveFileGuard.desktop "$payload/usr/share/applications/io.github.plfjy.SensitiveFileGuard.desktop"
install -m 0644 data/io.github.plfjy.SensitiveFileGuard.metainfo.xml "$payload/usr/share/metainfo/io.github.plfjy.SensitiveFileGuard.metainfo.xml"
install -m 0644 data/io.github.plfjy.SensitiveFileGuard.svg "$payload/usr/share/icons/hicolor/scalable/apps/io.github.plfjy.SensitiveFileGuard.svg"
for document in README.md docs/Linux安装指南.md docs/linux-release.md docs/安全模型.md docs/SSH访问模型.md; do
  install -m 0644 "$document" "$payload/usr/share/doc/sensitive-file-guard/$(basename "$document")"
done
install -m 0644 LICENSE-MIT "$payload/usr/share/licenses/sensitive-file-guard/LICENSE-MIT"
install -m 0644 LICENSE-APACHE "$payload/usr/share/licenses/sensitive-file-guard/LICENSE-APACHE"
install -m 0755 packaging/linux/install-release.sh "$bundle_dir/install.sh"
printf '%s\n' "$release_version" > "$bundle_dir/VERSION"
printf '%s\n' "$source_commit" > "$bundle_dir/SOURCE_COMMIT"

(
  cd "$bundle_dir"
  find . -type f ! -name manifest.sha256 -print0 | sort -z | xargs -0 sha256sum > manifest.sha256
)

mkdir -p "$output_dir"
artifact="$output_dir/$bundle_name.tar.gz"
tar --sort=name --mtime="@$source_epoch" --owner=0 --group=0 --numeric-owner \
  -C "$work_dir" -cf - "$bundle_name" | gzip -n > "$artifact"
sha256sum "$artifact" > "$artifact.sha256"
echo "$artifact"
