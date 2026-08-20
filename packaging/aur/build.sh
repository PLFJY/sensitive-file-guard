#!/usr/bin/env bash
# Build the AUR VCS package without makepkg rewriting pkgver in the checkout.
set -euo pipefail

package_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$package_dir"
exec makepkg --holdver "$@"
