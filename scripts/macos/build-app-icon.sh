#!/bin/sh
set -eu

if [ "$(uname -s)" != "Darwin" ]; then
    echo "build-app-icon.sh requires macOS" >&2
    exit 2
fi

source_svg=${1:?source SVG is required}
output_icns=${2:?output ICNS path is required}

test -f "$source_svg" || {
    echo "icon source is missing: $source_svg" >&2
    exit 2
}
for command_name in rsvg-convert iconutil; do
    command -v "$command_name" >/dev/null 2>&1 || {
        echo "missing required icon tool: $command_name" >&2
        exit 2
    }
done

work=$(mktemp -d "${TMPDIR:-/tmp}/guard-icon.XXXXXX")
cleanup() { rm -rf -- "$work"; }
trap cleanup EXIT HUP INT TERM
iconset="$work/Guard.iconset"
mkdir -p "$iconset" "$(dirname -- "$output_icns")"

render() {
    pixels=$1
    filename=$2
    rsvg-convert -w "$pixels" -h "$pixels" "$source_svg" \
        -o "$iconset/$filename"
}

render 16 icon_16x16.png
render 32 icon_16x16@2x.png
render 32 icon_32x32.png
render 64 icon_32x32@2x.png
render 128 icon_128x128.png
render 256 icon_128x128@2x.png
render 256 icon_256x256.png
render 512 icon_256x256@2x.png
render 512 icon_512x512.png
render 1024 icon_512x512@2x.png

iconutil --convert icns --output "$output_icns" "$iconset"
test -s "$output_icns"
