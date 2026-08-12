#!/bin/sh
set -eu

if [ "$(uname -s)" != "Darwin" ]; then
    echo "bundle-gtk-runtime.sh requires macOS" >&2
    exit 2
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH= cd -- "$script_dir/../.." && pwd)
app=${1:-"$repo_dir/build/macos-release/Guard.app"}
case "$app" in
    *'|'*|*'
'*) echo "unsupported app path: $app" >&2; exit 2 ;;
esac
test -x "$app/Contents/MacOS/Guard" || {
    echo "Guard executable is missing from bundle: $app" >&2
    exit 2
}

for command_name in otool install_name_tool pkg-config file realpath brew codesign; do
    command -v "$command_name" >/dev/null 2>&1 || {
        echo "missing required command: $command_name" >&2
        exit 2
    }
done

frameworks="$app/Contents/Frameworks"
resources="$app/Contents/Resources"
rm -rf -- "$frameworks" "$resources"
mkdir -p "$frameworks" "$resources/gdk-pixbuf/loaders"
mkdir -p "$resources/share/glib-2.0/schemas" "$resources/share/icons/hicolor"

loader_dir=$(pkg-config --variable=gdk_pixbuf_moduledir gdk-pixbuf-2.0)
loader_cache=$(pkg-config --variable=gdk_pixbuf_cache_file gdk-pixbuf-2.0)
brew_prefix=$(brew --prefix)
test -d "$loader_dir" && test -f "$loader_cache" || {
    echo "gdk-pixbuf loader metadata is unavailable" >&2
    exit 2
}

work=$(mktemp -d "${TMPDIR:-/tmp}/guard-macos-bundle.XXXXXX")
cleanup() {
    rm -rf -- "$work"
}
trap cleanup EXIT INT TERM
queue="$work/queue"
processed="$work/processed"
sources="$work/sources"
: >"$queue"
: >"$processed"
: >"$sources"

enqueue() {
    source_file=$1
    target_file=$2
    target_kind=$3
    printf '%s|%s|%s\n' "$source_file" "$target_file" "$target_kind" >>"$queue"
}

copy_runtime_file() {
    source_file=$(realpath "$1")
    base=$(basename "$source_file")
    target_file="$frameworks/$base"
    existing_source=$(awk -F '|' -v base="$base" '$1 == base { print $2; exit }' "$sources")
    if [ -n "$existing_source" ] && [ "$existing_source" != "$source_file" ]; then
        cmp -s "$existing_source" "$source_file" || {
            echo "runtime dependency basename collision: $existing_source and $source_file" >&2
            exit 2
        }
    fi
    if [ ! -e "$target_file" ]; then
        cp -L "$source_file" "$target_file"
        chmod u+w "$target_file"
        codesign --remove-signature "$target_file" 2>/dev/null || true
        printf '%s|%s\n' "$base" "$source_file" >>"$sources"
        enqueue "$source_file" "$target_file" framework
    fi
    printf '%s\n' "$target_file"
}

for loader in "$loader_dir"/*; do
    test -f "$loader" || continue
    target="$resources/gdk-pixbuf/loaders/$(basename "$loader")"
    cp -L "$loader" "$target"
    chmod u+w "$target"
    codesign --remove-signature "$target" 2>/dev/null || true
    enqueue "$(realpath "$loader")" "$target" loader
done

sed "s|$loader_dir|@GUARD_APP@/Contents/Resources/gdk-pixbuf/loaders|g" \
    "$loader_cache" >"$resources/gdk-pixbuf/loaders.cache.in"
cp -L "$brew_prefix/share/glib-2.0/schemas/gschemas.compiled" \
    "$resources/share/glib-2.0/schemas/gschemas.compiled"
for icon_file in index.theme icon-theme.cache; do
    if [ -f "$brew_prefix/share/icons/hicolor/$icon_file" ]; then
        cp -L "$brew_prefix/share/icons/hicolor/$icon_file" \
            "$resources/share/icons/hicolor/$icon_file"
    fi
done
cp "$repo_dir/packaging/macos/THIRD_PARTY_NOTICES.md" \
    "$resources/THIRD_PARTY_NOTICES.md"
: >"$resources/guard-release-runtime"

enqueue "$app/Contents/MacOS/Guard" "$app/Contents/MacOS/Guard" main
line_number=1
while :; do
    line=$(sed -n "${line_number}p" "$queue")
    test -n "$line" || break
    line_number=$((line_number + 1))
    source_file=${line%%|*}
    remainder=${line#*|}
    target_file=${remainder%%|*}
    target_kind=${remainder##*|}
    if grep -Fqx "$target_file" "$processed"; then
        continue
    fi
    printf '%s\n' "$target_file" >>"$processed"
    own_id=$(otool -D "$source_file" 2>/dev/null | sed -n '2p')
    otool -L "$source_file" | sed '1d' | awk '{print $1}' | while IFS= read -r dependency; do
        test -n "$dependency" || continue
        if [ -n "$own_id" ] && [ "$dependency" = "$own_id" ]; then
            continue
        fi
        case "$dependency" in
            /System/Library/*|/usr/lib/*) continue ;;
            @loader_path/*)
                resolved=$(realpath "$(dirname "$source_file")/${dependency#@loader_path/}")
                ;;
            @executable_path/*)
                continue
                ;;
            @rpath/*)
                resolved=
                for rpath in $(otool -l "$source_file" | \
                    awk '/cmd LC_RPATH/{getline; getline; print $2}'); do
                    case "$rpath" in
                        @loader_path/*)
                            candidate="$(dirname "$source_file")/${rpath#@loader_path/}/${dependency#@rpath/}"
                            ;;
                        /*)
                            candidate="$rpath/${dependency#@rpath/}"
                            ;;
                        *) continue ;;
                    esac
                    if [ -f "$candidate" ]; then
                        resolved=$(realpath "$candidate")
                        break
                    fi
                done
                test -n "$resolved" || {
                    echo "unresolved non-system @rpath dependency in $source_file: $dependency" >&2
                    exit 2
                }
                ;;
            /*)
                resolved=$(realpath "$dependency")
                ;;
            *)
                echo "unsupported dependency in $source_file: $dependency" >&2
                exit 2
                ;;
        esac
        bundled=$(copy_runtime_file "$resolved")
        base=$(basename "$bundled")
        case "$target_kind" in
            main) replacement="@rpath/$base" ;;
            framework) replacement="@loader_path/$base" ;;
            loader) replacement="@loader_path/../../../Frameworks/$base" ;;
            *) echo "unknown target kind: $target_kind" >&2; exit 2 ;;
        esac
        install_name_tool -change "$dependency" "$replacement" "$target_file"
    done
    if [ "$target_kind" = framework ]; then
        install_name_tool -id "@rpath/$(basename "$target_file")" "$target_file"
    elif [ "$target_kind" = loader ] && [ -n "$own_id" ]; then
        install_name_tool -id "@loader_path/$(basename "$target_file")" "$target_file"
    fi
done

if ! otool -l "$app/Contents/MacOS/Guard" | \
    awk '/cmd LC_RPATH/{seen=1} seen && /path @executable_path\/\.\.\/Frameworks/{found=1} END{exit !found}'; then
    install_name_tool -add_rpath '@executable_path/../Frameworks' \
        "$app/Contents/MacOS/Guard"
fi

count=$(find "$frameworks" -type f | wc -l | tr -d ' ')
echo "bundled $count recursively required non-system libraries"
echo "bundled gdk-pixbuf loaders and relocatable GTK runtime metadata"
