#!/bin/sh
set -eu

if [ "$(uname -s)" != "Darwin" ]; then
    echo "test-ui-layout.sh requires macOS" >&2
    exit 2
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH= cd -- "$script_dir/../.." && pwd)
app=${1:-"$repo_dir/build/macos-release/Sensitive File Guard.app"}
guard="$app/Contents/MacOS/SensitiveFileGuard"
test -x "$guard" || {
    echo "Guard executable is missing: $guard" >&2
    exit 2
}

run_page() {
    page=$1
    argument=$2
    log=$(mktemp "${TMPDIR:-/tmp}/guard-ui-layout.XXXXXX")
    "$guard" "$argument" >"$log" 2>&1 &
    pid=$!
    cleanup_page() {
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
        rm -f -- "$log"
    }
    trap cleanup_page EXIT HUP INT TERM

    bounds=
    attempt=0
    while [ "$attempt" -lt 20 ]; do
        bounds=$(swift -e '
            import CoreGraphics
            let wanted = Int(CommandLine.arguments[1])!
            let windows = CGWindowListCopyWindowInfo(
                [.optionOnScreenOnly, .excludeDesktopElements],
                kCGNullWindowID
            ) as? [[String: Any]] ?? []
            for window in windows {
                guard (window[kCGWindowOwnerPID as String] as? Int) == wanted,
                      let raw = window[kCGWindowBounds as String] as? [String: Any],
                      let width = raw["Width"] as? Int,
                      let height = raw["Height"] as? Int else { continue }
                print("\(width) \(height)")
                break
            }
        ' "$pid")
        test -n "$bounds" && break
        sleep 0.25
        attempt=$((attempt + 1))
    done
    test -n "$bounds" || {
        echo "$page UI window did not appear" >&2
        sed -n '1,80p' "$log" >&2
        exit 1
    }
    set -- $bounds
    test "$1" -le 800 || {
        echo "$page UI width expanded to $1 points" >&2
        exit 1
    }
    test "$2" -le 600 || {
        echo "$page UI height expanded to $2 points" >&2
        exit 1
    }
    echo "PASS: $page long-status layout stayed at $1x$2 points"
    cleanup_page
    trap - EXIT HUP INT TERM
}

run_page overview --ui-layout-smoke
run_page protection --ui-layout-smoke-protection
run_page log --ui-layout-smoke-log

close_log=$(mktemp "${TMPDIR:-/tmp}/guard-ui-close.XXXXXX")
"$guard" --ui-close-smoke >"$close_log" 2>&1 &
close_pid=$!
close_attempt=0
while kill -0 "$close_pid" 2>/dev/null && [ "$close_attempt" -lt 20 ]; do
    sleep 0.25
    close_attempt=$((close_attempt + 1))
done
if kill -0 "$close_pid" 2>/dev/null; then
    kill "$close_pid" 2>/dev/null || true
    wait "$close_pid" 2>/dev/null || true
    echo "GUI process remained in the Dock after close-request" >&2
    sed -n '1,80p' "$close_log" >&2
    rm -f -- "$close_log"
    exit 1
fi
wait "$close_pid"
rm -f -- "$close_log"
echo "PASS: macOS close-request exited the GUI process"
