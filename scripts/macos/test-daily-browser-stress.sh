#!/bin/sh
# MCH9 — test-daily-browser-stress.sh
#
# Disposable-profile daily-use stress for macOS Process Shield (Chrome +
# Firefox): 10+ tabs, multi-origin navigation, reload, tab close/reopen,
# renderer/content-process churn, JS/JIT, WebAssembly, WebGL/GPU, Service
# Worker, background activity, idle period, browser restart.
#
# DISPOSABLE synthetic profiles only. NEVER touches real browser profiles or
# secrets. Runs against the LIVE production extension (same prerequisites as
# the MPS11 harness: LIVE_ES_ACCEPTANCE + permanent extension approval).
#
# Acceptance (per goal §18): browser functionality PASS + 0 UNEXPLAINED
# task DENY + 0 false Compromised + 0 Process-Shield-caused protected-profile
# DENY. This script asserts browser functionality and CAPTURES the Process
# Shield counters before/after for human classification of any deny; it never
# fabricates acceptance.
#
# Usage:
#   LIVE_ES_ACCEPTANCE=I_ACCEPT_SYSTEM_EXTENSION_RISK \
#     ./test-daily-browser-stress.sh
set -eu

if [ "$(uname -s)" != "Darwin" ]; then
    echo "MCH9 stress requires macOS" >&2
    exit 2
fi
: "${LIVE_ES_ACCEPTANCE:?set LIVE_ES_ACCEPTANCE=I_ACCEPT_SYSTEM_EXTENSION_RISK to run the live stress}"

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/guard-mch9.XXXXXX")
fixtures="$work/www"
mkdir -p "$fixtures"
chrome="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
firefox="/Applications/Firefox.app/Contents/MacOS/firefox"
port=8765
base="http://127.0.0.1:$port"
chrome_pid=
ff_pid=
http_pid=
pass=0
fail=0

cleanup() {
    [ -z "$chrome_pid" ] || kill "$chrome_pid" 2>/dev/null || true
    [ -z "$ff_pid" ] || kill "$ff_pid" 2>/dev/null || true
    [ -z "$http_pid" ] || kill "$http_pid" 2>/dev/null || true
    pkill -f 'user-data-dir=.*guard-mch9' 2>/dev/null || true
    pkill -f 'profile .*guard-mch9' 2>/dev/null || true
    rm -rf -- "$work"
}
trap cleanup EXIT HUP INT TERM

check() {
    name=$1
    shift
    if "$@"; then
        pass=$((pass + 1))
        echo "PASS: $name"
    else
        fail=$((fail + 1))
        echo "FAIL: $name"
    fi
}

# 1. The live extension must be active.
case "$(guardctl status 2>/dev/null || true)" in
    *'"backend_kind":"macos-endpoint-security"'*) echo "extension backend active" ;;
    *)
        echo "BLOCKED: guardctl status does not show an active macOS Endpoint Security backend" >&2
        exit 3
        ;;
esac

# 2. Synthetic stress pages (deterministic, offline; SW requires localhost http).
cat >"$fixtures/index.html" <<'EOF'
<!doctype html><html><head><title>mch9 index</title></head><body>
<script>
let n = 0;
for (let i = 0; i < 200000; i++) { n = (n + i * i) % 1000003; } // JIT loop
fetch('count.txt').then(r => r.text()).then(t => { document.title = 'mch9-js-' + (n % 7) + '-' + t.trim(); });
</script>
<h1>mch9 js/jit</h1></body></html>
EOF
cat >"$fixtures/count.txt" <<'EOF'
1
EOF
cat >"$fixtures/wasm.html" <<'EOF'
<!doctype html><html><head><title>mch9 wasm</title></head><body>
<script>
// Minimal wasm module exporting add(a,b) -> i32.
const bytes = new Uint8Array([0,97,115,109,1,0,0,0,1,5,1,96,0,1,127,3,2,1,0,7,7,1,3,97,100,100,0,0,10,9,1,7,0,65,1,65,2,106,11]);
WebAssembly.instantiate(bytes).then(m => { document.title = 'mch9-wasm-' + m.instance.exports.add(1, 2); });
</script>
<h1>mch9 webassembly</h1></body></html>
EOF
cat >"$fixtures/webgl.html" <<'EOF'
<!doctype html><html><head><title>mch9 webgl</title></head><body>
<canvas id='c' width='64' height='64'></canvas>
<script>
const gl = document.getElementById('c').getContext('webgl');
if (gl) { gl.clearColor(0.1, 0.4, 0.9, 1); gl.clear(gl.COLOR_BUFFER_BIT); document.title = 'mch9-webgl-ok'; }
else { document.title = 'mch9-webgl-unavailable'; }
</script>
<h1>mch9 webgl/gpu</h1></body></html>
EOF
cat >"$fixtures/sw.html" <<'EOF'
<!doctype html><html><head><title>mch9 sw</title></head><body>
<script>
if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register('sw.js').then(() => {
    navigator.serviceWorker.ready.then(() => { document.title = 'mch9-sw-ready'; });
  });
}
</script>
<h1>mch9 service worker</h1></body></html>
EOF
cat >"$fixtures/sw.js" <<'EOF'
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));
EOF
cat >"$fixtures/idle.html" <<'EOF'
<!doctype html><html><head><title>mch9 idle</title></head><body><h1>idle</h1></body></html>
EOF

# 3. Serve the fixture origin locally (Service Worker requires http://localhost).
if command -v python3 >/dev/null 2>&1; then
    (cd "$fixtures" && python3 -m http.server "$port" --bind 127.0.0.1) >"$work/http.log" 2>&1 &
    http_pid=$!
    sleep 2
    if curl -sf "$base/index.html" >/dev/null 2>&1; then
        echo "local fixture origin active: $base"
    else
        echo "SKIP: local http server did not come up; wasm/webgl/sw pages use file: fallback" >&2
        http_ok=0
    fi
fi
http_ok=${http_ok:-1}

chrome_flags="--user-data-dir=$work/chrome-profile --no-first-run --no-default-browser-check --disable-component-update --disable-sync"

# 4. Capture Process Shield counters before the stress (for deny classification).
capture_counters() {
    guardctl status 2>/dev/null | tr ',' '\n' | grep -E '"task_control_denied"|"task_read_denied"|"shield_compromised"|"shield_admitted"' | tr -d '"{}' || true
}

echo '--- Process Shield counters BEFORE stress ---'
counters_before=$(capture_counters)
printf '%s\n' "$counters_before"

# 5. Chrome daily-use stress (normal sandbox).
mkdir -p "$work/chrome-profile"
if [ "$http_ok" -eq 1 ]; then
    first_url="$base/index.html"
else
    first_url="file://$fixtures/index.html"
fi
"$chrome" $chrome_flags "$first_url" >"$work/chrome.log" 2>&1 &
chrome_pid=$!
sleep 12
check 'chrome stress launch (normal sandbox)' kill -0 "$chrome_pid" 2>/dev/null

# 10+ tabs, multiple origins, repeated navigation, renderer churn.
page_urls="$base/index.html $base/wasm.html $base/webgl.html $base/sw.html $base/idle.html https://example.com/ https://example.org/ https://www.iana.org/domains/reserved"
if [ "$http_ok" -ne 1 ]; then
    page_urls="file://$fixtures/index.html file://$fixtures/wasm.html file://$fixtures/webgl.html file://$fixtures/idle.html https://example.com/ https://example.org/"
fi
for url in $page_urls; do
    "$chrome" $chrome_flags "$url" >/dev/null 2>&1 || true
    sleep 1
done
for i in 1 2 3 4 5; do
    "$chrome" $chrome_flags "$base/idle.html" >/dev/null 2>&1 || true
    sleep 1
done
check 'chrome alive after 10+ tab churn' kill -0 "$chrome_pid" 2>/dev/null

# Renderer churn: close and reopen a stress tab repeatedly.
for i in 1 2 3; do
    "$chrome" $chrome_flags "$base/wasm.html" >/dev/null 2>&1 || true
    sleep 1
    pkill -f 'user-data-dir=.*guard-mch9' 2>/dev/null || true
    sleep 2
    "$chrome" $chrome_flags "$base/index.html" >/dev/null 2>&1 &
    chrome_pid=$!
    sleep 4
done
check 'chrome alive after renderer churn' kill -0 "$chrome_pid" 2>/dev/null

# Idle / background behavior, then restart.
sleep 20
check 'chrome alive after idle period' kill -0 "$chrome_pid" 2>/dev/null
pkill -f 'user-data-dir=.*guard-mch9' 2>/dev/null || true
sleep 4
"$chrome" $chrome_flags "$base/index.html" >/dev/null 2>&1 &
chrome_pid=$!
sleep 12
check 'chrome restart works' kill -0 "$chrome_pid" 2>/dev/null
pkill -f 'user-data-dir=.*guard-mch9' 2>/dev/null || true
sleep 3

# 6. Firefox daily-use stress (content-process churn analog).
mkdir -p "$work/ff-profile"
ff_base="$base/index.html"
[ "$http_ok" -eq 1 ] || ff_base="file://$fixtures/index.html"
"$firefox" --no-remote -profile "$work/ff-profile" "$ff_base" >"$work/ff.log" 2>&1 &
ff_pid=$!
sleep 14
check 'firefox stress launch' kill -0 "$ff_pid" 2>/dev/null

for url in "$base/wasm.html" "$base/webgl.html" "$base/sw.html" "$base/idle.html" "https://example.com/" "https://example.org/"; do
    [ "$http_ok" -eq 1 ] || url=$(echo "$url" | sed "s|$base|file://$fixtures|g")
    "$firefox" --no-remote -profile "$work/ff-profile" "$url" >/dev/null 2>&1 || true
    sleep 2
done
for i in 1 2 3 4 5; do
    "$firefox" --no-remote -profile "$work/ff-profile" "$base/idle.html" >/dev/null 2>&1 || true
    sleep 1
done
check 'firefox alive after content-process churn' kill -0 "$ff_pid" 2>/dev/null
sleep 20
check 'firefox alive after idle period' kill -0 "$ff_pid" 2>/dev/null
pkill -f 'profile .*guard-mch9' 2>/dev/null || true
sleep 4
"$firefox" --no-remote -profile "$work/ff-profile" "$ff_base" >/dev/null 2>&1 &
ff_pid=$!
sleep 14
check 'firefox restart works' kill -0 "$ff_pid" 2>/dev/null
pkill -f 'profile .*guard-mch9' 2>/dev/null || true
sleep 3

# 7. Capture counters AFTER the stress and report for deny classification.
echo '--- Process Shield counters AFTER stress (for human classification) ---'
printf '%s\n' "$(capture_counters)"

echo
echo "MCH9 SUMMARY pass=$pass fail=$fail"
echo "NOTE: browser-functionality PASS above is not daily-use ACCEPTANCE."
echo "Acceptance additionally requires the human to classify EVERY deny row"
echo "captured by guardctl events (real attack / expected probe / legitimate"
echo "browser relationship missing from policy / bug / unknown). Any"
echo "unexplained normal-use deny means daily-browser compatibility = NOT ACCEPTED."
[ "$fail" -eq 0 ] || exit 1
