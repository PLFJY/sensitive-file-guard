#!/bin/sh
# MCH2 — capture-process-authority-matrix.sh
#
# Metadata-only capture of which exact browser process ROLES touch which
# protected-resource classes, using real Endpoint Security observations from
# the live guard-es audit store against DISPOSABLE synthetic profiles.
#
# NEVER reads browser memory, cookie/key contents, or real profiles. Only
# audit metadata (event rows) + process argv/exe identity is used to infer
# roles. This is EVIDENCE for MCH4/MCH5 SecretAuthority targeting; it is NOT
# a compatibility or security acceptance run.
#
# Prerequisites (checked below):
#   - guardctl on PATH and the production extension ACTIVE (LIVE_ES_ACCEPTANCE
#     + system-extension approval, same as the MPS11 harness);
#   - a DISPOSABLE Chrome profile already enrolled as a protected browser
#     profile (enrollment is an interactive GUI step by design).
#
# Usage:
#   LIVE_ES_ACCEPTANCE=I_ACCEPT_SYSTEM_EXTENSION_RISK \
#     DISPOSABLE_CHROME_PROFILE=/tmp/guard-mch2-profile \
#     ./capture-process-authority-matrix.sh
#
# Output: $work/authority-matrix.tsv with columns
#   browser  role  executable  protected_kind  access_class  event_code  count
# where role is inferred ONLY from argv/exe metadata (Chrome --type=..., Firefox
# content/utility naming) and NEVER grants any authority by itself.
set -eu

if [ "$(uname -s)" != "Darwin" ]; then
    echo "MCH2 capture requires macOS" >&2
    exit 2
fi
: "${LIVE_ES_ACCEPTANCE:?set LIVE_ES_ACCEPTANCE=I_ACCEPT_SYSTEM_EXTENSION_RISK to run a live capture}"
: "${DISPOSABLE_CHROME_PROFILE:?DISPOSABLE_CHROME_PROFILE is required (disposable profile root, already enrolled)}"

chrome="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
work=$(mktemp -d "${TMPDIR:-/tmp}/guard-mch2.XXXXXX")
matrix="$work/authority-matrix.tsv"
trap 'pkill -f "user-data-dir=.*guard-mch2" 2>/dev/null || true; pkill -f "profile .*guard-mch2" 2>/dev/null || true; rm -rf -- "$work"' EXIT HUP INT TERM

# 1. The live extension must be active (backend ACTIVE, not diagnostic mode).
status_json=$(guardctl status 2>/dev/null || true)
case "$status_json" in
    *'"backend_kind":"macos-endpoint-security"'*)
        echo "extension backend active"
        ;;
    *)
        echo "BLOCKED: guardctl status does not show an active macOS Endpoint Security backend" >&2
        exit 3
        ;;
esac

# 2. The disposable Chrome profile must be enrolled as protected.
guardctl resources >"$work/resources.json" 2>/dev/null || true
if ! grep -q "$DISPOSABLE_CHROME_PROFILE" "$work/resources.json" 2>/dev/null; then
    echo "BLOCKED: $DISPOSABLE_CHROME_PROFILE is not in the protected-resources list." >&2
    echo "        Enroll the disposable profile interactively in the GUI first (MPS11 pattern)." >&2
    exit 3
fi

# 3. Drive disposable Chrome: multiple tabs, multiple origins, navigation,
#    reload, renderer churn, service worker. Normal sandbox; no --no-sandbox.
"$chrome" \
    --user-data-dir="$DISPOSABLE_CHROME_PROFILE" \
    --no-first-run --no-default-browser-check --disable-sync \
    --disable-component-update --disable-features=OptimizationHints \
    "data:text/html,<title>mch2-a</title>t1" >/dev/null 2>&1 &
sleep 6
for url in "https://example.com/" "https://example.org/" "https://www.iana.org/domains/reserved" "data:text/html,<title>mch2-b</title>t2"; do
    "$chrome" --user-data-dir="$DISPOSABLE_CHROME_PROFILE" "$url" >/dev/null 2>&1 || true
    sleep 2
done
# Renderer churn: open and close several tabs.
for i in 1 2 3 4 5; do
    "$chrome" --user-data-dir="$DISPOSABLE_CHROME_PROFILE" "data:text/html,<title>churn-$i</title>x" >/dev/null 2>&1 || true
    sleep 1
done
# Let background network/service-worker activity settle.
sleep 8

# 4. Capture audit metadata (metadata only). Map each event pid to the live
#    process argv to infer the browser role.
ps_snapshot="$work/ps.tsv"
ps -axo pid=,command= | sed 's/^[[:space:]]*//' >"$ps_snapshot" 2>/dev/null || true

role_of_pid() {
    pid=$1
    line=$(awk -v p="$pid" '$1 == p { sub(/^[0-9]+[[:space:]]+/, ""); print; exit }' "$ps_snapshot" 2>/dev/null || true)
    [ -n "$line" ] || return
    case "$line" in
        *'--type=renderer'*) echo "renderer" ;;
        *'--type=gpu-process'*) echo "gpu" ;;
        *'--type=utility'*'network.mojom.NetworkService'*) echo "network_service" ;;
        *'--type=utility'*) echo "utility" ;;
        *'--type=crashpad'*) echo "crash_handler" ;;
        *'--type=extension'*) echo "extension_related" ;;
        *'--type='*) echo "other_helper" ;;
        *'Google Chrome'*|*'Chromium'*) echo "main" ;;
        *'firefox'*|*'Firefox'*) echo "main" ;;
        *) echo "unknown" ;;
    esac
}

# 5. Emit the matrix: per event row, one line browser/role/kind/event/decision.
guardctl events --limit 2000 2>/dev/null | awk '
    /"event_code":/ {
        line = $0
        pid = ""; code = ""; kind = ""; decision = ""; exe = ""; browser = ""
        if (match(line, /"pid":[ ]*[0-9]+/)) pid = substr(line, RSTART+6, RLENGTH-6)
        if (match(line, /"event_code":"[^"]*"/)) code = substr(line, RSTART+13, RLENGTH-14)
        if (match(line, /"resource_kind_code":"[^"]*"/)) kind = substr(line, RSTART+21, RLENGTH-22)
        if (match(line, /"decision":"[^"]*"/)) decision = substr(line, RSTART+11, RLENGTH-12)
        if (match(line, /"exe":"[^"]*"/)) exe = substr(line, RSTART+6, RLENGTH-7)
        if (match(line, /"resource_browser":"[^"]*"/)) browser = substr(line, RSTART+18, RLENGTH-19)
        if (code ~ /^browser_/ || code ~ /^process_shield_/ || code ~ /^ssh_/) {
            print browser "\t" pid "\t" exe "\t" kind "\t" code "\t" decision
        }
    }
' >"$work/raw.tsv" 2>/dev/null || true

# Join with role inference and aggregate into the final matrix.
{
    printf 'browser\trole\texecutable\tprotected_kind\taccess_class\tevent_code\tcount\n'
    while IFS=$(printf '\t') read -r browser pid exe kind code decision; do
        [ -n "$pid" ] || continue
        role=$(role_of_pid "$pid")
        [ -n "$role" ] || role="unknown"
        access="read"
        case "$decision" in
            *[Ww]rite*) access="write" ;;
        esac
        printf '%s\t%s\t%s\t%s\t%s\t%s\t1\n' "$browser" "$role" "$exe" "$kind" "$access" "$code"
    done <"$work/raw.tsv"
} | sort | uniq -c | awk '{ c=$1; $1=""; sub(/^[[:space:]]+/, ""); print $0 "\t" c }' >"$matrix" 2>/dev/null || true

if [ ! -s "$matrix" ]; then
    echo "BLOCKED: no classifiable audit rows captured (extension live but no events); nothing to output" >&2
    exit 3
fi

echo "MCH2 authority-matrix capture complete (metadata only):"
cat "$matrix"
echo
echo "Matrix written to: $matrix"
echo "NOTE: role inference from argv/exe is evidence for SecretAuthority"
echo "targeting (MCH4/MCH5). It is NOT authority and NOT an acceptance result."
