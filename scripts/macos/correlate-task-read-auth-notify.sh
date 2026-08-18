#!/bin/sh
# GET_TASK_READ AUTH<->NOTIFY correlation probe (P1 review, finding 6).
# Question: when an AUTH_GET_TASK_READ deny and a NOTIFY_GET_TASK_READ
# telemetry event both appear for the same requester/target, are they the
# same capability acquisition (Apple: notify fires only AFTER a send right
# was granted) or two adjacent but distinct requests?
# Method: run a controlled /bin/ps task_read on a task-protected target
# (guard-es, the extension itself - safe: GET_TASK_READ notify is telemetry
# only on this build, no Compromised transition) and capture the audit
# window BEFORE/AFTER. Print exact ts_ms/requester/target of every new
# Deny(task_read) and notify_get_task_read row so a human can judge.
set -eu

if [ "$(uname -s)" != "Darwin" ]; then
    echo "correlation probe requires macOS" >&2
    exit 2
fi

GUARDCTL=${GUARDCTL:-/Applications/Sensitive File Guard.app/Contents/MacOS/guardctl}
test -x "$GUARDCTL" || { echo "guardctl not found: $GUARDCTL" >&2; exit 2; }

target_pid=$(pgrep -x guard-es | head -1 || true)
test -n "$target_pid" || { echo "guard-es target not running" >&2; exit 2; }

echo "target=guard-es pid=$target_pid"
"$GUARDCTL" events --limit 50 2>/dev/null | head -3

# Controlled probe: read the target's task metadata with /bin/ps.
ps -o lstart= -p "$target_pid" >/dev/null 2>&1 || true
sleep 1

echo '--- audit rows after the probe (latest 25) ---'
"$GUARDCTL" events --limit 25 2>/dev/null | head -25

echo
echo '--- explain every new DENY / notify row ---'
"$GUARDCTL" events --limit 25 2>/dev/null | awk 'NR>1 {print $1}' | while read -r id; do
    row=$("$GUARDCTL" --json explain "$id" 2>/dev/null || true)
    code=$(printf '%s' "$row" | sed -n 's/.*"event_code": "\([^"]*\)".*/\1/p')
    ts=$(printf '%s' "$row" | sed -n 's/.*"ts_ms": \([0-9]*\).*/\1/p')
    diag=$(printf '%s' "$row" | sed -n 's/.*"backend_diag": "\([^"]*\)".*/\1/p')
    case "$code" in
        *task_read*|*compromised*|*task_notify*)
            echo "id=$id ts_ms=$ts code=$code diag=$diag"
            ;;
    esac
done

echo
echo 'INTERPRETATION: compare ts_ms of the Deny(task_read) row with the'
echo 'notify_get_task_read row for the same requester (/bin/ps) and target.'
echo 'Equal/adjacent ts_ms + same requester/target supports a single'
echo 'acquisition (Apple: notify fires only after the grant). Divergent'
echo 'ts_ms or different objects disproves the correlation. Until a'
echo 'controlled probe proves one-acquisition semantics, GET_TASK_READ'
echo 'strong-signal semantics stay NOT ACCEPTED (health Reduced).'
