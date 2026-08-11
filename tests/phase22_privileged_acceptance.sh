#!/usr/bin/env bash
# Phase 22.2 privileged BPF acceptance. Run as:
#   sudo tests/phase22_privileged_acceptance.sh
# All files and payloads are synthetic; the sink is a disposable non-loopback
# dummy address in the local network namespace.
set -euo pipefail

if [[ $EUID -ne 0 ]]; then echo "BLOCKED: run as root" >&2; exit 2; fi
if [[ ! -v SUDO_USER || $SUDO_USER == root ]]; then echo "BLOCKED: run through sudo from the desktop user" >&2; exit 2; fi
repo=$(cd -- "$(dirname -- "$BASH_SOURCE")/.." && pwd)
guardd="$repo/target/release/guardd"
guardctl="$repo/target/release/guardctl"
[[ -x $guardd && -x $guardctl ]] || { echo "BLOCKED: cargo build --release first" >&2; exit 2; }
user=$SUDO_USER
uid=$(id -u "$user")
tmp=$(mktemp -d /tmp/guardd-phase22.2-accept.XXXXXX)
dummy=guard22dummy$$
dummy6=2001:db8:22:1::1
daemon=; sink=; local_sink=; action_worker=; quarantine_incident=
cleanup() {
  [[ -n $daemon ]] && kill "$daemon" 2>/dev/null || true
  [[ -n $sink ]] && kill "$sink" 2>/dev/null || true
  [[ -n $local_sink ]] && kill "$local_sink" 2>/dev/null || true
  [[ -n $action_worker ]] && kill "$action_worker" 2>/dev/null || true
  if [[ $quarantine_incident =~ ^ssh-[0-9a-fA-F]{16}$ ]]; then
    rm -rf -- "/var/lib/guardd/quarantine/$quarantine_incident"
  fi
  ip link del "$dummy" 2>/dev/null || true
  rm -rf -- "$tmp"
}
trap cleanup EXIT
key="$tmp/id_ed25519"; key2="$tmp/id_rsa"; config="$tmp/config.json"; socket="$tmp/guardd.sock"
printf '%s\n' '-----BEGIN GUARD SYNTHETIC PRIVATE KEY-----' 'PHASE22.2_MARKER_ONE_ONLY' '-----END GUARD SYNTHETIC PRIVATE KEY-----' >"$key"
printf '%s\n' '-----BEGIN GUARD SYNTHETIC PRIVATE KEY-----' 'PHASE22.2_MARKER_TWO_ONLY' '-----END GUARD SYNTHETIC PRIVATE KEY-----' >"$key2"
chown "$uid" "$tmp" "$key" "$key2"; chmod 700 "$tmp"; chmod 600 "$key" "$key2"
printf '{"enforcement_mode":"conservative","browsers":[],"enrolled_exes":[],"ssh_keys":["%s","%s"],"ssh_behavior_window_secs":1}\n' "$key" "$key2" >"$config"
chmod 600 "$config"

echo '==> Backend-unavailable read allowance'
"$guardd" --enforce-browser-config "$config" --ipc-socket "$socket" \
  --audit-db "$tmp/unavailable-audit.db" --test-disable-ssh-behavior-backend \
  >"$tmp/unavailable.log" 2>&1 &
daemon=$!
for _ in $(seq 1 100); do [[ -S $socket ]] && break; sleep .05; done
[[ -S $socket ]] || { cat "$tmp/unavailable.log" >&2; exit 1; }
runuser -u "$user" -- python3 -c 'import pathlib,sys; pathlib.Path(sys.argv[1]).read_bytes()' "$key"
status_json=$("$guardctl" --socket "$socket" --json status)
printf '%s' "$status_json" | python3 -c 'import json,sys; d=json.load(sys.stdin)["data"]; assert d["ssh_behavior_status"] == "UNAVAILABLE"'
"$guardctl" --socket "$socket" --json events --limit 20 | python3 -c 'import json,sys; assert any(e["event_code"] == "ssh_behavior_key_accessed" for e in json.load(sys.stdin)["data"])'
"$guardctl" --socket "$socket" --json incidents list | python3 -c 'import json,sys; assert not any(i["state"] == "pending_decision" for i in json.load(sys.stdin).get("data",[]))'
kill "$daemon"; wait "$daemon" || true; daemon=
rm -f "$socket"
echo 'PASS: backend-unavailable mode allowed and reported the read with honest status'

echo '==> Host/backend preflight'
grep -qw bpf /sys/kernel/security/lsm || { echo 'BLOCKED: BPF LSM is not active'; exit 2; }
[[ -r /sys/kernel/btf/vmlinux ]] || { echo 'BLOCKED: kernel BTF is unavailable'; exit 2; }
ip link add "$dummy" type dummy
ip addr add 198.18.0.1/32 dev "$dummy"
ip -6 addr add "$dummy6/128" dev "$dummy"
ip link set "$dummy" up

"$guardd" --enforce-browser-config "$config" --ipc-socket "$socket" --audit-db "$tmp/audit.db" >"$tmp/guardd.log" 2>&1 &
daemon=$!
for _ in $(seq 1 100); do
  grep -q 'enforcement active' "$tmp/guardd.log" && break
  if ! kill -0 "$daemon" 2>/dev/null; then cat "$tmp/guardd.log" >&2; exit 1; fi
  sleep .05
done
grep -q 'enforcement active' "$tmp/guardd.log" || { cat "$tmp/guardd.log" >&2; exit 1; }
if grep -q 'SSH behavioral backend unavailable' "$tmp/guardd.log"; then
  echo 'FAIL: BPF backend did not attach for active-backend acceptance' >&2
  cat "$tmp/guardd.log" >&2; exit 1
fi
grep -q 'SSH behavioral BPF send containment attached' "$tmp/guardd.log" || {
  echo 'FAIL: no positive live BPF attachment evidence' >&2; cat "$tmp/guardd.log" >&2; exit 1
}
echo 'PASS: daemon reports live BPF behavioral backend'
echo "INFO: running build: $("$guardctl" --socket "$socket" --json status | tr '\n' ' ')"

read_key() {
  runuser -u "$user" -- python3 -c 'import pathlib,sys; pathlib.Path(sys.argv[1]).read_bytes()' "$key"
}
start_sink() {
  local port_file=$1 bytes_file=$2 max_connections=${3:-1} host=${4:-198.18.0.1}
  python3 - "$port_file" "$bytes_file" "$max_connections" "$host" <<'PY' &
import pathlib, socket, sys
port_file, bytes_file = map(pathlib.Path, sys.argv[1:3])
max_connections = int(sys.argv[3])
host = sys.argv[4]
family = socket.AF_INET6 if ":" in host else socket.AF_INET
s=socket.socket(family); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind((host,0,0,0) if family == socket.AF_INET6 else (host,0)); s.listen(max_connections)
port_file.write_text(str(s.getsockname()[1]))
total=0
for _ in range(max_connections):
    c,_=s.accept(); c.settimeout(1)
    try: total += len(c.recv(4096))
    except TimeoutError: pass
    c.close()
bytes_file.write_text(str(total))
PY
  sink=$!
  while [[ ! -s $port_file ]]; do sleep .02; done
}
external_send() {
  local mode=$1 port=$2 host=${3:-198.18.0.1}
  runuser -u "$user" -- python3 -c '
import os,pathlib,socket,sys,time
key,port,mode,host=sys.argv[1],int(sys.argv[2]),sys.argv[3],sys.argv[4]
def send_once():
    s=socket.create_connection((host,port),timeout=2)
    try: s.sendall(b"PHASE22.1_DUMMY")
    finally: s.close()
if mode in ("read-fork-send", "read-fork-exec-send"):
    pathlib.Path(key).read_bytes()
    if os.fork() == 0:
        if mode == "read-fork-exec-send":
            child_code = """import socket,sys
try:
 s=socket.create_connection((sys.argv[1],int(sys.argv[2])),timeout=2)
 s.sendall(b"PHASE22.1_DUMMY")
 s.close()
except OSError:
 raise SystemExit(1)
raise SystemExit(0)"""
            os.execv(sys.executable, [sys.executable, "-c", child_code, host, str(port)])
        try:
            send_once()
        except OSError:
            os._exit(1)
        os._exit(0)
    _,status=os.wait()
    if status: raise SystemExit(1)
    raise SystemExit(0)
if mode == "connect-read-send":
    s=socket.create_connection((host,port),timeout=2)
    try:
        pathlib.Path(key).read_bytes()
        s.sendall(b"PHASE22.1_DUMMY")
    finally: s.close()
    raise SystemExit(0)
if mode.startswith("read"): pathlib.Path(key).read_bytes()
if mode == "read-send-reread-wait-send":
    try: send_once()
    except OSError: pass
    pathlib.Path(key).read_bytes(); time.sleep(1.3)
    send_once()
else:
    if mode == "read-wait-send": time.sleep(1.3)
    send_once()
' "$key" "$port" "$mode" "$host"
}

echo '==> Legitimate read and release key-read event'
read_key
key_events=$("$guardctl" --socket "$socket" --json events --limit 200)
key_count=$(printf '%s' "$key_events" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(sum(1 for e in d.get("data",[]) if e.get("event_code") == "ssh_behavior_key_accessed"))')
[[ $key_count == 1 ]] || { echo "FAIL: expected one key-read event, got $key_count"; exit 1; }
"$guardctl" --socket "$socket" --json incidents list | python3 -c 'import json,sys; assert not any(i["state"] == "pending_decision" for i in json.load(sys.stdin).get("data",[]))'
echo 'PASS: read allowed and one key-read event emitted'

echo '==> AF_UNIX allow case'
local_sock="$tmp/local.sock"
python3 - "$local_sock" "$tmp/unix-bytes" <<'PY' &
import pathlib,socket,sys
p,out=map(pathlib.Path,sys.argv[1:])
s=socket.socket(socket.AF_UNIX); s.bind(str(p)); s.listen(1)
c,_=s.accept(); out.write_text(str(len(c.recv(128))))
PY
local_sink=$!
while [[ ! -S $local_sock ]]; do sleep .02; done
runuser -u "$user" -- python3 -c 'import pathlib,socket,sys; pathlib.Path(sys.argv[1]).read_bytes(); s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[2]); s.sendall(b"LOCAL")' "$key" "$local_sock"
wait "$local_sink"; local_sink=
[[ $(<"$tmp/unix-bytes") == 5 ]] || { echo 'FAIL: AF_UNIX was blocked'; exit 1; }
echo 'PASS: AF_UNIX after key read allowed'

echo '==> Loopback allow case'
python3 - "$tmp/loop-port" "$tmp/loop-bytes" <<'PY' &
import pathlib,socket,sys
port_file,out=map(pathlib.Path,sys.argv[1:])
s=socket.socket(); s.bind(('127.0.0.1',0)); s.listen(1); port_file.write_text(str(s.getsockname()[1]))
c,_=s.accept(); out.write_text(str(len(c.recv(128))))
PY
loop_sink=$!
while [[ ! -s $tmp/loop-port ]]; do sleep .02; done
runuser -u "$user" -- python3 -c 'import pathlib,socket,sys; pathlib.Path(sys.argv[1]).read_bytes(); s=socket.create_connection(("127.0.0.1",int(sys.argv[2]))); s.sendall(b"LOOP"); s.close()' "$key" "$(<$tmp/loop-port)"
wait "$loop_sink"
[[ $(<$tmp/loop-bytes) == 4 ]] || { echo 'FAIL: loopback was blocked'; exit 1; }
echo 'PASS: loopback after key read allowed'

echo '==> IPv6 TCP loopback allow case'
python3 - "$tmp/loop6-port" "$tmp/loop6-bytes" <<'PY' &
import pathlib,socket,sys
port_file,out=map(pathlib.Path,sys.argv[1:])
s=socket.socket(socket.AF_INET6); s.bind(('::1',0)); s.listen(1); port_file.write_text(str(s.getsockname()[1]))
c,_=s.accept(); out.write_text(str(len(c.recv(128))))
PY
loop_sink=$!
while [[ ! -s $tmp/loop6-port ]]; do sleep .02; done
runuser -u "$user" -- python3 -c 'import pathlib,socket,sys; pathlib.Path(sys.argv[1]).read_bytes(); s=socket.create_connection(("::1",int(sys.argv[2]))); s.sendall(b"LOOP6"); s.close()' "$key" "$(<$tmp/loop6-port)"
wait "$loop_sink"
[[ $(<$tmp/loop6-bytes) == 5 ]] || { echo 'FAIL: IPv6 loopback was blocked'; exit 1; }
echo 'PASS: IPv6 TCP loopback after key read allowed'

udp_case() {
  local host=$1 expected=$2 label=$3
  local suffix=${label//[^a-zA-Z0-9]/-} port_file="$tmp/udp-$suffix-port" bytes_file="$tmp/udp-$suffix-bytes"
  python3 - "$host" "$port_file" "$bytes_file" <<'PY' &
import pathlib,socket,sys
host=sys.argv[1]; port_file=pathlib.Path(sys.argv[2]); out=pathlib.Path(sys.argv[3])
family=socket.AF_INET6 if ':' in host else socket.AF_INET
s=socket.socket(family,socket.SOCK_DGRAM); s.bind((host,0)); s.settimeout(1)
port_file.write_text(str(s.getsockname()[1]))
try: data,_=s.recvfrom(256); out.write_text(str(len(data)))
except TimeoutError: out.write_text('0')
PY
  local udp_sink=$!
  while [[ ! -s $port_file ]]; do sleep .02; done
  set +e
  runuser -u "$user" -- python3 -c 'import pathlib,socket,sys; pathlib.Path(sys.argv[1]).read_bytes(); h=sys.argv[2]; f=socket.AF_INET6 if ":" in h else socket.AF_INET; s=socket.socket(f,socket.SOCK_DGRAM); s.sendto(b"PHASE22.2_UDP",(h,int(sys.argv[3])))' "$key" "$host" "$(<$port_file)"
  local sender_status=$?
  set -e
  wait "$udp_sink"
  if [[ $expected == allow ]]; then
    [[ $sender_status -eq 0 && $(<$bytes_file) -gt 0 ]] || { echo "FAIL: $label UDP was blocked"; exit 1; }
  else
    [[ $sender_status -ne 0 && $(<$bytes_file) == 0 ]] || { echo "FAIL: $label UDP delivered bytes"; exit 1; }
  fi
  echo "PASS: $label UDP $expected ($(<$bytes_file) bytes delivered)"
}

echo '==> UDP loopback and external matrix'
udp_case 127.0.0.1 allow 'IPv4 loopback'
udp_case ::1 allow 'IPv6 loopback'
udp_case 198.18.0.1 block 'IPv4 external'
udp_case "$dummy6" block 'IPv6 external'

echo '==> External direct send and PendingDecision reread regression'
port_file="$tmp/port"; bytes_file="$tmp/bytes"; start_sink "$port_file" "$bytes_file"
set +e; external_send read-send "$(<$port_file)"; worker_status=$?; set -e
wait "$sink"; sink=
[[ $worker_status -ne 0 && $(<$bytes_file) == 0 ]] || { echo 'FAIL: external payload was delivered'; exit 1; }
echo 'PASS: first external payload blocked with zero bytes delivered'
incident_json=$("$guardctl" --socket "$socket" --json incidents list)
printf '%s' "$incident_json" | python3 -c 'import json,sys; d=json.load(sys.stdin); assert any(i["state"]=="pending_decision" for i in d.get("data",[]))'
echo 'PASS: incident entered PendingDecision'

echo '==> Multiple protected keys share one process-tree exposure'
port_file="$tmp/port-multikey"; bytes_file="$tmp/bytes-multikey"; start_sink "$port_file" "$bytes_file"
set +e
runuser -u "$user" -- python3 -c 'import pathlib,socket,sys,time; pathlib.Path(sys.argv[1]).read_bytes(); pathlib.Path(sys.argv[2]).read_bytes(); s=socket.create_connection((sys.argv[3],int(sys.argv[4]))); s.sendall(b"PHASE22.2_MULTI"); time.sleep(.3)' "$key" "$key2" 198.18.0.1 "$(<$port_file)"
worker_status=$?
set -e
wait "$sink"; sink=
[[ $worker_status -ne 0 && $(<$bytes_file) == 0 ]] || { echo 'FAIL: multi-key payload was delivered'; exit 1; }
"$guardctl" --socket "$socket" --json incidents list | python3 -c 'import json,sys; wanted=set(sys.argv[1:]); assert any(wanted.issubset(set(i.get("accessed_key_paths",[]))) for i in json.load(sys.stdin).get("data",[]))' "$key" "$key2"
echo 'PASS: both keys were retained on one exposure without duplicate tree state'

port_file="$tmp/port-reread"; bytes_file="$tmp/bytes-reread"; start_sink "$port_file" "$bytes_file" 2
set +e; external_send read-send-reread-wait-send "$(<$port_file)"; worker_status=$?; set -e
wait "$sink"; sink=
[[ $worker_status -ne 0 && $(<$bytes_file) == 0 ]] || { echo 'FAIL: PendingDecision reread bypass reproduced'; exit 1; }
echo 'PASS: PendingDecision remained blocked after reread and expiry'

echo '==> Pre-existing external connection is blocked after key read'
port_file="$tmp/port-preexisting"; bytes_file="$tmp/bytes-preexisting"; start_sink "$port_file" "$bytes_file"
set +e; external_send connect-read-send "$(<$port_file)"; worker_status=$?; set -e
wait "$sink"; sink=
[[ $worker_status -ne 0 && $(<$bytes_file) == 0 ]] || { echo 'FAIL: pre-existing external payload was delivered'; exit 1; }
echo 'PASS: pre-existing external connection blocked before payload delivery'

echo '==> External IPv6 send is blocked'
read_key
port_file="$tmp/port-ipv6"; bytes_file="$tmp/bytes-ipv6"; start_sink "$port_file" "$bytes_file" 1 "$dummy6"
set +e; external_send read-send "$(<$port_file)" "$dummy6"; worker_status=$?; set -e
wait "$sink"; sink=
[[ $worker_status -ne 0 && $(<$bytes_file) == 0 ]] || { echo 'FAIL: external IPv6 payload was delivered'; exit 1; }
echo 'PASS: external IPv6 payload blocked before delivery'

echo '==> Future fork+exec child inherits exposure; unrelated UID/process does not'
port_file="$tmp/port-child"; bytes_file="$tmp/bytes-child"; start_sink "$port_file" "$bytes_file"
set +e; external_send read-fork-exec-send "$(<$port_file)"; worker_status=$?; set -e
wait "$sink"; sink=
[[ $worker_status -ne 0 && $(<$bytes_file) == 0 ]] || { echo 'FAIL: future child external send was delivered'; exit 1; }
echo 'PASS: future fork+exec child external send blocked'

start_decision_worker() {
  local ready=$1 go=$2 result=$3 port=$4
  runuser -u "$user" -- python3 - "$key" "$ready" "$go" "$result" "$port" <<'PY' &
import pathlib,socket,sys,time
key,ready,go,result=map(pathlib.Path,sys.argv[1:5]); port=int(sys.argv[5])
key.read_bytes()
def attempt():
    s=socket.create_connection(('198.18.0.1',port),timeout=2)
    try: s.sendall(b'PHASE22.2_RETRY')
    finally: s.close()
try: attempt()
except OSError: pass
ready.write_text('ready')
for _ in range(200):
    if go.exists(): break
    time.sleep(.05)
try:
    attempt(); result.write_text('allowed')
except OSError:
    result.write_text('blocked')
time.sleep(2)
PY
  action_worker=$!
  while [[ ! -s $ready ]]; do kill -0 "$action_worker" 2>/dev/null || { echo 'FAIL: decision worker exited'; exit 1; }; sleep .02; done
}

latest_pending_id() {
  "$guardctl" --socket "$socket" --json incidents list | python3 -c 'import json,sys; p=[i for i in json.load(sys.stdin).get("data",[]) if i["state"]=="pending_decision"]; assert p; print(max(p,key=lambda i:i.get("first_network_ms") or 0)["id"])'
}

echo '==> Block keeps the exact tree blocked until exit without termination'
port_file="$tmp/port-block-action"; bytes_file="$tmp/bytes-block-action"; start_sink "$port_file" "$bytes_file" 2
start_decision_worker "$tmp/block-ready" "$tmp/block-go" "$tmp/block-result" "$(<$port_file)"
block_id=$(latest_pending_id)
"$guardctl" --socket "$socket" --json incidents block "$block_id" >/dev/null
kill -0 "$action_worker"
"$guardctl" --socket "$socket" --json incidents show "$block_id" | python3 -c 'import json,sys; d=json.load(sys.stdin)["data"]; assert d["state"]=="blocked_until_exit" and d["resolution"]=="block"'
touch "$tmp/block-go"
for _ in $(seq 1 100); do [[ -s $tmp/block-result ]] && break; sleep .02; done
[[ $(<$tmp/block-result) == blocked ]] || { echo 'FAIL: Block action allowed retry'; exit 1; }
kill "$action_worker" 2>/dev/null || true; wait "$action_worker" 2>/dev/null || true; action_worker=
wait "$sink"; sink=
[[ $(<$bytes_file) == 0 ]] || { echo 'FAIL: Block action delivered bytes'; exit 1; }
echo 'PASS: Block preserved containment without killing the process'

echo '==> Allow releases only the exact incident tree'
port_file="$tmp/port-allow-action"; bytes_file="$tmp/bytes-allow-action"; start_sink "$port_file" "$bytes_file" 2
start_decision_worker "$tmp/allow-ready" "$tmp/allow-go" "$tmp/allow-result" "$(<$port_file)"
allow_id=$(latest_pending_id)
"$guardctl" --socket "$socket" --json incidents allow "$allow_id" >/dev/null
"$guardctl" --socket "$socket" --json incidents show "$allow_id" | python3 -c 'import json,sys; d=json.load(sys.stdin)["data"]; assert d["state"]=="allowed" and d["resolution"]=="allow"'
touch "$tmp/allow-go"
for _ in $(seq 1 100); do [[ -s $tmp/allow-result ]] && break; sleep .02; done
[[ $(<$tmp/allow-result) == allowed ]] || { echo 'FAIL: Allow action did not release retry'; exit 1; }
wait "$sink"; sink=
[[ $(<$bytes_file) -gt 0 ]] || { echo 'FAIL: Allow action delivered zero bytes'; exit 1; }
wait "$action_worker"; action_worker=
echo 'PASS: Allow released the selected tree'

echo '==> Block & Quarantine terminates the tree and moves an attributable script'
offender="$tmp/synthetic-offender.py"
cat >"$offender" <<'PY'
#!/usr/bin/python3
import pathlib,socket,sys,time
key,ready=map(pathlib.Path,sys.argv[1:3]); port=int(sys.argv[3])
key.read_bytes()
try:
    s=socket.create_connection(('198.18.0.1',port),timeout=2)
    try: s.sendall(b'PHASE22.2_QUARANTINE')
    finally: s.close()
except OSError: pass
ready.write_text('ready')
time.sleep(30)
PY
chown "$uid" "$offender"; chmod 700 "$offender"
port_file="$tmp/port-quarantine"; bytes_file="$tmp/bytes-quarantine"; start_sink "$port_file" "$bytes_file"
runuser -u "$user" -- "$offender" "$key" "$tmp/quarantine-ready" "$(<$port_file)" &
action_worker=$!
while [[ ! -s $tmp/quarantine-ready ]]; do kill -0 "$action_worker" 2>/dev/null || { echo 'FAIL: quarantine worker exited'; exit 1; }; sleep .02; done
quarantine_incident=$(latest_pending_id)
"$guardctl" --socket "$socket" --json incidents block-and-quarantine "$quarantine_incident" >/dev/null
wait "$action_worker" 2>/dev/null || true; action_worker=
wait "$sink"; sink=
[[ ! -e $offender && $(<$bytes_file) == 0 ]] || { echo 'FAIL: quarantine did not remove the source or bytes escaped'; exit 1; }
"$guardctl" --socket "$socket" --json incidents show "$quarantine_incident" | python3 -c 'import json,sys; d=json.load(sys.stdin)["data"]; assert d["state"]=="quarantined" and d["resolution"]=="block_and_quarantine" and "Quarantined an attributable artifact" in d["resolution_detail"]'
python3 - "/var/lib/guardd/quarantine/$quarantine_incident/metadata.json" <<'PY'
import json,pathlib,sys
p=pathlib.Path(sys.argv[1]); d=json.loads(p.read_text())
assert d['attribution_type']=='explicit_script' and len(d['sha256'])==64
assert (p.parent/'artifact').is_file()
PY
echo 'PASS: Block & Quarantine killed the reader tree and stored artifact plus metadata'

port_file="$tmp/port-unrelated"; bytes_file="$tmp/bytes-unrelated"; start_sink "$port_file" "$bytes_file"
external_send send-only "$(<$port_file)"; wait "$sink"; sink=
[[ $(<$bytes_file) == 15 ]] || { echo 'FAIL: unrelated same-UID process was blocked'; exit 1; }
echo 'PASS: unrelated same-UID process allowed'

echo '==> Commit->push process separation and observation expiry'
read_key
port_file="$tmp/port-push"; bytes_file="$tmp/bytes-push"; start_sink "$port_file" "$bytes_file"
external_send send-only "$(<$port_file)"; wait "$sink"; sink=
[[ $(<$bytes_file) == 15 ]] || { echo 'FAIL: later push-style process was blocked'; exit 1; }
echo 'PASS: later process after reader exit allowed'

port_file="$tmp/port-expiry"; bytes_file="$tmp/bytes-expiry"; start_sink "$port_file" "$bytes_file"
external_send read-wait-send "$(<$port_file)"; wait "$sink"; sink=
[[ $(<$bytes_file) == 15 ]] || { echo 'FAIL: observing exposure did not expire'; exit 1; }
echo 'PASS: untouched observing exposure expired normally'

echo 'INFO: root resolution above validates action effects; interactive same-UID polkit and GTK dismissal require desktop acceptance.'
echo 'PASS: Phase 22.2 synthetic privileged matrix completed'
