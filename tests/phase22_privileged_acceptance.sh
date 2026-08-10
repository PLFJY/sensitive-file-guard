#!/usr/bin/env bash
# Phase 22.1 privileged BPF acceptance. Run as:
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
tmp=$(mktemp -d /tmp/guardd-phase22.1-accept.XXXXXX)
dummy=guard22dummy$$
dummy6=2001:db8:22:1::1
daemon=; sink=; local_sink=
cleanup() {
  [[ -n $daemon ]] && kill "$daemon" 2>/dev/null || true
  [[ -n $sink ]] && kill "$sink" 2>/dev/null || true
  [[ -n $local_sink ]] && kill "$local_sink" 2>/dev/null || true
  ip link del "$dummy" 2>/dev/null || true
  rm -rf -- "$tmp"
}
trap cleanup EXIT
key="$tmp/id_ed25519"; config="$tmp/config.json"; socket="$tmp/guardd.sock"
printf '%s\n' '-----BEGIN GUARD SYNTHETIC PRIVATE KEY-----' 'PHASE22.1_MARKER_ONLY' '-----END GUARD SYNTHETIC PRIVATE KEY-----' >"$key"
chown "$uid" "$tmp" "$key"; chmod 700 "$tmp"; chmod 600 "$key"
printf '{"enforcement_mode":"conservative","browsers":[],"enrolled_exes":[],"ssh_keys":["%s"],"ssh_behavior_window_secs":1}\n' "$key" >"$config"
chmod 600 "$config"

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
  echo 'FAIL: BPF backend did not attach; fail-closed fallback is not acceptance' >&2
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
key_count=$(printf '%s' "$key_events" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(sum(1 for e in d.get("data",[]) if e.get("backend_diag","").startswith("ssh_behavior_key_read;")))')
[[ $key_count == 1 ]] || { echo "FAIL: expected one key-read event, got $key_count"; exit 1; }
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

echo '==> External direct send and PendingDecision reread regression'
port_file="$tmp/port"; bytes_file="$tmp/bytes"; start_sink "$port_file" "$bytes_file"
set +e; external_send read-send "$(<$port_file)"; worker_status=$?; set -e
wait "$sink"; sink=
[[ $worker_status -ne 0 && $(<$bytes_file) == 0 ]] || { echo 'FAIL: external payload was delivered'; exit 1; }
echo 'PASS: first external payload blocked with zero bytes delivered'
incident_json=$("$guardctl" --socket "$socket" --json incidents list)
printf '%s' "$incident_json" | python3 -c 'import json,sys; d=json.load(sys.stdin); assert any(i["state"]=="pending_decision" for i in d.get("data",[]))'
echo 'PASS: incident entered PendingDecision'

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

echo 'BLOCKED/NOT RUN: polkit Allow Upload, Stop & Quarantine, GTK response, and browser/ssh-agent suites require deployment authorization.'
echo 'PASS: Phase 22.1 synthetic BPF cases completed'
