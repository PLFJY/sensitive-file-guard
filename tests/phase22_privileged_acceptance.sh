#!/usr/bin/env bash
# Phase 22 privileged BPF acceptance. Run from a built checkout as root via:
#   sudo tests/phase22_privileged_acceptance.sh
#
# This creates only a disposable marker file and sends only a fixed dummy
# payload to a loopback listener. It never reads ~/.ssh or contacts a network.
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "run with sudo so guardd can use fanotify/BPF LSM" >&2
  exit 2
fi
if [[ -z ${SUDO_USER:-} || ${SUDO_USER} == root ]]; then
  echo "run through sudo from the desktop user; SUDO_USER is required" >&2
  exit 2
fi

repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
guardd="$repo/target/release/guardd"
[[ -x $guardd ]] || { echo "build first: cargo build --release" >&2; exit 2; }
user=$SUDO_USER
uid=$(id -u "$user")
tmp=$(mktemp -d /tmp/guardd-phase22-accept.XXXXXX)
cleanup() {
  [[ -n ${daemon:-} ]] && kill "$daemon" 2>/dev/null || true
  [[ -n ${listener:-} ]] && kill "$listener" 2>/dev/null || true
  rm -rf -- "$tmp"
}
trap cleanup EXIT
chown "$uid" "$tmp"

key="$tmp/id_ed25519"
config="$tmp/config.json"
printf '%s\n' '-----BEGIN GUARD SYNTHETIC PRIVATE KEY-----' 'PHASE22_MARKER_ONLY' '-----END GUARD SYNTHETIC PRIVATE KEY-----' >"$key"
chown "$uid" "$key"
chmod 600 "$key"
printf '{"enforcement_mode":"conservative","browsers":[],"enrolled_exes":[],"ssh_keys":["%s"],"ssh_behavior_window_secs":1}\n' "$key" >"$config"
chmod 600 "$config"

"$guardd" --enforce-browser-config "$config" --audit-db "$tmp/audit.db" >"$tmp/guardd.log" 2>&1 &
daemon=$!
for _ in $(seq 1 100); do
  grep -q 'enforcement active' "$tmp/guardd.log" && break
  if ! kill -0 "$daemon" 2>/dev/null; then
    cat "$tmp/guardd.log" >&2
    exit 1
  fi
  sleep .05
done
grep -q 'enforcement active' "$tmp/guardd.log" || { cat "$tmp/guardd.log" >&2; exit 1; }
if grep -q 'SSH behavioral backend unavailable' "$tmp/guardd.log"; then
  echo "FAIL: BPF backend did not attach; this is not a behavioral acceptance pass" >&2
  cat "$tmp/guardd.log" >&2
  exit 1
fi
grep 'SSH behavioral BPF send containment attached' "$tmp/guardd.log" | grep -q 'status="ACTIVE"' || {
  echo "FAIL: guardd did not produce positive ACTIVE BPF attachment evidence" >&2
  cat "$tmp/guardd.log" >&2
  exit 1
}

port_file="$tmp/port"
bytes_file="$tmp/bytes"
python3 -c '
import pathlib, socket, sys
port_file, bytes_file = map(pathlib.Path, sys.argv[1:])
s=socket.socket(); s.bind(("127.0.0.1",0)); s.listen(1)
port_file.write_text(str(s.getsockname()[1]))
c,_=s.accept(); c.settimeout(3)
try: data=c.recv(4096)
except TimeoutError: data=b""
bytes_file.write_text(str(len(data)))
' "$port_file" "$bytes_file" &
listener=$!
while [[ ! -s $port_file ]]; do sleep .02; done
port=$(<"$port_file")

# The connection is deliberately made before the read. The following send is
# therefore proof of `socket_sendmsg`, not merely a connect hook.
set +e
runuser -u "$user" -- python3 -c '
import pathlib, socket, sys
key, port = sys.argv[1], int(sys.argv[2])
s=socket.create_connection(("127.0.0.1", port))
pathlib.Path(key).read_bytes()
s.sendall(b"PHASE22_DUMMY_PAYLOAD")
' "$key" "$port"
worker_status=$?
set -e
wait "$listener"
listener=
[[ $worker_status -ne 0 ]] || { echo "FAIL: guarded send unexpectedly succeeded" >&2; exit 1; }
[[ $(<"$bytes_file") == 0 ]] || { echo "FAIL: listener received bytes before block" >&2; exit 1; }

echo "PASS: pre-existing loopback socket send was blocked before dummy payload"
echo "Next required manual cases: future child, expiry, authorized allow, and quarantine race."
