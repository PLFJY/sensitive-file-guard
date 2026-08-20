#!/usr/bin/env python3
"""Transparent local-only process/IPC scenarios for SSH broker acceptance.

No key content is read by this helper. Child stdout is /dev/null for the fake
executable case so even a firewall regression cannot copy fixture bytes into a
test artifact.
"""

import argparse
import json
import os
import signal
import socket
import struct
import subprocess
import sys
import time

PROTOCOL_VERSION = 5


def request(socket_path, operation):
    payload = json.dumps({"version": PROTOCOL_VERSION, "op": operation}).encode()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.connect(socket_path)
        client.sendall(struct.pack(">I", len(payload)) + payload)
        header = recv_exact(client, 4)
        length = struct.unpack(">I", header)[0]
        return json.loads(recv_exact(client, length))


def send_without_receiving(socket_path, operation):
    """Send one complete request, then close before reading its response."""
    payload = json.dumps({"version": PROTOCOL_VERSION, "op": operation}).encode()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.connect(socket_path)
        client.sendall(struct.pack(">I", len(payload)) + payload)


def recv_exact(stream, length):
    chunks = []
    remaining = length
    while remaining:
        chunk = stream.recv(remaining)
        if not chunk:
            raise RuntimeError("guardd closed the IPC response early")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def authorize(socket_path, key, pid, extra=None):
    operation = {
        "kind": "ssh_load_authorize",
        "path": key,
        "ssh_add_pid": pid,
    }
    if extra:
        operation.update(extra)
    return request(socket_path, operation)


def stopped_child(executable, argv):
    reader, writer = os.pipe()
    pid = os.fork()
    if pid == 0:
        try:
            os.close(writer)
            os.kill(os.getpid(), signal.SIGSTOP)
            agent_socket = os.read(reader, 108).decode()
            os.close(reader)
            devnull = os.open("/dev/null", os.O_WRONLY)
            os.dup2(devnull, 1)
            os.execve(
                executable,
                argv,
                {"SSH_AUTH_SOCK": agent_socket, "LC_ALL": "C"},
            )
        finally:
            os._exit(127)
    os.close(reader)
    waited, status = os.waitpid(pid, os.WUNTRACED)
    if waited != pid or not os.WIFSTOPPED(status):
        raise RuntimeError("child did not enter the required stopped state")
    return pid, writer


def finish_child(pid, writer, verified_agent, delay=0):
    if delay:
        time.sleep(delay)
    os.write(writer, verified_agent.encode())
    os.close(writer)
    os.kill(pid, signal.SIGCONT)
    _, status = os.waitpid(pid, 0)
    if os.WIFEXITED(status):
        return os.WEXITSTATUS(status)
    return 128 + os.WTERMSIG(status)


def abort_child(pid, writer):
    """Reap a stopped fixture child after any failed authorization step."""
    try:
        os.close(writer)
    except OSError:
        pass
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        os.waitpid(pid, 0)
    except ChildProcessError:
        pass


def authorized_agent(response):
    if not response.get("ok"):
        raise RuntimeError(f"authorization failed: {response.get('error')}")
    return response["body"]["data"]["agent_socket"]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=[
        "wrong-pid", "non-child", "running-child", "fake-declared",
        "fake-exec", "double-open", "expired", "swap-after-authorize",
        "ignore-pin-swap", "disconnect-after-request",
    ])
    parser.add_argument("--socket", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--agent", required=True)
    parser.add_argument("--ssh-add", default="/usr/bin/ssh-add")
    parser.add_argument("--other-pid", type=int)
    parser.add_argument("--replacement-socket")
    parser.add_argument("--child-pid-file")
    args = parser.parse_args()
    os.environ["SSH_AUTH_SOCK"] = args.agent

    if args.mode == "wrong-pid":
        response = authorize(args.socket, args.key, 2_147_483_000)
        print(json.dumps({"response": response}))
        return 0
    if args.mode == "non-child":
        response = authorize(args.socket, args.key, args.other_pid or 1)
        print(json.dumps({"response": response}))
        return 0
    if args.mode == "fake-declared":
        response = authorize(args.socket, args.key, 2_147_483_000, {
            "ssh_add_exe": "/tmp/client-claimed-ssh-add",
            "ssh_add_dev": 1,
            "ssh_add_ino": 1,
            "start_time": 1,
        })
        print(json.dumps({"response": response}))
        return 0
    if args.mode == "running-child":
        child = subprocess.Popen(
            ["/usr/bin/sleep", "30"],
            env={"SSH_AUTH_SOCK": args.agent, "LC_ALL": "C"},
        )
        try:
            response = authorize(args.socket, args.key, child.pid)
            print(json.dumps({"response": response}))
        finally:
            child.terminate()
            child.wait()
        return 0
    if args.mode == "disconnect-after-request":
        before = request(args.socket, {"kind": "leases_list"})
        before_ids = {
            lease["id"] for lease in before.get("body", {}).get("data", [])
        }
        pid, writer = stopped_child(args.ssh_add, [args.ssh_add, args.key])
        try:
            send_without_receiving(
                args.socket,
                {
                    "kind": "ssh_load_authorize",
                    "path": args.key,
                    "ssh_add_pid": pid,
                },
            )
            time.sleep(0.2)
            after = request(args.socket, {"kind": "leases_list"})
            new_leases = [
                lease
                for lease in after.get("body", {}).get("data", [])
                if lease["id"] not in before_ids
            ]
            print(json.dumps({"new_leases": new_leases}))
        finally:
            abort_child(pid, writer)
        return 0

    if args.mode == "fake-exec":
        pid, writer = stopped_child("/usr/bin/cat", ["/usr/bin/cat", args.key])
        try:
            response = authorize(args.socket, args.key, pid)
            exit_code = finish_child(pid, writer, authorized_agent(response))
        except BaseException:
            abort_child(pid, writer)
            raise
    elif args.mode == "double-open":
        pid, writer = stopped_child(
            args.ssh_add,
            [args.ssh_add, args.key, args.key],
        )
        try:
            response = authorize(args.socket, args.key, pid)
            exit_code = finish_child(pid, writer, authorized_agent(response))
        except BaseException:
            abort_child(pid, writer)
            raise
    else:
        pid, writer = stopped_child(args.ssh_add, [args.ssh_add, args.key])
        try:
            if args.child_pid_file:
                with open(args.child_pid_file, "w", encoding="ascii") as output:
                    output.write(str(pid))
            response = authorize(args.socket, args.key, pid)
            pinned_path = authorized_agent(response)
            if args.mode in ("swap-after-authorize", "ignore-pin-swap"):
                if not args.replacement_socket:
                    raise RuntimeError(f"{args.mode} needs --replacement-socket")
                os.unlink(args.agent)
                os.link(args.replacement_socket, args.agent)
                delay = 0
            else:
                delay = 31
            agent_path = (
                args.agent
                if args.mode == "ignore-pin-swap"
                else pinned_path
            )
            exit_code = finish_child(pid, writer, agent_path, delay=delay)
        except BaseException:
            abort_child(pid, writer)
            raise
    print(json.dumps({"response": response, "child_exit": exit_code}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
