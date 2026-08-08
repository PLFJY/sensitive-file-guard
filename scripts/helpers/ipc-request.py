#!/usr/bin/env python3
"""Send one transparent framed guardd IPC request and optionally stay alive."""

import argparse
import json
import os
import socket
import struct
import time

parser = argparse.ArgumentParser()
parser.add_argument("--socket", required=True)
parser.add_argument("--operation-json", required=True)
parser.add_argument("--output", required=True)
parser.add_argument("--pid-file", required=True)
parser.add_argument("--hold-seconds", type=int, default=0)
args = parser.parse_args()

open(args.pid_file, "w", encoding="ascii").write(str(os.getpid()))
payload = json.dumps({"version": 2, "op": json.loads(args.operation_json)}).encode()
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
    client.connect(args.socket)
    client.sendall(struct.pack(">I", len(payload)) + payload)
    header = client.recv(4)
    length = struct.unpack(">I", header)[0]
    response = b""
    while len(response) < length:
        response += client.recv(length - len(response))
open(args.output, "wb").write(response)
time.sleep(args.hold_seconds)
