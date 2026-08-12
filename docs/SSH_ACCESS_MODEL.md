# SSH private-key access model

Both backends mediate an enrolled SSH private key before a new reader receives
file data. Policy uses exact key identity, owner UID, reader PID/start token,
canonical executable path/device/inode, and verified ancestry. A successful
manual approval creates a ten-second in-memory `SshReadAccessLease` bound to
that exact key and reader tree. Another root, expiry, root exit, identity
change, cross UID, timeout, or restart cannot reuse it.

## macOS

The Endpoint Security system extension retains the specific `AUTH_OPEN`
operation within its bounded kernel deadline. The GTK prompt is metadata-only.
Allow requires device-owner LocalAuthentication in a correctly signed Guard
client; after authentication the extension revalidates the current reader and
key identity before responding. Block, close, insufficient deadline, queue
pressure, disconnect, reader exit, timeout, response error, or late
authentication fails closed and creates no lease.

The pending helper only observes metadata and opens the signed Guard UI. It
cannot resolve a request. XPC accepts only exact Team/signing identifiers and
the connection EUID; an ad-hoc or same-Team unlisted same-UID helper cannot
self-approve, and no hidden noninteractive client flag skips
LocalAuthentication.

The specialized `guardctl ssh load` broker is intentionally unsupported on the
macOS Alpha and says so explicitly. Ordinary `ssh-add` is an ordinary reader
and uses the same manual approval/process-tree lease path. SSH-agent signing
authority after a key is loaded remains outside this file-read firewall's V1
scope.

## Linux

Guardd mediates an enrolled SSH private key at `FAN_ACCESS_PERM`, before a
reader receives file data. A normal read enters a bounded daemon-memory queue
keyed by the key, UID, and stable reader root. Repeated reads from that root
join the same request; different process roots never share it.

The GTK prompt shows only metadata: executable path, PID, start time, and key
path. **Allow** invokes the non-cached Polkit action
`org.guardd.ssh-read-resolve`. Guardd then re-resolves the reader and verifies
the PID/start token, executable file identity, UID, and key owner before it
replies to the held fanotify read. A successful answer creates a ten-second
`SshReadAccessLease` for that exact resource and reader tree. It is in memory
only, expires naturally, is revoked if the root exits, and can be revoked via
the existing lease interface.

The resolving client keeps its authenticated IPC connection open while Polkit
is displayed; it does not apply the short status-poll timeout to a password
prompt. Guardd remains responsible for the 60-second authorization deadline
and cancels if that authenticated peer actually disconnects.

After Polkit succeeds, guardd completes reader revalidation and lease creation
under the enforcement-engine mutex, then releases that mutex before replying to
the held fanotify permission, recording the audit event, or constructing the
IPC response. A lock guard must never be kept in a `match` scrutinee whose arms
re-enter the engine: blocking the fanotify loop can stall unrelated protected
filesystem access system-wide.

**Block**, dialog close, a full queue, repeated blocked requests during the
short suppression interval, identity change, reader exit, and the 60-second
pending timeout all answer `FAN_DENY`. Authentication failures leave the
request pending so the user can retry or block it.

The verified `guardctl ssh load` path is intentionally separate. Its stopped
`ssh-add` child and pinned trusted `ssh-agent` use the existing one-shot load
lease; a normal SSH read prompt is not shown for that operation.
