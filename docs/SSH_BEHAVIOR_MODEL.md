# SSH Behavioral Protection Contract

This is the canonical contract for protected SSH private keys.

1. **SSH private-key reads are never blocked.**
2. A protected-key read creates a metadata-only `ssh_behavior_key_accessed`
   event and an informational desktop notification.
3. The exact process instance and its future descendants are watched briefly
   for actual external outbound sends (10 seconds by default, configurable
   from 1–60 seconds).
4. An external send during that window is blocked before payload transmission
   and creates a pending incident.
5. The user choices are **Block & Quarantine**, **Block**, and **Allow**.
6. BPF/backend failure degrades network protection but never blocks key reads.

Browser cookie/session/auth resources keep their existing pre-open denial
model. This document changes only SSH private-key behavior.

## State model

```text
protected-key read
        |
        | FAN_ALLOW + informational event/notification
        v
    Observing --------------------> Expired
        |                         (window elapsed)
        | external TCP/UDP send
        | blocked before egress
        v
 PendingDecision
    |       |       |
    |       |       +-- Allow ----------------> Allowed -> Exited
    |       +---------- Block ------> BlockedUntilExit -> Exited
    +------------------ Block & Quarantine ----> Quarantined
```

`PendingDecision` never expires automatically. Closing the dialog is Block:
networking remains denied and the process continues local work. A surviving
descendant keeps the incident live after the original reader exits.

## Read path

For the narrow SSH `FAN_ACCESS_PERM` event, guardd resolves stable process
identity, creates or updates the process-tree exposure, tries to arm BPF,
records metadata, and returns `FAN_ALLOW`. Identity resolution, BPF attachment,
or per-exposure map-update failure cannot become `FAN_DENY`.

One process tree has one live exposure. Reading additional protected keys
deduplicates them into `accessed_keys` and refreshes the deadline only while
the incident is `Observing`. A pending or user-blocked incident is never
reopened by another read.

The notification is:

```text
SSH private key accessed

<program> accessed:
<key path>

External network activity from this process will be watched briefly.
```

## Network path

The Linux BPF LSM hook is `socket_sendmsg`, not `connect`, so it covers actual
payload attempts on both newly created and pre-existing connected sockets. It
does not inspect payloads. It allows AF_UNIX, AF_NETLINK, IPv4 loopback
`127.0.0.0/8`, IPv6 loopback `::1`, and other clearly local-only families.
External IPv4/IPv6 TCP and UDP sends are eligible.

For datagram `sendto`, Linux has already copied the userspace address into the
kernel `msghdr` before `security_socket_sendmsg`; the BPF program therefore
uses a kernel-memory read for `msg_name`.

The supported claim is only:

> A process that recently accessed a protected SSH private key attempted
> external outbound network activity.

It does not prove that the payload contained the key.

## Decisions

- **Block & Quarantine** retains network denial, freezes/terminates the
  identity-verified process tree, and quarantines only a safely attributable
  user-owned executable or explicit script. System interpreters and broad
  directories are never quarantine targets. `cap-std` provides the
  capability-scoped move/copy/create primitives for the thin quarantine
  adapter. If no safe artifact exists, the tree is still terminated and the
  result says so.
- **Block** keeps external networking denied for the current incident/tree
  until its last member exits. It does not terminate, quarantine, or create a
  permanent denylist.
- **Allow** permits networking only for the current incident/tree. It creates
  no whitelist, hash trust, path trust, or same-UID exception.

All actions cross the non-cached polkit boundary. IPC accepts only an incident
ID and the fixed action enum; it never accepts an authoritative PID, path,
command, or destination from the client.

## Examples

- `git commit` or a signer reads a key: read succeeds, notification appears,
  no dialog appears, and the commit continues. A later independent `git push`
  is unrelated and is not blocked.
- A malicious `npm postinstall` reads a key and immediately sends externally:
  read succeeds; the first external payload is blocked; the decision dialog
  appears.
- Read then AF_UNIX/loopback TCP/loopback UDP: local message is delivered and
  no incident becomes pending.
- BPF unavailable: read succeeds and is reported; status says Unavailable and
  explains that immediate outbound traffic cannot currently be blocked.

## Backend status

Active status means the send, fork, exit, and quarantine hooks attached.
Unavailable/degraded status must say that key access is still allowed and
reported while immediate external network blocking is unavailable or partial.
It must never claim that denial of key access compensates for backend failure.

## Non-goals and known bypasses

This is bounded temporal correlation, not information-flow tracking or DLP.
There is no payload inspection, TLS interception, domain/IP reputation,
UID-wide taint, shell-session taint, persistent process reputation, or malware
classification. A process can wait beyond the observation window, hand data
to an unrelated pre-existing process, use unobserved kernel paths, exploit the
kernel/daemon, or abuse an already-unlocked ssh-agent. Root compromise and
daemon crash are outside the protection boundary.

