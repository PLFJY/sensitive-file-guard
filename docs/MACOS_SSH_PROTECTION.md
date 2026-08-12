# macOS SSH private-key protection

The macOS Endpoint Security backend treats an explicitly enrolled SSH private
key as an `AUTH_OPEN` disclosure gate. The core invariant is that a process
requesting `FREAD` cannot receive key bytes until its exact pending read is
approved or covered by a valid short lease.

## Enrollment

`guardctl ssh protect PATH` is a LocalAuthentication-gated, signed XPC request.
The extension:

- applies the shared `guard-ssh` name rules and rejects `.pub`, `known_hosts`,
  `authorized_keys*`, and `config`;
- canonicalizes and stats the file without opening, parsing, hashing, or
  logging its contents;
- requires the file owner to equal the transport-authenticated peer EUID;
- updates the root-owned authoritative configuration and live resource index.

An existing disabled policy remains disabled. A first SSH-only configuration
created by the explicit protect command starts enabled. Configuration metadata
is returned only to its authenticated owner.

## AUTH_OPEN decisions

- A same-UID open containing `FREAD` requires an explicit confirmation unless
  a valid exact-key process-tree lease applies.
- Cross-UID opens are denied immediately and never prompt.
- A same-UID write-only open is allowed with its exact requested flags. This
  product is an access firewall, not an integrity monitor; write-only access
  cannot disclose bytes. Any combined `FREAD|FWRITE` open still requires
  approval.
- Missing identity, insufficient ES interaction budget, queue pressure,
  process exit, and dropped permissions fail closed.

The native callback never waits for GTK. It retains only the opaque
authorization operation, transfers it to the bounded runtime queue, and keeps
the deadline scheduler as the final deny owner.

## Prompt and lease

The prompt shows only executable, PID/stable process metadata, canonical key
path, and remaining time. Its buttons are exactly `Block` and `Allow`; there is
no permanent or executable-wide grant.

Allow must first succeed through LocalAuthentication in the signed UI/client.
The extension then re-resolves the exact reader, verifies UID and root-process
liveness, and stats the enrolled path again. The current owner, device, and
inode must match the held event. Only then does it create a ten-second
`SshReadAccessLease` scoped to:

- one protected key resource;
- one verified reader root and positively verified descendants;
- one UID;
- the short in-memory expiry.

Another invocation of the same executable is a different root and prompts
again. Root exit revokes the lease. A late LocalAuthentication success cannot
revive a timed-out permission: if the retained ES response already resolved,
the just-created lease is revoked before an error is returned.

Block and window close deny immediately without LocalAuthentication. A failed
or cancelled authentication can retry only while the same pending deadline is
still safe; timeout remains terminal.

## Agent behavior

The Linux `SshLoadLease` shortcut depends on Linux-specific agent-socket peer
verification. It was not ported by analogy. On macOS:

```text
guardctl ssh load PATH
```

returns a clear unsupported message before forking or touching an agent.
Ordinary `/usr/bin/ssh-add PATH` is supported through the same explicit manual
read approval as any other reader.

No Network Extension, BPF hook, agent-socket hardlink, traffic tracing, or
network correlation participates in macOS SSH policy.

## Audit and acceptance

Typed metadata-only events are:

- `ssh_key_access_confirmation_required`
- `ssh_key_access_allowed`
- `ssh_key_access_blocked`
- `ssh_key_access_timed_out`

They never contain key bytes or fingerprints. Automated tests use synthetic
files or a newly generated temporary Ed25519 key only. Run:

```sh
scripts/macos/test-ephemeral-ssh-key.sh target/debug/guardctl
```

For real kernel-mediated Block, Allow, descendant, unrelated-process, and audit
acceptance on a provisioned host, run:

```sh
scripts/macos/run-ssh-policy-acceptance.sh build/macos/Guard.app
```

That script stops with status 77 before generating a key if the signed CLI
cannot reach the activated extension. Until an Apple-provisioned ES extension
with Full Disk Access is available, the live kernel assertions remain BLOCKED,
not passed.
