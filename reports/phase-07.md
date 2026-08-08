# Phase 07 — IPC, Audit, and `guardctl`

## Implemented behavior

The daemon is now operable without a GUI. Three new components wire together:

1. **`guard-audit` crate** — SQLite-backed audit persistence.
2. **`guardd` IPC server** — Unix-domain-socket request dispatcher with
   kernel-verified peer credentials.
3. **`guardctl` binary** — control CLI with all required subcommands.

### Audit persistence (`crates/guard-audit`)

`AuditStore` records every authorization decision as an `AuditRecord` with the
fields required by `07_IPC_AUDIT_AND_CLI.md`: event ID (auto-increment), timestamp,
decision, deny reason, resource kind/id, path, PID + start time, executable path,
exe owner uid, trust tier, process browser, parent summary, lease id, and a
backend diagnostic string.

Design:
- The hot path calls `AuditStore::record`, which is **non-blocking**: it pushes
  the record onto a bounded (`sync_channel(8192)`) channel and returns
  immediately. If the channel is full the record is dropped and a `dropped`
  counter is incremented — the authorization loop is never stalled by disk I/O.
- A dedicated writer thread owns the single SQLite write `Connection`, drains the
  channel, and batch-commits (threshold 64, or on `Flush`/`Quit`). WAL mode is
  enabled so concurrent readers (IPC queries) do not block the writer.
- Read queries open a fresh read-only connection per call (cheap in SQLite, fully
  concurrent under WAL). `flush()` forces the writer to drain + commit so a CLI
  query sees the latest records.
- `AuditRecord` is a plain metadata struct with **no content/blob field**; the
  `path` column stores the path string, never file bytes. The no-secret invariant
  is structural and asserted by tests.

`EnforcementEngine::decide_with_context` (replacing the Phase 06 `decide` hot
path) now returns `(Decision, Option<AuditRecord>)`; `guardd::main` enqueues the
record non-blocking right after the fanotify response is sent.

### IPC (`crates/guard-ipc` + `crates/platform-linux::ipc` + `apps/guardd::ipc`)

- **Transport**: `AF_UNIX` stream socket, default `/run/guardd/guardd.sock`
  (overridable via `guardd --ipc-socket PATH`). Framing is a 4-byte big-endian
  length prefix + JSON payload. `read_request` rejects frames larger than
  `MAX_REQUEST_BYTES` (64 KiB) and malformed/truncated prefixes, so a peer cannot
  exhaust daemon memory.
- **Peer authentication**: `SO_PEERCRED` (`pid`/`uid`/`gid`) obtained via
  `getsockopt` on the accepted fd. The daemon authorizes using this kernel-verified
  `uid` exclusively; the JSON request carries no `uid` field and a UID supplied in
  JSON is never honored.
- **Protocol**: versioned envelope (`PROTOCOL_VERSION = 1`). `RequestOp` is
  internally tagged (`{"kind":"status",...}`); `ResponseBody` is adjacently tagged
  (`{"kind":"events","data":[...]}`) so that newtype variants wrapping `Vec`/`Box`
  serialize correctly (serde's internally-tagged representation does not support
  non-struct newtype variants — this was the cause of the first end-to-end test
  failure and is now fixed).
- **Server loop** (`serve_loop`): spawns one thread; each connection is handled
  inline. Requests are tiny and the engine `Mutex` is held for microseconds only
  (a status/resources query is a few map iterations), so the authorization loop is
  not blocked. Concurrent read-only clients are served without deadlock.
- **Authorization** (per spec):
  - any authenticated peer: `status`, `resources list`, `browsers list`,
    `config check`
  - ordinary user: own `events` / `explain` / `leases` only (`uid_filter =
    Some(peer_uid)`; cross-user `explain` returns "permission denied")
  - root (uid 0): all events/leases; lease revoke for any user
  - non-root may revoke only their own leases; a not-found lease for a non-root
    user returns "permission denied or lease not found" to avoid leaking existence

### `guardctl` (`apps/guardctl`)

Thin client: connects to the socket, sends one framed `Request`, prints one
`Response`. All authorization is daemon-side. Subcommands:

| Command | Maps to |
| --- | --- |
| `status` | `RequestOp::Status` |
| `resources list` | `RequestOp::ResourcesList` |
| `browsers list` | `RequestOp::BrowsersList` |
| `events [--limit N]` | `RequestOp::Events { limit }` |
| `explain EVENT_ID` | `RequestOp::Explain { event_id }` |
| `leases list` | `RequestOp::LeasesList` |
| `leases revoke LEASE_ID` | `RequestOp::LeasesRevoke { lease_id }` |
| `config check` | `RequestOp::ConfigCheck` |

`--socket PATH` selects the socket (default `/run/guardd/guardd.sock`); `--json`
emits raw pretty-printed JSON instead of the human-readable table format. The
human formatter prints decision/resource/trust fields as stable strings derived
from the `Debug` impls.

## Authorization hot-path impact

- Audit recording is non-blocking (bounded channel + writer thread); the fanotify
  response is sent before the audit `record()` call, and `record()` never blocks
  (drops on full channel instead).
- IPC handlers take the engine `Mutex` only for the duration of a cheap query
  (status/resources/browsers/config/leases) — no I/O, no allocation-heavy work —
  so the fanotify event loop is not starved. The audit `flush()` called by
  `events`/`explain` handlers waits on the writer thread, not the engine mutex.
- SQLite reads open a fresh read-only connection per query (WAL concurrency); the
  writer thread holds the single write connection.

## Exact commands run

```
cargo fmt
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test -p guard-ipc
cargo test -p guardctl
cargo test -p guardd
cargo test -p platform-linux
cargo test -p guard-audit -p guard-core -p guard-browser -p guard-test-fixtures
```

## Test results

All Phase 07 tests run **without root** (IPC + SQLite work as a normal user; the
privileged fanotify path is Phase 06). No test is BLOCKED.

### Required tests (mapped to `07_IPC_AUDIT_AND_CLI.md`)

| Required test | Evidence |
| --- | --- |
| IPC peer UID spoof attempt fails | `ipc::tests::ordinary_user_cannot_see_other_users_events` (guardd) — peer uid 1000 cannot see uid 1001's events; `platform_linux::ipc::tests::framed_round_trip_and_peer_uid_is_kernel_verified` — `PeerCreds.uid == getuid()`, kernel-verified via `SO_PEERCRED`, JSON carries no uid |
| oversized request rejected | `ipc::tests::oversized_request_rejected_by_server` (guardd, over the real `serve_loop`) + `platform_linux::ipc::tests::oversized_request_rejected_by_server` (transport) + `platform_linux::ipc::tests::client_side_rejects_oversized_response` (client rejects absurd response length) |
| concurrent read-only clients do not block authorization loop | `ipc::tests::concurrent_clients_do_not_block` (guardd — 8 concurrent `status` clients against the real `serve_loop`) + `platform_linux::ipc::tests::concurrent_clients_round_trip` (8 framed round-trips) |
| audit event can be explained from CLI | `ipc::tests::explain_round_trips_from_audit_record` (record → query → explain) + `ipc::tests::end_to_end_explain_via_ipc_transport` (full IPC transport round-trip: record → `events` over socket → `explain` over socket) + `guardctl::tests::explain_event_from_json_body` (CLI parses the adjacently-tagged `Explain` body) |
| log contains no fixture secret marker content | `ipc::tests::audit_record_no_secret_content_through_ipc` (EventInfo JSON has no `content`/`blob`/`cookie_value`/`password`/`key_bytes` keys) + `guard_audit::tests::audit_record_never_carries_secret_content` (serialized record + persisted row contain no `GUARD_SYNTHETIC_COOKIE_FIXTURE` marker) |

### Full counts

- `guardd` — 32 passed (16 `enforce` from Phase 06 + 16 new `ipc`). New IPC
  handler tests: status/resources/browsers/config, events uid-filter, root-sees-all,
  explain round-trip, explain denied for other user, explain not-found, leases
  uid-filter, lease revoke authorization, protocol version mismatch, no-secret,
  concurrent clients, end-to-end explain via IPC, oversized rejected.
- `guardctl` — 3 passed (decision formatter, request serialization with correct
  version, explain body parsing).
- `guard-ipc` — 2 passed (request op round-trips, response ok/err round-trip).
- `platform-linux` — 28 passed (24 pre-existing + 4 new `ipc` transport tests).
- `guard-audit` — 5 passed (schema round-trip, query-by-id, uid isolation,
  no-secret, dropped-counter under burst).

`cargo clippy --all-targets --all-features -- -D warnings` — clean.
`cargo fmt --check` — clean.

## Known limitations

- **IPC server thread is not joined on shutdown**: `guardd::main` drops the IPC
  `JoinHandle` on exit (the accept loop is blocked in `accept`); the process
  exits and the OS reclaims the thread. A graceful drain (reject new conns, serve
  in-flight, then exit) is deferred to Phase 14 (systemd install/recovery).
- **Audit db path defaults to `/var/lib/guardd/audit.db`**; if that path is not
  writable the daemon falls back to an in-memory store (logged at WARN) so
  enforcement still runs. Phase 14 will create the directory with correct
  ownership under systemd.
- **No `guardctl` binary-against-live-`guardd` shell script**: the end-to-end
  path (daemon IPC + audit + CLI) is exercised through the in-process IPC
  transport tests (`end_to_end_explain_via_ipc_transport`,
  `concurrent_clients_do_not_block`, `oversized_request_rejected_by_server`),
  which use the real `serve_loop`, real `SO_PEERCRED`, real SQLite, and the real
  `guard-ipc` wire format. Spawning the `guardd` binary additionally requires
  `CAP_SYS_ADMIN` (fanotify), which is the Phase 06 privileged script's domain;
  the Phase 07 components themselves need no privilege.
- **Lease grant flow is not yet wired**: `leases list` / `leases revoke` operate
  on the `LeaseSet` the engine already carries (empty in this phase). The
  `MigrationLease` grant path is Phase 08; `SshLoadLease` is Phase 11. The IPC
  authorization for revocation is fully tested with synthetic leases.
- **`ResponseBody::Explain` is boxed** to keep the enum small (EventInfo is ~328
  bytes); this is a wire-format-internal detail, transparent to CLI consumers.

## Security assumptions

- Peer identity comes **exclusively** from `SO_PEERCRED` (`PeerCreds.uid`). The
  `Request`/`RequestOp` structs have no `uid` field; a client cannot influence
  the uid used for authorization. Verified by `framed_round_trip_and_peer_uid_is_kernel_verified`
  (`PeerCreds.uid == getuid()`) and `ordinary_user_cannot_see_other_users_events`.
- Authorization is fail-closed for cross-user access: a non-root peer receives
  only its own events/leases; cross-user `explain` returns "permission denied";
  cross-user lease revoke returns "permission denied". A not-found lease for a
  non-root user returns a generic "permission denied or lease not found" so
  existence is not leaked.
- Audit records carry metadata only — no cookie values, passwords, key bytes, or
  DB rows. The `AuditRecord` struct has no content field; the `path` column stores
  the path string. Asserted structurally and by marker-content tests.
- Request frames are bounded (`MAX_REQUEST_BYTES = 64 KiB`); oversized frames are
  rejected and the connection is closed without a response (framing is corrupted
  once the declared length exceeds the limit, so no response can be safely
  written on the same stream).
- Protocol version is checked; a mismatch yields an error response, never a
  misinterpreted dispatch.
- No real browser profile or SSH key is touched by any test; all tests use
  `guard-test-fixtures` synthetic profiles or hand-built marker records.
