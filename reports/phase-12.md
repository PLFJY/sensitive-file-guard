# Phase 12 — AI/Coding-Agent Compatibility

## Objective

Demonstrate that an ordinary coding agent does not require secret-file
exemptions. No brand names (Codex/Claude/Gemini) are special-cased. The agent
model is:

- agent reads browser profile => DENY
- agent reads SSH private key => DENY
- agent edits normal project files => unaffected
- agent runs `git` => unaffected
- agent runs `ssh` using an already-loaded `ssh-agent` => allowed by normal OS
  flow (Phase 11's `SshLoadLease` governs the *load*; once loaded, the agent
  uses the agent socket like any other process)
- agent can inspect `guardctl explain --json EVENT_ID` after a permission
  failure to get a stable, machine-readable reason code

Filesystem denial uses ordinary `EPERM`/`EACCES` from the OS. `guardd` does NOT
inject custom text into `open(2)` errors.

## Implemented behavior

### Stable reason codes (`guard-core::policy::DenyReason`)
[`DenyReason::reason_code()`](file:///home/plfjy/sensitive-file-guard/crates/guard-core/src/policy.rs#L49-L79)
returns a stable snake_case string for each deny reason. These strings are a
**public contract**: tools may branch on them, and they must never change shape
once shipped (add new codes, never rename existing ones).

| `DenyReason` variant | `reason_code()` | Spec example |
| --- | --- | --- |
| `UnknownProcess` | `browser_protected_resource` | ✓ |
| `NotTrustedIdentity` | `identity_untrusted` | ✓ |
| `CrossBrowserWithoutLease` | `migration_lease_required` | ✓ |
| `SshPrivateKeyRawRead` | `ssh_private_key_raw_read_denied` | ✓ |
| `LeaseExpired` | `lease_expired` | |
| `LeaseRevoked` | `lease_revoked` | |
| `LeaseScopeMismatch` | `lease_scope_mismatch` | |
| `WrongUid` | `wrong_uid` | |
| `IdentityMismatch` | `identity_mismatch` | |
| `OneShotLeaseUsed` | `one_shot_lease_used` | |

### Stable resource kind codes (`guard-core::resource::ProtectedResourceKind`)
[`ProtectedResourceKind::kind_code()`](file:///home/plfjy/sensitive-file-guard/crates/guard-core/src/resource.rs#L32-L45)
returns a stable snake_case string for each resource kind:

| `ProtectedResourceKind` variant | `kind_code()` |
| --- | --- |
| `CookieStore` | `browser_cookie_store` |
| `SessionStore` | `browser_session_store` |
| `BrowserKeyMaterial` | `browser_key_material` |
| `WebStorage` | `browser_web_storage` |
| `SavedCredentials` | `browser_saved_credentials` |
| `History` | `browser_history` |
| `SshPrivateKey` | `ssh_private_key` |

### IPC: `EventInfo` carries the stable codes
[`EventInfo`](file:///home/plfjy/sensitive-file-guard/crates/guard-ipc/src/lib.rs#L231-L259)
gained two fields:

- `reason_code: Option<String>` — `None` for `Allow`/`AllowByLease`; the stable
  code for any `Deny`. `#[serde(skip_serializing_if = "Option::is_none")]` so
  allow-events stay compact.
- `resource_kind_code: String` — the stable kind code. `#[serde(default)]` so
  events from a pre-Phase-12 daemon still deserialize (defaults to empty
  string).

The existing human-readable `deny_reason` (Rust debug name like
`"SshPrivateKeyRawRead"`) and `resource_kind` fields are retained for backward
compatibility; tools should prefer `reason_code` / `resource_kind_code`.

[`event_to_info`](file:///home/plfjy/sensitive-file-guard/apps/guardd/src/ipc.rs#L463-L488)
populates both new fields from the typed `DenyReason` / `ProtectedResourceKind`
already stored in the audit record — no extra storage columns, no re-derivation.

### CLI: `guardctl explain --json`
The global `--json` flag already existed (Phase 07). With Phase 12, the JSON
output of `guardctl explain --json EVENT_ID` now includes `reason_code` and
`resource_kind_code`. The human-readable
[`print_explain`](file:///home/plfjy/sensitive-file-guard/apps/guardctl/src/main.rs#L399-L437)
also prints `reason_code` and `kind_code` lines so a developer at a terminal
sees the stable codes without needing `--json`.

Example `guardctl explain --json 7` output (abridged):
```json
{
  "id": 7,
  "decision": "Deny(SshPrivateKeyRawRead)",
  "deny_reason": "SshPrivateKeyRawRead",
  "reason_code": "ssh_private_key_raw_read_denied",
  "resource_kind": "SshPrivateKey",
  "resource_kind_code": "ssh_private_key",
  "path": "/home/u/.ssh/id_ed25519",
  "exe": "/usr/bin/guard-test-probe",
  ...
}
```

### No `open(2)` error injection
Per the spec, `guardd` does NOT attempt to inject custom text into arbitrary
`open(2)` errors. A denied open returns ordinary `EPERM` (fanotify permission
event denial). Tools that want to understand *why* use
`guardctl explain --json EVENT_ID` + the `reason_code` field — this is the
supported machine-readable introspection path.

### Agent simulator
The existing [`guard-test-probe`](file:///home/plfjy/sensitive-file-guard/apps/guard-test-probe/src/main.rs)
binary serves as the generic "agent simulator" child process: it opens/reads a
path and reports success or the OS error. It contains NO network code, NO
brand-specific logic, and NO special handling. It is the same binary used in
Phase 02's fanotify PoC and Phase 06's browser enforcement tests. An AI
coding agent is just another ordinary process from `guardd`'s perspective —
no exe is special-cased.

## Hot-path impact

- Zero. The `reason_code()` and `kind_code()` methods are only called in
  `event_to_info` (the IPC/query path), not on the fanotify hot path. The hot
  path still uses the typed `DenyReason` enum directly for the audit record.
- `reason_code()` and `kind_code()` are simple `match` expressions returning
  `&'static str` — no allocation, no hashing.

## Exact commands run

```
cargo fmt
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
```

The privileged end-to-end script is
[`scripts/test-agent-compat-root.sh`](file:///home/plfjy/sensitive-file-guard/scripts/test-agent-compat-root.sh),
run as `sudo bash scripts/test-agent-compat-root.sh`. It requires
`CAP_SYS_ADMIN` for `FAN_CLASS_CONTENT` and is therefore provided for a human
to run; the non-interactive build agent cannot obtain it.

## Test results

`cargo fmt --check` — clean.
`cargo clippy --all-targets --all-features -- -D warnings` — clean.
`cargo test --all-features` — **181 passed, 0 failed.**

### Required tests (mapped to `12_AI_AGENT_COMPATIBILITY.md`)

| Required test | Evidence |
| --- | --- |
| normal project access works | `scripts/test-agent-compat-root.sh` Test 1 (agent reads normal project `.rs` file => succeeds, content matches) + Test 2 (agent writes/edits normal project file => succeeds) |
| browser fixture denied | `scripts/test-agent-compat-root.sh` Test 3 (agent reads browser cookie fixture => denied with EPERM) |
| SSH test key denied | `scripts/test-agent-compat-root.sh` Test 4 (agent reads SSH test key => denied with EPERM) |
| `guardctl explain --json` explains denial | `scripts/test-agent-compat-root.sh` Test 5 (guardctl explain --json on a denial event => contains `reason_code` + `resource_kind_code` fields with non-empty values) + `guardctl::tests::explain_event_from_json_body` (parses the adjacently-tagged Explain JSON and asserts `reason_code == "migration_lease_required"` + `resource_kind_code == "browser_cookie_store"`) + `guardd::ipc::tests::*` explain round-trip (asserts `reason_code == Some("migration_lease_required")`) |
| git operation on a local temp repo remains functional | `scripts/test-agent-compat-root.sh` Test 6 (git init + add + commit on a temp repo => succeeds; guardd does not interfere with ordinary repos) |

### Additional tests

| Test | Evidence |
| --- | --- |
| reason codes are stable snake_case | `guard_core::policy::tests::reason_codes_are_stable_snake_case` (asserts all 10 codes match the spec contract) |
| reason codes are unique | `guard_core::policy::tests::reason_codes_are_unique` (no two deny reasons share a code) |
| kind codes are stable snake_case | `guard_core::policy::tests::kind_codes_are_stable_snake_case` (asserts all 7 kind codes) |
| IPC explain carries reason_code | `guardd::ipc::tests` explain round-trip (asserts `e.reason_code == Some("migration_lease_required")` + `!e.resource_kind_code.is_empty()`) |
| guardctl parses explain JSON with reason_code | `guardctl::tests::explain_event_from_json_body` (asserts `reason_code` + `resource_kind_code` fields) |

### Full counts

- `guard_audit` — 5 passed (unchanged).
- `guard_browser` — 21 passed (unchanged).
- `guard_core` — 24 passed (21 from Phase 11 + 3 new Phase 12:
  `reason_codes_are_stable_snake_case`,
  `reason_codes_are_unique`,
  `kind_codes_are_stable_snake_case`).
- `guard-ipc` — 7 passed (unchanged; the `EventInfo` struct gained fields but
  no new test was needed — the existing explain round-trip covers it).
- `guard-ssh` — 10 passed (unchanged).
- `guard-test-fixtures` — 9 passed (unchanged).
- `platform-linux` — 29 passed (unchanged).
- `guardd` — 67 passed (unchanged; the existing explain IPC test gained
  `reason_code` assertions — no new test function, same count).
- `guardctl` — 6 passed (unchanged; the existing `explain_event_from_json_body`
  test was updated with the new fields — no new test function, same count).
- `guard-tui` — 2 passed (unchanged).
- `smoke` integration — 1 passed (unchanged).
- **Total: 181 passed, 0 failed.**

### Privileged end-to-end script (BLOCKED: requires root)

`scripts/test-agent-compat-root.sh` covers 8 scenarios that require
`CAP_SYS_ADMIN`:

1. agent reads normal project file => succeeds (content matches)
2. agent writes normal project file => succeeds
3. agent reads browser cookie fixture => denied (EPERM)
4. agent reads SSH test key => denied (EPERM)
5. `guardctl explain --json` on a denial event => contains `reason_code` +
   `resource_kind_code` with non-empty values
6. git init + add + commit on a local temp repo => succeeds
7. audit events JSON + explain JSON + guardd log contain no secret markers
   (no `GUARD_SYNTHETIC_COOKIE_FIXTURE`, no `BEGIN OPENSSH PRIVATE KEY`)
8. clean daemon shutdown on SIGTERM

The script uses a synthetic Chromium profile, an ephemeral `ssh-keygen`-generated
ed25519 keypair, and a normal project dir + git repo — all under an isolated
temp directory. It never touches the developer's real `~/.ssh`, real browser
profile, or real repos. It contains no network exfiltration code.

**Status: BLOCKED for the non-interactive build agent** (cannot obtain
`CAP_SYS_ADMIN`). A human can run `sudo bash scripts/test-agent-compat-root.sh`
to execute the 8 privileged scenarios.

## Known limitations

1. **`reason_code` / `resource_kind_code` are not persisted as separate SQLite
   columns.** They are derived from the typed `DenyReason` / `ProtectedResourceKind`
   enums at query time in `event_to_info`. This means the stable strings cannot
   drift from the enum — if a variant is renamed in Rust, the code updates
   automatically. The trade-off is that a tool scraping the raw SQLite audit
   table sees the enum's serde-serialized form, not the snake_case code; the
   stable codes are only exposed via the IPC/JSON path.
2. **privileged end-to-end tests are BLOCKED** for the non-interactive build
   agent (no `CAP_SYS_ADMIN`). The 8-scenario script is provided for a human to
   run; unit + IPC tests prove the reason-code logic without root.
3. **`open(2)` errors are plain `EPERM`.** The spec explicitly forbids injecting
   custom text into `open(2)` errors. An agent that gets `EPERM` must call
   `guardctl explain --json` (or `guardctl events`) to learn the reason — the
   errno alone does not carry the `reason_code`. This is the intended design:
   the filesystem boundary stays clean, and introspection is an explicit
   out-of-band query.

## Security notes

- **no brand special-casing.** `guardd` never checks for "codex", "claude",
  "gemini", or any agent brand. An AI coding agent is just another ordinary
  process: it is denied raw browser/SSH reads like any other untrusted exe,
  and it is allowed to read/write ordinary project files + run git like any
  other process.
- **no secret contents in explain/events output.** The `EventInfo` struct
  carries only metadata (path, exe, uid, pid, decision, reason codes). The
  audit record never contains file contents (enforced since Phase 06/10).
  `test-agent-compat-root.sh` Test 7 verifies no `GUARD_SYNTHETIC_*` markers
  or `BEGIN OPENSSH PRIVATE KEY` headers leak into the JSON/log output.
- **reason codes are a read-only contract.** Tools may read and branch on
  `reason_code`; they cannot influence the decision. The decision is still made
  by the deterministic policy engine in `guardd` — the reason code is just a
  stable label for the outcome.
