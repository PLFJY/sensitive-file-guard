# AGENTS.md — Sensitive Data Firewall

This file restates the non-negotiable constraints for any agent working in this
repository. Read it before changing code. Source of truth: `00_GLOBAL_CONTRACT.md`
and `01_ARCHITECTURE_CONTEXT.md` under `sensitive-data-firewall-harness/`.

## Mission
Prevent unauthorized local processes from reading protected local secrets
(browser session/auth data + SSH private keys) **before** the protected file is
successfully opened. This is an access firewall, not an antivirus/EDR/DLP.

## Engineering style (KISS)
- No speculative framework architecture. No ManagerFactoryStrategy chains.
- No microservices. No custom crypto. No custom database engine.
- No pointless unit-test explosion. Every abstraction must remove real
  duplication or isolate an OS boundary.
- Plain Rust enums/structs/traits. `thiserror`/`anyhow` at boundaries.
- `serde` + JSON for low-volume local IPC/config. SQLite only when queryable
  persisted state is actually useful.
- No `unsafe` outside OS/FFI boundaries unless justified in a SAFETY comment.
- Comments explain non-obvious invariants, not obvious syntax.

## Security & testing rules
- NEVER use, read, or export the developer's real browser cookies, saved
  passwords, session tokens, or SSH private keys.
- Integration tests MUST use only synthetic browser-profile fixtures and
  ephemeral test SSH keys (see `guard-test-fixtures`).
- No test may upload secrets to a remote server. No "stealer" test may contain
  network exfiltration. Probes only attempt local open/read/copy on fixtures.
- Do not weaken system security globally to make a test pass. Do not silently
  disable Secure Boot/SIP/SELinux/AppArmor.
- Audit logs must NEVER contain secret contents (no cookie values, passwords,
  key bytes, browser DB rows, or private-key material).

## Authorization hot path
- The authorization path MUST NOT wait for a human UI.
- Decision model: `Allow | Deny(reason) | AllowByLease(lease_id)`. No risk
  scores. No ML.
- Deny immediately when policy says deny, then audit, then notify out-of-band.

## Process identity
- Never trust process name alone. Use PID + start token/time + canonical exe
  path + exe file identity (st_dev + st_ino). Missing fields are not permission
  to allow.

## Quality gate for every phase
1. inspect existing code, preserve working behavior
2. implement
3. `cargo fmt --check`
4. `cargo clippy --all-targets --all-features -- -D warnings`
5. relevant unit/integration tests
6. fix failures (do not merely describe them)
7. update docs for new user-visible behavior
8. write `reports/phase-XX.md`
9. only then continue to the next phase

If a test needs root/kernel/entitlement that is genuinely unavailable: complete
everything possible, give the exact blocked command/error, provide a deterministic
script for a human to run later, and mark that test BLOCKED. Never claim a
blocked test passed.
