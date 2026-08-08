# Phase 03 — Shared Domain Model and Policy Engine

## Implemented behavior

Moved allow/deny logic out of the Linux syscall path into `guard-core`, as pure
platform-independent data types plus a deterministic `evaluate` function. No
root, no OS interception, and no UI is required to unit-test policy decisions.

Modules added under `crates/guard-core/src/`:

- `resource.rs` — `ProtectedResourceId`, `ProtectedResourceKind`
  (`CookieStore`, `SessionStore`, `BrowserKeyMaterial`, `WebStorage`,
  `SavedCredentials`, `History`, `SshPrivateKey`), `BrowserFamily`, `BrowserId`,
  `ProfileId`, `ProtectedResource`. Criticality helpers
  (`is_browser` / `is_ssh` / `is_critical_browser`).
- `identity.rs` — `TrustTier` (`SystemPackage`, `Sandbox`,
  `EnrolledUserWritable`, `Unknown`), `ProcessStableId` (PID + start time +
  canonical exe path + `st_dev` + `st_ino`), `StableIdentity` (everything but
  the PID — what leases bind to), `ProcessIdentity` (uid/gid/browser/trust tier
  + cmdline for audit only).
- `lease.rs` — `LeaseId`, `MigrationLease` (source browser/profile, target
  browser, uid, stable target identity, expiry, revoked, read_only),
  `SshLoadLease` (single resource, uid, stable target identity, expiry,
  revoked, one-shot `used` flag), `LeaseSet`.
- `policy.rs` — `Decision` (`Allow | Deny(reason) | AllowByLease(lease_id)`),
  `DenyReason`, `AccessOperation` (`Open | Read | Copy`), `AccessEvent`, and
  `evaluate(event, leases, now)`.

Policy decisions are deterministic, with no risk scores and no ML:

- Browser branch: wrong UID => `WrongUid`; not a trusted browser => `UnknownProcess`
  (no browser id) or `NotTrustedIdentity` (browser id present but untrusted);
  own profile => `Allow`; another browser's profile requires a scope-matching,
  identity-matching, non-revoked, non-expired `MigrationLease` =>
  `AllowByLease`, else `CrossBrowserWithoutLease` (or `IdentityMismatch` when a
  scope-matching lease exists but the process identity differs — PID reuse).
- SSH branch: requires a scope-matching, identity-matching, non-revoked,
  non-expired, not-yet-used `SshLoadLease` => `AllowByLease`; otherwise
  `SshPrivateKeyRawRead` (or `IdentityMismatch` / `OneShotLeaseUsed` /
  `LeaseRevoked` / `LeaseExpired` for the closest matching lease).

The "unprotected target => allow" rule is enforced at the platform layer: the
policy is only consulted for resources that are enrolled as protected.

## Exact commands run

```
cargo fmt
cargo fmt --check
cargo clippy -p guard-core --all-targets --all-features -- -D warnings
cargo test -p guard-core --no-fail-fast
```

## Test results

`cargo test -p guard-core` — 17 passed, 0 failed.

Table-driven tests cover every required baseline rule plus the negative
lease/identity cases:

| Test | Rule |
| --- | --- |
| `trusted_browser_own_profile_allowed` | trusted browser + own profile => Allow |
| `cross_browser_without_lease_denied` | cross-browser => Deny(CrossBrowserWithoutLease) |
| `cross_browser_with_valid_lease_allowed_by_lease` | valid MigrationLease => AllowByLease |
| `unknown_process_browser_denied` | unknown process => Deny(UnknownProcess) |
| `untrusted_browser_denied` | browser id but untrusted => Deny(NotTrustedIdentity) |
| `ssh_private_key_ordinary_process_denied` | ordinary process + SSH key => Deny(SshPrivateKeyRawRead) |
| `ssh_private_key_with_valid_lease_allowed_by_lease` | valid SshLoadLease => AllowByLease |
| `expired_migration_lease_denied` | expired lease => Deny(LeaseExpired) |
| `revoked_migration_lease_denied` | revoked lease => Deny(LeaseRevoked) |
| `used_ssh_lease_denied` | one-shot lease already used => Deny(OneShotLeaseUsed) |
| `wrong_uid_denied` | cross-user => Deny(WrongUid) |
| `wrong_profile_lease_does_not_apply` | lease scope mismatch => Deny(CrossBrowserWithoutLease) |
| `migration_lease_bound_to_different_exe_denied` | identity mismatch => Deny(IdentityMismatch) |
| `pid_reuse_same_pid_different_start_time_denied` | PID reuse => Deny(IdentityMismatch) |
| `ssh_lease_wrong_uid_does_not_apply` | SSH lease wrong uid => Deny(SshPrivateKeyRawRead) |
| `kind_classification_helpers` | criticality classification sanity |

`cargo clippy -p guard-core --all-targets --all-features -- -D warnings` — clean.
`cargo fmt --check` — clean.

## Known limitations

- The policy engine is pure data-in/decision-out. It does not yet resolve a
  live PID into a `ProcessIdentity` (that is Phase 04's identity resolver), nor
  does it own the registry of which resources are protected (Phase 05).
- `AccessOperation::Read`/`Copy` are modeled but, on Linux, enforcement is at
  `Open` time (fanotify `FAN_OPEN_PERM`); a copy is denied because the source
  open is denied.
- No "trust this app to read everything" super-rule exists by design.

## Security assumptions

- The platform layer only calls `evaluate` for enrolled protected resources;
  unprotected opens are allowed without consulting policy.
- `now` and `expires_at` use the same monotonic/epoch clock; lease expiry is
  checked with `now >= expires_at`.
- Leases bind to `StableIdentity` (exe path + start time + dev + ino), never to
  a PID alone, so PID reuse cannot satisfy a lease.
- Missing identity fields are never permission to allow — an unresolvable
  process resolves to `TrustTier::Unknown` and is denied for protected
  resources.
