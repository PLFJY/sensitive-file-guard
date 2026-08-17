# MCH4-6 — SecretAuthority Shield Targeting + Runtime Authority Admission

## Status

IMPLEMENTED + UNIT-TESTED. Daily-browser compatibility remains NOT ACCEPTED;
health remains Reduced (see §5). Live extension re-verification stays BLOCKED
on this host (human approval + reboot), so the targeting change has NOT been
live-validated against real browsers yet — it is unit-tested and designed to
fail closed.

## Repository

HEAD: 8720595 (main). Working-tree changes only.

## 1. MCH4 — SecretAuthority-based shield targeting (implemented)

The shield no longer task-protects every enrolled browser executable:

- Shielding at AUTH_EXEC is now limited to the PERMANENT authority candidate:
  a browser Main process (session root, or a Main joining an existing
  session). Such entries carry `authority = true`.
- Helpers (role Helper / role-less enrollments) are tracked in the
  BrowserSession model but get NO shield entry and NO task restrictions at
  exec time — the "do not lock every browser helper" rule. They are promoted
  only on a protected read (MCH5).
- Laundered / rejected execs get no entry either.
- Guard components and dynamic lease roots remain task-protected
  unconditionally (non-Browser reasons), unchanged from MPS6.
- `is_task_protected(facts)`: true for browser-authority entries and for
  non-browser shield entries; false for unprotected helpers. `handle_task`
  and `handle_task_notify` and `apply_strong_signal` now scope on this
  predicate: a task request against an unprotected helper is ALLOWED (no
  deny storm from browser-internal helper relationships), and helpers never
  generate compromise signals.

Central guarantee preserved: an unknown external process attempting task
control/read against a SecretAuthority (the browser Main, or a promoted
helper) is still DENIED via the exact Apple platform allowlist. This is the
same protection the MPS11 live probe validated (probe -> real Chrome main ->
DENY).

## 2. MCH5 — Runtime authority admission (implemented)

`MacProcessShield::ensure_authority(facts)`: admits (or upgrades) the exact
live instance to SecretAuthority with the REQUIRED ordering — it runs inside
the identity resolver's `resolve()`, which is the protected AUTH_OPEN choke
point, BEFORE the portable policy can return Allow:

```text
protected AUTH_OPEN
  -> resolver.resolve()
  -> ensure_authority() [admit into Process Shield]
  -> identity returned (trusted, Normal)
  -> policy ALLOW
  -> secret bytes available
```

Forbidden ordering (ALLOW then shield) is impossible by construction: the
admission error propagates and the protected open FAILS CLOSED
(`Deny(UnknownProcess)` + permission.deny in guard-es), never returning an
unshielded trusted identity.

Admission kind:
- session member (launch observed via AUTH_EXEC): `AuthExec` — health stays
  strong for that instance;
- never launch-observed (warm start): `PreexistingUnverified` — health
  Reduced until restart (unchanged warm-start semantics).

Warm-start task-target coverage is preserved for authority candidates only:
`handle_task` still admits a preexisting browser MAIN (role Main) or a Guard
component fail-closed before the task decision; unprotected helpers are left
unprotected (they hold no secret authority) and are promoted on their first
protected read.

## 3. MCH6 — Task relationship policy (groundwork, no new allows)

No browser-internal task relationship was added. The default remains
browser helper -> SecretAuthority = DENY (12.3), and the round-2 session
machinery (`signal_relation`, `is_same_session`) is in place to add a narrow,
evidence-backed relationship later. The compatibility win comes from MCH4:
helpers are not task-protected, so browser-internal helper relationships are
no longer evaluated (no deny storm) — without granting anyone authority.

## 4. Tests executed (exact results)

cargo fmt --all -- --check                              PASS
cargo clippy --workspace --all-targets --all-features -D warnings  PASS
cargo test --workspace --all-features                  PASS 291 passed, 0 failed
git diff --check                                       PASS

New/updated unit tests (all PASS):
- task_protection_covers_authority_and_guard_components_only
- ensure_authority_admission_kind_depends_on_observed_launch
- resolver_promotes_session_helper_before_protected_read (MCH5 ordering at
  the File Shield layer: helper promoted BEFORE the trusted identity is
  returned; AuthExec admission; no preexisting flag)
- admit_browser_records_session_membership_and_rejects_laundering (updated:
  helper NOT shielded at exec; promoted via ensure_authority; laundered
  helper never shielded)
- strong_signal_transition_* (updated: non-authority browser entries are out
  of strong-signal scope)
- notify tests (targets admitted as authority via ensure_authority)

## 5. Health classification

- Disabled (toggle): unchanged.
- Enabled: Reduced — CS_INVALIDATED unvalidated (MCH7) + authority
  classification incomplete (live MCH2 matrix pending). The MCH4 targeting
  itself is designed fail-closed but is not yet live-validated.

## 6. Security conclusions

- Unknown external -> SecretAuthority task control/read: PREVENTED (unit;
  live recheck pending).
- Browser helper task access to SecretAuthority: DENIED by default (12.3).
- Browser-internal helper relationships: no longer evaluated (helpers not
  task-protected) -> the class-A deny storm source is removed by design.
- Signed-helper laundering: no session membership, no shield entry, no task
  authority (unit).

## 7. Files changed (exact)

crates/platform-macos/src/process_shield.rs
crates/platform-macos/src/endpoint_security.rs
crates/platform-macos/src/browser_trust.rs

## 8. Blockers / unverified assumptions

- Live MCH2 matrix and any live daily-use run: BLOCKED (human approval +
  reboot). The MCH4 helper-unshielding behavior is UNVERIFIED RISK until a
  live Chrome/Firefox run confirms no legitimate helper->authority task
  relationship was needed (the MCH2 matrix + MCH6 evidence step will answer
  this; crash-handler task access to the Main is a known open question).

## 9. MCH8 — harmless MV3 extension fixture (created; live test BLOCKED)

scripts/macos/fixtures/mv3-harmless-extension/ contains a harmless Manifest V3
fixture: background service worker (install/startup/tab wake + storage.local +
tabs API), content script (benign DOM annotation), popup page, options page.
Validated: manifest JSON + all JS syntax OK. Live extension-compatibility run
(tab churn, service-worker wake, content-script injection, popup/options,
storage) is BLOCKED on this host with the rest of the live harness; the
fixture is the deterministic artifact for that run. Extension compatibility
never implies extension task-memory authority: the fixture gets no task
authority over SecretAuthority targets.
