# MCH2-3 — BrowserSession Model + Authority-Matrix Harness

## Status

IMPLEMENTED + UNIT-TESTED (MCH3). MCH2 live capture script added; live run
BLOCKED on this host (same human steps as MPS12). Daily-browser compatibility
remains NOT ACCEPTED.

## Repository

HEAD: 8720595 (main). Working-tree changes only; files in §7.

## 1. MCH3 — BrowserSession runtime model (implemented)

New module crates/platform-macos/src/browser_session.rs. Three concepts from
the security model are now separated in code:

- BrowserIdentity: exact enrolled browser executable (existing trust store;
  role now surfaced via BrowserTrustDecision.role).
- BrowserSession: ONE legitimate running browser session, membership derived
  ONLY from verified runtime relationships:
  * root = enrolled Main executable whose AUTH_EXEC was observed outside any
    browser session (launched by user/launchd/shell);
  * every other member joined through a verified parent relationship: its
    AUTH_EXEC was observed AND its exact parent instance is already a session
    member (parent key comes from the process graph at exec time);
  * exit removes the member; root exit dissolves the whole session; PID reuse
    never inherits membership.
- Not admitted: BrowserIdentity only. Two rejection classes:
  * ExternalLaunch — parent is provably NOT a browser session member and NOT a
    browser executable (attacker process): signed-helper laundering;
  * Unverifiable — parent facts missing / warm-start browser parent without a
    session (no false rejection, but no membership either).

Never accepted as authority: same UID, same Team ID, same signing ID, same
basename, matching argv. A genuine browser signature is NOT a capability
token (laundering rejection is explicit and tested).

Wiring (process_shield.rs + endpoint_security.rs):
- MacProcessShield.admit_browser(facts, role, parent_key, parent_is_browser)
  classifies against the tracker and stores session id on the entry;
- handle_exec resolves role (trust store) + parent (process graph) at AUTH_EXEC
  time and records the membership outcome in the shield audit event
  (session_membership=new_root/joined/rejected_external/rejected_unverifiable,
  metadata only);
- remove_terminal keeps the tracker in sync (member exit / root dissolution);
- MacProcessShield.signal_relation(requester, target) answers
  SameSession / DifferentSession / RequesterExternal / Unverifiable.

## 2. MCH7 refinement — notify signals are now session-relationship-aware

The round-1 browser-identity fallback heuristic is now layered UNDER verified
session topology in handle_task_notify:

- GET_TASK / GET_TASK_READ / REMOTE_THREAD_CREATE: strong only when the
  requester is NOT allowlisted AND NOT a verified same-session member.
- A laundered signed helper (rejected ExternalLaunch) creating a remote
  thread in the real browser is now STRONG (previously the browser-identity
  heuristic treated any enrolled executable as browser-internal telemetry).
  This closes the round-1 weakening for the laundering case.
- Warm-start / unverifiable membership falls back to the browser-identity
  heuristic (no false compromise for browsers running across ES restarts).
- CS_INVALIDATED remains DETECTED telemetry (unvalidated, health Reduced).

## 3. MCH2 — authority-matrix capture harness (script added, live BLOCKED)

scripts/macos/capture-process-authority-matrix.sh: metadata-only capture that
- requires the live production extension + an enrolled DISPOSABLE Chrome
  profile (prerequisites checked, BLOCKED otherwise);
- drives disposable Chrome with normal sandbox: multiple tabs, multiple
  origins, navigation, reload, renderer churn, background activity;
- joins live audit rows (guardctl events) with process argv/exe to infer
  browser process roles (renderer/gpu/network_service/utility/main/...);
- emits authority-matrix.tsv: browser, role, executable, protected_kind,
  access_class, event_code, count.
- NEVER reads file contents / cookies / keys; role inference from argv/exe is
  explicitly labeled as evidence only, not authority.

LIVE RUN: BLOCKED on this host (extension approval + reboot), same as MPS12.
Until a live matrix exists, no browser role (other than the session root) is
promoted to SecretAuthority (MCH4/MCH5 remain pending on that evidence).

## 4. Tests executed (exact results)

cargo fmt --all -- --check                              PASS
cargo clippy --workspace --all-targets --all-features -D warnings  PASS
cargo test --workspace --all-features                  PASS 288 passed, 0 failed
sh -n scripts/macos/capture-process-authority-matrix.sh  PASS

git diff --check                                       PASS

New unit tests (all PASS):
- browser_session (8): main roots a new session; helpers join only via a
  verified parent member; signed-helper laundering rejected + never joins;
  warm-start parent without session is unverifiable (not external); unknown
  parent unverifiable; second browser instance is a separate session; root
  exit dissolves / member exit removes only member; PID reuse never inherits
  membership.
- process_shield (1): admit_browser records membership, rejects laundering,
  session dissolves on root exit, signal_relation answers correctly.
- endpoint_security: task_notify_remote_thread_is_contextual_per_requester
  extended with same-session telemetry + laundered-helper STRONG cases.
- strong_signal_decision test updated to the relation-aware signature.

## 5. Health classification

- Disabled (user toggle): unchanged from MCH0.
- Enabled: Reduced — CS_INVALIDATED unvalidated (MCH7) + authority
  classification incomplete (no live MCH2 matrix yet, MCH4/5 pending).

## 6. Security conclusions

- Signed-helper laundering: BLOCKED at the session layer (no membership) and
  STRONG at the notify layer (attacker-launched helper -> remote-thread signal
  -> Compromised) — unit-verified; live recheck pending (MCH10).
- Unknown external -> SecretAuthority task access: unchanged PREVENTED policy
  (task_access_allowlist + shielded-target deny), pending MCH4 targeting.

## 7. Files changed (exact)

crates/platform-macos/src/browser_session.rs        (new)
crates/platform-macos/src/process_shield.rs
crates/platform-macos/src/endpoint_security.rs
crates/platform-macos/src/browser_trust.rs
crates/platform-macos/src/lib.rs
apps/guard-es/src/policy.rs
scripts/macos/capture-process-authority-matrix.sh     (new)

## 8. Blockers / unverified assumptions

- Live MCH2 matrix: BLOCKED (human approval + reboot).
- Warm-start session behavior on real browsers (fallback heuristic) is
  assumption until a live run verifies it.
- MCH4/MCH5 (SecretAuthority targeting + runtime admission) explicitly
  deferred until the live matrix defines authority-holder roles.
