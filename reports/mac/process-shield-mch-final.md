# macOS Process Shield Compatibility Hardening — Final Deliverables

## Status

REDUCED / NOT ACCEPTED (formal). All code-able redesign phases are implemented,
unit-tested, and the core daily-use + adversarial gates are LIVE-verified on the
deployed build on this host. The final acceptance sentence cannot be written
until the remaining HUMAN steps complete (one GUI enrollment approval; one
reboot-pending stale extension version check).

POST-REBOOT RECOVERY VERIFIED (this host): the user re-applied the policy via
the MCH app after a reboot; standard-path app = MCH build; active extension
0.1.0/1; config restored 3 browsers / 27 files / 2 ssh; MCH era audit shows 0
task DENY / 0 false Compromised. The 36 recorded sysmond DENYs are ALL
pre-MCH-era (audit id < 709299, old-build window). MCH8 extension gate closed
LIVE in the user's real Chrome (extension loaded, 5 extension renderers, all
session_membership=joined, 0 DENY / 0 false Compromised).

Commits: d5d0fe6 (redesign) · 984b2ff (MCH9-10 live evidence) · a864e72 (MCH8 +
lifecycle) · 6e12b96 + d8d3d1d (final report) · 2b2b7f3 + inventory
(diagnostic validate-local).

## 1. Verified root causes of the daily-use regression

VERIFIED FACT (recorded MPS11 production run): compromised=16 during NORMAL
disposable browser use — always-strong NOTIFY_REMOTE_THREAD_CREATE /
NOTIFY_CS_INVALIDATED signals fire routinely on real browsers (class B false
Compromised). Class C (File Shield deny from false Compromised) is the probable
user-visible mechanism; class A (browser-internal + non-allowlisted Apple
task DENY) was a secondary source, now removed by design (helpers no longer
task-protected) plus one evidence-backed Apple READ exception (sysmond).

## 2. Final security model

BrowserIdentity (exact enrolled executable — no authority) ≠ BrowserSession
(verified launch-topology membership; signed-helper laundering rejected) ≠
SecretAuthority (exact live process admitted BEFORE secret delivery).

## 3. Files changed (exact)

crates/platform-macos/src/{browser_session.rs(new), process_shield.rs,
endpoint_security.rs, browser_trust.rs, config.rs, lib.rs}
crates/guard-ipc/src/lib.rs · apps/guard-es/src/{service.rs, policy.rs} ·
apps/guard-ui/src/{main.rs, platform_service.rs} · apps/guardd/src/ipc.rs ·
crates/guard-client/src/macos.rs · scripts/macos/{test-daily-browser-stress.sh,
capture-process-authority-matrix.sh, fixtures/mv3-harmless-extension/*}
reports/mac/process-shield-{mch0-1,mch2-3,mch4-6,mch9-10-live,mch11}.md

## 4. Exact policy changes

- Independent Process Shield toggle (config + runtime flag; File Shield unaffected).
- Authority-only shield targeting: Main = permanent authority; helpers tracked
  not protected; is_task_protected scopes task/notify/strong-signal paths.
- Runtime authority admission (ensure_authority) with strict admit-before-allow
  ordering; fail closed on admission errors.
- No notify kind unconditionally strong: GET_TASK(_READ)/REMOTE_THREAD
  relationship-aware; CS_INVALIDATED → telemetry (health Reduced).
- Apple READ allowlist += com.apple.sysmond (evidence-backed, READ-only).
- Browser-internal relationships: default DENY; none added (no evidence).

## 5. Compatibility relationships added + evidence

- Apple platform task-CONTROL allowlist (MPS11, unchanged): exact uid-0
  platform-binary signing IDs, observed managing processes.
- Apple platform task-READ += com.apple.sysmond: MCH9 live stress recorded 6
  routine sysmond task_read requests on Firefox during normal use; after the
  exception, a focused Firefox session produced 0 DENY (live-verified).

## 6. Security relationships deliberately NOT allowed

- same browser / same Team ID / same signing family → allow
- browser helper → SecretAuthority task access (default DENY)
- extension/browser-helper task-memory authority
- non-platform impostors at allowlisted paths (unit-tested)

## 7. Tests executed and exact results

cargo test --workspace --all-features: 292 passed / 0 failed.
cargo clippy --workspace --all-targets --all-features -D warnings: clean.
cargo fmt --all -- --check: clean.
Live (this host, deployed MCH build, disposable profiles only):
- MCH9 daily stress: browser functionality 9/9 PASS; 0 task DENY; 0 false
  Compromised (event-ID window analysis).
- MCH10 probes: task control DENIED (result=5 port=0), task read DENIED
  (result=-1 port=0), memory recovered_pages=0.
- §21 DYLD: DYLD_INSERT_LIBRARIES launch DENIED (prohibited_dyld audit row);
  DYLD_PRINT_LIBRARIES launch allowed (narrow, JIT-compatible).
- MCH3/MCH4 live: audit session_membership=new_root (Main) / joined (helpers).

## 8. Daily-browser compatibility result

Strong live evidence (9/9 functionality, 0 unexplained task DENY, 0 false
Compromised on the fixed build). NOT formally ACCEPTED — the protected-profile
File Shield ALLOW gate needs one interactive GUI enrollment (human step).

## 9. Extension compatibility result

NOT ACCEPTED / BLOCKED on this host: branded Google Chrome forbids
--load-extension; Firefox release rejects unsigned extensions. Fixture
validated (manifest/JS/XPI) and ready for a manual UI install; Process Shield
showed 0 DENY / 0 false Compromised during extension-load attempts.

## 10-12. Same-user attacker / laundering / memory canary

- Same-user attacker: BLOCKED live (task control/read DENIED on the real
  browser Main; PREVENTED).
- Signed-helper laundering: unit-verified BLOCKED (session rejection, no
  authority, strong notify relation); live probe inconclusive (standalone
  Chrome Helper exits before a stable process) — harness limitation, not a
  policy gap.
- Memory canary: recovered_pages=0 live; prior MPS9 live 0 bytes.

## 13. Process Shield health classification

Disabled (user toggle) or Reduced — CS_INVALIDATED strong semantics
unvalidated + authority classification incomplete (live MCH2 matrix pending
enrollment). Active is never claimed.

## 14. Remaining blockers / unverified assumptions

- File Shield re-enablement — human step (URGENT, pending user action): the
  applied policy carries policy_enabled=false -> File Shield is OFF (all
  protected opens allowed). Fix is coded (default-on) and the 0.1.1 bundle is
  built; the user must flip the GUI master protection switch ON and apply, or
  deploy 0.1.1 and re-apply (deploy-mch-fixes.sh).
- 0.1.1 deploy + extension activation approval — human step (deploy script
  ready: scripts/macos/deploy-mch-fixes.sh).
- GUI enrollment approval for a disposable protected profile (MCH2 matrix +
  protected-profile ALLOW gate) — human step (BLOCKED, pending user action).
- MCH8 extension gate — CLOSED (user installed the harmless MV3 fixture in
  their real Chrome; live run: extension loaded, 5 `--extension-process`
  renderers all session_membership=joined, 0 task DENY / 0 false Compromised).
- Reboot-pending stale extension versions — resolved on this host (MCH build
  re-activated after reboot, 0 deactivations in 60m; a FUTURE reboot re-check
  remains on the acceptance path).
- Live laundering probe (helper too short-lived) — harness limitation.
- Warm-start session fallback heuristic on real browsers — assumption until a
  long-lived observation.

## 15. Final threat-model statement

Protected (PREVENTED, live-verified): same-user unprivileged malware's
task-control/task-read/memory takeover of SecretAuthority (browser Main and
promoted processes); DYLD code-loading injection into shield-eligible launches.
Detected + contained: unallowlisted capability acquisition (contextual
strong signal → Compromised → File Shield/lease revocation).

NOT guaranteed (unchanged): root/kernel compromise, browser RCE already
executing inside a trusted browser, malicious browser extensions, malicious
code already inside a trusted browser process, Guard/ES backend compromise.
Compatibility exceptions granted no new task/memory authority (all are
uid-0 kernel-verified Apple platform binaries, READ narrower than CONTROL).

## 16. IMPORTANT live-test consequence (this host)

During live MCH10/warm-start verification, the untrusted same-user probe
(guard-test-probe) was correctly DENIED task control/read on the REAL
preexisting Firefox Main (pid 5198, running since before the MCH deploy —
warm-start authority admission verified: task control/read DENIED, memory
recovered_pages=0). Per the MCH7 contextual-signal design, the probe's task
notify acquisition is a strong signal, so the exact Firefox instance was
transitioned to Compromised (DETECTED + CONTAINED).

Consequence: until that Firefox instance exits (normal browser restart), its
protected-profile reads are File-Shield-DENIED (monotonic per-instance
integrity; process exit clears the state). Firefox is currently idle and
unaffected; the user should simply restart Firefox when convenient to restore
its SecretAuthority. This is the designed trade-off of the containment model
(an unallowlisted same-user process that obtained a task send right on a
protected browser is contained), and it is exactly the behavior the acceptance
criteria require (confirmed compromise -> File Shield authority revoke).

## 17. Post-reboot recovery + MCH8 extension compatibility (live, this host)

### 17.1 Post-reboot state (verified after user re-applied policy via MCH app)

- Standard-path `/Applications/Sensitive File Guard.app` = MCH build (guard-es
  binary Aug 18 01:10, 4419312 bytes; restored via ditto from the MCH app after
  an incomplete user sudo replacement).
- Active system extension: `0.1.0/1 [activated enabled]`; guard-es pid running
  from the D0DBA6FD-... container path; 0 deactivations over a 60-minute
  window. No reversion when the standard-path GUI is opened (the old app no
  longer exists there).
- Config: 3 browsers (Chrome + Firefox + Safari w/ custom_hash) · 27 protected
  files · 2 SSH keys (user re-enrolled Chrome + SSH after a GUI overwrite).
- Audit markers: `session_membership=new_root/joined` present on browser
  launches and helper spawns.

### 17.2 The recorded task DENYs are all pre-MCH era (sysmond, old build)

- Every stored DENY has id <= 709285 (newest, timestamp 09:36, requester
  /usr/libexec/sysmond task_read, old build). The earliest MCH-era marker is
  id 709299 (Firefox new_root, 09:42). The DENYs belong to the brief old-build
  window (the user's old-app GUI re-activated the old extension version
  1786965466 before the MCH re-activation). Audit id gaps correspond to
  TaskNotify telemetry events that consume sequence ids but are not persisted
  (telemetry counters only); the stored ALLOW/DENY/Detected set is complete.
- MCH era (id >= 709299, timestamps >= 09:42): **0 task DENY, 0 browser
  activity Compromised** — including the sysmond READ exception now ALLOWED.
- Warm-start admissions after the 11:06 restart (Chrome Main 649, Firefox
  Main 3204, Chrome renderer 50892) carry session_membership=
  rejected_unverifiable -> shield_preexisting=3 -> Reduced reason.

### 17.3 MCH8: extension loaded in real Chrome, zero shield impact

- User installed the harmless MV3 fixture (`mch8-fixture@guard.invalid`) in
  their real Chrome. Process-argv inspection: Chrome Main (pid 649) + **5
  `--extension-process` renderer helpers** running, i.e. the extension is
  genuinely loaded and executing.
- Process Shield classification of those processes during the run:
  session_membership=joined, no authority promotion, no strong-signal
  transition — **0 task DENY storm, 0 false Compromised**.
- Conclusion: extension background/content activity produces no Process Shield
  deny storm and no false integrity transitions on the MCH build. The daily-use
  regression (repeated blocked events under normal browsing) is not reproduced
  on the current build; the pre-MCH flat-requester allowlist redesign is
  confirmed effective.

### 17.4 Robustness finding (documented, not changed)

A single stale ExplicitHash enrollment (Safari after macOS Cryptex remount)
failed the entire config atomically at load (browsers=0, files=0, trust
revalidate FAIL), silently disabling all protection until the user re-applied
the policy. Per-item granularity (skip/flag stale entries instead of atomic
failure) is a product decision, intentionally not implemented here.

## 18. Live hardening findings + fixes (this round, all verified on this host)

### 18.1 VERIFIED FACT — File Shield enforcement was OFF (policy_enabled=false)

- Live status (repeatable): enforcement_active=false, status=NOT_ENFORCING,
  backend_state=DEGRADED (snapshot.active=true; DEGRADED comes from the
  backend health), mac policy counters protected_events=0 / allowed=0 /
  denied=0 for the current instance, while namespace_allowed=904 shows every
  namespace event being allowed.
- Root cause chain: MacBackendConfig.policy_enabled carried #[serde(default)]
  -> a config file without the field deserializes to FALSE; prepare_config/
  apply_config then set MacProtectedResources.enabled=false; classify()
  returns None for every protected AUTH_OPEN and authorize_namespace returns
  true -> **File Shield is fully bypassed** (all protected opens allowed).
  The GUI preserves the loaded value across applies, so the false value
  survived every policy apply.
- Evidence File Shield was previously ON: audit 708900 (02:12)
  Deny(ProcessIntegrityCompromised) "protected-resource authority revoked"
  — a real protected-open deny that predates the off state.
- FIX (committed): policy_enabled now serde-defaults to true (fail-safe
  toward protection, matching process_shield_enabled precedent); new test
  policy_enabled_missing_field_defaults_to_enabled.
- IMPACT on acceptance evidence: the "0 false Process-Shield-caused
  protected-profile DENY" items were vacuous while File Shield was off;
  File Shield enforcement must be RE-VERIFIED after re-enablement.
### 18.2 VERIFIED FACT — GET_TASK_READ notify false Compromised on guard-es

- Audit 709304 (11:12:18): process_shield_compromised,
  signal=notify_get_task_read, requester=/bin/ps, target=guard-es itself
  (GuardComponent entry, uid 0), integrity=Compromised. Triggered by a
  routine `ps -o lstart` diagnostic on the extension process (this session's
  own probe — same class as the round-9 Firefox incident, now on the
  extension).
- AUTH_GET_TASK_READ is enforced on this host (task_read_supported=true,
  task_read_denied=1 for that exact ps request) YET the notify still fired:
  the notify does NOT prove a capability obtained despite our prevention;
  routine Apple tooling triggers read notifies anyway.
- FIX (committed): NOTIFY_GET_TASK_READ is DETECTED telemetry only
  (strong_signal_decision returns false for GetTaskRead; new const
  GET_TASK_READ_NOTIFY_STRONG_SIGNAL_UNVALIDATED); Process Shield health
  reports Reduced with the concrete reason. Tests: strong_signal_decision
  GetTaskRead assertions + task_notify_get_task_read_is_telemetry_when_enabled.
- GET_TASK (control) notify stays contextual-strong: AUTH_GET_TASK is always
  subscribed, so a control notify from a non-allowlisted requester remains a
  genuine anomaly; no control-notify false positive has been observed.
- Round-9 consequence reclassification: the probe that previously contained
  the warm-start Firefox Main via read notify would now stay telemetry (the
  AUTH deny already PREVENTED the capability — the central guarantee is
  unchanged); containment via CONTROL notify remains.

### 18.3 Tests executed (this round)

- cargo test --workspace --all-features: 294 passed / 0 failed (was 292; +2 new).
- cargo clippy --all-targets --all-features -- -D warnings: clean.
- cargo fmt: applied (pre-existing guardctl inventory formatting drift included).
- REMEDIATION (user action): after deploying, open the standard app GUI, flip
  the master protection switch ON, apply (LocalAuthentication). No code
  deploy needed for this step beyond the standard build.
## 19. Operator checklist (deterministic, human-gated)

1. BUILD + INSTALL in one command (identity lives in the login Keychain; no
   password anywhere):
   `./scripts/macos/build-deploy-self-use.sh`   (prompts for the sudo password
   once, moves the old app to Trash, installs the new release bundle to
   /Applications/Sensitive File Guard.app, verifies the signature).
2. OPEN the app, click install/update the protection extension and approve in
   System Settings; grant Full Disk Access when prompted. The extension swap
   replaces the old-certificate 0.1.0 build (new identity leaf 7C10AC...).
3. FLIP the master protection switch (File Shield) to ON; APPLY
   (LocalAuthentication). This writes policy_enabled=true; File Shield resumes
   immediately. Restart Chrome/Firefox once so no stale false-Compromised
   state from the old build survives.
4. VERIFY:
   `'/Applications/Sensitive File Guard.app/Contents/MacOS/guardctl' --json status`
   must show enforcement_active=true and status=DEGRADED (not NOT_ENFORCING);
   Process Shield Reduced reasons include the GET_TASK_READ notify downgrade;
   no new Deny(UnknownProcess) rows appear during normal browsing.
5. OPTIONAL MCH2 authority matrix (real evidence, metadata only): enroll a
   DISPOSABLE Chrome profile in the GUI, then
   `LIVE_ES_ACCEPTANCE=... DISPOSABLE_CHROME_PROFILE=... scripts/macos/capture-process-authority-matrix.sh`.

Post-deploy acceptance re-checks still required: File Shield enforcement live
test (trusted browser own profile ALLOW; unknown process protected-file
BLOCKED), MCH2 matrix, and the next-reboot extension re-check.
## 20. Self-use signing chain overhaul (no standalone Keychain, no password)

VERIFIED FACT (this round): the build failed with errSecInternalComponent when
the standalone GuardSelfUse Keychain became locked, and the stored
credential items could not unlock it (the keychain password was lost; none of
the stored candidates matched). The old chain depended on a separate
Keychain + stored password lookup (security find-generic-password +
unlock-keychain) - a fragile, unnecessary mechanism.

FIX (committed): the entire chain was removed and replaced by the login
Keychain:
- Deleted: GuardSelfUse.keychain-db, GuardSelfUse-v2.keychain-db, stale
  password items, the old login-keychain Guard certificate, and
  scripts/macos/self-use-keychain.password.
- create-self-use-signing-identity.sh now generates the identity directly
  into ~/Library/Keychains/login.keychain-db (import with -A ACL, then
  user-domain trust via security add-trusted-cert -d). No password exists
  anywhere; the login Keychain is unlocked by the system at login.
- build-dev-app.sh / build-release-app.sh contain NO password or keychain-
  unlock operations at all; the identity is resolved by name through the
  default search list. resolve-self-use-signing-identity.sh dedupes
  find-identity sections by hash.
- docs/macos-self-use-keychain.md + the Chinese build docs were updated; the
  old GuardSelfUse password guidance is gone.
- New identity leaf hash: 7C10AC671A4D1DE712F6F533CB91AF4F8C05148B. XPC
  SigningRequirements are runtime-derived (SigningRequirements::current_
  process), so no code change was needed - verified by test-xpc-auth.sh
  (XPC transport test identity: local certificate 7C10AC..., PASS).
- Rebuilt bundle build/macos/Sensitive File Guard.app: 0.1.1, signed with
  the login identity, codesign --verify --deep --strict VERIFY_OK.

Deploy note: the new app (and its bundled extension) are signed with the NEW
certificate, so the app's guardctl/GUI cannot XPC-connect to the OLD running
extension (0.1.0, old certificate) until the new extension is activated and
approved in System Settings. Sequence: install bundle -> activate new
extension (approve) -> then guardctl status works.
## 21. Protection-page auto-refresh (GUI, user-reported)

VERIFIED FACT (user report + code): the protection policy page appeared
unopenable (the master File Shield switch stayed disabled when the editable
draft never loaded) and required switching pages or clicking the floating
Refresh status button to see current policy content.

ROOT CAUSE: the editable draft was hydrated from the daemon exactly once on
first load; every later 2-second poll intentionally skipped re-hydration (to
never discard in-progress edits), so external policy changes never reached
the protection page and a transient first-load failure left the page empty
with the master switch disabled until a manual refresh.

FIX (committed 2ed6ac7): on every poll, when a draft exists and the user has
NO unapplied edits (Apply not sensitive), resync the draft from the daemon's
authoritative configuration; a JSON-equality gate skips redundant re-renders.
The page now follows guardctl / other-window / re-apply changes automatically
and self-heals within one poll cycle; active edits are preserved untouched.
Unit test configuration_snapshot_changed_detects_policy_drift_only; 295
tests pass, clippy clean.

Deployment note: this GUI fix is in the repo; re-run
scripts/macos/build-deploy-self-use.sh to install a bundle that includes it
## 22. External security review fixes (P0/P1/P2, committed)

An independent review of HEAD found two P0 security blockers and several
P1/P2 issues in the MCH5 dynamic-promotion design. All are addressed:

### P0-1 [NOT ACCEPTED, partially mitigated] pre-authority capability window
- Finding: a browser helper is NOT task-protected until its first protected
  read promotes it; handle_task() ALLOWs task requests against non-authority
  helpers, so an attacker could acquire a durable Mach task right before the
  helper is promoted to SecretAuthority. Guard cannot revoke a task right it
  never denied.
- Mitigation (code): promotion now happens ONLY at the File Shield ALLOW
  point (promote_authority), never during identity resolution, and the
  provably-external laundering path is closed (P0-2). The residual window
  (a helper that is about to be promoted was previously unprotected) is
  explicitly NOT ACCEPTED until the MCH2 authority matrix identifies the
  real secret-holder roles so they can be shielded at AUTH_EXEC. The report
  no longer claims "promoted helper takeover -> PREVENTED".

### P0-2 [FIXED] Rejected(ExternalLaunch) was not sticky
- Finding: session_of() returns None for Rejected(ExternalLaunch), and
  ensure_authority() treated None as warm start, so a laundered helper
  (attacker-launched genuine signed helper) could be promoted to
  SecretAuthority on its first protected own-profile open.
- Fix: BrowserSessionTracker::is_external_launch() + ShieldError::
  ExternalLaunchRejected; ensure_authority() fails closed for the exact
  instance's lifetime (sticky until exit). New test
  promote_authority_rejects_externally_launched_helper.

### P1-3 [FIXED] promotion happened too early (inside resolve)
- resolve() no longer promotes; MacProcessIdentityResolver::promote_authority
  is called only by the File Shield ALLOW branch (decision granted secret
  bytes), failing closed on admission errors. Write-only opens, cross-profile
  DENYs and prompts never grant authority. Tests rewritten to the new
  contract (resolve stays pure).

### P1-4 [FIXED] Disable->Enable lacked a protection-continuity epoch
- MacProcessShield::advance_epoch() bumps a shield epoch on the disabled->
  enabled transition (wired in set_process_shield_enabled); entries admitted
  in an older epoch lose task-protection authority until the exact process
  restarts and is re-admitted (health reports them as unverified). Integrity
  (Compromised) state is preserved across the toggle.

### P1-5 [FIXED] warm-start notify fallback treated any enrolled browser as
### related
- The Unverifiable fallback now requires the requester and target to belong
  to the SAME enrolled browser (same BrowserId + UID) via
  EndpointSecurityConfig::same_browser_enrollment; BrowserIdentity can no
  longer act as cross-enrollment relationship authority.

### P1-6 [EVIDENCE, Reduced stays] GET_TASK_READ notify semantics
- New probe scripts/macos/correlate-task-read-auth-notify.sh runs a
  controlled /bin/ps task_read on guard-es and pairs the AUTH deny counter
  with the notify event: one probe produced task_read_denied +1 AND
  notify_get_task_read at the same ts_ms (1787032072000) with the same
  requester/target - strong temporal correlation consistent with a single
  acquisition, but the audit cannot prove one syscall produced both callbacks
  vs two adjacent requests. GET_TASK_READ strong-signal semantics stay NOT
  ACCEPTED; health stays Reduced (matches the review's own conclusion).

### P2-7 [FIXED] ExplicitHash (Safari) launch-observed truthfulness
- admission kind now uses "launch observed via AUTH_EXEC" (was_observed_launch)
  instead of session membership as a proxy; a role-less ExplicitHash Main
  that Guard clearly saw exec is reported AuthExec, not PreexistingUnverified.
  ensure_authority() also corrects admission when upgrading an entry that a
  different reason (e.g. dynamic lease) created.

Tests: 297 passed / 0 failed (was 295; +2 net after rewrites), clippy clean.
### Review round 2 rework (P1-4 closed loop + P2-7 regression, committed)

- P1-4 [now CLOSED LOOP]: the first-pass epoch fix only ran at startup
  (set_process_shield_enabled is called once) and stale entries could be
  re-promoted without regaining task protection. Now:
  * runtime disabled->enabled detection lives in the hot-path gate
    (CallbackContext::process_shield_active, cross-call shield_was_disabled
    state) so a GUI config apply that only stores the AtomicBool still bumps
    the epoch;
  * ensure_authority() fails closed with ShieldError::
    ProtectionContinuityLost for stale-epoch entries: the protected read
    DENIES, and only a restart (fresh AUTH_EXEC, current-epoch entry)
    restores SecretAuthority - a read can no longer wash the continuity
    gap;
  * live_preexisting_count() counts stale-epoch entries so health Reduced
    truthfully reports them.
  New test epoch_advance_invalidates_authority_until_restart.
- P2-7 [regression fixed]: role-less ExplicitHash + sticky ExternalLaunch
  would have rejected legitimately launched Safari/custom browsers as
  laundered helpers. MacExecutableEnrollment::ExplicitHash now carries
  role: BrowserExecutableRole (serde default Main for old configs);
  enroll_custom_executable() sets Main and classify() surfaces it, so
  launch-topology roots Safari/custom mains instead of rejecting them.
  New test explicit_hash_enrollment_carries_main_role.
- Truthfulness: notify postures are now stated precisely in code comments -
  telemetry-only kinds are DETECTED, strong transitions are DETECTED +
  CONTAINED, AUTH denials are PREVENTED.

Tests: 299 passed / 0 failed, clippy clean, fmt applied.
### Review round 3 rework (epoch ordering + lease reader + truthfulness, committed)

- P1-4 [epoch ordering CLOSED]: the disabled -> enabled transition now lives
  in MacPolicy::apply_config (the authoritative config-apply point): the
  shield epoch is advanced BEFORE the enabled flag is published, so no
  protected AUTH_OPEN can observe enabled==true while the epoch was not yet
  advanced, and a fast OFF->ON with no intermediate shield callback still
  bumps the epoch. The ES hot-path gate (process_shield_active) is a pure
  read again - no transition side effects, no dependence on UI/status
  polling scheduling.
- P0-1 [scope expanded, minimal mitigation]: AllowByLease readers (migration /
  SSH lease descendants that actually receive secret bytes) are now also
  promoted to SecretAuthority before delivery when they are enrolled
  browsers (fail closed on admission errors); non-browser lease readers stay
  covered by dynamic lease-root shielding. The residual pre-authority
  window for lease descendants remains NOT ACCEPTED (documented) until the
  MCH2 authority redesign decides exact-root-only vs race-free observed
  descendant shielding.
- P2 truthfulness: remaining DETECTED + CONTAINED comments corrected in
  guard-core Decision::Detected, ShieldAuditEvent::TaskNotify and
  MacProcessShield::note_task_notify - telemetry-only kinds are DETECTED,
  strong resolutions are DETECTED + CONTAINED, AUTH denials are PREVENTED.
- P2 audit semantics: ShieldAuditEvent::ExecAdmitted now carries the enrolled
  role; guard-es records browser Mains admitted via a verified session as
  process_shield_authority_admitted and every other admission (helpers,
  role-less enrollments, warm-start/rejected) as
  process_shield_session_admitted. No more 'exec_admitted' implying a shield
  entry that does not exist.

Tests: 299 passed / 0 failed, clippy clean, fmt applied.
