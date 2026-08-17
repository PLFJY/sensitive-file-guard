# MCH0-1 — Independent Process Shield Toggle + Strong-Signal Revalidation

## Status

IMPLEMENTED + UNIT-TESTED. Daily-browser compatibility remains NOT ACCEPTED
(this round is hardening infrastructure and signal semantics, not a new
daily-use acceptance claim). Live Endpoint Security re-verification remains
BLOCKED on this host by the same human steps as MPS12 (permanent extension
approval + reboot to clear stale extension versions).

## Repository

- HEAD: 8720595 (main, before this round)
- This round: working-tree changes only, files listed in §7.

## 1. MCH1 — Verified root-cause classification of the daily-use regression

The daily-use symptom is "normal browser use -> opening tabs / ordinary
browsing -> repeated Process Shield blocked events" (still present after
browser extensions were removed).

VERIFIED FACT (from the recorded MPS11 production live run):
- During NORMAL disposable Chrome/Firefox launch + JS load + relaunch with the
  production extension active, the live Process Shield counters reached
  compromised=16 and task-deny rows appeared (reported in
  process-shield-mps12.md). 16 browser processes were transitioned to
  Compromised without any attack — i.e. always-strong notify signals
  (NOTIFY_REMOTE_THREAD_CREATE / NOTIFY_CS_INVALIDATED) fire routinely on real
  browsers.

VERIFIED FACT (code): at MPS12, handle_task_notify treated RemoteThreadCreate
and CsInvalidated as unconditionally strong; NOTIFY_GET_TASK(_READ) notifies
were already contextual (strong only when the requester was not allowlisted);
task access on shielded targets denies every non-allowlisted requester,
including browser-internal requesters.

Classification of the recorded false positives:
- A. AUTH_GET_TASK(_READ) false-positive DENY — POSSIBLE for browser-internal
  or Apple-daemon requesters outside the exact signing-ID allowlist (INFERENCE
  from deny rows present during normal use; exact requester identities were
  not retained in the MPS11 run).
- B. false ProcessIntegrity::Compromised transition — VERIFIED FACT for
  REMOTE_THREAD_CREATE / CS_INVALIDATED: compromised=16 during normal use.
- C. File Shield DENY caused secondarily by false Compromised — INFERENCE
  (strong); with a protected profile enrolled (hardening-2 scenario), a
  Compromised browser instance is denied its own protected reads via the
  process-integrity gate, which matches the user-visible "blocked events"
  while browsing.
- D. notification/audit spam only — does NOT match the blocked-events
  symptom; not the primary cause.

Conclusion: the primary verified false-positive class is B (always-strong
notify signals on real browsers), with C as the probable user-visible
mechanism once a profile is protected, and A as a secondary class that needs
exact-requester metadata capture before any browser-internal relationship is
ever allowed (MCH6).

## 2. MCH0 — Emergency independent Process Shield toggle

Requirement: run File Shield Active / Process Shield Disabled without
disabling the product, truthfully displayed, no silent system changes.

Implementation (KISS, existing architecture preserved):
- MacBackendConfig.process_shield_enabled (serde default true = backward
  compatible; independent of policy_enabled). File: crates/platform-macos/
  src/config.rs.
- ONE shared Arc<AtomicBool> runtime flag created in guard-es service startup,
  wired into: EndpointSecurityBackend (exec/task/notify decision gates),
  MacProcessIdentityResolver (warm-start reconciliation + integrity), MacPolicy
  (apply_config flips it atomically with the rest of the policy). Files:
  endpoint_security.rs, browser_trust.rs, apps/guard-es/src/service.rs,
  apps/guard-es/src/policy.rs.
- Disabled semantics (each gate verified by unit test):
  * AUTH_EXEC: every exec allowed; no shield admission, no DYLD code-loading
    deny, no shield audit.
  * AUTH_GET_TASK(_READ): every task request allowed; no warm-start admission,
    no deny counters.
  * task notify: ignored entirely; no telemetry, no audit, no compromise
    transitions.
  * resolver: never warm-start-reconciles a trusted browser into the shield;
    always surfaces Normal integrity (stale Compromised entries from before
    the toggle never fail File Shield).
  * dynamic lease-root shielding skipped while disabled.
- File Shield (protected AUTH_OPEN) is untouched in every path.
- Status: ProcessShieldInfo.state == "Disabled" with reason "Process Shield is
  disabled by policy; browser process-injection protection is unavailable.
  File Shield remains active."; enabled flag added to the IPC DTO; GUI shows
  the truthful Disabled line and a dedicated Process Shield switch on macOS
  that applies the config through the existing authoritative XPC path without
  touching the notification helper.
- No global security settings are changed; the ES client stays subscribed and
  simply never denies while disabled.

SECURITY ACCEPTANCE: MCH0 enforcement semantics accepted for the disabled
state (File Shield independence proven by unit tests). Live XPC apply of the
toggle still requires a running extension (BLOCKED on this host).

## 3. MCH7 — Strong-signal revalidation

Evidence-driven changes (process_shield.rs + endpoint_security.rs):
- No notify kind is unconditionally strong anymore. New pure resolver
  strong_signal_decision(kind, legitimate_relationship, requester_is_browser_identity):
  * GET_TASK / GET_TASK_READ: strong when the requester obtained capability
    without an accepted relationship (unchanged from MPS Hardening).
  * REMOTE_THREAD_CREATE: strong ONLY for an unknown external requester
    (not an exact enrolled browser executable, not an allowlisted Apple
    platform service). Browser-internal remote-thread creation is telemetry
    until real-browser evidence proves otherwise (per goal §14).
  * CS_INVALIDATED: UNVALIDATED automatic-compromise semantics -> DETECTED
    telemetry only; the constant
    CS_INVALIDATED_STRONG_SIGNAL_UNVALIDATED (true) drives Process Shield
    health = Reduced with the exact reason; flip to true-only-after-evidence.
  * TRACE: telemetry.
- Rationale (VERIFIED FACT): MPS11 recorded compromised=16 during normal use;
  keeping CS_INVALIDATED/REMOTE_THREAD always-strong reproduced the false
  Compromised class. The downgrade trades detection depth for daily-use
  correctness; per goal §14/§22 health reports Reduced, never Active.

SECURITY ACCEPTANCE: strong-signal semantics NOT accepted as final; the
reduced posture is intentional and truthfully reported. Adversarial recheck of
the remaining strong path (unknown external -> SecretAuthority) is still
unit-verified (task_notify_remote_thread_is_contextual_per_requester) and must
be re-run live (MCH10).

## 4. Tests executed (exact results)

cargo fmt --all -- --check                              PASS
cargo clippy --workspace --all-targets --all-features -D warnings  PASS
cargo test --workspace --all-features                  PASS 279 passed, 0 failed
git diff --check                                       PASS

New unit tests (all PASS):
- config: process_shield_enabled_defaults_true_and_is_independent_of_file_shield
- process_shield: notify_signal_classification_matches_mch7_revalidation;
  strong_signal_decision_resolves_context_per_requester
- endpoint_security: task_notify_disabled_flag_skips_signals_and_compromise;
  task_notify_cs_invalidated_is_telemetry_when_enabled;
  task_notify_remote_thread_is_contextual_per_requester
- browser_trust: resolver_with_disabled_shield_skips_warm_start_reconciliation;
  resolver_with_disabled_shield_ignores_stale_compromise_state
- service: process_shield_info_disabled_is_truthful_and_file_shield_independent;
  process_shield_info_enabled_reports_reduced_with_mch7_reason

## 5. Health classification

- Process Shield disabled by user: Disabled (File Shield independent).
- Process Shield enabled: Reduced — "code-signing invalidation signal is
  downgraded to telemetry until validated (MCH7)" (plus any host feature gaps).
  Active is NOT claimed while CS_INVALIDATED semantics are unvalidated.

## 6. Blockers / unverified assumptions

- BLOCKED (human): permanent system-extension approval + reboot to clear stale
  extension versions; required for any live re-run of the production extension.
- UNVERIFIED RISK: exact requester identities behind the recorded task-deny
  rows (class A) were not retained; a metadata-capture run is still required
  before any browser-internal task relationship may be considered (MCH6).
- UNVERIFIED RISK: REMOTE_THREAD_CREATE browser-internal telemetry behavior on
  real Chrome/Firefox (assumed from architecture; needs live observation).

## 7. Files changed (exact)

crates/platform-macos/src/config.rs
crates/platform-macos/src/process_shield.rs
crates/platform-macos/src/endpoint_security.rs
crates/platform-macos/src/browser_trust.rs
crates/guard-ipc/src/lib.rs
apps/guard-es/src/service.rs
apps/guard-es/src/policy.rs
apps/guard-ui/src/main.rs
apps/guard-ui/src/platform_service.rs
crates/guard-client/src/macos.rs (test fixture only)
