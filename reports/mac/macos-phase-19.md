# macOS Phase 19 — activation preflight hardening

## BASE HEAD

`fe5d9839270cdef008b1f2ad98976a165cf22767`

## PRODUCT TARGET

Prepare a reviewable SIP-off self-use candidate without activating it while SIP
is enabled. This phase adds final-artifact entitlement checks to the GUI and
hardens the transition from offline verification to the first synthetic live
test.

## PREVIOUS BLOCKER

The Phase 17 incident proved that an Endpoint Security callback error could
deny an unrelated open before the target was known to be protected. That scope
bug is fixed and covered by the Phase 18 mandatory safety gate. Live evidence
remains invalidated until a controlled rerun.

## SELF-USE SIGNING MODEL

The local name is now resolved through `security find-identity` to exactly one
valid 40-hex certificate/private-key identity before `codesign` runs. The tested
identity resolved to `E640217586EA797109605A205995F48BA53163B4`. A stale second
certificate with the same display name remains untouched and can no longer make
the build select ambiguously. No certificate or private key is stored in the
repository or app.

## SIP STATUS

`csrutil status`: `System Integrity Protection status: enabled.`

No SIP change, application launch, extension activation, Full Disk Access
change, or TCC change occurred in this phase.

## SYSTEM EXTENSION DEVELOPER MODE

Not changed or assumed. It will be enabled manually only after the reboot gate.

## EMBEDDED ENTITLEMENTS

Final ignored candidate: `build/macos-phase19-final/Guard.app`.

- host identifier `io.github.plfjy.SensitiveFileGuard`:
  `com.apple.developer.system-extension.install = true`;
- extension identifier `io.github.plfjy.SensitiveFileGuard.guard-es`:
  `com.apple.developer.endpoint-security.client = true`;
- both report `Authority=Guard Local Development Certificate`;
- marker contains exact `SAFETY_GATE=mac-auth-scope-v1`;
- `verify-bundle.sh` reports a valid self-contained arm64 self-use bundle.

The GUI now reads the nested extension's final code signature with
Security.framework (`SecStaticCode*` and `SecCodeCopySigningInformation`). It
does not trust the source entitlement plist. The install button requires both
the host and nested extension entitlements. Missing, invalid, or unreadable
signed code disables activation. Results are cached for the lifetime of the
running signed app.

## XPC IDENTITY

Unchanged: Apple Team requirements remain available for formal builds; self-use
requirements pin the exact local certificate plus expected Guard signing IDs.
Same UID, process name, or identifier alone is not trusted.

## SYSTEM EXTENSION ACTIVATION

Not attempted. `systemextensionsctl list` still reports Guard as
`terminated waiting to uninstall on reboot`; no `guard-es` process is running.
The unrelated Little Snitch pending-uninstall entry was observed but not
modified.

The live PoC now requires both a successful Guard lifecycle result and an exact
enabled/active `systemextensionsctl` row. Before opening even the synthetic
fixture, it also requires a running `guard-es` whose on-disk code-signing
identifier exactly matches the expected extension bundle ID.

## FULL DISK ACCESS

Not changed or tested.

## ENDPOINT SECURITY CLIENT

Not started. Live result remains BLOCKED.

## AUTH_OPEN SYNTHETIC DENY

Not run. Live result remains BLOCKED.

## AUTH_OPEN SYNTHETIC ALLOW

Not run. Live result remains BLOCKED.

## BROWSER ACCEPTANCE

Not run; no real or synthetic browser profile was opened.

## BROWSER MIGRATION

Not run.

## SSH BLOCK

Not run; no real SSH key was read.

## SSH ALLOW

Not run.

## DEADLINE SAFETY

Covered by the mandatory self-use gate; existing bounded-deadline tests pass.

## NAMESPACE SAFETY

Covered by the mandatory self-use gate; existing hardlink, rename, sequence-gap,
and bounded-alias tests pass.

## RESTART / UPDATE

A reboot is required to finish removing the old Guard extension before any new
activation. Update/live acceptance is not run in this phase.

## FALLBACK STATUS

No LaunchDaemon fallback was implemented. The System Extension path has not
failed under the corrected, fully verified environment.

## TEST RESULTS

PASS:

- `scripts/macos/self-use-safety-gate.sh`: 117 tests
  (`8 + 3 + 4 + 16 + 15 + 71`) plus selected all-target/all-feature clippy;
- final-artifact local-certificate self-use release build and deep verification;
- Security.framework nested-entitlement test with a signed synthetic extension
  under `Guard Review With Spaces.app`;
- missing nested extension fails closed without activation;
- identity name and exact hash both resolve to the same valid signing identity;
- `sh -n scripts/macos/*.sh`;
- relevant release builds for `guard-es`, `guard-ui`, `guardctl`,
  `guard-notify`, and `guard-test-probe`;
- `git diff --check`;
- SIP-on live PoC interlock exits 77 before build/fixture/activation;
- SIP-on final preflight verifies the bundle, then exits 77 before executing it.

The requested workspace-wide `cargo clippy --workspace --all-targets
--all-features` is not a valid Darwin gate because it unconditionally compiles
Linux fanotify/inotify/SO_PEERCRED code against Apple's `libc`; it fails in
`platform-linux` before reaching the macOS changes. Linux was explicitly out of
scope and was not modified. The macOS target set passes clippy and tests.

## REMAINING LIMITATIONS

- Offline review cannot prove a kernel Endpoint Security authorization result.
- The old Guard system extension removal must finish on reboot.
- Developer mode, activation, FDA, authenticated production XPC/backend health,
  synthetic AUTH_OPEN, browser, SSH, deadline live behavior, namespace live
  behavior, and restart/update acceptance remain to be run.
- No responsible review can promise a literal 100% absence of OS-level failure;
  the corrected scope invariant, activation interlocks, synthetic-only first
  test, and Recovery rollback materially reduce and contain the risk.

## FINAL STATUS

`OFFLINE SELF-USE CANDIDATE VERIFIED; LIVE SIP-OFF RE-ACCEPTANCE PAUSED AT REBOOT GATE`
