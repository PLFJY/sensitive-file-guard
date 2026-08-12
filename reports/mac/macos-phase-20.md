# macOS Phase 20 — self-use documentation and reboot handoff

## BASE HEAD

`1a4c874` (`fix(mac): harden self-use activation preflight`)

## PRODUCT TARGET

Make the repository tell one accurate macOS story: experimental self-use is the
primary path, SIP-off is intentional but delayed until all offline gates pass,
and formal SIP-on provisioning/notarization remains optional future work.

## PREVIOUS BLOCKER

Older guides incorrectly treated Apple provisioning as the only possible live
path and mixed entitlement-free UI smoke packages with enforcement candidates.
They also did not give sufficiently prominent incident containment and rollback
instructions.

## SELF-USE SIGNING MODEL

The guides now distinguish entitlement-free local smoke, certificate-backed
SIP-off self-use, and formally provisioned SIP-on release. They document that a
display name resolves to one exact valid identity hash and that certificate/key
material remains in Keychain.

## SIP STATUS

Current machine: SIP enabled. Documentation explicitly keeps SIP enabled during
build, tests, signing, and bundle inspection. It does not promise that software
can disable SIP or that risk is literally zero.

## SYSTEM EXTENSION DEVELOPER MODE

Documented as a manual, administrator-authorized command after the reboot and
SIP-off gate. No unsupported automatic status claim is made.

## EMBEDDED ENTITLEMENTS

Documentation requires checking the final signed host and nested extension,
not just source plists. It explains the GUI's two independent entitlement rows
and fail-closed install button.

## XPC IDENTITY

Documentation describes Apple Team and exact local-certificate requirements as
separate authenticated modes. Same UID remains insufficient.

## SYSTEM EXTENSION ACTIVATION

Not attempted. The next action is a normal SIP-on reboot to finish removing the
old Guard extension. The owner should not disable SIP during that first reboot.

## FULL DISK ACCESS

Documented as a separate user-controlled System Settings approval. Guard never
edits TCC.

## ENDPOINT SECURITY CLIENT

Not started; documentation requires exact backend health rather than treating a
lifecycle callback as enforcement proof.

## AUTH_OPEN SYNTHETIC DENY

Not run; documented as the first live kernel test after ordinary-file sanity.

## AUTH_OPEN SYNTHETIC ALLOW

Not run; documented as an exact enrolled synthetic probe/canary test.

## BROWSER ACCEPTANCE

Not run; documentation forbids using real profiles for acceptance.

## BROWSER MIGRATION

Not run; remains after basic synthetic AUTH_OPEN.

## SSH BLOCK

Not run; documentation requires an ephemeral generated fixture only.

## SSH ALLOW

Not run.

## DEADLINE SAFETY

No behavior change; documentation preserves deadline-gated fail-closed rules.

## NAMESPACE SAFETY

No behavior change; documentation preserves hardlink/rename/sequence-gap gates.

## RESTART / UPDATE

Current Guard state is `terminated waiting to uninstall on reboot`. A normal
reboot with SIP still enabled is now required. After return, verify the exact
Guard row is gone and no `guard-es` process exists before considering Recovery
and `csrutil disable`.

## FALLBACK STATUS

Not implemented or documented as active. The LaunchDaemon fallback remains
conditional on a fully verified System Extension activation failure.

## TEST RESULTS

PASS: documentation contradiction search, shell syntax checks for macOS scripts,
link/path spot checks, and `git diff --check`. Phase 19 contains the associated
code, signing, test, and offline bundle evidence.

## REMAINING LIMITATIONS

All live tests remain BLOCKED pending the staged reboot and the owner's later
explicit SIP-off decision. The docs do not claim production distribution,
notarization, Apple approval, SIP-on support, or current security acceptance.

## FINAL STATUS

`DOCUMENTATION ALIGNED; PAUSED FOR SAFE SIP-ON REBOOT AND POST-REBOOT AUDIT`
