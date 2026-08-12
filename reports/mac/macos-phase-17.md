# macOS Phase 17 — AUTH_OPEN availability incident and offline safety repair

## BASE HEAD

`602ee05`

## PRODUCT TARGET

Self-use, locally signed Endpoint Security enforcement on an owner-controlled
SIP-off Mac. This report does not claim SIP-on distribution or Apple approval.

## PREVIOUS BLOCKER

The locally signed System Extension moved from user approval to real Active
state. Authenticated XPC and `es_new_client` were reachable. Before the first
synthetic deny/allow test, ordinary applications on the machine stopped
opening. Live work was stopped immediately.

## INCIDENT AND ROOT CAUSE

The active backend reported all of the following at the same time:

```text
backend_state=ACTIVE
enforcement_active=false
protected resources=0
AUTH_OPEN failed closed because process identity could not be graphed:
same audit process key changed stable identity
```

The old callback normalized and inserted every opener into the process graph
before checking whether the target file was protected. Any graph conflict
therefore returned zero authorized FFLAGS for an unrelated file. A conflict in
a long-lived launcher can deny subsequent application starts even with policy
disabled and zero protected resources.

Spaces were not the cause. ES paths are copied from length-delimited byte
tokens into `PathBuf` and never passed through shell word splitting. Dedicated
tests now cover protected and ordinary paths containing spaces.

Apple's installed Endpoint Security SDK states that exec increments
`pidversion`. The strict `(pid, pidversion) + start time + executable file
identity` invariant remains in place. The repair does not accept executable
replacement under the same audit key; diagnostics now identify whether start
time, executable path, executable file identity, or UID changed.

The callback is now structured as:

```text
empty/disabled policy -> ALLOW immediately
target scope candidate -> no protected match -> ALLOW immediately
protected match -> strict target validation -> strict process identity
                -> deadline/queue/policy -> ALLOW or DENY
```

AUTH_LINK and AUTH_RENAME use the same scope-first boundary. Truncated target
facts fail closed only after their available path/identity already matches a
protected target; unrelated truncated events are allowed.

## SELF-USE SIGNING MODEL

Unchanged: exact local certificate pin plus expected signing identifiers. No
certificate or private key is stored in the repository or app bundle.

## SIP STATUS

SIP is currently enabled. It will remain enabled throughout offline review.

## SYSTEM EXTENSION DEVELOPER MODE

Not queried or changed during this repair. The OS exposes no read-only status
command on this machine.

## EMBEDDED ENTITLEMENTS

The earlier final signed self-use artifact was verified to contain host system
extension install and nested Endpoint Security client entitlements. A new
post-repair artifact will be verified offline before any activation.

## XPC IDENTITY

The earlier live extension accepted the Guard client signed by the pinned
local certificate. Same-UID-only trust remains forbidden and unchanged.

## SYSTEM EXTENSION ACTIVATION

Before the incident the extension was independently confirmed Active by the
lifecycle API and `systemextensionsctl list`. It was then deactivated. Current
state is:

```text
Guard Endpoint Security [terminated waiting to uninstall on reboot]
guard-es process: absent
```

A reboot is required to finish removal. No further activation is authorized in
this phase.

## FULL DISK ACCESS

No TCC database changes were made. FDA is still a separate user-controlled
prerequisite.

## ENDPOINT SECURITY CLIENT

The earlier live client reached ACTIVE, which proves the SIP-off local
entitlement can create a real Endpoint Security client. The callback safety bug
invalidates that run as security acceptance.

## AUTH_OPEN SYNTHETIC DENY

NOT RUN after the incident. No result is claimed.

## AUTH_OPEN SYNTHETIC ALLOW

NOT RUN after the incident. No result is claimed.

## BROWSER ACCEPTANCE

NOT RUN. No real browser profile or secret was read.

## BROWSER MIGRATION

NOT RUN.

## SSH BLOCK

NOT RUN. No real SSH key was read.

## SSH ALLOW

NOT RUN.

## DEADLINE SAFETY

Existing pending/deadline tests pass. Deadline failures are now reachable only
after a protected scope match.

## NAMESPACE SAFETY

Scope-first link/rename tests pass, including unrelated paths, protected paths,
spaces, and truncated-path behavior. Existing hardlink/alias/rename tests also
remain green.

## RESTART / UPDATE

BLOCKED pending reboot to finish removal of the incident build. Update/live
replacement is intentionally not attempted with SIP enabled.

## FALLBACK STATUS

No LaunchDaemon fallback was implemented. The System Extension and real ES
client did activate; the failure was callback logic, not activation viability.

## REMAINING LIMITATIONS

- A real post-repair AUTH_OPEN run is still required.
- SIP-off and reboot are intentionally deferred until the owner is asked.
- Software cannot honestly guarantee zero kernel/OS failure risk; the new
  invariant limits Guard-originated deny decisions to confirmed protected
  targets.

## TEST RESULTS

```text
cargo test -p platform-macos --all-features
PASS: 69 tests

cargo clippy -p platform-macos --all-targets --all-features -- -D warnings
PASS

cargo test -p guard-ui --all-features
PASS: 16 tests

cargo clippy -p guard-ui --all-targets --all-features -- -D warnings
PASS

cargo fmt --check
PASS

git diff --check
PASS

Docker
NOT STARTED
```

## FINAL STATUS

`OFFLINE AUTH_OPEN SAFETY REPAIR PASSED; LIVE SIP-OFF ACCEPTANCE PAUSED`

This is not `SELF-USE SECURITY ACCEPTED ON TESTED SIP-OFF MAC`.
