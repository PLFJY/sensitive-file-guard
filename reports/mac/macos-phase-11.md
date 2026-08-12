# macOS Phase 11 — Final Security Acceptance

## Final summary

```text
BASE HEAD: 8a354aa
FINAL HEAD: Phase 11 commit (see git log; a commit cannot contain its own hash)
MACOS ARCH / VERSION: Mac16,12 / arm64 / macOS 26.6.1 (25G76)
BUNDLE OUTPUT: build/macos-release/Guard.app; Guard-0.1.0-arm64.zip
SYSTEM EXTENSION STATUS: NOT INSTALLED / NOT ACTIVE
ENTITLEMENT STATUS: local test bundle intentionally has no restricted entitlements; Apple profiles unavailable
FDA STATUS: UNKNOWN / NOT TESTABLE because the Endpoint Security extension is inactive
BROWSER MATRIX: synthetic/unit PASS; real disposable Chrome/Firefox and hostile reads BLOCKED
SSH MATRIX: synthetic/unit PASS; real ephemeral-key Block/Allow/ssh-add BLOCKED
XPC AUTH MATRIX: signed clients PASS; ad-hoc and same-Team unlisted clients DENY; live extension unavailable
DEADLINE MATRIX: fake-clock/race/health PASS; live ES deadline diagnostics BLOCKED
NAMESPACE MATRIX: synthetic hardlink/symlink/link/rename/atomic-update PASS; live kernel matrix BLOCKED
LINUX REGRESSION: NOT RUN — explicitly outside user scope
PACKAGING / NOTARIZATION: self-contained local arm64 PASS; Developer ID/notarization BLOCKED
KNOWN BOUNDARIES: root/browser compromise, already-open descriptors, extension downtime, agent signing authority
FINAL STATUS: FUNCTIONALLY COMPLETE / SECURITY ACCEPTANCE BLOCKED
```

This is not `SECURITY-ACCEPTED ALPHA`. Required real entitled gates did not
run, and this host has System Integrity Protection disabled. No blocked result
is counted as a pass.

## Environment record

| Item | Observed value |
|---|---|
| Mac model / architecture | Mac16,12 / arm64 |
| macOS | 26.6.1 (25G76) |
| Xcode / SDK | Xcode 26.6 (17F113) / SDK 26.5 |
| Rust | rustc 1.97.0 |
| GTK / libadwaita | 4.22.4 / 1.9.3 |
| App bundle version/build | 0.1.0 / 1 |
| System extension version/build | 0.1.0 / 1 |
| Available signing identity | Apple Development; Team `YSGFZUQGW6` |
| Developer ID identities | None available |
| Host restricted entitlement | Absent in local-only artifact by design |
| Extension ES entitlement | Absent in local-only artifact by design |
| Provisioning profiles | Unavailable |
| System extension | Unknown / not installed |
| Endpoint Security XPC | Unreachable; extension inactive |
| Full Disk Access | Unknown / cannot test inactive extension |
| Pending helper final state | NotRegistered |
| SIP | **Disabled** before this phase; unchanged |
| Notary Keychain profile | Unavailable |

The local artifact has valid Apple Development signatures, matching Team IDs,
hardened runtime, and no restricted entitlement claims. That is correct for
local launch testing but is not a distributable/entitled configuration.

## Source safety

The final preflight created a dedicated disposable root:

```text
/var/folders/.../guard-final-acceptance.kHIUUH
```

It contained only empty `home`, browser-fixture, SSH-fixture, and output
directories plus the generated GTK loader cache. The preflight stopped before
any browser profile or SSH key fixture was created and removed the root on
exit. The browser/SSH/namespace live scripts also stopped at authenticated-XPC
preflight before their `mktemp` fixture/enrollment steps.

No normal profile under `~/Library/Application Support`, no real cookie/session
database, no `~/.ssh` key, and no agent socket was opened, enrolled, copied, or
modified.

## Phase fixes

Two locally fixable regressions were found and corrected before issuing final
status:

1. The signed XPC self-approval test constructed a temporary app by copying
   only Guard's executable. With the Phase 10 release layout, dyld correctly
   rejected that incomplete test app because bundled GTK Frameworks were
   absent. The script now copies the release Frameworks and Resources, then
   re-signs the complete temporary app. The signed-client and two wrong-client
   tests pass again.
2. A macOS `guardctl status` XPC failure was prefixed with a Linux
   `/run/guardd/guardd.sock` message. macOS now names the authenticated Endpoint
   Security XPC service; a target-specific regression test protects the
   diagnostic.

Added `preflight-final-acceptance.sh`, which creates a disposable scope,
verifies the release bundle/GTK runtime, requires SIP enabled, release signing,
active extension, authenticated enforcement health, no FDA-required state, and
an enabled helper. It exits 77 with all observed blockers before interactive
fixtures.

## Gate matrix

### Gate A — build/shared regression

| Check | Result | Evidence |
|---|---|---|
| Rust format | PASS | `cargo fmt --check` |
| Selected macOS/portable Clippy | PASS | All targets/features, warnings denied |
| Selected macOS/portable tests | PASS | 204 passed, 0 failed |
| Release build | PASS | arm64 optimized release bundle rebuilt |
| Native C/Objective-C compile | PASS | `-Wall -Wextra -Werror` |
| macOS/platform/package boundaries | PASS | All three scripts |
| `git diff --check` / shell syntax | PASS | Clean |
| Workspace/Linux commands | NOT RUN | User explicitly excluded Linux and workspace Linux targets |
| Docker | NOT STARTED | Explicitly prohibited |

The explicit package list excluded `guardd` and `platform-linux`. No workspace
command was used in Phase 11.

### Gate B — bundle/signing

| Check | Result | Notes |
|---|---|---|
| Guard bundled GTK launch | PASS | Isolated HOME; exit 0 |
| Self-contained runtime | PASS | 44 dylibs/13 loaders; no Homebrew runtime path |
| System extension placement | PASS | `Contents/Library/SystemExtensions` |
| Nested/outer signatures | PASS | Explicit signing; strict/deep verification |
| Hardened runtime | PASS | Verified on all component roles |
| Team relationship | PASS | Local components Team `YSGFZUQGW6` |
| Scoped formal entitlement path | PASS (static) | Release builder/profile gates and component checks |
| Actual provisioned entitlements | BLOCKED | Matching Apple profiles unavailable |
| Developer ID / Gatekeeper / notarization | BLOCKED | Identity and notary profile unavailable |

### Gate C — activation and FDA

**BLOCKED.** Final preflight returned 77:

```text
BLOCKED: SIP must be enabled for final security acceptance
BLOCKED: local-only signing is not a release acceptance identity
system-extension state=Unknown diagnostic=system extension is not installed
BLOCKED: the provisioned system extension is not active
BLOCKED: authenticated Endpoint Security XPC health is unavailable
BLOCKED: enforcement is not active
pending_helper=NotRegistered
BLOCKED: the pending helper is not enabled
FINAL_SECURITY_ACCEPTANCE_PREFLIGHT=BLOCKED
```

The earlier real activation request on this intentionally entitlement-free
local app failed closed with `Missing entitlement
com.apple.developer.system-extension.install`. FDA withhold/regrant cannot be
tested without an authorized active ES client. No TCC database operation or
global security relaxation was attempted.

### Gates D–G — ES primitive and browser matrix

| Matrix item | Synthetic/unit | Real disposable entitled run |
|---|---|---|
| Unknown reader denied before read | PASS | BLOCKED before fixture |
| Explicit trusted identity allowed | PASS | BLOCKED before fixture |
| Chrome own profile/helper behavior | Discovery/policy PASS | BLOCKED before profile creation |
| Firefox own profile/helper behavior | Discovery/policy PASS | BLOCKED before profile creation |
| Chromium own-profile model | Discovery/policy PASS | NOT CLAIMED as live-supported |
| Shell/Python/Node/Rust hostile reads | Policy/probe boundaries PASS | BLOCKED |
| Fake browser / wrong signer | PASS | Wrong signed transport client DENY; live file read BLOCKED |
| Migration Block/close | PASS | BLOCKED |
| Migration Allow/LA/revalidation | PASS | BLOCKED |
| Unrelated/expiry/root-exit/sibling scope | PASS | BLOCKED |
| macOS FREAD-only response | PASS | Live claim BLOCKED |

`run-browser-policy-acceptance.sh` exited 77 before `mktemp` because signed
guardctl could not reach the activated extension. Therefore no browser is
listed as security-accepted on macOS; Chrome/Firefox/Chromium are implemented
and synthetically discovered, not promoted from discovery alone.

### Gate H — SSH manual approval

Unit/runtime coverage passed for Block, Allow, exact key/UID/root, verified
descendant, unrelated root, expiry, root exit, queue pressure, timeout, late
completion, and fresh-runtime lease loss. Cross-UID fails closed. Specialized
`guardctl ssh load` reports it is unsupported on macOS; ordinary `ssh-add` is
documented to use manual approval.

The real ephemeral-key script exited 77 at XPC preflight before `mktemp` or
`ssh-keygen`, so no live Block/Allow/ordinary-ssh-add result is claimed.

### Gate I — self-approval defense

| Client | Result against Team-signed temporary XPC service |
|---|---|
| Signed Guard CLI | PASS |
| Signed Guard UI | PASS |
| Signed pending observer | PASS; metadata-only |
| Ad-hoc same-UID probe | DENY |
| Same-Team unlisted same-UID probe | DENY |
| Hidden noninteractive Allow | Absent; unit test PASS |
| Allow before LocalAuthentication | Unit test DENY |
| Authentication cancellation/timeout | No Allow sent; PASS |
| Malformed/replayed request | Fail closed / terminal-state tests PASS |

This validates transport and authorization logic, not live ES enforcement.

### Gate J — deadline safety

| Item | Result |
|---|---|
| Effective deadline derived from ES message | PASS |
| Short deadline immediate fail-closed | PASS |
| Product timeout before kernel deadline | PASS |
| Timer vs Allow exactly once | PASS |
| Timer vs Block/drop exactly once | PASS |
| Late LocalAuthentication creates no lease | PASS |
| Response error releases once and degrades health | PASS |
| Semantic pending/allow/deny/timeout counters | PASS |
| Real ES deadline/sequence diagnostic | BLOCKED |

No test intentionally waited past a real ES deadline.

### Gate K — namespace bypasses

Synthetic kernel-fact tests passed for pre-existing hardlink identity, symlink
target identity, link-out, rename-out, parent rename, rename into a sensitive
destination, SSH namespace denial, alias capacity/saturation, and the exact
owning browser's narrow atomic replacement. Sequence loss disables ancestry
leases and requests repair.

The live namespace script exited 77 at XPC preflight before creating its Chrome
profile, so the real kernel matrix remains BLOCKED.

### Gate L — restart, update, and recovery

| Item | Result |
|---|---|
| Bundled app/GTK restart | PASS |
| Pending helper observer restart | PASS on temporary authenticated XPC service |
| Fresh runtime drops pending/leases | PASS |
| Protocol mismatch fails clearly | PASS |
| Local 0.1.0 → 0.1.1 replacement | PASS |
| Synthetic config/audit/profile persistence | PASS |
| Recovery/uninstall source exclusion | PASS |
| Real extension replacement/restart/config reload | BLOCKED |
| FDA removal/regrant recovery | BLOCKED |

### Gate M — performance sanity

The pending helper, polling the temporary authenticated service every 500 ms
for five seconds, used 0:00.02 CPU time and sampled 0.1% CPU. Bundled GTK smoke
started normally. No obviously pathological behavior appeared in local tests.

Unprotected ES fast-path overhead, own-browser protected-open latency,
extension CPU/memory, and real prompt launch latency are **BLOCKED** because no
active entitled extension exists. No security-weakening ES response caching was
added, and performance acceptance is not claimed from unit timings.

### Gate N — audit/privacy

Metadata-only audit schema/round-trip/filter/pagination/drop tests passed.
Fixture policy tests assert audit records cannot carry secret content. XPC,
status, diagnostics, and reports contain identities/counters/paths only. No
cookie value, browser DB row, password, session value, private-key byte, or
LocalAuthentication secret was generated or inspected during Phase 11.

## Commands run

```text
cargo fmt --check
cargo clippy <explicit macOS/portable package list> \
  --all-targets --all-features -- -D warnings
cargo test <explicit macOS/portable package list> \
  --all-targets --all-features

xcrun clang -fsyntax-only ... -Wall -Wextra -Werror \
  native/macos/*.m
xcrun clang -fsyntax-only ... -Wall -Wextra -Werror \
  native/macos/endpoint_security_bridge.c

tests/check_platform_boundaries.sh
tests/check_macos_boundaries.sh
tests/check_macos_packaging.sh
sh -n scripts/macos/*.sh tests/check_macos*.sh
git diff --check

SIGNING_IDENTITY='Apple Development: …' DEVELOPMENT_TEAM=YSGFZUQGW6 \
LOCAL_SIGNING_ONLY=1 CODESIGN_TIMESTAMP=none \
scripts/macos/build-release-app.sh

HOME=<disposable> \
build/macos-release/Guard.app/Contents/MacOS/Guard --packaging-smoke

scripts/macos/test-xpc-auth.sh build/macos-release/Guard.app

SIGNING_IDENTITY='Apple Development: …' DEVELOPMENT_TEAM=YSGFZUQGW6 \
scripts/macos/test-release-update.sh

VERIFY_SIGNING_MODE=local \
scripts/macos/preflight-final-acceptance.sh \
  build/macos-release/Guard.app

GUARD_APP=build/macos-release/Guard.app \
scripts/macos/run-browser-policy-acceptance.sh
scripts/macos/run-ssh-policy-acceptance.sh \
  build/macos-release/Guard.app
GUARD_APP=build/macos-release/Guard.app \
scripts/macos/run-namespace-health-acceptance.sh
```

## Required external acceptance rerun

Before any status promotion:

1. Re-enable SIP through Apple's supported Recovery flow and boot normally.
2. Obtain approved host/Endpoint Security provisioning profiles, a Developer
   ID Application identity, and an external notary Keychain profile.
3. Build, notarize, staple, and install the release app in `/Applications`.
4. Activate/approve the extension and grant FDA through System Settings.
5. Register the helper and make the final preflight pass.
6. Run every printed disposable browser/SSH/namespace script, the ES primitive,
   FDA revoke/regrant, real restart/replacement, and performance measurements.
7. Inspect fixture-only audit metadata and remove all temporary enrollments.

Root/password access alone cannot supply Apple restricted-entitlement
authorization, a Developer ID identity, a notary profile, or change SIP without
the supported recovery/reboot flow. The project must remain at:

```text
FUNCTIONALLY COMPLETE / SECURITY ACCEPTANCE BLOCKED
```
