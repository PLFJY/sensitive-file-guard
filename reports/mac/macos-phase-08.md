# macOS Phase 08 — SSH Private-Key Manual Approval

## Phase

Name / number: Phase 08 — SSH Private-Key Manual Approval

## Base

- starting commit / branch: `c951597` / `main`
- platform / macOS version: macOS 26.6.1 (Build 25G76)
- architecture: arm64 / Apple Silicon
- Xcode / SDK: Xcode 26.6 (17F113), macOS SDK 26.5
- Rust: rustc 1.97.0
- GTK / libadwaita: 4.22.4 / 1.9.3

## Implemented

- Extended the live macOS resource index with explicitly enrolled SSH private
  keys, inode aliases, exact configured paths after replacement, and separate
  SSH status counts. Browser behavior remains unchanged.
- Added `FREAD`-aware SSH policy to the Endpoint Security service. Same-UID
  reads without a valid lease enter a typed deadline-bounded pending request;
  cross-UID and missing-identity attempts deny immediately.
- Documented and implemented write-only behavior: same-UID write-only opens are
  allowed because they cannot disclose bytes and integrity enforcement is not
  this product's scope. Any open containing `FREAD`, including
  `FREAD|FWRITE`, requires approval.
- Reused the asynchronous ES pending owner without blocking the native callback
  thread. Queue capacity is eight, same root/key/file-identity reads may join,
  and queue pressure, insufficient interaction budget, process exit, timeout,
  or dropped authorization denies fail closed.
- Connected SSH pending list/get/resolve and helper snapshots to authenticated,
  transport-EUID-scoped XPC. Block/close remains a restrictive operation;
  Allow crosses LocalAuthentication in the signed client.
- After Allow, the extension re-resolves the exact PID/start/executable
  identity, verifies peer/key owner UID, root liveness, configured key path,
  and current device/inode against the held event before creating a lease.
- Added ten-second in-memory `SshReadAccessLease` records scoped to one exact
  key, one UID, one verified process root, and positively verified descendants.
  An unrelated invocation prompts again; root exit and explicit revoke disable
  the lease.
- Made a late Allow unable to recreate access: if timeout already won, no lease
  is created; if the retained ES response becomes terminal during resolution,
  the newly created lease is revoked before returning an error.
- Ported `guardctl ssh protect PATH` to the authenticated macOS config path.
  Shared `guard-ssh` rules reject `.pub` and reserved names; enrollment
  canonicalizes/stats and checks owner without opening, parsing, hashing, or
  logging the key.
- Explicitly left the Linux-specific specialized `guardctl ssh load` shortcut
  unsupported on macOS. It returns before forking or touching an agent;
  ordinary `ssh-add` uses the normal manual read flow. No Network Extension,
  BPF, agent-socket hardlink, or network-correlation logic was added.
- Added metadata-only audit codes for confirmation required, allowed, blocked,
  and timed out, with matching GTK rendering.
- Added a real ephemeral Ed25519 metadata fixture, a process-tree probe, a
  signed-XPC self-approval adversarial test, and a deterministic provisioned-
  host acceptance script.

## Principal files

- macOS policy/control: `apps/guard-es/src/policy.rs`,
  `apps/guard-es/src/service.rs`
- Resource/config boundary: `crates/platform-macos/src/resource_index.rs`,
  `crates/platform-macos/src/config.rs`,
  `crates/platform-macos/src/endpoint_security.rs`
- Portable runtime/domain: `crates/guard-runtime/src/lib.rs`,
  `crates/guard-core/src/policy.rs`, `crates/guard-audit/src/lib.rs`
- Client/UI/CLI: `crates/guard-client/src/macos.rs`,
  `apps/guard-ui/src/main.rs`, `apps/guardctl/src/main.rs`
- Probes/acceptance: `apps/guard-test-probe/src/main.rs`,
  `native/macos/xpc_wrong_signed_probe.m`,
  `scripts/macos/test-ephemeral-ssh-key.sh`,
  `scripts/macos/run-ssh-policy-acceptance.sh`
- Documentation: `docs/MACOS_SSH_PROTECTION.md`,
  `docs/INSTALL_MACOS_DEV.md`, `README.md`

## Commands run

```text
cargo fmt --all -- --check

MACOSX_DEPLOYMENT_TARGET=13.0 cargo clippy \
  -p guard-core -p guard-browser -p guard-ssh -p guard-ipc \
  -p guard-client -p guard-audit -p guard-platform -p guard-runtime \
  -p guard-test-fixtures -p platform-macos -p guard-ui -p guard-es \
  -p guardctl -p guard-notify -p guard-test-probe \
  --all-targets --all-features -- -D warnings

MACOSX_DEPLOYMENT_TARGET=13.0 cargo clippy \
  -p guard-es --all-targets -- -D warnings

MACOSX_DEPLOYMENT_TARGET=13.0 cargo test -q \
  -p guard-core -p guard-browser -p guard-ssh -p guard-ipc \
  -p guard-client -p guard-audit -p guard-platform -p guard-runtime \
  -p guard-test-fixtures -p platform-macos -p guard-ui -p guard-es \
  -p guardctl -p guard-notify -p guard-test-probe \
  --all-targets --all-features

MACOSX_DEPLOYMENT_TARGET=13.0 cargo build -p guard-es
MACOSX_DEPLOYMENT_TARGET=13.0 cargo build --release \
  -p platform-macos -p guard-client -p guard-ui -p guard-es \
  -p guardctl -p guard-notify -p guard-test-probe --all-features

xcrun clang -fsyntax-only -fobjc-arc -fblocks -fmodules \
  -Wall -Wextra -Werror -mmacosx-version-min=13.0 -Inative/macos \
  native/macos/system_extension_bridge.m \
  native/macos/code_signature_bridge.m native/macos/xpc_bridge.m \
  native/macos/local_auth_bridge.m native/macos/user_agent_bridge.m \
  native/macos/xpc_wrong_signed_probe.m

xcrun clang -fsyntax-only -fblocks -Wall -Wextra -Werror \
  -mmacosx-version-min=13.0 -Inative/macos \
  native/macos/endpoint_security_bridge.c

scripts/macos/test-ephemeral-ssh-key.sh target/debug/guardctl
target/debug/guardctl ssh load /synthetic/never-open-this
tests/check_platform_boundaries.sh
tests/check_macos_boundaries.sh
sh -n scripts/macos/*.sh
git diff --check

SIGNING_IDENTITY=<available Apple Development identity> \
DEVELOPMENT_TEAM=<signing Team ID> scripts/macos/build-dev-app.sh
scripts/macos/inspect-signing.sh
scripts/macos/test-xpc-auth.sh build/macos/Guard.app

scripts/macos/run-ssh-policy-acceptance.sh build/macos/Guard.app
```

## Test results

| Test | Result | Notes |
|---|---|---|
| Rust formatting | PASS | `cargo fmt --all -- --check` |
| macOS-host Clippy | PASS | Full selected portable/macOS/app/probe set; warnings denied |
| Rust unit/integration tests | PASS | 190 passed, 0 failed; synthetic/ephemeral fixtures only |
| Default extension build | PASS | Real service path compiled without `es-poc` |
| Release build | PASS | macOS platform, app, extension, CLI, helper, and local probe |
| Native bridge strict compile | PASS | Objective-C and Endpoint Security C; warnings denied |
| Platform boundary checks | PASS | No macOS SSH network/BPF/Linux agent machinery |
| FREAD without lease | PASS | Creates a held typed SSH pending request in fake-ES policy tests |
| Cross-UID read/write-only | PASS | Immediate deny and no prompt |
| Block | PASS | Held permission receives zero flags before any read completes |
| Allow and exact response flags | PASS | LocalAuthentication client gate plus post-auth policy resolution tested |
| Reader revalidation | PASS | Stable process, UID, root liveness, configured key, owner, dev, and inode checked |
| Key replacement during prompt | PASS | Replacement causes post-auth deny and no lease |
| Ten-second root-bound lease | PASS | Exact key/UID/root, verified descendant, unrelated-root isolation |
| Process exit/revoke | PASS | Root exit revokes SSH read lease |
| Deadline/late Allow | PASS | Insufficient budget and expired resolution deny; no lease recreation |
| Pending join and pressure | PASS | Same root joins; different roots separate; ninth pending request denied |
| Write-only policy | PASS | Same-UID `FWRITE` allowed; combined `FREAD|FWRITE` still prompts |
| Enrollment name/owner rules | PASS | `.pub`, reserved names, and wrong owner rejected without key reads |
| Real ephemeral key metadata test | PASS | New Ed25519 fixture suggested; public/reserved files excluded; fixture removed |
| `guardctl ssh load` on macOS | PASS | Clear unsupported error before path access, fork, or agent handling |
| Typed audit/privacy | PASS | Required codes emitted; synthetic key contents absent |
| Signed authenticated XPC path | PASS | Signed Guard UI/CLI/helper reached temporary service |
| Unsigned/same-Team self-approval | PASS | Both direct SSH Allow attempts rejected before handler response |
| Development bundle/signing | PASS | App, extension, CLI, and helper satisfy designated requirements |
| Live kernel-mediated Block | BLOCKED | Activated Apple-provisioned ES extension/FDA unavailable |
| Live kernel-mediated Allow/ssh-add | BLOCKED | Same external gate; no claim that real bytes were mediated on this host |
| Live `guardctl ssh protect` persistence | BLOCKED | Requires the activated privileged extension control path |
| Linux build/test | NOT RUN | Explicitly excluded by user |
| Docker | NOT STARTED | Explicitly excluded by user |

## Live Endpoint Security blocker

The deterministic live acceptance stopped before generating or enrolling its
ephemeral key and returned status 77:

```text
BLOCKED: signed guardctl cannot reach the activated extension
guardctl: connecting to guardd IPC socket /run/guardd/guardd.sock: authenticated XPC request failed: Couldn’t communicate with a helper application.
```

The missing Apple-provisioned, installed, activated Endpoint Security extension
with Full Disk Access cannot be replaced by a password prompt. No global macOS
security control was weakened. `scripts/macos/run-ssh-policy-acceptance.sh`
contains the deterministic future procedure: create one mktemp Ed25519 key,
enroll it, exercise Block, Allow, descendant access, unrelated-process
re-prompt, and verify typed audit before requiring enrollment cleanup.

## Signed self-approval boundary

The signed XPC regression used a temporary entitlement-stripped copy of the
real extension executable so launchd could host the transport without claiming
live ES enforcement. An ad-hoc process and a same-Team but unlisted signing ID,
both under the same UID, directly sent:

```text
SshReadResolve { action: Allow }
```

Neither received any XPC response. Exact production signing requirements reject
the connection before the request handler; the held-read behavior itself is
covered by synthetic policy tests and remains part of the live-ES blocker.

## Security and privacy state

- No developer browser profile, cookie, password, session token, SSH private
  key, `~/.ssh`, or existing `SSH_AUTH_SOCK` was read or modified.
- The only real SSH key was a newly generated temporary Ed25519 fixture. It was
  used for filename/metadata discovery only and deleted with its mktemp tree.
- Phase 08 temporary fixture count was zero after tests.
- Audit rows carry canonical path and verified process/resource metadata only;
  no key bytes or fingerprints are computed or stored.
- `/Library/Application Support/Sensitive Data Firewall/config.json` remained
  absent after testing.
- No temporary launchd test job remained after signed XPC testing.
- No network exfiltration, Network Extension, BPF, or traffic-correlation test
  was created or run.
- No SIP, Secure Boot, or other global control was weakened.

## Next phase readiness

READY for Phase 09. Browser and SSH resources now share one live Endpoint
Security authorization service while retaining distinct policy, pending,
FFLAGS, lease, audit, and UI semantics. Namespace/topology and health reporting
can build on the exact configured-path/inode index and the existing fail-closed
backend health boundary.
