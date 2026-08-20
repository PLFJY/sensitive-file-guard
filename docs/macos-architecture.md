# macOS backend architecture review

Status: architecture review, not a new macOS acceptance claim. Linux
fanotify/BPF mechanisms and Linux freeze evidence are not reused as macOS
proof.

## Product boundary

The macOS product should keep the existing four layers:

1. `guard-core`: deterministic policy decisions, protected-resource types,
   leases, exact process identity facts, and secret-free audit records.
2. `guard-runtime`: bounded pending authorization lifecycle and one terminal
   response per request.
3. `guard-platform`: portable contracts for file authorization, process facts,
   health, configuration, and service control.
4. `platform-macos` plus `guard-es`: Endpoint Security, audit tokens, code
   signing, TCC/system-extension lifecycle, authenticated XPC, and Apple-specific
   process-control hooks.

The macOS adapter must translate native facts into portable inputs; portable
crates must not import Endpoint Security types. Linux fanotify marks, inode
handle indexes, BPF maps, pidfds, systemd, and polkit have no macOS analogue in
the portable model.

## File Shield

Use `ES_EVENT_TYPE_AUTH_OPEN` as the pre-open authorization boundary. Apple
defines it as an operating-system request for permission to open a file, and
the event exposes the target plus requested open flags. Respond with the
minimal allowed flags; an unrelated resource is immediately allowed, while a
protected resource requires full process and resource identity.

The callback path must remain bounded:

- copy only required message facts while the ES message is valid;
- compute deterministic allow/deny immediately;
- never wait for UI on the callback thread;
- retain an opaque authorization only for the existing typed migration/SSH
  confirmation flow and only within the message deadline;
- deadline exhaustion, dropped sequence, identity change, queue pressure, or
  missing facts fail closed for protected resources;
- do not cache responses for path- or instance-sensitive decisions.

Apple documents that missed authorization deadlines can terminate/restart the
client and repeated misses can prevent future ES connections. `seq_num` and
`global_seq_num` therefore feed separate continuity health; a gap is not an
assumed deny.

## Process identity and admission

The primary process key is the ES `audit_token` plus start time and executable
file identity. Authorization also validates Team ID, signing ID, CDHash/code
signing flags, executable path, responsible/parent audit tokens, and role.
`es_process_t` signing fields describe kernel-observed state at event time, but
Apple explicitly notes that Endpoint Security itself does not fully validate
all executable pages. For high-value enrollment, use Security.framework dynamic
validation (`SecCodeCheckValidity`) against an explicit requirement; do not trust
name, bundle ID, Team ID, or path alone.

Browser identity remains separate from SecretAuthority. An exact process may be
admitted only after an allowed AUTH_OPEN for a classified authentication-state
resource. Admission records contain identity metadata and resource kind, never
secret bytes. Exit, exec, code-signing invalidation, sequence loss, and policy
generation changes revoke the admission.

## Process Shield scope

Subscribe only to authorization/notification events that have a demonstrated
product reason. Candidate boundaries include AUTH/NOTIFY process checks,
signals, suspend/resume, trace, and code-signing invalidation. Each primitive
must have its own OFF-success/ON-denial oracle; notification-only events remain
DETECTED, never PREVENTED. No broad “browser may control browser” rule is
acceptable.

Root/kernel compromise, already-open file descriptors, attacks completed before
first SecretAuthority admission, and interfaces not represented by the accepted
ES event set remain out of scope. This is an access firewall, not a complete
EDR.

## TCC and system-extension lifecycle

Package the Endpoint Security implementation as a system extension inside the
signed host app and manage install/update through SystemExtensions.framework.
Apple requires the Endpoint Security client entitlement; client creation must
distinguish missing entitlement, insufficient privilege, TCC denial, too many
clients, and internal failure. Activation approval alone is not ACTIVE: health
also requires a live ES client, subscribed event set, authenticated XPC, loaded
policy, and intact sequence/deadline state.

TCC is an external prerequisite, not something the product bypasses or edits.
Consumer installs guide the user through Privacy & Security approval. Managed
deployments may use PPPC, bound to the exact bundle/path identifier and code
requirement; Apple states that conflicting PPPC payloads resolve to the more
restrictive setting. Missing Full Disk Access/TCC approval is DISABLED or
UNSUPPORTED with an exact reason, never a silent fallback.

## Signing and distribution

- Sign the host, system extension, CLI/helper, and notification component with
  distinct stable identifiers and the minimum entitlements.
- Host app alone carries `com.apple.developer.system-extension.install`; the ES
  extension alone carries `com.apple.developer.endpoint-security.client`.
- Enable Hardened Runtime and avoid runtime exception entitlements unless a
  measured requirement exists. Shipping artifacts must not contain
  `get-task-allow`.
- Validate nested code, use Developer ID signatures and secure timestamps,
  notarize with `notarytool`, staple the ticket, and verify with `codesign`,
  `spctl`, and `systemextensionsctl` before release.
- Enrollment pins a designated requirement and validates the running code; a
  version update may retain trust only when it still satisfies that requirement
  and all role/path constraints.

## Acceptance sequence

1. Synthetic AUTH_OPEN deny/allow-before-open oracle and deadline/sequence-loss
   tests.
2. Authenticated XPC same-UID adversarial matrix and config-generation rollback.
3. Disposable Safari/Firefox/Chromium-family profile classification; accept
   only installed and separately evidenced families.
4. Exact SecretAuthority admission and process-control primitive matrix.
5. TCC denied/approved, system-extension install/update/remove, daemon/client
   restart, sleep/wake, logout/login, and OS update recovery.
6. Signed/notarized release verification, performance, and a fresh cross-layer
   suite with no mandatory BLOCKED result.

## Apple references

- [Endpoint Security overview](https://developer.apple.com/documentation/endpointsecurity)
- [Endpoint Security client lifecycle](https://developer.apple.com/documentation/endpointsecurity/client)
- [AUTH_OPEN](https://developer.apple.com/documentation/endpointsecurity/es_event_type_auth_open)
- [Authorization message deadlines](https://developer.apple.com/documentation/endpointsecurity/es_message_t/deadline)
- [Endpoint Security process identity and signing fields](https://developer.apple.com/documentation/endpointsecurity/es_process_t)
- [System Extensions](https://developer.apple.com/documentation/systemextensions)
- [Code Signing Services](https://developer.apple.com/documentation/security/code-signing-services)
- [Dynamic code validation](https://developer.apple.com/documentation/security/seccodecheckvalidity%28_%3A_%3A_%3A%29)
- [Hardened Runtime](https://developer.apple.com/documentation/security/hardened-runtime)
- [Notarizing macOS software](https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution)
- [Apple PPPC deployment reference](https://support.apple.com/guide/deployment/privacy-preferences-policy-control-payload-dep38df53c2a/web)
