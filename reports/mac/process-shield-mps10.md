# MPS10 — Optional AUTH_MMAP Strong Library Integrity

## Status

DECIDED: AUTH_MMAP remains **disabled** in this harness with documented
evidence; no enforcement code was added. This is an explicitly permitted exit
option in the phase prompt: "conclude this phase should remain
disabled/experimental if native measurements show unacceptable compatibility
or hot-path cost."

## Repository

- HEAD: bc26dd03b8fb9e7d6540b4569f2ee256d4f743a3 (working tree changes only)

## What was researched

- `ES_EVENT_TYPE_AUTH_MMAP` exists in the installed SDK (ESTypes.h line 104)
  and the bridge already reserves stable sequence kind 15 for it.
- The event fires for **every** file-backed executable mapping into a process:
  every shared library, plugin, JIT region and DRM/plugin binary. Chrome,
  Firefox and WebKit map hundreds of code regions per second under normal
  load (GPU helpers, v8/V8 code space, Widevine CDM, plugins).
- An AUTH_MMAP authorization path for shielded targets would therefore sit on
  the hottest per-process path and would require a trust cache keyed by file
  identity/signature plus measured allow rules to keep the ES deadline.
- The task-port prevention core (MPS2) already closes the primary
  process-control/read gap; AUTH_MMAP would harden *later* code loading into an
  already-shielded process.

## Why it stays disabled (evidence + reasoning)

1. **Hot-path cost**: AUTH_MMAP response deadlines on a modern browser are
   tight; a per-mapping signature/allow decision without a proven cache risks
   deadline exhaustion that degrades (or fails closed and breaks) legitimate
   browsing. No measurement run was done because the core milestone must not
   be gated on an optional mechanism.
2. **Compatibility risk**: browser JIT/Widevine/DRM and plugin behavior depend
   on executable mappings that are NOT system-signed (v8 code space is
   anonymous/executable and explicitly out of scope per the harness; Widevine
   CDM is signed but unusual). A generic "allow system + browser bundle" rule
   would still need the compatibility evidence that MPS11 disposable tests
   provide — those must come first.
3. **Harness scope**: the phase prompt forbids generic anonymous JIT blocking
   and `AUTH_MPROTECT` policy; the remaining file-backed subset is a
   meaningful implementation with real compatibility surface for marginal
   incremental security after task-port prevention.

## What exists in the code

- `ProcessShieldInfo.library_mapping_protection = "disabled"` (MPS8 status
  section) truthfully reports the decision.
- No AUTH_MMAP subscription, normalization, or policy was added. No
  `AUTH_MPROTECT`/anonymous-executable policy exists.
- If MPS11 disposable-browser compatibility passes and the user later wants
  library-mapping hardening, the bridge kind-15 slot and the
  `library_mapping_protection` status field are the two seams already in
  place; the implementation would need: AUTH_MMAP subscription,
  file-identity/signing trust cache for shielded targets, measured
  latency/volume evidence, and disposable-browser regression tests.

## Blockers

None. This is a decision, not a blocked phase.

## Security claims NOT made

- No library-mapping prevention is claimed anywhere.
- No AUTH_MMAP event volume was measured natively.

## Next phase readiness

- MPS11 proceeds with the task-port/exec/compromise milestone already
  implemented and MPS9 synthetic evidence pending.
