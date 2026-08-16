# MPS12 — Safari Integration + Final macOS Process Shield Acceptance

## Status

PASS — final regression green; Safari observed working under the active
Process Shield extension; real-host evidence collected for the full
prevention -> compromise-state -> compatibility chain.

## Repository

- HEAD: bc26dd03b8fb9e7d6540b4569f2ee256d4f743a3 (working tree changes only)

## Safari approach (metadata only)

- Safari is NOT enrolled in the current macOS browser trust config (browsers:
  Chrome + Firefox). Its profile is not a protected resource, so File Shield
  does not intercept it and Process Shield does not admit its processes as
  shielded targets.
- Observed: Safari + WebKit helpers (com.apple.WebKit.GPU, Networking, etc.)
  launch and run with the extension active; `SAFARI_ALIVE_AFTER_PAGE_LOAD`
  PASS; task counters showed denied=0/admitted=0/compromised=0 during the
  Safari run (no interception, no deny storm).
- Because Safari targets are not shielded, no Safari-specific task-access
  rules are needed; the harness's "add narrow signing/role rules only after
  metadata observation" step concludes with "none required for the current
  enrollment". No real Safari cookies/history/session contents were read.

## Final regression (real host)

```text
cargo fmt --all -- --check                                    PASS
cargo clippy --workspace --all-targets --all-features -D warnings PASS
cargo test --workspace --all-features                        PASS
git diff --check                                             PASS (below)
```

Live evidence (MPS9 + MPS11 + MPS12):
- synthetic task control/read denied; canary not recovered; DYLD injection
  denied; controlled compromise -> File Shield deny        (MPS9, PASS)
- Chrome/Firefox disposable compatibility (7 cases)          (MPS11, PASS)
- untrusted same-user probe recheck after exceptions         (MPS11, PASS)
- Safari under active extension                              (MPS12, PASS)
- AUTH_MMAP remains disabled (MPS10 decision)

## Final security claims

```text
PREVENTED (authorization denies before capability/exec):
  - same-user untrusted task control/read against shielded targets
  - DYLD code-loading launch injection into shielded targets
DETECTED + CONTAINED (notify-only):
  - remote-thread creation / code-signing invalidation -> Compromised
  - task-capability + TRACE notifies -> metadata telemetry (never PREVENTED)
  - compromise -> File Shield deny + lease revocation
```

The final acceptance sentence is NOT written: per the harness, it may only be
written when prevention, compromise-state integration AND disposable-browser
compatibility all pass on a real host with the production (non-POC) extension
active. This run used the production build (service mode) but the permanent
system-extension activation still requires one human approval in System
Settings (the approval record churned during the repeated activation cycles).
The deterministic step is: open System Settings > General > Login Items &
Extensions > Endpoint Security Extensions > approve Guard Endpoint Security
once, or run `/Applications/Guard.app/Contents/MacOS/Guard
--activate-system-extension`. After approval, the machine keeps the Process
Shield build active.

## Remaining non-goals (documented)

- malicious browser extensions;
- browser-internal renderer/JIT RCE;
- root/kernel compromise;
- DevTools/remote-debugging paths not covered by the implemented ES policy;
- generic malware classification (deterministic policy only).

## Blockers

One human step: permanent system-extension approval (user must click Allow in
System Settings once). Everything else passed on this host.
