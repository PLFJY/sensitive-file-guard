# Linux browser expansion acceptance contract

Status: planning contract only. This document does not enroll a new browser or
expand the accepted Linux Platform Freeze scope. Firefox is the only currently
accepted family/installation; every other row remains **NOT ACCEPTED** until
all mandatory evidence below is fresh and complete.

## Per-browser contract

| Browser | Candidate native profile layout | Candidate secret sources to prove | Current state |
|---|---|---|---|
| Firefox | `~/.mozilla/firefox`, resolved through `profiles.ini`; native executable under `/usr/lib/firefox` or `/usr/lib64/firefox` | `cookies.sqlite` + sidecars, `logins.json`, `key4.db`, session restore, origin storage, `webappsstore.sqlite` | **ACCEPTED** for the already frozen native-host scope |
| Firefox ESR | distribution-specific `~/.mozilla/firefox-esr` and executable under `/usr/lib/firefox-esr` or `/usr/lib64/firefox-esr` | Same Gecko categories, but paths and process roles must be observed independently | **NOT ACCEPTED / NOT INSTALLED** |
| Chromium | `~/.config/chromium`, including each profile selected by `Local State` | profile Cookies + sidecars, Login Data, Web Data, Sessions, Local/Session Storage, IndexedDB, key material referenced by `Local State` | **NOT ACCEPTED** |
| Google Chrome | `~/.config/google-chrome`, independently discovered native `/opt/google/chrome/chrome` | Same Chromium categories, with Chrome-specific profile discovery and process graph evidence | **NOT ACCEPTED / NOT INSTALLED** |
| Zen | `~/.zen`; no assumption that every Firefox path/role is identical | Gecko-derived stores only after live layout observation, including Zen-specific profiles and helper roles | **NOT ACCEPTED / NOT INSTALLED** |

Snap, Flatpak, AppImage, network filesystems, and alternate vendor layouts are
separate targets. Native-package success cannot be reused as their evidence.

## Mandatory evidence for every row

1. **Profile discovery** — disposable home only; prove exact profile roots,
   multiple-profile handling, symlink/canonicalization behavior, and executable
   ownership/signature/package identity. Discovery is a suggestion, never an
   authorization decision.
2. **Secret classification** — enumerate the exact files and dynamic trees that
   contain authentication state. Prove SQLite sidecars, atomic replacement,
   rename-in/out, new subdirectories, and unrelated-file noninterference. No
   real profile or secret bytes may be inspected.
3. **File Shield oracle** — for each source, Guard OFF must recover a synthetic
   canary and Guard ON must deny an unknown same-UID reader before a readable fd
   exists, with exact requester/resource audit and zero canary recovery.
4. **Normal workload** — launch the installed browser against a disposable
   populated profile. Startup, browsing, login-fixture mutation, session save,
   clean shutdown, and restart must have zero unexplained denials and File
   Shield must remain ACTIVE or truthfully REDUCED for a documented host limit.
5. **SecretAuthority derivation** — authority comes only from a real allowed
   File Shield event for a classified secret source. Record PID plus start
   token, executable identity, role, ancestry, profile, and resource kind;
   never record secret contents. Browser identity alone is insufficient.
6. **Process Shield admission** — admit the exact live authority instance before
   releasing the triggering file authorization. PID-only, browser-wide, UID-wide,
   and process-tree-wide admission are forbidden.
7. **Process attack matrix** — every claimed primitive requires Guard OFF
   success, Guard ON denial, exact requester/target attribution, and zero
   canary recovery. A primitive that does not traverse the selected kernel hook
   stays NOT ACCEPTED.
8. **Lifecycle and productization** — PID reuse, executable update, browser
   update, daemon restart, config upgrade/downgrade, performance, human status,
   JSON status, and audit wording must pass fresh gates.

Acceptance is per browser family, packaging channel, executable role, and host
kernel capability. Passing Firefox never promotes Firefox ESR or Zen; passing
Chromium never promotes Chrome.
