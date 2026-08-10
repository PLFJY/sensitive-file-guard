# Phase 20 — Linux Deployment, Browser Portability, and AUR Packaging

## Decision

Linux V1 remains **SECURITY-ACCEPTED ALPHA ON THE TESTED ARCH HOST only in
`strict-filesystem` mode**. This phase makes source deployment and Arch
packaging reviewable; it does not extend privileged security acceptance to
Debian, Ubuntu, Fedora, Snap, or Flatpak.

## Implemented

- Added `docs/INSTALL_LINUX.md` and linked it from the concise README install
  section. It documents systemd, fanotify, `/proc`, root/CAP_SYS_ADMIN,
  polkit/`pkcheck`, user D-Bus, `notify-send`, build/runtime dependencies,
  lifecycle commands, health checks, troubleshooting, and tested/expected/
  experimental/unsupported status.
- Changed the example configuration to an intentionally empty
  `strict-filesystem` template. It has no UID 1000, `REPLACE_USER`, profile,
  or guessed SSH-key path. Missing inferred profile ownership is now a startup
  error instead of silently becoming UID 0.
- Added `guardctl browser discover [--home PATH]`. It only emits existing
  profile roots and canonical, executable native candidates; it edits nothing
  and grants no trust. Native Firefox and Debian-style Firefox ESR are separate
  Firefox-family configuration entries. Focused tests cover ESR representation,
  fake `firefox` rejection, and sandbox reporting.
- Removed the dormant basename browser classifier from the Linux identity
  module. Runtime browser matching remains configured canonical `/proc/<pid>/exe`
  identity plus device/inode and policy trust tier.
- Declared Snap and Flatpak browser forms unsupported for the Alpha path. Their
  namespace identity and filesystem-mark visibility have not been security-
  accepted; they are reported, not enrolled.
- Reworked source installation: an unprivileged `cargo build --release`
  precedes root installation; the installer installs all four production
  binaries, preserves config, and does not enable/start guardd. Root deployment
  tests now require prebuilt artifacts rather than compiling into root's Cargo
  home.
- Kept one service template with install-time absolute-path substitution:
  source installs render `/usr/local/bin`; packages render `/usr/bin`. The
  capability and hardening directives are not duplicated or weakened.
- Added `packaging/aur/` with VCS `PKGBUILD`, generated `.SRCINFO`, packaging
  `.gitignore`, and `sysusers.d` group definition. Added MIT and Apache-2.0
  license texts at repository root.

## Deployment and browser decisions

| Form | Decision |
| --- | --- |
| Native Arch Firefox / Chromium / Chrome | Expected configuration support; Arch strict mode remains the only accepted evidence. |
| Debian Firefox ESR | Represented by explicit Firefox-family profile root and canonical ESR executable; no package-name special case. |
| Debian, Ubuntu, Fedora native browsers | Expected to work with emitted/reviewed canonical paths; not privilege-tested in this phase. |
| Brave, Edge, Vivaldi, custom builds | Retained through explicit `exe_paths`; common native locations are suggested when present. |
| Snap / Flatpak | Unsupported for the security-accepted Alpha path; no process, package, or application-ID trust. |

The native executable table is in `docs/INSTALL_LINUX.md`. `/usr/bin/firefox`
and `/usr/bin/firefox-esr` are deliberately not treated as sufficient evidence:
they can be wrappers. Operators configure the canonical final executable
observed by `/proc/<pid>/exe`.

## AUR package

No upstream tag exists (`git tag --sort=-v:refname` produced no release tag),
so this is `sensitive-file-guard-git` with:

```sh
pkgver() {
  printf '%s.r%s.g%s' VERSION COMMIT_COUNT SHORT_HASH
}
```

Dependencies are `glibc`, `libgcc`, `polkit`, and `systemd`; `libnotify` and `openssh`
are correctly optional because `guard-notify` invokes `notify-send` and the SSH
agent workflow is optional. `rusqlite` remains bundled, so no system SQLite
dependency was added. Build dependencies are `cargo`, `git`, and `rust`.

The package installs:

```text
/usr/bin/{guardd,guardctl,guard-tui,guard-notify}
/usr/lib/systemd/system/guardd.service
/usr/lib/systemd/user/guard-notify.service
/usr/lib/sysusers.d/sensitive-file-guard.conf
/usr/share/polkit-1/actions/org.guardd.policy
/usr/share/guardd/guardd-config.example.json
/usr/share/doc/sensitive-file-guard/{README,INSTALL_LINUX,SECURITY_MODEL}.md
/usr/share/licenses/sensitive-file-guard-git/{LICENSE-MIT,LICENSE-APACHE}
```

It intentionally does not package `guard-test-probe`, an active `/etc` config,
or an enable/start action. `systemd-sysusers` creates only `guardd-users`; it
does not guess a desktop account. The documented post-install action is:

```sh
sudo usermod -aG guardd-users "$USER"
# log out/in, copy and edit the example deliberately
sudo systemctl enable --now guardd
systemctl --user enable --now guard-notify
```

## Validation

| Check | Result |
| --- | --- |
| `makepkg --printsrcinfo > .SRCINFO` | PASS; checked-in `.SRCINFO` regenerated from PKGBUILD. |
| `namcap PKGBUILD` | PASS (no output / zero exit). |
| `bash -n deploy/install.sh scripts/test-systemd-root.sh scripts/test-strict-filesystem-root.sh` | PASS. |
| Staged `package()` file-list and forbidden-content inspection | PASS; exactly the listed production assets, with no `target/`, fixtures, secrets, audit DB, caches, or `/home/plfjy` path. |
| Clean `makepkg -C -f --noconfirm` archive | PASS; built `sensitive-file-guard-git-0.1.0.r6.g2425da7-1-x86_64.pkg.tar.zst` from the fetched VCS source. |
| `namcap` on the generated archive | PASS with two reviewed warnings: it cannot infer that `polkit` and `systemd` are required by the packaged policy and units. Both remain deliberate runtime dependencies. |
| Generated archive file-list and forbidden-content inspection | PASS; only the four production binaries and declared service, policy, example, documentation, and license assets. No build tree, fixtures, audit DB, cache, developer path, real browser path, or SSH path. |
| Install generated package with `sudo` | BLOCKED; `sudo -n true` returned `sudo: a password is required`, so no system package installation was attempted. |

The package build command is:

```sh
cargo build --frozen --release --workspace --exclude guard-test-probe
```

Arch's package-wide GCC LTO conflicts with the bundled static SQLite archive
when Rust performs the final `rust-lld` link. The PKGBUILD therefore uses
`options=('!lto')`; makepkg hardening flags remain in effect. This is a build
compatibility setting, not a runtime security exception.

## Rust quality gates

```text
cargo fmt --check                                           PASS
cargo clippy --workspace --all-targets --all-features
  -- -D warnings                                            PASS
cargo test --workspace --all-features                       PASS (203 tests)
cargo build --release                                       PASS
```

`shellcheck` was not installed, so it was not run.

## Privileged deployment/security reruns

All fixtures selected by these scripts are synthetic. The final environment
did not permit a polkit elevation. The exact observed failure was:

```text
$ pkexec env PATH="$PATH" ENFORCEMENT_MODE=strict-filesystem \
    bash scripts/test-browser-adversarial-root.sh
Error executing command as another user: Not authorized
```

The same unavailable privilege boundary prevents an evidence-backed rerun of
`test-systemd-root.sh`, `test-installed-auth-root.sh`, and
`test-strict-filesystem-root.sh`; all are **BLOCKED**, not PASS. Phase 19.1's
existing Arch strict evidence remains the accepted baseline and was not
regressed by non-privileged Rust tests.

## Files changed

`README.md`, `docs/INSTALL_LINUX.md`, `docs/SECURITY_MODEL.md`,
`deploy/install.sh`, both service templates, the config example,
`deploy/guardd-users.sysusers`, `apps/guardctl/src/main.rs`,
`apps/guardd/src/enforce.rs`, `crates/platform-linux/src/identity.rs`, the two
root-test scripts, `LICENSE-MIT`, `LICENSE-APACHE`, and `packaging/aur/`.

## Remaining limitations

1. Only the tested Arch host has strict privileged acceptance evidence.
2. Snap/Flatpak identity and mark visibility are unsupported, not inferred.
3. Strict filesystem performance and fanotify's documented fail-open/crash,
   pre-open descriptor, rename-only, queue-overflow, and root-compromise
   boundaries remain unchanged from Phase 19/19.1.
4. AUR publication and any privileged package installation remain human actions.

## Post-validation deployment follow-up: explicit setup CLI

An attempted post-package activation exposed that an enabled unit with no
`/etc/guardd/config.json` exited before creating its IPC socket. This was not a
browser identity bypass: no fanotify enforcement was running. The follow-up
adds `guardctl setup` to turn the previously manual configuration step into a
safe explicit initialization flow.

- `sudo guardctl setup --home "$HOME"` requires an explicit selected home when
  running as root, discovers only native profile/final-executable pairs, prints
  the proposed configuration, asks for confirmation (or requires explicit
  `--yes`), and writes a new mode-`0600` config without overwriting an existing
  one.
- It emits `strict-filesystem`, omits `owner_uid` for daemon-side statting, and
  deliberately leaves `ssh_keys` empty. It refuses an empty native discovery
  result and reports sandboxed candidates without enrolling them.
- `guardd.service` now has `ConditionPathExists=/etc/guardd/config.json`, so a
  machine missing deliberate configuration does not enter a misleading restart
  loop. Setup does not enable or start the daemon.
- Source installation now installs only a non-active example under
  `/usr/local/share/guardd`; it no longer creates an empty active config that
  would block setup or create a false impression of coverage.

Focused non-privileged validation passed: 15 `guardctl` tests, including setup
creation/no-overwrite/empty-discovery/deduplication cases; a synthetic-profile
CLI run produced strict JSON with one canonical executable, no UID/SSH guess,
and a new mode-`0750` config directory containing a mode-`0600` file.
`systemd-analyze verify` passed for the rendered unit. The full workspace
`cargo fmt --check`, clippy with `-D warnings`, all-feature test suite,
release build, shell syntax checks, and `git diff --check` also passed.

This follow-up was not in the original
`sensitive-file-guard-git-0.1.0.r6.g2425da7-1` validation archive. Rebuild and
install from a commit containing it before invoking the installed `guardctl
setup`.

## Post-validation security correction: legacy Firefox WebStorage

Static review of the user-supplied open-source `HackBrowserData` source showed
that its Firefox local-storage extractor reads the legacy per-profile
`webappsstore.sqlite` database. The installed classifier protected the modern
`storage/` tree but did not classify this legacy database or its SQLite
sidecars. This was a real protected-scope omission.

The correction classifies `webappsstore.sqlite` plus its WAL, SHM, and rollback
journal sidecars as `WebStorage` in both browser discovery and the Strict
structural classifier. Synthetic fixture coverage and focused unit tests verify
discovery and root/nested strict classification. No real profile data or
extracted output was read during the investigation.

Audit evidence independently confirmed that the extractor process itself was
not trusted by name or package: its reads of Firefox `logins.json`,
`cookies.sqlite`, and `key4.db` were denied as `UnknownProcess`. Browser
history/bookmarks are outside this firewall's secret-resource scope; legacy
WebStorage is not, and is now covered by this correction.

The currently installed AUR package predates this correction. A privileged
deployment/Strict regression using only synthetic fixtures remains required
after rebuilding a package from a commit containing it; it is **BLOCKED** in
this environment because privileged execution is unavailable.

## Post-validation deployment correction: desktop notifications

Investigation of an installed package found `guard-notify` disabled and its
older runs unable to connect to the daemon socket before the user's
supplementary group refreshed. After enabling it in the refreshed user session,
the daemon IPC connection succeeded, but `notify-send` failed with `Permission
denied` despite a working direct desktop notification and user D-Bus session.

The cause was `ProtectHome=true` in the user unit. Transient user-unit probes
isolated that setting: `PrivateTmp=true` and `ProtectSystem=strict` succeeded;
`ProtectHome=true` alone made `notify-send` fail; and
`ProtectHome=read-only` succeeded with all normal notifier sandbox properties.
The packaged unit now uses the read-only setting. A user-level compatibility
drop-in was installed for the already-installed package, then `guard-notify`
was enabled/restarted and confirmed `active` with `ProtectHome=read-only`.
The matching sandboxed `notify-send` probe exited successfully. No real
protected file was opened merely to generate a notification test event.
