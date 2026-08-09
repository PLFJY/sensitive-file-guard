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

Dependencies are `glibc`, `polkit`, and `systemd`; `libnotify` and `openssh`
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
| Clean `makepkg -f --noconfirm` archive | BLOCKED. The VCS source is the public remote's last commit, which cannot include this uncommitted Phase 20 work. The initial attempted build also exposed a local makepkg-injected `rust-lld` flag that omitted bundled SQLite symbols; PKGBUILD now clears those user-local Rust flags and the exact frozen build command passed against the fetched source. No package archive or `namcap`-on-archive result is claimed. |

The package build command is:

```sh
env -u CARGO_ENCODED_RUSTFLAGS -u RUSTFLAGS \
  cargo build --frozen --release --workspace --exclude guard-test-probe
```

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
4. A clean AUR archive must be rerun after these files are committed to the
   upstream VCS source used by `makepkg`; publication remains a human action.
