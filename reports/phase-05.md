# Phase 05 — Browser Discovery and Protected Resource Registry

## Implemented behavior

`guard-browser` now discovers browser profiles and turns them into concrete
`ProtectedResource`s, and a `ProtectedResourceRegistry` answers the hot-path
"is this path protected?" question.

Modules under `crates/guard-browser/src/`:

- `registry.rs` — `ProtectedResourceRegistry` + `TreeRoot`.
- `chromium.rs` — Chromium-family discovery + pure `classify_profile_relative`.
- `firefox.rs` — Firefox/Zen discovery + pure `classify_profile_relative`.
- `lib.rs` — `CustomProfile` config enrollment that drives discovery by
  explicit `BrowserId` + `BrowserFamily` (no trust from path names).

Resource classification:

Chromium-family (per `user_data_dir` / profile):
- `Local State` => `BrowserKeyMaterial` (os_crypt encrypted_key), profile id `(local-state)`
- `Network/Cookies`, `Network/Cookies-wal`, `Network/Cookies-shm` => `CookieStore`
- legacy profile-relative `Cookies*` => `CookieStore`
- `Login Data*`, `Web Data*` (incl. `-journal`) => `SavedCredentials`
- `Sessions/`, `Session Storage/` => `SessionStore` (tree)
- `Local Storage/`, `IndexedDB/` => `WebStorage` (tree)

Firefox (per profile dir):
- `cookies.sqlite`, `cookies.sqlite-wal`, `cookies.sqlite-shm` => `CookieStore`
- `logins.json` => `SavedCredentials`
- `key4.db` => `BrowserKeyMaterial` (NSS key DB)
- `sessionstore-backups/` => `SessionStore` (tree)
- `storage/` => `WebStorage` (tree)

Registry design:
- **Concrete critical files** are enrolled individually and matched by exact
  canonical path (file-identity-anchored protection for the highest-value
  targets).
- **Directory trees** are enrolled as `TreeRoot`s and matched by path prefix,
  so a file created inside a tree after discovery is still classified as
  protected without re-scanning on every open. The fanotify layer (Phase 06)
  marks these tree dirs recursively.
- `classify(path)` canonicalizes the path (best-effort), checks exact file
  match, then prefix-matches against tree roots, synthesizing a
  `ProtectedResource` for tree descendants.

Custom profile enrollment: `CustomProfile { browser, family, root, owner_uid }`
+ `enroll_into(&mut registry)` lets the user enroll non-standard locations
from config. The `BrowserId`/`family` come from config, never inferred from the
path — so a path named "Chrome" grants no trust by itself.

Multi-profile support: Chromium discovery enumerates profile subdirs of the
user-data-dir (detected via `Network/Cookies` / `Cookies` / `Preferences`);
Firefox discovery handles both single-profile-dir and `~/.mozilla/firefox/`
multi-profile roots. No hard-coded username or single profile.

## Exact commands run

```
cargo test -p guard-browser --no-fail-fast
cargo fmt
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
```

## Test results

`cargo test -p guard-browser` — 21 passed, 0 failed. All discovery tests use
only synthetic `guard-test-fixtures` profiles (harmless markers, no real
secrets, no network I/O).

| Test | Covers |
| --- | --- |
| `classify_cookie_sidecars` (chromium + firefox) | WAL/SHM sidecars => CookieStore |
| `classify_legacy_cookies` | profile-relative Cookies => CookieStore |
| `classify_local_state_key_material` | Local State => BrowserKeyMaterial |
| `classify_login_and_web_data_saved_credentials` | Login/Web Data => SavedCredentials |
| `classify_session_and_storage_trees` (chromium + firefox) | Sessions/storage => SessionStore/WebStorage trees |
| `classify_logins_and_keymaterial` (firefox) | logins.json/key4.db classification |
| `classify_unrelated_*` | unrelated paths => None |
| `discover_synthetic_chromium_profile` | multi-kind discovery on synthetic fixture |
| `discover_multiple_chromium_profiles` | Default + Profile 1 |
| `discover_synthetic_firefox_profile` | cookies+wal => 2 cookie resources, key material, trees |
| `discover_multiple_firefox_profiles` | profile-a + profile-b |
| `discover_does_not_touch_real_profiles` (chromium + firefox) | only reads supplied temp dir |
| `custom_chromium_profile_enrollment_works` | config enrollment + tree-descendant classification |
| `custom_firefox_profile_enrollment_works` | config enrollment |
| `classify_enrolled_file_returns_resource` / `classify_tree_descendant_synthesizes_resource` / `classify_unprotected_path_returns_none` | registry hot-path |

`cargo clippy --all-targets --all-features -- -D warnings` — clean.
`cargo fmt --check` — clean.

## Known limitations

- **fanotify recursive-mark race**: a file created under a tree dir between the
  directory mark and the per-file marks could, in principle, be missed by the
  event layer. Classification still works (prefix match), but an open event
  might not fire. This is addressed/document in Phase 06; an optional
  strict/broad-monitor benchmark mode is deferred (the prompt marks it
  optional). The registry does not silently claim race-free recursion.
- Discovery does not watch for newly created profiles at runtime; a rescan
  trigger (inotify on the profiles root or a manual `guardctl reload`) is left
  to Phase 06/07.
- `Local State` is enrolled with a synthetic profile id `(local-state)`; a
  cross-browser migration lease scoped to it would need `source_profile =
  (local-state)`.
- Firefox `key4.db` is treated as `BrowserKeyMaterial` (NSS key DB); `key3.db`
  (legacy) is not classified (obsolete format).
- No real developer profile is ever opened by tests; all tests use
  `guard-test-fixtures` synthetic profiles.

## Security assumptions

- Protection is anchored to canonical paths (concrete files) and protected
  directory prefixes (trees). A path is protected iff it matches an enrolled
  file or falls under an enrolled tree.
- `BrowserId`/`family` are config-supplied; discovery never trusts a path name.
  "Custom Chrome path" enrollment does not grant any trust to processes — it
  only registers which files are protected. Process trust is resolved
  separately by the Phase 04 identity layer.
- `owner_uid` is supplied per enrollment (the profile owner); the policy uses
  it to reject cross-user access.
