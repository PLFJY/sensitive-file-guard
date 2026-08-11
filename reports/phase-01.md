# Phase 01 — Repository Bootstrap

## Implemented behavior

Created the minimal maintainable Rust workspace for Linux V1 of Sensitive Data
Firewall.

### Workspace layout

```
Cargo.toml                      # workspace, resolver=2, workspace deps
.gitignore
AGENTS.md                       # KISS + security/testing constraints
README.md                       # V1 threat model + do-not-test-on-real-secrets warning
crates/
  guard-core/                   # logging foundation (tracing)
  guard-browser/                # placeholder (Phase 05)
  guard-ssh/                    # placeholder (Phase 10/11)
  guard-ipc/                    # placeholder (Phase 07)
  platform-linux/               # placeholder (Phase 02/04)
  guard-test-fixtures/          # synthetic fixture generators + tests
apps/
  guardd/                       # bootstrap stub (init_logging, status)
  guardctl/                     # bootstrap stub
tests/
  fixtures/                     # layout slot (fixtures are programmatic)
  integration/
    smoke.rs                    # cross-crate fixture smoke test
reports/
  phase-01.md                   # this file
```

### Toolchain
- Stable Rust (toolchain on host: rustc 1.97.0, cargo 1.97.0).
- No MSRV pinned yet (no measured reason). Edition 2021.
- Workspace dependency declarations in root `Cargo.toml`; crates use
  `dep.workspace = true`.
- No database. No GUI. No `unsafe`.

### Logging foundation
`guard-core::logging::init_logging()` initializes a `tracing_subscriber` with
`EnvFilter` (`RUST_LOG` honored; default `info` for guard crates). Idempotent —
safe to call multiple times (tests confirm this).

### Synthetic fixtures (`guard-test-fixtures`)
Generators create temp-rooted trees containing only harmless marker strings:

- `ChromiumProfile`: `Local State`, `*/Network/Cookies` + `Cookies-wal` +
  `Cookies-shm`, `Login Data`, `Web Data`, `Sessions/`, `Session Storage/`,
  `Local Storage/`, `IndexedDB/.../leveldb/`.
- `FirefoxProfile`: `cookies.sqlite` + `-wal`, `logins.json`, `key4.db`,
  `sessionstore-backups/`, `storage/default/`.
- `SshFixture`: isolated temp HOME with `.ssh/id_ed25519_fake` (0600, marker
  content — NOT a real key), `.pub`, `config`, `known_hosts`.
- `markers`: all marker constants + `contains_any_marker()` helper for audit
  redaction tests.

Fixtures never touch the developer's real browser profiles or real `~/.ssh`.
No fixture or test performs network I/O.

## Exact commands run

```sh
cargo --version            # cargo 1.97.0
rustc --version            # rustc 1.97.0
cargo build --all-targets  # OK
cargo fmt --check          # initially failed -> ran `cargo fmt` -> clean
cargo clippy --all-targets --all-features -- -D warnings   # OK, 0 warnings
cargo test --all           # 11 tests pass
```

## Test results

```
guard-core            unittests: 1 passed  (init_logging_is_idempotent)
guard-test-fixtures   unittests: 9 passed
  markers::tests::marker_detection_works
  chromium::tests::chromium_fixture_creates_expected_tree
  chromium::tests::chromium_fixture_cleans_up_on_drop
  chromium::tests::chromium_fixture_supports_custom_profile_name
  firefox::tests::firefox_fixture_creates_expected_tree
  firefox::tests::firefox_fixture_cleans_up_on_drop
  ssh::tests::ssh_fixture_creates_expected_tree
  ssh::tests::ssh_fixture_cleans_up_on_drop
  ssh::tests::ssh_private_key_has_restrictive_permissions
smoke (integration):  1 passed  (workspace_smoke_with_all_fixtures)
Total: 11 passed; 0 failed; 0 ignored
```

fmt: clean. clippy `-D warnings`: clean.

## Known limitations

- Binaries (`guardd`/`guardctl`) are bootstrap stubs only; no
  fanotify interception or IPC yet (Phase 02+).
- `crates/guard-browser`, `guard-ssh`, `guard-ipc`, `platform-linux` are
  placeholders with doc comments only.
- The `SshFixture` private key is a non-real marker file; Phase 10/11 tests
  needing a loadable key will generate an ephemeral keypair via `ssh-keygen`
  under an isolated `HOME`.
- `tests/integration/smoke.rs` is registered as a `[[test]]` target of the
  `guard-test-fixtures` crate (cargo does not auto-scan `tests/`
  subdirectories); this is noted in the crate's `Cargo.toml`.

## Security assumptions

- No real secrets are read, written, or logged by any test or fixture.
- All fixture content is identifiable marker ASCII; `contains_any_marker` will
  be used in later phases to assert audit logs contain no secret bytes.
- No test weakens system security; no test performs network exfiltration.

## Quality gate

- [x] workspace builds
- [x] fmt passes
- [x] clippy `-D warnings` passes
- [x] unit test proving fixture creation/cleanup passes
- [x] `reports/phase-01.md` written
