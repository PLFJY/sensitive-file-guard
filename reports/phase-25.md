# Phase 25 — Coalesced browser-import authorization

## Outcome

Edge can start several short-lived importer utility processes for one browser
data import. The daemon now treats one successful human confirmation as a
60-second, memory-only coalescing grant for sibling processes only when all of
these daemon-verified facts match: UID, source browser/profile, target browser,
and target executable path/device/inode.

Every sibling is revalidated and receives its own root-bound lease before its
fanotify permission is allowed. No polkit `*_keep` setting, disk state, global
process whitelist, or executable-wide lease is introduced. The GTK UI also
shows one dialog for the same import-session tuple.

## Validation

```text
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --workspace
```
