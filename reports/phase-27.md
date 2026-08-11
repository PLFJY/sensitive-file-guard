# Phase 27 — unified authorization dialog lifecycle

## Delivered

- Added a GTK-free `PendingDialogController` with one active request, a FIFO
  queue, typed migration/SSH deduplication keys, and explicit choice,
  authorization, retry, and terminal states.
- Replaced refresh-owned `shown_migrations` / `shown_ssh_reads` sets with the
  controller. Successful daemon snapshots remove only requests that have not
  been displayed; an active request survives an empty or changing snapshot,
  including while Polkit authentication is running.
- Unified browser migration and SSH read dialog rendering and resolver flow.
  The two daemon APIs and their security policies remain distinct, while GTK
  lifecycle, retry, close-to-block, and queue handling are shared.
- Added pure state-machine tests for duplicate refreshes, single-dialog FIFO
  behavior, authorization persistence, retry, terminal handoff, snapshot
  expiry, and cross-kind deduplication.

## Verification

- `cargo fmt --check`
- `cargo test --workspace --no-fail-fast`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo build --release -p guard-ui -p guardd -p guardctl -p guard-notify`

All completed successfully.
