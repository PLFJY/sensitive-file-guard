# Phase 19.1 — Strict Rename-Away Inode Promotion

## Decision

```text
SECURITY-ACCEPTED ALPHA ON TESTED ARCH HOST
```

This decision remains limited to explicit `strict-filesystem` mode and the V1
threat model. Conservative mode remains unaccepted because of its measured
replacement race. All fixtures in this pass were disposable and synthetic.
No real browser profile, credential, SSH key, or public network was used.
The reviewed base was commit `e6278994f6eee03a747b47f6ed9580e2fccd79fd`.

## Review finding

Phase 19 classified a new sensitive inode by structural path for the current
`FAN_OPEN_PERM` event but did not immediately add `(st_dev, st_ino)` to the
shared index. Before topology refresh, this sequence could allow the second
open:

```text
new Cookies inode
  -> first structural open ALLOW or DENY
  -> rename outside configured namespace
  -> nlink=1, unknown inode, unrelated fast allow
```

The external-hardlink repair did not cover this case because its synchronous
namespace search is intentionally limited to `st_nlink > 1`.

## Fix

`StrictClassifier::classify_fd` now inserts every structural path hit into the
inode index before returning `Protected`. The fanotify response therefore
cannot be sent before identity promotion. The same rule applies to an owning
browser ALLOW and an unauthorized DENY.

A focused unit test opens a new synthetic Cookies path, classifies it, renames
it outside the browser root, and proves the external descriptor still
classifies through the inode index.

## Privileged rename-away evidence

The root harness uses same-process sequences to avoid topology convergence
accidentally making the tests pass:

| Case | Sequence | Observed result |
| --- | --- | --- |
| A | enrolled browser moves staged inode to Cookies, opens once, immediately renames outside; unauthorized open | DENY, zero recovery |
| B | unauthorized first Cookies open denied, same process renames outside and immediately retries | DENY twice, zero recovery |
| C | inode renamed into Cookies and back outside without any open at the sensitive name | external open succeeded; open-only boundary observed |

Case C is not hidden as PASS. `FAN_OPEN_PERM` does not receive rename events
and cannot label an object based only on a pathname it formerly occupied. The
inode carried only the attacker's synthetic staging payload; no browser opened
or wrote it while sensitive. A browser using a descriptor opened before the
transit would fall under the already documented pre-open/inherited-fd non-goal.

The complete current suite result was:

```text
test-strict-filesystem-root.sh
PASS=25 FAIL=0 BLOCKED=0 OBSERVED=1

external-hardlink replacement:
iterations: 10000
successful unauthorized reads: 0
denied: 10000
other errors: 0
```

## Alias-scan amplification

Eight concurrent unauthorized workers opened an unrelated `st_nlink=2` file
2,000 times each on the marked filesystem. This deliberately forced at least
16,000 exceptional namespace scans.

```text
opens:               16000
wall time:           889 ms
fanotify overflows:  0
classifier failures: 0
audit drops:         0
```

This is bounded evidence on small synthetic namespaces, not a denial-of-service
guarantee for arbitrarily large profiles or hostile sustained load. The finite
fanotify queue and targeted firewall DoS remain documented limitations.

## Regression results

| Suite | PASS | FAIL | BLOCKED |
| --- | ---: | ---: | ---: |
| Strict filesystem including A/B/C and alias flood | 25 | 0 | 0 |
| Browser adversarial, Strict | 24 | 0 | 0 |
| Desktop notifications | 15 | 0 | 0 |
| Strict bounded concurrency | 1 | 0 | 0 |
| SSH broker adversarial, Strict | 29 | 0 | 0 |

The concurrent run again processed 180,624 strict events with zero queue
overflow, audit drop, classifier failure, or topology degradation. SSH broker
behavior was unchanged.

## Commands executed

The privileged commands were actually executed on the Arch host through the
desktop polkit path (`pkexec`), with the invoking user's Rust toolchain passed
explicitly:

```text
pkexec env ... ALIAS_ITERATIONS=10000 ALIAS_FLOOD_ITERATIONS=2000 \
  bash scripts/test-strict-filesystem-root.sh
pkexec env ... ENFORCEMENT_MODE=strict-filesystem \
  bash scripts/test-browser-adversarial-root.sh
pkexec env ... bash scripts/test-strict-concurrency-root.sh
pkexec env ... ENFORCEMENT_MODE=strict-filesystem \
  bash scripts/test-ssh-broker-adversarial-root.sh
```

The non-privileged quality command was:

```text
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo build --release
```

## Rust quality gates

```text
cargo fmt --check                                           PASS
cargo clippy --workspace --all-targets --all-features
  -- -D warnings                                            PASS
cargo test --workspace --all-features                       201 passed, 0 failed
cargo build --release                                       PASS
```

## Remaining boundary

Strict Mode guarantees first-open policy for configured sensitive namespaces
and retains inode identity after the first classified open. It does not claim
to mediate rename operations that contain no open event. Eliminating that
rename-only history gap would require a hook that observes namespace mutation
(for example an LSM-based design); no new backend is introduced in this pass.
