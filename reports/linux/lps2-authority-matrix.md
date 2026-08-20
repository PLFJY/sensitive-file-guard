# LPS2 — Firefox SecretAuthority Evidence Matrix

Date: 2026-08-20. The matrix is derived from real File Shield **ALLOW** audit
events on a physical host, using only a disposable Firefox profile. It does not
read, copy, or report browser secret bytes.

## Evidence method

The normal user built debug `guardd` and `guardctl`; debug audit persistence is
used solely because release builds intentionally omit ordinary ALLOW rows from
the hot path. Root `guardd` ran conservative File Shield enforcement. Firefox
then ran headless as the normal non-root user against an already-populated
disposable profile. While Firefox was still alive, the LPS2 oracle retained an
ALLOW row only if all of the following held:

- audit PID + `/proc/PID/stat` start time still matched;
- a freshly opened pidfd still named that PID;
- `/proc/PID/exe` object identity (path, device, inode, owner and mode) was
  available; and
- argv and a bounded ancestor chain could be read without recording profile
  contents.

Fresh host evidence is retained as metadata only at:

```text
/tmp/sfg-lps2-evidence-20260820-220018/lps2-firefox-authority-matrix.json
```

Its oracle result was:

```text
LPS2_FIREFOX_ALLOW_EVENTS_LIVE_INSTANCE_VERIFIED=PASS
LPS2_SECRET_AUTHORITY_CANDIDATES=1
LPS2_ROLE=Main RESOURCE=web_storage
LPS2_FIREFOX_SECRET_AUTHORITY_MATRIX=PASS
```

## Current matrix

| Browser / exact role | Protected resource evidenced | Exact-instance evidence | LPS3 candidate |
|---|---|---|---|
| Firefox `/usr/lib/firefox/firefox` Main | `browser_web_storage` | PID + start time + matching pidfd; executable device/inode `66314/7888038`, root-owned `0755`; direct `runuser → systemd` ancestry | Yes, only as a **new live exact instance** after LPS3 admission |
| Firefox Renderer | none | no File Shield ALLOW event | No |
| Firefox Utility / GPU / Extension / Other | none | no File Shield ALLOW event | No |
| Firefox cookie store / session store / key material | none in this workload | no File Shield ALLOW event | No additional role authority inferred |
| Chromium / Chrome / Zen | not installed / not live-tested | none | **NOT ACCEPTED** |

`browser_web_storage` is a protected browser data class and is sufficient to
show that this exact Firefox Main instance can receive protected local state.
It does **not** prove cookie-store, session-store, or key-material reads, and
it does not turn a browser family, process tree, UID, executable pathname, or
future PID into SecretAuthority.

The physical run used a Firefox system executable with the observed root-owned
object identity. The process exited during fixture cleanup; LPS2 deliberately
retains no authority after exit. A later LPS3 policy must establish a new exact
instance at lifecycle admission and fail closed on PID/start-time mismatch.

## Capsule limitation

The capsule remains BPF LSM `REDUCED / NOT HOST-EQUIVALENT` (`bpf()` program
load is `EPERM` in LPS0). LPS2's File Shield audit collection is meaningful
only for the physical-host fallback shown above; it is not a capsule Process
Shield acceptance result.

## LPS3 boundary

Only evidence-proven Firefox Main instances that match the exact executable
object and lifecycle record may be considered for LPS3. Unknown same-UID
requesters and every unobserved browser child role remain outside any allow
exception.
