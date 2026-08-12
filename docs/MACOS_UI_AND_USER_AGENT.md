# macOS GTK 控制中心与待处理 helper（技术参考）

> macOS 自用安装请阅读[中文 macOS 指南](INSTALL_MACOS.md)。

The macOS product keeps the existing GTK4/libadwaita control center. Native
code is limited to operating-system boundaries: Endpoint Security,
LocalAuthentication, authenticated XPC, SystemExtensions, and SMAppService.

## macOS protection state

The macOS UI does not show the Linux `strict-filesystem` or `conservative`
choices. Its status view reports these independent facts:

- Endpoint Security extension: active, pending approval, restart required,
  installed but disabled, unknown/not installed, or error;
- Full Disk Access: granted, required, or unknown based on the extension's
  Endpoint Security client result;
- protection policy: enabled or disabled in the authoritative macOS config;
- pending helper: running, enabled but not responding, pending approval, not
  registered, or missing from the app bundle.

The ordinary Protection switch updates `policy_enabled` through authenticated
XPC and LocalAuthentication. It does not activate, deactivate, or uninstall the
system extension. Extension lifecycle remains an explicit setup/removal action.

## User-session LaunchAgent

The app embeds:

```text
Guard.app/Contents/Library/LaunchAgents/
  top.plfjy.SensitiveFileGuard.guard-notify.plist
```

The plist uses `BundleProgram = Contents/MacOS/guard-notify`. The GTK app
registers or unregisters it with `SMAppService.agentServiceWithPlistName` on
macOS 13 and later. It is an unprivileged per-user LaunchAgent, not a root
LaunchDaemon.

`guard-notify` has no policy resolver. Its one authenticated XPC poll combines
a liveness heartbeat with the browser-import and SSH-read pending snapshot for
the connection's transport EUID. A new pending ID starts the sibling
`Guard --pending-only` executable. Repeated snapshots do not open duplicate
windows.

The Alpha helper polls every 500 ms while XPC is healthy and exponentially
backs off to five seconds while the extension is unavailable. The active
worst-case discovery latency is therefore 500 ms; after an unavailable period,
recovery discovery is bounded by five seconds. Both are below the 60-second
interactive pending budget. The signed Phase 06 transport measurement at the
final 500-ms setting observed 0.02–0.03 seconds of cumulative CPU and 0.0–0.1%
sampled CPU across repeated five-second runs.

Native notifications are intentionally omitted in this phase. The pending GTK
dialog is authoritative, and directly activating it avoids duplicating private
path metadata into a supplemental notification channel.

## Pending-only behavior

The helper passes only `--pending-only`; there is no request ID or approval
argument. GApplication receives a filtered argv so this local lifecycle flag is
not rejected as an unknown GTK option.

- one active dialog is shown at a time;
- repeated pending snapshots are deduplicated;
- Allow crosses LocalAuthentication before XPC resolution;
- cancellation returns to the explicit choice state and sends no Allow;
- Block and window close remain fail-closed;
- an authorization timeout or already-resolved result closes the stale dialog;
- after the final terminal item, a pending-only window exits;
- a manually opened control center remains open.

Browser and SSH prompts show the remaining authorization time and only fixed
metadata: browser/profile/resource type or program/executable/PID/key path.
They never contain browser secret values or SSH private-key bytes.
