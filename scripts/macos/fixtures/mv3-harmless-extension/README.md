# MCH8 — Harmless Manifest V3 Extension Fixture

Used ONLY against DISPOSABLE browser profiles for Process Shield extension
compatibility testing. It exercises:

- background service worker (install/startup wake, tab-activity wake)
- content script (harmless DOM annotation on every page)
- popup page + popup.js (storage.local read/write, tabs.query)
- options page + options.js (storage.local)
- storage.local (background + pages)
- tabs API (onUpdated, query)

No network calls, no remote code, no secrets, no data collection.

Load into disposable Chrome: chromium --load-extension=<this directory> with a
DISPOSABLE profile. Expected under Process Shield: normal extension behavior;
0 unexplained task DENY storm; 0 false Compromised state. Extension
compatibility != extension task-memory authority (the fixture gets no task
authority over SecretAuthority targets by design).
