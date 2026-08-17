// MCH8 harmless background service worker. Exercises storage.local and the
// tabs API only; no network, no secrets, no remote code.
const FIXTURE_KEY = "mch8_bg_state";

chrome.runtime.onInstalled.addListener(async () => {
  await chrome.storage.local.set({ [FIXTURE_KEY]: { installed: true, ts: Date.now() } });
});

chrome.runtime.onStartup.addListener(async () => {
  const prev = (await chrome.storage.local.get(FIXTURE_KEY))[FIXTURE_KEY] ?? {};
  await chrome.storage.local.set({
    [FIXTURE_KEY]: { ...prev, wakeups: (prev.wakeups ?? 0) + 1, ts: Date.now() },
  });
});

// Wake-on-tab activity: query tabs and update the fixture counter.
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo) => {
  if (changeInfo.status !== "complete") return;
  const prev = (await chrome.storage.local.get(FIXTURE_KEY))[FIXTURE_KEY] ?? {};
  await chrome.storage.local.set({
    [FIXTURE_KEY]: { ...prev, tabsSeen: (prev.tabsSeen ?? 0) + 1, lastTab: tabId },
  });
});

// ping() used by the popup/options pages to prove the service worker is alive.
self.ping = async () => {
  const prev = (await chrome.storage.local.get(FIXTURE_KEY))[FIXTURE_KEY] ?? {};
  return { ok: true, state: prev };
};
