// MCH8 harmless popup: reads/writes storage.local and queries tabs.
const KEY = "mch8_bg_state";
async function render() {
  const { [KEY]: state } = await chrome.storage.local.get(KEY);
  document.getElementById("state").textContent = JSON.stringify(state ?? {});
}
document.getElementById("bump").addEventListener("click", async () => {
  const { [KEY]: state } = await chrome.storage.local.get(KEY);
  await chrome.storage.local.set({
    [KEY]: { ...(state ?? {}), popupBumps: (state?.popupBumps ?? 0) + 1 },
  });
  await render();
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  console.log("mch8 fixture: active tab", tabs[0]?.id);
});
render();
