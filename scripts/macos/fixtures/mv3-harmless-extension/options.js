// MCH8 harmless options page: storage.local only.
const KEY = "mch8_bg_state";
async function render() {
  const { [KEY]: state } = await chrome.storage.local.get(KEY);
  document.getElementById("state").textContent = JSON.stringify(state ?? {});
  document.getElementById("note").value = state?.note ?? "";
}
document.getElementById("save").addEventListener("click", async () => {
  const { [KEY]: state } = await chrome.storage.local.get(KEY);
  await chrome.storage.local.set({
    [KEY]: { ...(state ?? {}), note: document.getElementById("note").value },
  });
  await render();
});
render();
