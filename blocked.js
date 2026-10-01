(function () {
  "use strict";
  var blockId = new URLSearchParams(location.search).get("id");
  var tabId, record;
  var status = document.getElementById("status"), button = document.getElementById("fp");

  async function initialize() {
    try {
      var tab = await chrome.tabs.getCurrent();
      if (!tab || !blockId) throw new Error("Cảnh báo này đã hết hiệu lực. Hãy mở lại trang cần truy cập.");
      tabId = tab.id;
      var response = await chrome.runtime.sendMessage({ type: "aitm-get-block", blockId: blockId, tabId: tabId });
      if (!response || response.error) throw new Error(response && response.error || "Không đọc được thông tin cảnh báo.");
      record = response.record;
      document.getElementById("host").textContent = record.hostname || "Tệp cục bộ";
      document.getElementById("detail").textContent = "URL: " + record.url + "\nĐiểm: " + record.score + " · Mức: " + record.tier;
      button.disabled = !record.hostname;
    } catch (e) { status.textContent = e.message; }
  }

  document.getElementById("safe").addEventListener("click", async function () {
    var cfg = await chrome.storage.managed.get(["safePortalUrl"]);
    location.href = cfg.safePortalUrl || "https://login.microsoftonline.com/";
  });
  chrome.storage.managed.get(["helpdeskContact"], function (cfg) {
    if (cfg && cfg.helpdeskContact) document.getElementById("helpdesk").textContent = cfg.helpdeskContact;
  });
  document.getElementById("close").addEventListener("click", async function () {
    var tab = await chrome.tabs.getCurrent();
    if (tab) chrome.tabs.remove(tab.id);
    else window.close();
  });
  button.addEventListener("click", async function () {
    if (!record) return;
    button.disabled = true; status.textContent = "Đang ghi nhận và mở lại trang…";
    try {
      var response = await chrome.runtime.sendMessage({ type: "aitm-continue", blockId: blockId, tabId: tabId });
      if (!response || response.error) throw new Error(response && response.error || "Không thể mở lại trang.");
    } catch (e) { status.textContent = e.message; button.disabled = false; }
  });
  initialize();
})();
