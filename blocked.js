(function () {
  var q = new URLSearchParams(location.search);
  var host = q.get("host") || "";
  var url = q.get("url") || "";
  var score = q.get("score") || "";
  var tier = q.get("tier") || "";

  document.getElementById("host").textContent = host || "(không xác định)";
  document.getElementById("detail").textContent =
    "URL: " + url + "\nĐiểm vân tay: " + score + "  ·  Mức: " + tier;

  chrome.storage.managed.get(["safePortalUrl", "helpdeskContact"], function (cfg) {
    cfg = cfg || {};
    var safe = cfg.safePortalUrl || "https://login.microsoftonline.com/";
    if (cfg.helpdeskContact) document.getElementById("helpdesk").textContent = cfg.helpdeskContact;

    document.getElementById("safe").addEventListener("click", function () {
      location.href = safe;
    });
  });

  document.getElementById("close").addEventListener("click", function () {
    chrome.tabs.getCurrent(function (t) {
      if (t && typeof t.id === "number") chrome.tabs.remove(t.id);
      else window.close();
    });
  });

  document.getElementById("fp").addEventListener("click", function () {
    chrome.runtime.sendMessage({
      type: "aitm-false-positive",
      payload: { hostname: host, url: url, score: score, tier: tier, fromInterstitial: true, ts: new Date().toISOString() }
    });
    var b = document.getElementById("fp");
    b.textContent = "Đã ghi nhận, IT sẽ xem xét ✓";
    b.disabled = true;
  });
})();
