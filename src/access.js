/* Block records and exact-host user exceptions are private to the extension. */
var tabActions = new Map();
function blockKey(tabId) { return "aitm_block_" + tabId; }
function allowKey(tabId) { return "aitm_allow_" + tabId; }
function withTabLock(tabId, action) {
  var previous = tabActions.get(tabId) || Promise.resolve();
  var next = previous.catch(function () {}).then(action);
  tabActions.set(tabId, next);
  next.finally(function () { if (tabActions.get(tabId) === next) tabActions.delete(tabId); }).catch(function () {});
  return next;
}
function pageUrl(value) {
  var url = new URL(value);
  if (!["https:", "http:", "file:"].includes(url.protocol)) throw new Error("Không thể mở địa chỉ này.");
  return url;
}
async function domainAllowed(sender) {
  if (!sender.tab || typeof sender.tab.id !== "number" || !sender.url) return false;
  var host = pageUrl(sender.url).hostname.toLowerCase().replace(/\.$/, "");
  if (!host) return false;
  var stored = await chrome.storage.session.get(allowKey(sender.tab.id));
  return (stored[allowKey(sender.tab.id)] || []).includes(host);
}
async function blockTab(sender, payload) {
  if (!sender.tab || typeof sender.tab.id !== "number") throw new Error("Không xác định được tab bị chặn.");
  var tabId = sender.tab.id;
  return withTabLock(tabId, async function () {
    if (await domainAllowed(sender)) return { allowed: true };
    var current = await chrome.tabs.get(tabId), blockedPage = chrome.runtime.getURL("blocked.html");
    if (current.url && current.url.startsWith(blockedPage + "?")) return { blocked: true };
    if (!current.url) {
      var existing = await chrome.storage.session.get(blockKey(tabId));
      if (existing[blockKey(tabId)]) return { blocked: true };
    }
    // Use Chrome's sender URL, never a URL supplied by the page payload.
    var detected = pageUrl(sender.url);
    if (sender.frameId === 0 && current.url) {
      var live = pageUrl(current.url);
      if (live.origin !== detected.origin) return { stale: true };
      // sender.url can retain the original document URL after pushState.
      detected = live;
    }
    var returnUrl = sender.frameId === 0 ? detected.href : pageUrl(current.url || sender.tab.url).href;
    var record = {
      id: crypto.randomUUID(), tabId: tabId, hostname: detected.hostname.toLowerCase().replace(/\.$/, ""),
      url: detected.href, returnUrl: returnUrl, frameId: sender.frameId,
      score: typeof payload.score === "number" ? payload.score : 0,
      tier: payload.tier || "", signals: Array.isArray(payload.signals) ? payload.signals.slice(0, 50) : [],
      ts: new Date().toISOString()
    };
    await chrome.storage.session.set({ [blockKey(tabId)]: record });
    await chrome.tabs.update(tabId, { url: blockedPage + "?id=" + encodeURIComponent(record.id) });
    var logging = await emit("aitm_domain_blocked", {
      blockId: record.id, hostname: record.hostname, url: record.url, returnUrl: record.returnUrl,
      score: record.score, tier: record.tier, signals: record.signals, action: "blocked"
    }, sender);
    return { blocked: true, logging: logging };
  });
}
async function verifiedBlock(message, sender) {
  var source = new URL(sender.url || "about:blank"), expected = new URL(chrome.runtime.getURL("blocked.html"));
  if (source.protocol !== expected.protocol || source.host !== expected.host || source.pathname !== expected.pathname) {
    throw new Error("Chỉ trang cảnh báo của extension được phép bỏ chặn.");
  }
  var tabId = message.tabId;
  if (!Number.isInteger(tabId) || (sender.tab && sender.tab.id !== tabId)) throw new Error("Tab không hợp lệ.");
  var stored = await chrome.storage.session.get(blockKey(tabId)), record = stored[blockKey(tabId)];
  var tab = await chrome.tabs.get(tabId);
  var target = chrome.runtime.getURL("blocked.html") + "?id=" + encodeURIComponent(message.blockId || "");
  // Without the tabs permission Chrome may omit extension-page URLs from Tab.
  // sender.url still authenticates our document; its random record is tab-bound.
  if (!record || record.id !== message.blockId || source.searchParams.get("id") !== record.id || (tab.url && tab.url !== target)) {
    throw new Error("Cảnh báo này đã hết hiệu lực. Hãy mở lại trang cần truy cập.");
  }
  return record;
}
async function continueBlocked(message, sender) {
  return withTabLock(message.tabId, async function () {
    var record = await verifiedBlock(message, sender);
    if (!record.hostname) throw new Error("Chỉ hỗ trợ bỏ chặn theo domain cho trang HTTP/HTTPS.");
    var stored = await chrome.storage.session.get(allowKey(record.tabId));
    var hosts = stored[allowKey(record.tabId)] || [];
    if (!hosts.includes(record.hostname)) hosts.push(record.hostname);
    await chrome.storage.session.set({ [allowKey(record.tabId)]: hosts.slice(-100) });
    var logging = await emit("aitm_false_positive_report", {
      blockId: record.id, hostname: record.hostname, url: record.url,
      action: "allow_and_continue", scope: "tab", fromInterstitial: true,
      score: record.score, tier: record.tier
    }, sender);
    await chrome.tabs.update(record.tabId, { url: pageUrl(record.returnUrl).href });
    await chrome.storage.session.remove(blockKey(record.tabId));
    return { ok: true, logging: logging };
  });
}
chrome.tabs.onRemoved.addListener(function (tabId) {
  withTabLock(tabId, function () {
    return chrome.storage.session.remove([blockKey(tabId), allowKey(tabId)]);
  }).catch(function () {});
});
