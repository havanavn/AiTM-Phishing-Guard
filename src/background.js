/*
 * background.js  (service worker, MV3)  v1.1
 *
 * - Telemetry: thêm định danh (deviceId/userId từ managed policy), ký HMAC-SHA256
 *   bằng telemetrySecret -> SIEM loại được alert giả. Queue offline + retry.
 * - Block: điều hướng TAB sang interstitial blocked.html (chrome.tabs.update).
 * - Chỉ nhận message từ chính extension (sender.id).
 */

var QUEUE_KEY = "aitm_tx_queue";
var MAX_QUEUE = 200;

function getManaged(keys) {
  return new Promise(function (res) { chrome.storage.managed.get(keys || null, function (c) { res(c || {}); }); });
}
function getLocal(key) {
  return new Promise(function (res) { chrome.storage.local.get([key], function (c) { res(c ? c[key] : undefined); }); });
}
function setLocal(obj) {
  return new Promise(function (res) { chrome.storage.local.set(obj, res); });
}

function toHex(buf) {
  return Array.prototype.map.call(new Uint8Array(buf), function (b) { return ("0" + b.toString(16)).slice(-2); }).join("");
}

async function hmacHex(secret, message) {
  var enc = new TextEncoder();
  var key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  var sig = await crypto.subtle.sign("HMAC", key, enc.encode(message));
  return toHex(sig);
}

// Gửi 1 event. Trả về true nếu thành công.
async function deliver(evt, cfg) {
  var endpoint = cfg.reportingEndpoint;
  if (!endpoint) return true; // không cấu hình -> coi như xong (không queue)
  var ts = Date.now().toString();
  var body = JSON.stringify(evt);
  var headers = { "Content-Type": "application/json", "X-AiTM-Timestamp": ts };
  if (cfg.telemetrySecret) {
    // chữ ký trên  ts + "." + body  -> chống replay + chống giả mạo
    headers["X-AiTM-Signature"] = "sha256=" + (await hmacHex(cfg.telemetrySecret, ts + "." + body));
  }
  try {
    var r = await fetch(endpoint, { method: "POST", headers: headers, body: body });
    return r.ok;
  } catch (e) {
    return false;
  }
}

async function enqueue(evt) {
  var q = (await getLocal(QUEUE_KEY)) || [];
  q.push(evt);
  if (q.length > MAX_QUEUE) q = q.slice(q.length - MAX_QUEUE);
  await setLocal({ [QUEUE_KEY]: q });
}

async function flushQueue() {
  var cfg = await getManaged(["reportingEndpoint", "telemetrySecret"]);
  var q = (await getLocal(QUEUE_KEY)) || [];
  if (!q.length) return;
  var remain = [];
  for (var i = 0; i < q.length; i++) {
    if (remain.length || !(await deliver(q[i], cfg))) remain.push(q[i]);
  }
  await setLocal({ [QUEUE_KEY]: remain });
}

async function emit(eventName, payload, sender) {
  var cfg = await getManaged(["reportingEndpoint", "telemetrySecret", "deviceId", "userId"]);
  var evt = {
    event: eventName,
    source: "vinsoc-aitm-guard",
    extVersion: chrome.runtime.getManifest().version,
    // Định danh để SOC biết AI bị phish -> IR reset đúng người
    deviceId: cfg.deviceId || null,
    userId: cfg.userId || null,
    tabUrl: sender && sender.tab ? sender.tab.url : undefined,
    frameId: sender ? sender.frameId : undefined,
    data: payload
  };
  if (!(await deliver(evt, cfg))) await enqueue(evt);
}

async function blockTab(sender, payload) {
  if (!sender || !sender.tab || typeof sender.tab.id !== "number") return;
  var params = new URLSearchParams({
    host: payload.hostname || "",
    url: payload.url || "",
    score: String(payload.score || ""),
    tier: payload.tier || ""
  });
  var target = chrome.runtime.getURL("blocked.html") + "?" + params.toString();
  try { await chrome.tabs.update(sender.tab.id, { url: target }); } catch (e) { /* overlay tạm vẫn còn */ }
}

chrome.runtime.onMessage.addListener(function (msg, sender) {
  if (!msg || !msg.type) return;
  if (!sender || sender.id !== chrome.runtime.id) return; // chỉ nhận từ chính extension

  switch (msg.type) {
    case "aitm-alert":
      emit("aitm_phishing_detected", msg.payload, sender); break;
    case "aitm-block":
      blockTab(sender, msg.payload || {}); break;
    case "aitm-false-positive":
      emit("aitm_false_positive_report", msg.payload, sender); break;
    case "aitm-config-warning":
      emit("aitm_config_warning", msg.payload, sender); break;
    // Trang device code thật (awareness layer)
    case "aitm-devicecode-view":
      emit("aitm_devicecode_page_view", msg.payload, sender); break;
    case "aitm-devicecode-accept":
      emit("aitm_devicecode_risk_accepted", msg.payload, sender); break;
    case "aitm-devicecode-leave":
      emit("aitm_devicecode_left", msg.payload, sender); break;
    case "aitm-devicecode-report":
      emit("aitm_devicecode_user_report", msg.payload, sender); break;
    // Hành vi exfil (heuristic tổng quát, ngoài O365)
    case "aitm-exfil-detected":
      emit("aitm_exfil_behavior_detected", msg.payload, sender); break;
    case "aitm-exfil-confirmed":
      emit("aitm_exfil_user_confirmed", msg.payload, sender); break;
    case "aitm-exfil-false-positive":
      emit("aitm_exfil_false_positive", msg.payload, sender); break;
  }
});

// Retry queue định kỳ (máy ngoài VPN, endpoint tạm lỗi)
chrome.alarms.create("aitm-flush", { periodInMinutes: 15 });
chrome.alarms.onAlarm.addListener(function (a) { if (a.name === "aitm-flush") flushQueue(); });

chrome.runtime.onInstalled.addListener(function (d) {
  console.log("[VinSOC AiTM Guard] installed/updated:", d.reason);
  flushQueue();
});
chrome.runtime.onStartup.addListener(flushQueue);
