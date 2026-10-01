/* Durable outbox. Serialize storage writes without locking them during network I/O. */
var QUEUE_KEY = "aitm_tx_queue", MAX_QUEUE = 200;
var queueWrites = Promise.resolve(), activeFlush = null;
function editQueue(edit) {
  var operation = queueWrites.then(async function () {
    var stored = await chrome.storage.local.get(QUEUE_KEY);
    var queue = Array.isArray(stored[QUEUE_KEY]) ? stored[QUEUE_KEY] : [];
    var result = edit(queue);
    await chrome.storage.local.set({ [QUEUE_KEY]: queue.slice(-MAX_QUEUE) });
    return result;
  });
  queueWrites = operation.catch(function () {});
  return operation;
}
function logUrl(value) {
  try {
    var url = new URL(value);
    return url.protocol === "file:" ? "file:///" : url.origin + url.pathname;
  } catch (e) { return ""; }
}
function cleanLog(value, key, depth) {
  if ((depth || 0) > 6) return null;
  if (typeof value === "string") return /^(url|tabUrl|referrer|returnUrl)$/i.test(key || "") ? logUrl(value) : value.slice(0, 2048);
  if (Array.isArray(value)) return value.slice(0, 50).map(function (v) { return cleanLog(v, "", (depth || 0) + 1); });
  if (value && typeof value === "object") {
    var result = {};
    Object.keys(value).slice(0, 50).forEach(function (k) { result[k] = cleanLog(value[k], k, (depth || 0) + 1); });
    return result;
  }
  return value;
}
async function hmacHex(secret, message) {
  var enc = new TextEncoder();
  var key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  var sig = await crypto.subtle.sign("HMAC", key, enc.encode(message));
  return Array.from(new Uint8Array(sig), function (b) { return b.toString(16).padStart(2, "0"); }).join("");
}
async function deliver(evt, cfg) {
  var controller = new AbortController(), timeout = setTimeout(function () { controller.abort(); }, 10000);
  try {
    var ts = Date.now().toString(), body = JSON.stringify(cleanLog(evt));
    var headers = { "Content-Type": "application/json", "X-AiTM-Timestamp": ts };
    if (cfg.telemetrySecret) headers["X-AiTM-Signature"] = "sha256=" + await hmacHex(cfg.telemetrySecret, ts + "." + body);
    var response = await fetch(cfg.reportingEndpoint, {
      method: "POST", headers: headers, body: body, signal: controller.signal,
      credentials: "omit", redirect: "error"
    });
    return response.ok;
  } catch (e) { return false; }
  finally { clearTimeout(timeout); }
}
function flushQueue() {
  if (activeFlush) return activeFlush;
  activeFlush = (async function () {
    if (!(await AITMSettings.load()).reportingEndpoint) return;
    var snapshot = await editQueue(function (queue) {
      queue.forEach(function (event) { if (!event.eventId) event.eventId = crypto.randomUUID(); });
      return queue.slice(0, 25);
    });
    for (var event of snapshot) {
      var cfg = await AITMSettings.load();
      if (!cfg.reportingEndpoint || !(await deliver(event, cfg))) break;
      await editQueue(function (queue) {
        var index = queue.findIndex(function (item) { return item.eventId === event.eventId; });
        if (index !== -1) queue.splice(index, 1);
      });
    }
  })().catch(function (error) {
    console.error("[AiTM] Log delivery:", error.message);
  }).finally(function () { activeFlush = null; });
  return activeFlush;
}
async function emit(eventName, payload, sender) {
  var cfg;
  try { cfg = await AITMSettings.load(); }
  catch (e) {
    console.error("[AiTM] Logging disabled: invalid deployment configuration.");
    return { status: "disabled" };
  }
  if (!cfg.reportingEndpoint) return { status: "disabled" };
  var event = cleanLog({
    eventId: crypto.randomUUID(), event: eventName, source: "aitm-phishing-guard",
    extVersion: chrome.runtime.getManifest().version, ts: new Date().toISOString(),
    deviceId: cfg && cfg.deviceId, userId: cfg && cfg.userId,
    tabUrl: sender && sender.tab ? sender.tab.url : undefined,
    frameId: sender ? sender.frameId : undefined, data: payload || {}
  });
  await editQueue(function (queue) { queue.push(event); });
  chrome.alarms.create("aitm-flush-soon", { when: Date.now() + 1000 });
  flushQueue();
  return { status: "queued", eventId: event.eventId };
}
