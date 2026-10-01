/* MV3 service worker: policy, logging and extension-owned navigation decisions. */
importScripts("config.js", "detector.js", "hook-policy.js", "settings.js", "telemetry.js", "access.js");

var EVENT_NAMES = {
  "aitm-alert": "aitm_phishing_detected",
  "aitm-false-positive": "aitm_false_positive_report",
  "aitm-config-warning": "aitm_config_warning",
  "aitm-devicecode-view": "aitm_devicecode_page_view",
  "aitm-devicecode-accept": "aitm_devicecode_risk_accepted",
  "aitm-devicecode-leave": "aitm_devicecode_left",
  "aitm-devicecode-report": "aitm_devicecode_user_report",
  "aitm-exfil-detected": "aitm_exfil_behavior_detected",
  "aitm-exfil-confirmed": "aitm_exfil_user_confirmed",
  "aitm-exfil-false-positive": "aitm_exfil_false_positive"
};

chrome.runtime.onMessage.addListener(function (msg, sender, respond) {
  if (!msg || !sender || sender.id !== chrome.runtime.id) return;
  var work;
  if (msg.type === "aitm-check-domain") work = domainAllowed(sender).then(function (allowed) { return { allowed: allowed }; });
  else if (msg.type === "aitm-block") work = blockTab(sender, msg.payload || {});
  else if (msg.type === "aitm-get-block") work = verifiedBlock(msg, sender).then(function (record) { return { record: record }; });
  else if (msg.type === "aitm-continue") work = continueBlocked(msg, sender);
  else if (Object.prototype.hasOwnProperty.call(EVENT_NAMES, msg.type)) work = emit(EVENT_NAMES[msg.type], msg.payload, sender);
  else return;
  work.then(respond, function (error) { respond({ error: error.message }); });
  return true;
});

chrome.alarms.create("aitm-flush", { periodInMinutes: 15 });
chrome.alarms.onAlarm.addListener(function (alarm) {
  if (alarm.name === "aitm-flush" || alarm.name === "aitm-flush-soon") flushQueue();
});
chrome.storage.onChanged.addListener(function (_changes, area) {
  if (area === "managed") flushQueue();
});
chrome.runtime.onInstalled.addListener(function () { flushQueue(); });
chrome.runtime.onStartup.addListener(flushQueue);
