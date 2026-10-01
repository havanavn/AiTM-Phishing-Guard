/* Background only. MAIN hooks are registered from extension-owned policy, never
 * from a DOM flag that the page could change. Existing tabs require a reload. */
var EXFIL_SCRIPT_ID = "aitm-exfil";
var hookPolicyQueue = Promise.resolve();

function policyHostPattern(value) {
  if (typeof value !== "string") return null;
  var host = value.trim().toLowerCase().replace(/\.$/, "");
  if (!host || host.length > 253 || !host.split(".").every(function (label) {
    return /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label);
  })) return null;
  return "*://*." + host + "/*";
}

async function syncHookPolicy() {
  var cfg = await new Promise(function (resolve, reject) {
    chrome.storage.managed.get(null, function (value) {
      if (chrome.runtime.lastError) reject(new Error(chrome.runtime.lastError.message));
      else resolve(value || {});
    });
  });
  var scripts = await chrome.scripting.getRegisteredContentScripts({ ids: [EXFIL_SCRIPT_ID] });
  if (cfg.enabled === false || cfg.behaviorMode === "off") {
    if (scripts.length) await chrome.scripting.unregisterContentScripts({ ids: [EXFIL_SCRIPT_ID] });
    return;
  }

  // Reuse the same CAPTCHA scope and trusted hosts as the isolated detector.
  var manifest = chrome.runtime.getManifest();
  var excluded = manifest.content_scripts.find(function (s) {
    return s.matches.includes("<all_urls>");
  }).exclude_matches.slice();
  var trusted = AITMDetector.DEFAULT_TRUSTED_DOMAINS.concat(
    Array.isArray(cfg.trustedAuthDomains) ? cfg.trustedAuthDomains : [],
    Array.isArray(cfg.orgIdpDomains) ? cfg.orgIdpDomains : []
  );
  trusted.forEach(function (host) {
    var pattern = policyHostPattern(host);
    if (pattern) excluded.push(pattern);
  });
  var script = {
    id: EXFIL_SCRIPT_ID,
    matches: ["<all_urls>"],
    excludeMatches: Array.from(new Set(excluded)),
    js: ["src/exfil-hook.js"],
    runAt: "document_start",
    allFrames: false,
    world: "MAIN",
    persistAcrossSessions: true
  };
  if (scripts.length) await chrome.scripting.updateContentScripts([script]);
  else await chrome.scripting.registerContentScripts([script]);
}

function scheduleHookPolicy() {
  // Serialize updates so rapid policy changes cannot leave stale registrations.
  hookPolicyQueue = hookPolicyQueue.then(syncHookPolicy).catch(function (error) {
    console.error("[AiTM] Cannot update behavior hooks:", error.message);
  });
  return hookPolicyQueue;
}

chrome.storage.onChanged.addListener(function (_changes, area) {
  if (area === "managed") scheduleHookPolicy();
});
scheduleHookPolicy();
