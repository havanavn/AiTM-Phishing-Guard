/*
 * content.js  (v1.1)
 * Điều phối phát hiện và phản ứng.
 *
 * Chế độ (blockMode, do IT đẩy qua managed policy):
 *   - "report": im lặng, chỉ telemetry (dùng cho pilot đo false positive)
 *   - "warn"  : overlay đỏ trong trang, cho phép đóng
 *   - "block" : chuyển tab sang interstitial của extension (JS trang bị loại bỏ
 *               hoàn toàn) + overlay tạm trong lúc chờ điều hướng
 *
 * Kill switch: enabled=false -> không làm gì.
 */

(function () {
  "use strict";

  if (window.__aitmGuardLoaded) return;
  window.__aitmGuardLoaded = true;

  var DEFAULT_THRESHOLD = 6;
  var HOST_ID = "aitm-guard-host";
  var DEFAULT_SAFE_PORTAL = "https://login.microsoftonline.com/";

  // ---------------------------------------------------------------------------
  // 1) Cấu hình (chrome.storage.managed — user không sửa được)
  // ---------------------------------------------------------------------------
  function loadConfig() {
    var defaults = {
      enabled: true,
      trustedAuthDomains: [],
      orgIdpDomains: [],
      threshold: DEFAULT_THRESHOLD,
      blockMode: "block",
      safePortalUrl: DEFAULT_SAFE_PORTAL,
      helpdeskContact: "IT Helpdesk"
    };
    return new Promise(function (resolve) {
      try {
        chrome.storage.managed.get(null, function (cfg) {
          cfg = cfg || {};
          resolve({
            enabled: cfg.enabled !== false,
            trustedAuthDomains: cfg.trustedAuthDomains || [],
            orgIdpDomains: cfg.orgIdpDomains || [],
            threshold: typeof cfg.detectionThreshold === "number" ? cfg.detectionThreshold : DEFAULT_THRESHOLD,
            blockMode: ["report", "warn", "block"].indexOf(cfg.blockMode) >= 0 ? cfg.blockMode : "block",
            safePortalUrl: cfg.safePortalUrl || DEFAULT_SAFE_PORTAL,
            helpdeskContact: cfg.helpdeskContact || "IT Helpdesk",
            _raw: cfg
          });
        });
      } catch (e) {
        resolve(defaults);
      }
    });
  }

  // ---------------------------------------------------------------------------
  // 2) Messaging tới background (telemetry, block)
  // ---------------------------------------------------------------------------
  function send(type, payload) {
    try { chrome.runtime.sendMessage({ type: type, payload: payload }); } catch (e) {}
  }

  function buildEvent(result, cfg, extra) {
    return Object.assign({
      url: location.href,
      hostname: result.hostname,
      score: result.score,
      pathScore: result.pathScore,
      tier: result.tier,
      mode: cfg.blockMode,
      signals: result.hits,
      domainSignals: result.domainSignals,
      isTopFrame: window.top === window.self,
      referrer: document.referrer || "",
      ts: new Date().toISOString(),
      ua: navigator.userAgent
    }, extra || {});
  }

  // ---------------------------------------------------------------------------
  // 3) Overlay cảnh báo (Shadow DOM, chống tamper) — dùng cho "warn" và làm
  //    lớp tạm trong "block" cho tới khi interstitial thay trang.
  // ---------------------------------------------------------------------------
  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  function buildWarning(result, cfg) {
    var domainNote = result.domainSignals.length
      ? "<div class='sig'>Dấu hiệu domain: " + escapeHtml(result.domainSignals.join("; ")) + "</div>" : "";
    var dismissBtn = cfg.blockMode === "warn"
      ? "<button id='aitm-dismiss' class='btn ghost'>Tôi hiểu rủi ro – đóng cảnh báo</button>" : "";

    return [
      "<style>",
      ":host{all:initial;}",
      ".overlay{position:fixed;inset:0;z-index:2147483647;background:rgba(120,0,0,.94);display:flex;align-items:center;justify-content:center;font-family:'Segoe UI',Roboto,Arial,sans-serif;}",
      ".card{max-width:640px;width:92%;background:#fff;border-top:10px solid #c50f1f;border-radius:10px;padding:28px 32px;box-shadow:0 10px 40px rgba(0,0,0,.5);}",
      ".badge{display:inline-block;background:#c50f1f;color:#fff;font-weight:700;padding:4px 12px;border-radius:4px;font-size:13px;letter-spacing:.5px;}",
      "h1{color:#c50f1f;font-size:24px;margin:14px 0 8px;line-height:1.25;}",
      "p{color:#222;font-size:15px;line-height:1.55;margin:8px 0;}",
      ".dom{background:#fde7e9;border:1px solid #f1bdc2;border-radius:6px;padding:10px 12px;font-family:Consolas,monospace;font-size:15px;color:#7a0a14;word-break:break-all;margin:12px 0;}",
      ".sig{font-size:13px;color:#7a0a14;margin-top:6px;}",
      "ul{margin:8px 0 14px;padding-left:20px;color:#222;font-size:14px;} li{margin:4px 0;}",
      ".actions{display:flex;gap:10px;flex-wrap:wrap;margin-top:18px;}",
      ".btn{border:0;border-radius:6px;padding:11px 18px;font-size:14px;font-weight:600;cursor:pointer;}",
      ".primary{background:#c50f1f;color:#fff;} .secondary{background:#e8e8e8;color:#333;} .ghost{background:transparent;color:#666;text-decoration:underline;}",
      ".foot{margin-top:16px;font-size:12px;color:#666;}",
      "</style>",
      "<div class='overlay' role='alertdialog' aria-modal='true'><div class='card'>",
      "<span class='badge'>⚠ CẢNH BÁO BẢO MẬT</span>",
      "<h1>Đây có thể là trang ĐĂNG NHẬP MICROSOFT GIẢ MẠO</h1>",
      "<p>Trang này giống trang đăng nhập Microsoft, nhưng <b>tên miền KHÔNG phải của Microsoft</b>. Đây là dấu hiệu tấn công <b>Adversary-in-the-Middle (evilginx)</b> nhằm đánh cắp mật khẩu và mã 2FA.</p>",
      "<div class='dom'>" + escapeHtml(result.hostname) + "</div>", domainNote,
      "<p><b>TUYỆT ĐỐI KHÔNG:</b></p><ul><li>Không nhập tài khoản / mật khẩu</li><li>Không nhập OTP, không xác nhận thông báo Authenticator</li><li>Không bấm \"Phê duyệt\" trên điện thoại</li></ul>",
      "<div class='actions'>",
      "<button id='aitm-safe' class='btn primary'>Đi tới cổng đăng nhập chính thức</button>",
      "<button id='aitm-report' class='btn secondary'>Báo cáo cho " + escapeHtml(cfg.helpdeskContact) + "</button>",
      "<button id='aitm-fp' class='btn ghost'>Đây là trang hợp lệ (báo nhầm)</button>",
      dismissBtn,
      "</div>",
      "<div class='foot'>AiTM Phishing Guard · điểm: " + result.score + " · cảnh báo do IT triển khai.</div>",
      "</div></div>"
    ].join("");
  }

  var reinjectObserver = null;

  function showWarning(result, cfg) {
    if (document.getElementById(HOST_ID)) return;
    var host = document.createElement("div");
    host.id = HOST_ID;
    var shadow = host.attachShadow({ mode: "open" });
    shadow.innerHTML = buildWarning(result, cfg);
    (document.documentElement || document.body).appendChild(host);
    try { document.documentElement.style.setProperty("overflow", "hidden", "important"); } catch (e) {}

    shadow.getElementById("aitm-safe").addEventListener("click", function () {
      location.href = cfg.safePortalUrl; // đưa user về đúng đường, không về about:blank
    });
    shadow.getElementById("aitm-report").addEventListener("click", function () {
      send("aitm-alert", buildEvent(result, cfg, { manualReport: true }));
      var b = shadow.getElementById("aitm-report"); b.textContent = "Đã gửi báo cáo ✓"; b.disabled = true;
    });
    shadow.getElementById("aitm-fp").addEventListener("click", function () {
      send("aitm-false-positive", buildEvent(result, cfg));
      var b = shadow.getElementById("aitm-fp"); b.textContent = "Đã ghi nhận, IT sẽ xem xét ✓"; b.disabled = true;
    });
    var dis = shadow.getElementById("aitm-dismiss");
    if (dis) dis.addEventListener("click", function () {
      if (reinjectObserver) reinjectObserver.disconnect();
      host.remove();
      try { document.documentElement.style.removeProperty("overflow"); } catch (e) {}
    });

    reinjectObserver = new MutationObserver(function () {
      if (!document.getElementById(HOST_ID)) (document.documentElement || document.body).appendChild(host);
    });
    reinjectObserver.observe(document.documentElement, { childList: true, subtree: false });
  }

  // ---------------------------------------------------------------------------
  // 4) Phản ứng theo chế độ
  // ---------------------------------------------------------------------------
  function react(result, cfg) {
    send("aitm-alert", buildEvent(result, cfg));
    if (cfg.blockMode === "report") return;           // im lặng
    showWarning(result, cfg);                           // warn + lớp tạm cho block
    if (cfg.blockMode === "block") {
      // Interstitial: background điều hướng cả TAB sang trang của extension.
      // JS của trang phishing bị loại bỏ hoàn toàn -> không còn cuộc đua tamper.
      send("aitm-block", {
        hostname: result.hostname, url: location.href,
        score: result.score, tier: result.tier, signals: result.hits
      });
    }
  }

  // ---------------------------------------------------------------------------
  // 5) Chạy
  // ---------------------------------------------------------------------------
  loadConfig().then(async function (cfg) {
    if (!cfg.enabled) return; // kill switch

    // Only the background can authorize a user exception for this tab/host.
    try {
      var exception = await chrome.runtime.sendMessage({ type: "aitm-check-domain" });
      if (exception && exception.allowed === true) return;
    } catch (e) {} // no authorization => keep protection active

    var trusted = AITMDetector.DEFAULT_TRUSTED_DOMAINS
      .concat(cfg.trustedAuthDomains).concat(cfg.orgIdpDomains);

    // Host tin cậy: không gắn observer nào cả (hiệu năng trên Outlook/Teams/SharePoint)
    if (AITMDetector.isTrustedHost(location.hostname, trusted)) return;

    // Validate policy (chỉ top frame, throttle 1 lần/ngày) -> telemetry để IT sửa cấu hình
    if (window.top === window.self) {
      var warnings = AITMDetector.validatePolicy(cfg._raw || {});
      if (warnings.length) {
        try {
          chrome.storage.local.get(["aitm_cfgwarn_ts"], function (o) {
            var last = (o && o.aitm_cfgwarn_ts) || 0;
            if (Date.now() - last > 86400000) {
              chrome.storage.local.set({ aitm_cfgwarn_ts: Date.now() });
              send("aitm-config-warning", { warnings: warnings, ts: new Date().toISOString() });
            }
          });
        } catch (e) {
          send("aitm-config-warning", { warnings: warnings, ts: new Date().toISOString() });
        }
      }
    }

    var done = false, domObserver = null, urlPoller = null, lastEvalTs = 0, debounceTimer = null;

    function teardown() {
      if (domObserver) { domObserver.disconnect(); domObserver = null; }
      if (urlPoller) { clearInterval(urlPoller); urlPoller = null; }
      window.removeEventListener("popstate", onNav, true);
      window.removeEventListener("hashchange", onNav, true);
      if (window.navigation) window.navigation.removeEventListener("navigatesuccess", onNav);
    }

    function run() {
      if (done) return true;
      var result = AITMDetector.evaluate(document, location, trusted, cfg.threshold);
      if (result) {
        done = true;
        react(result, cfg);
        teardown();
        return true;
      }
      return false;
    }

    function scheduleRun() {
      if (done) return;
      var now = Date.now();
      if (now - lastEvalTs > 300) { lastEvalTs = now; run(); }
      else {
        clearTimeout(debounceTimer);
        debounceTimer = setTimeout(function () { lastEvalTs = Date.now(); run(); }, 300);
      }
    }

    // --- Điều hướng SPA ---
    // Navigation API + polling dự phòng: không patch History.prototype của trang.
    function onNav() {
      if (done) return;
      setTimeout(scheduleRun, 150); // cho DOM kịp render route mới
    }
    window.addEventListener("popstate", onNav, true);
    window.addEventListener("hashchange", onNav, true);
    if (window.navigation && typeof window.navigation.addEventListener === "function") {
      try { window.navigation.addEventListener("navigatesuccess", onNav); } catch (e) {}
    }
    // Poll dự phòng cho trình duyệt thiếu Navigation API.
    urlPoller = setInterval(function () {
      if (done) return;
      scheduleRun(); // phát hiện cả nội dung mới trong closed Shadow DOM
    }, 2000);

    // --- DOM render muộn ---
    domObserver = new MutationObserver(scheduleRun);
    domObserver.observe(document.documentElement, { childList: true, subtree: true });

    run();
  });
})();
