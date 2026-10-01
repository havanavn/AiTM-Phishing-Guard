/*
 * devicecode.js  (v1.2)
 * Cảnh báo trên trang nhập DEVICE CODE thật của Microsoft.
 *
 * Khác với AiTM: đây là domain Microsoft chính chủ, người dùng làm một việc
 * "hợp lệ". Vector tấn công là kẻ gian gửi mã cho nạn nhân nhập -> token được
 * Microsoft cấp thẳng cho app của attacker. Tập đoàn đã chặn flow này bằng
 * Conditional Access; lớp này là awareness để phủ nốt phần còn lại.
 *
 * Chế độ (managed policy `deviceCodeMode`):
 *   "off"   : không làm gì
 *   "warn"  : overlay đỏ + nút "Tôi hiểu rủi ro" để hiện trang nhập mã (mặc định).
 *             KHÔNG ghi nhớ: mỗi lần tải trang đều cảnh báo lại.
 *   "block" : overlay đỏ, KHÔNG có nút chấp nhận
 *
 * Chỉ được nạp trên các URL trong manifest (…/oauth2/deviceauth, /devicelogin).
 */

(function () {
  "use strict";

  if (window.top !== window.self) return;
  if (window.__aitmDeviceCodeLoaded) return;
  window.__aitmDeviceCodeLoaded = true;

  var HOST_ID = "aitm-devicecode-host";

  // Xác nhận lần nữa bằng path (manifest match đã lọc, đây là phòng hờ)
  var p = (location.pathname || "").toLowerCase();
  if (!/\/oauth2\/deviceauth|\/devicelogin/.test(p)) return;

  function send(type, payload) {
    try { chrome.runtime.sendMessage({ type: type, payload: payload }); } catch (e) {}
  }

  function esc(s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  // Tín hiệu vector đến: link mở từ email / chat -> user KHÔNG tự khởi tạo
  function suspiciousReferrer() {
    var r = (document.referrer || "").toLowerCase();
    if (!r) return null;
    var m = r.match(/^https?:\/\/([^/]+)/);
    var host = m ? m[1] : "";
    var mailChat = /outlook\.(office|live|office365)\.com|outlook\.com|mail\.google\.com|teams\.(microsoft|live)\.com|teams\.cloud\.microsoft|slack\.com|zalo\.me|web\.telegram\.org|messenger\.com|web\.whatsapp\.com/;
    return mailChat.test(host) ? host : null;
  }

  function buildOverlay(cfg, ref) {
    var refLine = ref
      ? "<div class='flag'>⚠ Bạn vừa mở trang này từ <b>" + esc(ref) + "</b> (email/chat). Người dùng hợp lệ hầu như không đến trang này qua liên kết được gửi tới.</div>"
      : "";
    var acceptBtn = cfg.mode === "warn"
      ? "<button id='dc-accept' class='btn ghost'>Tôi hiểu rủi ro – tiếp tục nhập mã</button>"
      : "";

    return [
      "<style>",
      ":host{all:initial;}",
      ".overlay{position:fixed;inset:0;z-index:2147483647;background:rgba(120,0,0,.95);display:flex;align-items:center;justify-content:center;font-family:'Segoe UI',Roboto,Arial,sans-serif;}",
      ".card{max-width:640px;width:92%;background:#fff;border-top:10px solid #c50f1f;border-radius:10px;padding:26px 30px;box-shadow:0 10px 40px rgba(0,0,0,.5);}",
      ".badge{display:inline-block;background:#c50f1f;color:#fff;font-weight:700;padding:4px 12px;border-radius:4px;font-size:13px;letter-spacing:.5px;}",
      "h1{color:#c50f1f;font-size:23px;margin:12px 0 6px;line-height:1.25;}",
      "p{color:#222;font-size:15px;line-height:1.5;margin:8px 0;}",
      ".two{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin:12px 0;}",
      ".box{border-radius:8px;padding:10px 12px;font-size:14px;line-height:1.45;}",
      ".ok{background:#e6f4ea;border:1px solid #b7dfc2;color:#1e4620;} .bad{background:#fde7e9;border:1px solid #f1bdc2;color:#7a0a14;}",
      ".box b{display:block;margin-bottom:4px;}",
      ".flag{background:#fff3cd;border:1px solid #ffe08a;color:#6b4e00;border-radius:6px;padding:9px 12px;font-size:14px;margin:10px 0;}",
      ".actions{display:flex;gap:10px;flex-wrap:wrap;margin-top:16px;}",
      ".btn{border:0;border-radius:6px;padding:11px 18px;font-size:14px;font-weight:600;cursor:pointer;}",
      ".primary{background:#c50f1f;color:#fff;} .secondary{background:#e8e8e8;color:#333;} .ghost{background:transparent;color:#666;text-decoration:underline;}",
      ".foot{margin-top:14px;font-size:12px;color:#666;}",
      "@media (max-width:520px){.two{grid-template-columns:1fr;}}",
      "</style>",
      "<div class='overlay' role='alertdialog' aria-modal='true'><div class='card'>",
      "<span class='badge'>⚠ CẢNH BÁO BẢO MẬT</span>",
      "<h1>Bạn đang mở trang nhập <u>mã thiết bị</u> (device code)</h1>",
      "<p>Trang này là <b>trang thật của Microsoft</b>. Nhưng cách đăng nhập bằng mã thiết bị đang bị lợi dụng để lừa đảo: kẻ gian gửi bạn một mã kèm lý do (xem tài liệu, xác nhận họp). Khi bạn nhập mã và xác thực, <b>họ nhận được quyền truy cập tài khoản của bạn — kể cả khi đã bật 2FA</b>.</p>",
      "<p><b>Tập đoàn đã chặn phương thức đăng nhập này.</b> Nếu ai đó yêu cầu bạn nhập mã tại đây, gần như chắc chắn là lừa đảo.</p>",
      refLine,
      "<div class='two'>",
      "<div class='box ok'><b>✓ Hợp lệ khi</b>Chính bạn vừa khởi tạo đăng nhập trên thiết bị khác (dòng lệnh, TV, phòng họp) và mã hiển thị trên thiết bị đó.</div>",
      "<div class='box bad'><b>✗ Lừa đảo khi</b>Mã đến từ email, Teams, chat, tin nhắn hoặc do người khác đọc cho bạn.</div>",
      "</div>",
      "<div class='actions'>",
      "<button id='dc-leave' class='btn primary'>Rời khỏi trang này</button>",
      "<button id='dc-report' class='btn secondary'>Báo cáo cho " + esc(cfg.helpdeskContact) + "</button>",
      acceptBtn,
      "</div>",
      "<div class='foot'>AiTM Phishing Guard · cảnh báo do IT triển khai.</div>",
      "</div></div>"
    ].join("");
  }

  function show(cfg) {
    if (document.getElementById(HOST_ID)) return;
    var ref = suspiciousReferrer();
    var host = document.createElement("div");
    host.id = HOST_ID;
    var shadow = host.attachShadow({ mode: "open" });
    shadow.innerHTML = buildOverlay(cfg, ref);
    (document.documentElement || document.body).appendChild(host);
    try { document.documentElement.style.setProperty("overflow", "hidden", "important"); } catch (e) {}

    var base = {
      url: location.href, hostname: location.hostname, referrer: document.referrer || "",
      suspiciousReferrer: ref, mode: cfg.mode, ts: new Date().toISOString(), ua: navigator.userAgent
    };
    send("aitm-devicecode-view", base);

    function close() {
      host.remove();
      try { document.documentElement.style.removeProperty("overflow"); } catch (e) {}
    }

    shadow.getElementById("dc-leave").addEventListener("click", function () {
      send("aitm-devicecode-leave", base);
      location.href = cfg.safePortalUrl;
    });
    shadow.getElementById("dc-report").addEventListener("click", function () {
      send("aitm-devicecode-report", Object.assign({ manualReport: true }, base));
      var b = shadow.getElementById("dc-report"); b.textContent = "Đã gửi báo cáo ✓"; b.disabled = true;
    });
    var acc = shadow.getElementById("dc-accept");
    if (acc) acc.addEventListener("click", function () {
      // Chấp nhận rủi ro: ghi telemetry (SOC đối chiếu với Entra sign-in log
      // authenticationProtocol=deviceCode). KHÔNG lưu lại: mỗi lần mở trang này
      // đều cảnh báo lại theo chính sách tập đoàn.
      send("aitm-devicecode-accept", base);
      close();
    });
  }

  chrome.storage.managed.get(["deviceCodeMode", "safePortalUrl", "helpdeskContact", "enabled"], function (raw) {
    raw = raw || {};
    if (raw.enabled === false) return; // kill switch chung
    var mode = ["off", "warn", "block"].indexOf(raw.deviceCodeMode) >= 0 ? raw.deviceCodeMode : "warn";
    if (mode === "off") return;

    var cfg = {
      mode: mode,
      safePortalUrl: raw.safePortalUrl || "https://myapps.microsoft.com/",
      helpdeskContact: raw.helpdeskContact || "IT Helpdesk"
    };
    // Luôn cảnh báo mỗi lần tải trang (không ghi nhớ chấp nhận rủi ro)
    if (document.documentElement) show(cfg);
    else document.addEventListener("DOMContentLoaded", function () { show(cfg); }, { once: true });
  });
})();
