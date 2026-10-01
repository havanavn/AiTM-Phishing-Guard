/*
 * exfil-content.js  (isolated world, run_at: document_start) — v4
 *
 * v4 (sửa lỗi lưu trạng thái):
 *   - "Báo nhầm" lưu vào chrome.storage.local (CHỈ extension đọc/ghi) thay vì sessionStorage
 *     (thuộc origin trang -> phishing page tự ghi được để tắt cảnh báo). TTL 30 ngày, cap 200
 *     host; nhớ qua các lần truy cập sau. IT muốn vĩnh viễn -> behaviorAllowlist.
 *   - Một object `state` duy nhất: FP -> state.muted = true ngay (không còn chặn âm thầm).
 *   - Nếu banner đã bị đóng mà lại có form bị soft-block -> render lại banner.
 */
(function () {
  "use strict";
  if (window.top !== window.self) return;
  if (window.__aitmExfilContentLoaded) return;
  window.__aitmExfilContentLoaded = true;

  var HOST_ID = "aitm-exfil-guard-host";
  var O365_HOST_ID = "aitm-guard-host";
  var MUTE_KEY = "aitm_exfil_mute";           // chrome.storage.local: { hostname: expiresAtMs }
  var MUTE_TTL = 30 * 24 * 3600 * 1000, MUTE_MAX = 200;
  var THRESHOLD = 5, WEAK_CAP = 3;

  // ---------------- storage helpers (extension-private) ----------------
  function loadCfg() {
    return new Promise(function (res) {
      try {
        chrome.storage.managed.get(
          ["enabled", "behaviorMode", "behaviorAllowlist", "helpdeskContact", "trustedAuthDomains", "orgIdpDomains"],
          function (c) { res(c || {}); }
        );
      } catch (e) { res({}); }
    });
  }
  function loadMuteList() {
    return new Promise(function (res) {
      try {
        chrome.storage.local.get([MUTE_KEY], function (o) {
          var m = (o && o[MUTE_KEY]) || {}, now = Date.now(), clean = {};
          Object.keys(m).forEach(function (h) { if (m[h] > now) clean[h] = m[h]; });
          res(clean);
        });
      } catch (e) { res({}); }
    });
  }
  function saveMute(host) {
    return new Promise(function (res) {
      try {
        chrome.storage.local.get([MUTE_KEY], function (o) {
          var m = (o && o[MUTE_KEY]) || {}, now = Date.now();
          Object.keys(m).forEach(function (h) { if (m[h] <= now) delete m[h]; });
          m[host] = now + MUTE_TTL;
          var keys = Object.keys(m);
          if (keys.length > MUTE_MAX) {               // giữ các mục còn hạn lâu nhất
            keys.sort(function (a, b) { return m[a] - m[b]; });
            keys.slice(0, keys.length - MUTE_MAX).forEach(function (k) { delete m[k]; });
          }
          var obj = {}; obj[MUTE_KEY] = m;
          chrome.storage.local.set(obj, function () { res(); });
        });
      } catch (e) { res(); }
    });
  }

  function send(type, payload) { try { chrome.runtime.sendMessage({ type: type, payload: payload }); } catch (e) {} }
  function esc(s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }
  function proceedForm() { try { window.dispatchEvent(new Event("aitm:exfil-proceed")); } catch (e) {} }

  // ---------------- scoring ----------------
  var streamCount = 0, weakAcc = 0;
  function scoreSignal(d) {
    if (d.containsPassword) {
      return { score: 6, kind: "pw", reason: d.via === "form"
        ? "form đăng nhập gửi MẬT KHẨU bạn vừa nhập tới máy chủ ngoài"
        : "gửi MẬT KHẨU bạn vừa nhập sang máy chủ ngoài" };
    }
    if (d.exfilHost) return { score: 5, kind: "exfil", reason: "gửi dữ liệu tới kênh nhận dữ liệu thường dùng bởi phishing kit" };
    if (d.keyAligned) {
      streamCount++;
      if (streamCount >= 4) return { score: 5, kind: "stream", reason: "gửi dữ liệu ra ngoài theo từng phím gõ trong ô mật khẩu" };
      return { score: 0 };
    }
    if (d.via === "form" && d.formHasPassword) return { score: 3, kind: "formpw", reason: "form có ô mật khẩu gửi tới máy chủ ngoài" };
    var w = 0, reason = "", kind = "weak";
    if (d.containsIdentifier) { w = 2; kind = "id"; reason = "gửi email/tên đăng nhập bạn vừa nhập sang máy chủ ngoài"; }
    else if (d.via === "websocket") { w = 1; kind = "ws"; reason = "mở kết nối realtime tới máy chủ ngoài khi đang ở form đăng nhập"; }
    else if (d.credLikeKeys) { w = 1; reason = "gửi dữ liệu form sang máy chủ ngoài"; }
    if (w > 0) {
      var allowed = Math.max(0, WEAK_CAP - weakAcc);
      w = Math.min(w, allowed); weakAcc += w;
      if (w > 0) return { score: w, kind: kind, reason: reason };
    }
    return { score: 0 };
  }

  // ---------------- UI ----------------
  function overlay(cfg, state) {
    if (document.getElementById(HOST_ID)) return;
    var sites = Object.keys(state.siteSet), reasons = Object.keys(state.reasonSet);
    var strong = state.strong, blocked = state.blocked;
    var el = document.createElement("div");
    el.id = HOST_ID;
    var sh = el.attachShadow({ mode: "open" });
    var title = blocked
      ? "Đã tạm dừng: trang này định gửi mật khẩu bạn nhập tới máy chủ ngoài"
      : strong ? "Trang này vừa gửi mật khẩu bạn nhập ra máy chủ ngoài"
               : "Trang này có hành vi bất thường với thông tin đăng nhập";
    var lis = reasons.slice(0, 3).map(function (r) { return "<li>" + esc(r) + "</li>"; }).join("");
    var siteLine = sites.length ? "<div class='sites'>Máy chủ nhận: <b>" + esc(sites.slice(0, 3).join(", ")) + "</b>" + (sites.length > 3 ? " …" : "") + "</div>" : "";
    var hint = blocked
      ? "Mật khẩu CHƯA được gửi. Nếu đây là trang bạn tin cậy, bấm \"Báo nhầm – vẫn gửi\" (sẽ không cảnh báo lại trang này trong 30 ngày)."
      : strong ? "Hãy đổi mật khẩu ngay và báo " + esc(cfg.helpdeskContact || "IT Helpdesk") + "."
               : "Đây là cảnh báo tự động dựa trên hành vi, có thể nhầm với dịch vụ hợp lệ. Nếu đây là trang bạn tin cậy, bấm \"Báo nhầm\" (sẽ không cảnh báo lại trang này trong 30 ngày).";
    var fpLabel = blocked ? "Báo nhầm – vẫn gửi" : "Báo nhầm";

    sh.innerHTML = [
      "<style>",
      ":host{all:initial;}",
      ".bar{position:fixed;top:0;left:0;right:0;z-index:2147483647;background:" + (strong || blocked ? "#b3261e" : "#8a5a00") + ";color:#fff;font-family:'Segoe UI',Roboto,Arial,sans-serif;box-shadow:0 2px 12px rgba(0,0,0,.35);}",
      ".in{max-width:920px;margin:0 auto;padding:12px 16px;display:flex;gap:14px;align-items:flex-start;}",
      ".ic{font-size:22px;line-height:1.2;} .tx{flex:1;} .tx b{font-size:15px;} .tx ul{margin:6px 0 0;padding-left:18px;font-size:13px;line-height:1.5;}",
      ".sites{font-size:13px;margin-top:6px;opacity:.95;} .h{font-size:12px;opacity:.9;margin-top:6px;}",
      ".btns{display:flex;gap:8px;flex-wrap:wrap;} .btn{border:0;border-radius:6px;padding:8px 12px;font-size:13px;font-weight:600;cursor:pointer;}",
      ".p{background:#fff;color:#333;} .g{background:transparent;color:#fff;text-decoration:underline;}",
      "</style>",
      "<div class='bar'><div class='in'><div class='ic'>⚠</div>",
      "<div class='tx'><b>" + esc(title) + "</b><ul>" + lis + "</ul>" + siteLine + "<div class='h'>" + hint + "</div></div>",
      "<div class='btns'><button id='x-confirm' class='btn p'>Đúng, đáng ngờ</button><button id='x-fp' class='btn g'>" + esc(fpLabel) + "</button></div>",
      "</div></div>"
    ].join("");
    (document.documentElement || document.body).appendChild(el);

    sh.getElementById("x-confirm").addEventListener("click", function () {
      send("aitm-exfil-confirmed", { sites: sites, reasons: reasons, strong: strong, blocked: blocked, url: location.href, ts: new Date().toISOString() });
      var tx = sh.querySelector(".tx"), btns = sh.querySelector(".btns");
      tx.innerHTML = "<b>Đã gửi cảnh báo tới " + esc(cfg.helpdeskContact || "IT Helpdesk") + "</b><div class='h'>"
        + (blocked ? "Mật khẩu của bạn chưa bị gửi. Hãy đóng tab này."
           : strong ? "Nếu bạn đã nhập mật khẩu ở trang này, hãy ĐỔI MẬT KHẨU NGAY từ cổng chính thức."
                    : "Hãy đóng tab này nếu bạn không chắc chắn về trang. Tránh nhập thêm thông tin.") + "</div>";
      btns.innerHTML = "<button id='x-done' class='btn g'>Đóng</button>";
      sh.getElementById("x-done").addEventListener("click", function () { el.remove(); });
    });
    sh.getElementById("x-fp").addEventListener("click", function () {
      state.muted = true;                       // hiệu lực NGAY trong trang này
      saveMute(location.hostname);              // nhớ 30 ngày, extension-private
      send("aitm-exfil-false-positive", { sites: sites, reasons: reasons, strong: strong, blocked: blocked, url: location.href, ts: new Date().toISOString() });
      el.remove();
      if (state.blocked) { state.blocked = false; proceedForm(); }
    });
  }

  // ---------------- main ----------------
  Promise.all([loadCfg(), loadMuteList()]).then(function (arr) {
    var cfg = arr[0], muteList = arr[1];
    if (cfg.enabled === false) return;
    var mode = ["off", "warn"].indexOf(cfg.behaviorMode) >= 0 ? cfg.behaviorMode : "warn";
    if (mode === "off") return;

    try {
      if (Array.isArray(cfg.behaviorAllowlist) && cfg.behaviorAllowlist.length) {
        document.documentElement.setAttribute("data-aitm-allow", cfg.behaviorAllowlist.join(","));
      }
    } catch (e) {}

    var trusted = (window.AITMDetector ? AITMDetector.DEFAULT_TRUSTED_DOMAINS : [])
      .concat(cfg.trustedAuthDomains || []).concat(cfg.orgIdpDomains || []);
    try { if (window.AITMDetector && AITMDetector.isTrustedHost(location.hostname, trusted)) return; } catch (e) {}

    var state = {
      muted: !!muteList[location.hostname],
      shown: false, strong: false, blocked: false, acc: 0,
      reasonSet: {}, siteSet: {}
    };

    window.addEventListener("aitm:exfil", function (ev) {
      var d = ev.detail || {};

      // Không acknowledge: MAIN world để nguyên submit khi đã mute.
      if (state.muted) return;

      // Banner đã hiện/đã đóng: nếu lại có form bị soft-block thì phải hiện lại (không chặn âm thầm)
      if (state.shown) {
        if (d.blocked) {
          ev.preventDefault();
          state.blocked = true;
          if (!document.getElementById(HOST_ID) && !document.getElementById(O365_HOST_ID)) overlay(cfg, state);
        }
        return;
      }

      var r = scoreSignal(d);
      if (r.score <= 0) return;
      state.acc += r.score;
      if (r.kind === "pw" || r.kind === "exfil" || r.kind === "stream") state.strong = true;
      if (d.blocked) { ev.preventDefault(); state.blocked = true; }
      state.reasonSet[r.reason] = 1;
      if (d.site) state.siteSet[d.site] = 1;

      if (state.acc >= THRESHOLD || state.blocked) {
        state.shown = true;
        send("aitm-exfil-detected", {
          sites: Object.keys(state.siteSet), score: state.acc, strong: state.strong, blocked: state.blocked,
          reasons: Object.keys(state.reasonSet), url: location.href, referrer: document.referrer || "",
          ts: new Date().toISOString(), ua: navigator.userAgent
        });
        if (document.getElementById(O365_HOST_ID)) return;  // O365 overlay đang che, giữ block
        overlay(cfg, state);
      } else if (d.blocked) {
        state.blocked = false; proceedForm();               // chưa đủ điểm -> không giữ block
      }
    }, true);
  });
})();
