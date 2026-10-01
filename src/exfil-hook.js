/*
 * exfil-hook.js  (world: MAIN, run_at: document_start)  — v1.8.0
 *
 * v3 (rà soát thuật toán):
 *   1) BẮT FORM POST truyền thống (<form action="https://evil/post.php">) — điểm mù lớn nhất
 *      của v2. Listener 'submit' ở capture phase. Nếu form gửi MẬT KHẨU vừa gõ cross-site
 *      tới host không hợp lệ -> preventDefault (soft-block: user vẫn có nút "Vẫn gửi"),
 *      vì sau khi điều hướng thì cảnh báo không còn ý nghĩa.
 *   2) Vệ sinh allowlist: bỏ mọi apex PaaS đa-tenant mà attacker tự tạo được subdomain
 *      (amazonaws.com, cloudflare.com, firebaseapp.com, supabase.co, clerk.accounts.dev).
 *      Chỉ giữ endpoint IdP thật; Cognito/Turnstile thu hẹp về host cụ thể.
 *   3) Nhất quán với detector: "ô credential" gồm cả SURROGATE (contenteditable có nhãn
 *      password, input che bằng -webkit-text-security). credSeen STICKY cả vòng đời trang.
 *   5) Regex từ khóa body có biên -> không khớp passport/shipping/pinterest/client_secret.
 *
 * v1.8.0: background đăng ký theo managed policy, loại host tin cậy / CAPTCHA.
 *   Không ghi đè Function.prototype.toString, attachShadow hoặc History.
 *
 * RIÊNG TƯ: giá trị password chỉ đọc trong bộ nhớ MAIN world để so khớp, KHÔNG gửi đi,
 * KHÔNG log. Event 'aitm:exfil' chỉ mang boolean/host đã tóm tắt.
 */
(function () {
  "use strict";
  try {
    if (window.__aitmExfilHooked) return;
    Object.defineProperty(window, "__aitmExfilHooked", { value: true, enumerable: false });

    // Preserve standard metadata without replacing global reflection APIs.
    function wrapMetadata(wrapped, original) {
      Object.defineProperty(wrapped, "name", { value: original.name, configurable: true });
      Object.defineProperty(wrapped, "length", { value: original.length, configurable: true });
      return wrapped;
    }

    // ---------------- Domain helpers ----------------
    var TWO_LEVEL = /^(co|com|net|org|edu|gov|ac|or|ne)\.(vn|uk|au|jp|br|in|sg|my|id|tw|hk|kr|cn|tr|mx|ar|nz|za|th|ph)$/i;
    function regDomain(host) {
      host = (host || "").toLowerCase().replace(/\.$/, "");
      var p = host.split(".");
      if (p.length <= 2) return host;
      var last2 = p.slice(-2).join(".");
      return TWO_LEVEL.test(last2) ? p.slice(-3).join(".") : last2;
    }
    var pageSite = regDomain(location.hostname);
    function inList(host, list) {
      host = (host || "").toLowerCase();
      return list.some(function (d) { return host === d || host.endsWith("." + d); });
    }

    var EXFIL_HOSTS = ["t.me", "telegram.me", "api.telegram.org", "discord.com", "discordapp.com",
      "ptb.discord.com", "canary.discord.com", "formspree.io", "getform.io", "formsubmit.co",
      "api.emailjs.com", "webhook.site", "pipedream.net", "ntfy.sh", "requestbin.com", "hookbin.com"];

    // CHỈ endpoint IdP thật. KHÔNG apex PaaS (S3/EC2, Cloudflare Workers, Firebase Hosting,
    // Supabase...) vì attacker tự tạo được subdomain và đọc được plaintext ở đó.
    var AUTH_PROVIDERS = ["auth0.com", "okta.com", "oktapreview.com", "okta-emea.com", "onelogin.com",
      "pingidentity.com", "pingone.com", "duosecurity.com", "login.microsoftonline.com", "login.microsoft.com",
      "login.live.com", "accounts.google.com", "identitytoolkit.googleapis.com", "securetoken.googleapis.com",
      "appleid.apple.com", "amazoncognito.com", "clerk.com", "stytch.com", "descope.com", "frontegg.com",
      "authgear.com", "recaptcha.net", "hcaptcha.com", "challenges.cloudflare.com"];
    var AUTH_PATTERNS = [/^cognito-idp\.[a-z0-9-]+\.amazonaws\.com$/i, /^cognito-identity\.[a-z0-9-]+\.amazonaws\.com$/i];
    var PAYMENT = ["stripe.com", "paypal.com", "braintreegateway.com", "braintree-api.com", "adyen.com",
      "checkout.com", "squareup.com", "authorize.net", "worldpay.com", "cybersource.com", "2checkout.com",
      "razorpay.com", "vnpay.vn", "momo.vn", "zalopay.vn", "payoo.vn", "onepay.vn", "napas.com.vn"];
    var ANALYTICS = ["google-analytics.com", "analytics.google.com", "googletagmanager.com", "doubleclick.net",
      "googlesyndication.com", "googleadservices.com", "facebook.com", "facebook.net", "tiktok.com",
      "tiktokw.us", "tiktokv.com", "byteoversea.com", "snapchat.com", "sc-static.net", "pinterest.com",
      "pinimg.com", "linkedin.com", "licdn.com", "bing.com", "clarity.ms", "hotjar.com", "hotjar.io",
      "fullstory.com", "mouseflow.com", "smartlook.com", "logrocket.io", "lr-ingest.io", "contentsquare.net",
      "heap.io", "heapanalytics.com", "pendo.io", "posthog.com", "mixpanel.com", "segment.io", "segment.com",
      "amplitude.com", "sentry.io", "datadoghq.com", "newrelic.com", "nr-data.net", "criteo.com",
      "taboola.com", "outbrain.com", "twitter.com", "x.com", "ads-twitter.com", "plausible.io",
      "matomo.cloud", "cloudflareinsights.com", "intercom.io", "crisp.chat", "zendesk.com", "hubspot.com",
      "hs-analytics.net", "hsforms.com", "klaviyo.com", "mailchimp.com", "optimizely.com", "vwo.com",
      "launchdarkly.com", "statsig.com", "split.io", "braze.com", "onesignal.com", "appsflyer.com",
      "adjust.com", "branch.io"];

    function extraAllow() {
      try {
        var v = document.documentElement.getAttribute("data-aitm-allow") || "";
        return v ? v.split(",").map(function (s) { return s.trim().toLowerCase(); }).filter(Boolean) : [];
      } catch (e) { return []; }
    }
    function isAllowlisted(host) {
      if (inList(host, AUTH_PROVIDERS) || inList(host, PAYMENT) || inList(host, extraAllow())) return true;
      for (var i = 0; i < AUTH_PATTERNS.length; i++) if (AUTH_PATTERNS[i].test(host)) return true;
      return false;
    }

    // ---------------- Nhận diện ô credential (đồng bộ với detector.js) ----------------
    // Cho THUỘC TÍNH field: lenient (user_password, txtPwd...)
    var ATTR_CRED = /pass|pwd|mật\s*khẩu|matkhau|passphrase|otp|\bpin\b|cvv|secret/i;
    // Cho BODY request: có biên -> không khớp passport/shipping/pinterest/client_secret
    var BODY_CRED = /(?<![a-z])(pass(word|wd|phrase)?|pwd|matkhau|otp|pin|cvv|(?<!client_)secret)(?![a-z])|mật\s*khẩu/i;

    function isMaskedEl(el) {
      try {
        var v = (getComputedStyle(el).getPropertyValue("-webkit-text-security") || "").trim();
        if (v && v !== "none") return true;
        return /-webkit-text-security\s*:\s*(disc|circle|square)/i.test(el.getAttribute("style") || "");
      } catch (e) { return false; }
    }
    function attrBag(el) {
      return [el.getAttribute("name"), el.getAttribute("id"), el.getAttribute("placeholder"),
        el.getAttribute("aria-label"), el.getAttribute("autocomplete"), el.getAttribute("data-label")]
        .filter(Boolean).join(" ");
    }
    function isEditableEl(el) {
      var ce = el.getAttribute && el.getAttribute("contenteditable");
      return el.isContentEditable === true || ce === "" || ce === "true" || el.getAttribute && el.getAttribute("role") === "textbox";
    }
    function isCredField(el) {
      if (!el || !el.getAttribute) return false;
      if (el.tagName === "INPUT") {
        var t = (el.getAttribute("type") || "text").toLowerCase();
        if (t === "password") return true;
        if (t === "hidden" || t === "submit" || t === "button" || t === "checkbox") return false;
        return isMaskedEl(el) || ATTR_CRED.test(attrBag(el));
      }
      if (isEditableEl(el)) {
        if (isMaskedEl(el) || ATTR_CRED.test(attrBag(el))) return true;
        var prev = el.previousElementSibling;
        return !!(prev && ATTR_CRED.test((prev.textContent || "").slice(0, 40)));
      }
      return false;
    }
    var SURROGATE_SEL = 'input[type="text"], input[type="tel"], input:not([type]), [contenteditable=""], [contenteditable="true"], [role="textbox"]';
    function findSurrogateIn(root) {
      try {
        var els = root.querySelectorAll(SURROGATE_SEL);
        for (var i = 0; i < els.length && i < 300; i++) if (isCredField(els[i])) return els[i];
      } catch (e) {}
      return null;
    }

    var credSeen = false, credFocused = false, lastKeyTs = 0, keyInCredCount = 0;
    var lastScanTs = 0, lastScanResult = false;
    function pageHasCredField() {
      if (credSeen) return true;
      var now = Date.now();
      if (now - lastScanTs < 500) return lastScanResult;      // cache 500ms, tránh quét lặp
      lastScanTs = now;
      try {
        lastScanResult = !!document.querySelector('input[type="password"]') || !!findSurrogateIn(document);
      } catch (e) { lastScanResult = false; }
      if (lastScanResult) credSeen = true;                    // STICKY
      return lastScanResult;
    }
    document.addEventListener("focusin", function (e) {
      credFocused = isCredField(e.target);
      if (credFocused) credSeen = true;
    }, true);
    document.addEventListener("focusout", function () { credFocused = false; }, true);
    window.addEventListener("keydown", function (e) {
      if (credFocused && e.key && e.key.length === 1) { lastKeyTs = Date.now(); keyInCredCount++; }
    }, true);

    // Giá trị bí mật hiện tại (password thật + surrogate) — chỉ để so khớp
    function currentSecrets() {
      var out = [];
      try {
        var pws = document.querySelectorAll('input[type="password"]');
        for (var i = 0; i < pws.length; i++) { var v = pws[i].value; if (v && v.length >= 4) out.push(v); }
        var els = document.querySelectorAll(SURROGATE_SEL);
        for (var j = 0; j < els.length && j < 300; j++) {
          var el = els[j];
          if (!isCredField(el)) continue;
          var val = el.tagName === "INPUT" ? el.value : (el.textContent || "");
          if (val && val.length >= 4) out.push(val.trim());
        }
      } catch (e) {}
      return out;
    }
    function currentIdentifiers() {
      var out = [];
      try {
        var els = document.querySelectorAll('input[type="email"], input[autocomplete="username"], input[name*="user" i], input[name*="email" i], input[id*="user" i], input[id*="email" i]');
        for (var i = 0; i < els.length; i++) { var v = els[i].value; if (v && v.length >= 5) out.push(v); }
      } catch (e) {}
      return out;
    }
    function encodings(v) {
      var arr = [v];
      try { arr.push(encodeURIComponent(v)); } catch (e) {}
      try { arr.push(JSON.stringify(v).slice(1, -1)); } catch (e) {}
      try { arr.push(btoa(unescape(encodeURIComponent(v)))); } catch (e) {}
      return arr;
    }
    function bodyContainsAny(bodyStr, values) {
      if (!bodyStr || !values.length) return false;
      for (var i = 0; i < values.length; i++) {
        var enc = encodings(values[i]);
        for (var j = 0; j < enc.length; j++) if (enc[j] && bodyStr.indexOf(enc[j]) >= 0) return true;
      }
      return false;
    }
    function bodyToString(body) {
      try {
        if (!body) return "";
        if (typeof body === "string") return body.slice(0, 65536);
        if (body instanceof URLSearchParams) return body.toString().slice(0, 65536);
        if (typeof FormData !== "undefined" && body instanceof FormData) {
          var parts = []; body.forEach(function (v, k) { if (typeof v === "string") parts.push(k + "=" + v); });
          return parts.join("&").slice(0, 65536);
        }
        if (body instanceof ArrayBuffer || ArrayBuffer.isView(body)) {
          var bytes = body instanceof ArrayBuffer ? new Uint8Array(body) : new Uint8Array(body.buffer, body.byteOffset, body.byteLength);
          return new TextDecoder().decode(bytes.subarray(0, 65536));
        }
      } catch (e) {}
      return "";
    }

    // A submit is blocked only if the isolated UI acknowledges the signal.
    // Policy off, muted sites or a listener still loading must not trap the form.
    function emit(sig) {
      try { return !window.dispatchEvent(new CustomEvent("aitm:exfil", { detail: sig, cancelable: true })); }
      catch (e) { return false; }
    }

    // ---------------- Đánh giá request JS (fetch/xhr/beacon/image) ----------------
    function assess(urlStr, body, via) {
      if (!pageHasCredField()) return;
      var u; try { u = new URL(urlStr, location.href); } catch (e) { return; }
      var host = u.hostname.toLowerCase(), site = regDomain(host);
      if (site === pageSite) return;
      if (isAllowlisted(host)) return;

      var exfilHost = inList(host, EXFIL_HOSTS), isAnalytics = inList(host, ANALYTICS);
      var bodyStr = bodyToString(body) + " " + (u.search || "");
      var containsPassword = bodyContainsAny(bodyStr, currentSecrets());
      var containsIdentifier = !containsPassword && bodyContainsAny(bodyStr, currentIdentifiers());
      var keyAligned = credFocused && (Date.now() - lastKeyTs) < 250 && keyInCredCount > 0;
      var credLikeKeys = BODY_CRED.test(bodyStr.slice(0, 4000));

      if (containsPassword || exfilHost || (!isAnalytics && (containsIdentifier || keyAligned || credLikeKeys))) {
        emit({ via: via, host: host, site: site, exfilHost: exfilHost, isAnalytics: isAnalytics,
               containsPassword: containsPassword, containsIdentifier: containsIdentifier,
               keyAligned: keyAligned, credLikeKeys: credLikeKeys, formHasPassword: false, blocked: false });
      }
    }

    // ---------------- (1) FORM POST truyền thống ----------------
    var pendingForm = null, pendingSubmitter = null;
    var bypass = (typeof WeakSet !== "undefined") ? new WeakSet() : { has: function () { return false; }, add: function () {}, delete: function () {} };

    document.addEventListener("submit", function (e) {
      try {
        var form = e.target;
        if (!form || form.tagName !== "FORM") return;
        if (bypass.has(form)) { bypass.delete(form); return; }      // user đã chọn "Vẫn gửi"

        var submitter = e.submitter;
        var actionAttr = submitter && submitter.hasAttribute("formaction")
          ? submitter.getAttribute("formaction") : form.getAttribute("action");
        var u = new URL(actionAttr || location.href, location.href);
        var host = u.hostname.toLowerCase(), site = regDomain(host);
        if (site === pageSite) return;
        if (isAllowlisted(host)) return;

        var formHasPw = !!(form.querySelector('input[type="password"]') || findSurrogateIn(form));
        if (!formHasPw && !credSeen) return;

        var fd = ""; try { fd = bodyToString(new FormData(form)); } catch (er) {}
        var containsPassword = bodyContainsAny(fd, currentSecrets());
        var containsIdentifier = !containsPassword && bodyContainsAny(fd, currentIdentifiers());
        var exfilHost = inList(host, EXFIL_HOSTS);

        // Soft-block: chỉ khi CHẮC (mật khẩu thật đang rời trang, hoặc form password tới kênh exfil)
        var strong = containsPassword || (exfilHost && formHasPw);
        var handled = emit({ via: "form", host: host, site: site, exfilHost: exfilHost, isAnalytics: false,
               containsPassword: containsPassword, containsIdentifier: containsIdentifier,
               keyAligned: false, credLikeKeys: false, formHasPassword: formHasPw, blocked: strong });
        if (strong && handled) {
          e.preventDefault(); e.stopImmediatePropagation();
          pendingForm = form; pendingSubmitter = submitter;
        }
      } catch (er) {}
    }, true);

    // isolated world báo "Vẫn gửi" -> nộp lại form, bỏ qua kiểm tra một lần
    window.addEventListener("aitm:exfil-proceed", function () {
      var f = pendingForm, submitter = pendingSubmitter;
      pendingForm = null; pendingSubmitter = null;
      if (!f) return;
      bypass.add(f);
      try { if (f.requestSubmit) f.requestSubmit(submitter || undefined); else f.submit(); }
      catch (e) { try { f.submit(); } catch (_) {} }
      finally { bypass.delete(f); } // validation failure must not exempt a later submit
    });

    // ---------------- Hooks JS API ----------------
    // Forward original arguments and receivers; preserve native errors.
    if (window.fetch) {
      var origFetch = window.fetch;
      window.fetch = wrapMetadata({
        fetch(input, init) {
          try { assess((typeof input === "string") ? input : (input && input.url) || "", init && init.body, "fetch"); } catch (e) {}
          return origFetch.apply(this, arguments);
        }
      }.fetch, origFetch);
    }
    if (window.XMLHttpRequest) {
      var op = XMLHttpRequest.prototype.open, se = XMLHttpRequest.prototype.send;
      var xhrUrl = new WeakMap();                 // không gắn thuộc tính lạ lên instance XHR
      XMLHttpRequest.prototype.open = wrapMetadata({
        open(method, url) { try { xhrUrl.set(this, url); } catch (e) {} return op.apply(this, arguments); }
      }.open, op);
      XMLHttpRequest.prototype.send = wrapMetadata({
        send(body) { try { assess(xhrUrl.get(this) || "", body, "xhr"); } catch (e) {} return se.apply(this, arguments); }
      }.send, se);
    }
    if (Navigator.prototype.sendBeacon) {
      var sb = Navigator.prototype.sendBeacon;
      Navigator.prototype.sendBeacon = wrapMetadata({
        sendBeacon(url, data) { try { assess(url, data, "beacon"); } catch (e) {} return sb.apply(this, arguments); }
      }.sendBeacon, sb);
    }
    if (window.WebSocket) {
      var OrigWS = window.WebSocket;
      var WS = function WebSocket(url, proto) {
        if (!new.target) throw new TypeError("WebSocket requires new");
        try {
          if (pageHasCredField()) {
            var u = new URL(url, location.href), host = u.hostname.toLowerCase();
            if (regDomain(host) !== pageSite && !inList(host, ANALYTICS) && !isAllowlisted(host)) {
              emit({ via: "websocket", host: host, site: regDomain(host), exfilHost: inList(host, EXFIL_HOSTS), isAnalytics: false,
                     containsPassword: false, containsIdentifier: false, keyAligned: false, credLikeKeys: false, formHasPassword: false, blocked: false });
            }
          }
        } catch (e) {}
        return Reflect.construct(OrigWS, Array.from(arguments), new.target);
      };
      // Giữ nguyên hình dạng native: prototype chung, static CONNECTING/OPEN/... với descriptor gốc,
      // prototype.constructor trỏ về wrapper để `ws.constructor === WebSocket`.
      try {
        Object.defineProperty(WS, "prototype", { value: OrigWS.prototype, writable: false, enumerable: false, configurable: false });
        Object.getOwnPropertyNames(OrigWS).forEach(function (k) {
          if (k === "prototype" || k === "name" || k === "length") return;
          var d = Object.getOwnPropertyDescriptor(OrigWS, k);
          if (d) try { Object.defineProperty(WS, k, d); } catch (e) {}
        });
        Object.defineProperty(OrigWS.prototype, "constructor", { value: WS, writable: true, enumerable: false, configurable: true });
      } catch (e) {}
      window.WebSocket = wrapMetadata(WS, OrigWS);
    }
    try {
      var d = Object.getOwnPropertyDescriptor(HTMLImageElement.prototype, "src");
      if (d && d.set) {
        var setSrc = Object.getOwnPropertyDescriptor({
          set src(v) { try { assess(String(v), "", "image"); } catch (e) {} return d.set.call(this, v); }
        }, "src").set;
        Object.defineProperty(HTMLImageElement.prototype, "src", {
          set: wrapMetadata(setSrc, d.set), get: d.get, enumerable: d.enumerable, configurable: true
        });
      }
    } catch (e) {}
  } catch (e) { /* không bao giờ làm hỏng trang */ }
})();
