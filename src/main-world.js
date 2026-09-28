/*
 * main-world.js  (world: MAIN, run_at: document_start)  — v1.7.3
 *
 * Chạy trong JS context CỦA TRANG, TRƯỚC mọi script của trang. Ba việc:
 *
 * 0) Ngụy trang hàm đã hook thành native (v1.7.3):
 *    Script chống bot (Cloudflare Turnstile / managed challenge, reCAPTCHA...) kiểm tra
 *    Function.prototype.toString.call(fn), fn.name, fn.length của fetch/XHR/WebSocket/
 *    attachShadow/pushState. Trước đây các hook của extension lộ rõ (fetch.name === "f",
 *    toString trả về source JS) -> Cloudflare coi là môi trường bị can thiệp -> "không thể
 *    verify". Nay: một registry WeakMap {wrapped -> original}; Function.prototype.toString
 *    được thay bằng bản tra registry rồi gọi native toString trên hàm gốc. Registry được
 *    chia sẻ cho exfil-hook.js qua window.__aitmMainHooked.mask (non-enumerable, frozen).
 *
 * 1) Vá bypass "closed shadowRoot":
 *    Patch Element.prototype.attachShadow để ép mode 'closed' -> 'open'. Nhờ đó
 *    element.shadowRoot luôn khả dụng và detector (isolated world) duyệt được.
 *
 * 2) Vá bypass "SPA pushState":
 *    Patch History.prototype.pushState/replaceState để dispatch Event
 *    'aitm:navigate' trên window. Event DOM đi xuyên qua isolated world, nên
 *    content.js nghe được mà không cần polling.
 *
 * Trên host Microsoft chính chủ (TRUSTED, đồng bộ với DEFAULT_TRUSTED_DOMAINS của
 * detector.js): KHÔNG hook gì cả (content.js/exfil-content.js cũng bỏ qua các host này),
 * chỉ đánh dấu trusted=true để exfil-hook.js cũng đứng ngoài -> footprint bằng 0 trên
 * Outlook/Teams/OneDrive/Word Online.
 *
 * Frame captcha (challenges.cloudflare.com, google.com/recaptcha, *.hcaptcha.com) được
 * loại hẳn khỏi content script bằng exclude_matches trong manifest.
 *
 * Giới hạn (ghi trong README): trang có thể lấy attachShadow nguyên bản từ một
 * iframe mới tạo để né patch. Đây là hardening, không phải rào chắn tuyệt đối.
 */
(function () {
  try {
    if (window.__aitmMainHooked) return;

    // PHẢI đồng bộ với DEFAULT_TRUSTED_DOMAINS (detector.js)
    var TRUSTED = [
      "login.microsoftonline.com", "login.microsoftonline.us", "login.partner.microsoftonline.cn",
      "login.microsoft.com", "login.windows.net", "sts.windows.net",
      "login.live.com", "account.live.com", "account.microsoft.com",
      "b2clogin.com", "ciamlogin.com",
      "aadcdn.msauth.net", "aadcdn.msftauth.net", "aadcdn.msauthimages.net", "logincdn.msauth.net",
      // apex Microsoft sở hữu toàn bộ
      "live.com", "microsoft.com", "microsoftonline.com", "office.com", "office.net", "office365.com",
      "outlook.com", "hotmail.com", "onedrive.com", "1drv.ms", "windowsazure.com", "microsoftazuread-sso.com"
    ];
    var h = (location.hostname || "").toLowerCase().replace(/\.$/, "");
    var trusted = TRUSTED.some(function (d) { return h === d || h.endsWith("." + d); });

    // --- 0) Registry ngụy trang native ---
    var registry = new WeakMap();                 // wrapped -> original
    var nativeToString = Function.prototype.toString;
    function resolve(fn) {
      var seen = 0;
      while (fn && registry.has(fn) && seen++ < 8) fn = registry.get(fn);
      return fn;
    }
    // Method shorthand: không có .prototype, giống hàm native hơn function expression
    var maskedToString = {
      toString() {
        // this không phải function -> native tự ném TypeError như bình thường
        return nativeToString.call(resolve(this));
      }
    }.toString;
    function mask(wrapped, original) {
      try {
        registry.set(wrapped, original);
        Object.defineProperty(wrapped, "name", { value: original.name, configurable: true });
        Object.defineProperty(wrapped, "length", { value: original.length, configurable: true });
      } catch (e) {}
      return wrapped;
    }

    Object.defineProperty(window, "__aitmMainHooked", {
      value: Object.freeze({ trusted: trusted, mask: mask }),
      enumerable: false, configurable: false, writable: false
    });

    if (trusted) return; // host Microsoft chính chủ: không đụng vào trang

    mask(maskedToString, nativeToString);
    Object.defineProperty(Function.prototype, "toString", {
      value: maskedToString, writable: true, enumerable: false, configurable: true
    });

    // --- 1) attachShadow: closed -> open ---
    if (Element.prototype.attachShadow) {
      var origAttach = Element.prototype.attachShadow;
      var patched = {
        attachShadow(init) {
          try {
            if (init && init.mode === "closed") init = Object.assign({}, init, { mode: "open" });
          } catch (e) {}
          return origAttach.call(this, init);
        }
      }.attachShadow;
      Element.prototype.attachShadow = mask(patched, origAttach);
    }

    // --- 2) History hooks -> Event 'aitm:navigate' ---
    function wrapHistory(name) {
      var orig = History.prototype[name];
      if (typeof orig !== "function") return;
      var wrapped = {
        [name]() {
          var r = orig.apply(this, arguments);
          try { window.dispatchEvent(new Event("aitm:navigate")); } catch (e) {}
          return r;
        }
      }[name];
      History.prototype[name] = mask(wrapped, orig);
    }
    wrapHistory("pushState");
    wrapHistory("replaceState");
  } catch (e) {
    /* im lặng: không bao giờ làm hỏng trang */
  }
})();
