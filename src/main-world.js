/*
 * main-world.js  (world: MAIN, run_at: document_start)
 *
 * Chạy trong JS context CỦA TRANG, TRƯỚC mọi script của trang. Hai việc:
 *
 * 1) Vá bypass "closed shadowRoot":
 *    Patch Element.prototype.attachShadow để ép mode 'closed' -> 'open'. Nhờ đó
 *    element.shadowRoot luôn khả dụng và detector (isolated world) duyệt được.
 *    Bỏ qua trên host Microsoft chính chủ để giảm footprint.
 *
 * 2) Vá bypass "SPA pushState":
 *    Patch History.prototype.pushState/replaceState để dispatch Event
 *    'aitm:navigate' trên window. Event DOM đi xuyên qua isolated world, nên
 *    content.js nghe được mà không cần polling.
 *
 * Giới hạn (ghi trong README): trang có thể lấy attachShadow nguyên bản từ một
 * iframe mới tạo để né patch. Đây là hardening, không phải rào chắn tuyệt đối.
 */
(function () {
  try {
    if (window.__aitmMainHooked) return;
    Object.defineProperty(window, "__aitmMainHooked", { value: true, enumerable: false });

    var TRUSTED = [
      "login.microsoftonline.com", "login.microsoftonline.us",
      "login.partner.microsoftonline.cn", "login.microsoft.com", "login.windows.net",
      "login.live.com", "account.microsoft.com", "account.live.com",
      "b2clogin.com", "ciamlogin.com", "microsoft.com", "office.com", "office365.com",
      "microsoftonline.com", "live.com", "windowsazure.com", "microsoftazuread-sso.com"
    ];
    var h = (location.hostname || "").toLowerCase();
    var trusted = TRUSTED.some(function (d) { return h === d || h.endsWith("." + d); });

    // --- 1) attachShadow: closed -> open (chỉ trên host không tin cậy) ---
    if (!trusted && Element.prototype.attachShadow) {
      var origAttach = Element.prototype.attachShadow;
      var patched = function attachShadow(init) {
        try {
          if (init && init.mode === "closed") {
            init = Object.assign({}, init, { mode: "open" });
          }
        } catch (e) {}
        return origAttach.call(this, init);
      };
      // giữ toString giống native để giảm khả năng bị dò
      try {
        patched.toString = function () { return origAttach.toString(); };
      } catch (e) {}
      Element.prototype.attachShadow = patched;
    }

    // --- 2) History hooks -> Event 'aitm:navigate' ---
    function wrapHistory(name) {
      var orig = History.prototype[name];
      if (typeof orig !== "function") return;
      var wrapped = function () {
        var r = orig.apply(this, arguments);
        try { window.dispatchEvent(new Event("aitm:navigate")); } catch (e) {}
        return r;
      };
      try { wrapped.toString = function () { return orig.toString(); }; } catch (e) {}
      History.prototype[name] = wrapped;
    }
    wrapHistory("pushState");
    wrapHistory("replaceState");
  } catch (e) {
    /* im lặng: không bao giờ làm hỏng trang */
  }
})();
