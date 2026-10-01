/*
 * detector.js  (v1.7.3)
 * Toàn bộ logic phát hiện. Chạy trong isolated world của content script.
 *
 * NGUYÊN LÝ CHỐNG evilginx / AiTM:
 *   evilginx proxy NGUYÊN BẢN trang Microsoft thật -> DOM giống hệt -> không thể
 *   phân biệt bằng giao diện. Tín hiệu đáng tin cậy duy nhất là DOMAIN.
 *
 * LUẬT:
 *   IF host KHÔNG thuộc allowlist
 *   AND ( [URL path đặc trưng AAD]  OR  [ô credential + vân tay DOM đủ điểm] )
 *   => PHISHING
 *
 * v1.1:
 *   - Allowlist bổ sung các host MS hợp lệ bị thiếu ở v1.0 (tránh false positive)
 *   - Tín hiệu URL PATH: evilginx proxy nguyên path AAD (/common/oauth2/v2.0/authorize,
 *     /kmsi, /login.srf...) -> path AAD trên host lạ là tín hiệu rất đặc hiệu, độc lập
 *     DOM, có ngay từ document_start.
 *   - Gate rẻ trước (querySelector light DOM) rồi mới duyệt shadow + serialize HTML.
 *   - validatePolicy(): cảnh báo orgIdpDomains khai apex quá rộng.
 */

var AITMDetector = (function () {
  "use strict";

  // --- Host đăng nhập CHÍNH THỨC của Microsoft (khớp host hoặc subdomain hợp lệ) ---
  var DEFAULT_TRUSTED_DOMAINS = [
    // Entra ID / Azure AD
    "login.microsoftonline.com",
    "login.microsoftonline.us",            // GCC High / DoD
    "login.partner.microsoftonline.cn",    // 21Vianet
    "login.microsoft.com",
    "login.windows.net",
    "sts.windows.net",
    "device.login.microsoftonline.com",
    "passwordreset.microsoftonline.com",
    "mysignins.microsoft.com",
    "aka.ms",
    "msft.sts.microsoft.com",
    "autologon.microsoftazuread-sso.com",  // Seamless SSO
    "account.activedirectory.windowsazure.com",
    // Microsoft Account (consumer)
    "login.live.com",
    "account.live.com",
    "account.microsoft.com",
    // Entra External ID / B2C
    "b2clogin.com",
    "ciamlogin.com",
    // CDN tài nguyên trang login
    "aadcdn.msauth.net",
    "aadcdn.msftauth.net",
    "aadcdn.msauthimages.net",
    "logincdn.msauth.net",
    // --- Apex do Microsoft sở hữu TOÀN BỘ (không có subdomain của bên thứ ba) ---
    // v1.7.3: thiếu các apex này -> OneDrive / Word Online / Outlook consumer
    // (onedrive.live.com, *.officeapps.live.com, outlook.live.com...) bị chấm điểm
    // như host lạ -> false positive. Background dùng cùng danh sách để loại hook.
    // KHÔNG thêm apex đa-tenant (sharepoint.com, azurewebsites.net,
    // blob.core.windows.net, azurestaticapps.net...) vì attacker tự tạo được subdomain.
    "live.com",
    "microsoft.com",
    "microsoftonline.com",
    "office.com",
    "office.net",
    "office365.com",
    "outlook.com",
    "hotmail.com",
    "onedrive.com",
    "1drv.ms",
    "windowsazure.com",
    "microsoftazuread-sso.com"
  ];

  // --- Path đặc trưng của AAD (evilginx giữ nguyên path khi proxy) ---
  var AAD_PATH_PATTERNS = [
    // /common|organizations|consumers|<tenant-guid>/oauth2/(v2.0/)?authorize
    /^\/(common|organizations|consumers|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\/oauth2\/(v2\.0\/)?(authorize|token|logout)/i,
    /^\/(common|organizations|consumers)\/(login|reprocess|SAS\/ProcessAuth|GetCredentialType|federation)/i,
    /^\/kmsi\b/i,                 // "Keep me signed in"
    /^\/login\.srf/i,             // MSA login
    /^\/ppsecure\/post\.srf/i,    // MSA post
    /^\/consumers\/GetCredentialType/i
  ];
  // Query string kiểu AAD authorize
  var AAD_QUERY_PATTERN = /(^|[?&])client_id=[^&]+.*(^|[?&])redirect_uri=/i;

  function normalizeHost(h) {
    return (h || "").toLowerCase().replace(/\.$/, "");
  }

  function isTrustedHost(hostname, trustedList) {
    var h = normalizeHost(hostname);
    if (!h) return false;
    return trustedList.some(function (d) {
      d = normalizeHost(d);
      return h === d || h.endsWith("." + d);
    });
  }

  // Dấu hiệu domain đáng ngờ. Trả {score, signals}. Chỉ chạy trên host KHÔNG tin cậy.
  function domainRiskSignals(hostname) {
    var h = normalizeHost(hostname);
    var s = [], score = 0;
    if (/(^|\.)xn--/.test(h)) { s.push("punycode (IDN homograph)"); score += 2; }
    if (/microsoft[-_.]online|online[-_.]microsoft|login[-_.]micro|micr[o0]s[o0]ft|0ffice|0utlook/.test(h)) {
      s.push("biến thể typosquat của thương hiệu Microsoft"); score += 2;
    } else if (/microsoft|microsoftonline|msftauth|office365|o365|outlook|entra|azure/.test(h)) {
      s.push("chứa từ khóa thương hiệu Microsoft trên domain không hợp lệ"); score += 1;
    }
    // Host trên nền tảng PaaS đa-tenant + đang mang trang login -> đáng ngờ nhẹ
    if (/\.(workers\.dev|pages\.dev|web\.app|firebaseapp\.com|netlify\.app|vercel\.app|github\.io|herokuapp\.com|r2\.dev|glitch\.me|repl\.co|onrender\.com)$/i.test(h)) {
      s.push("host trên nền tảng PaaS miễn phí"); score += 1;
    }
    return { score: score, signals: s };
  }

  /**
   * Chấm điểm URL path/query. Trả về {score, hits}.
   * Path AAD trên host lạ: +4 (đủ mạnh để cảnh báo mà không cần chờ form render).
   */
  function scoreUrlPath(pathname, search) {
    var score = 0, hits = [];
    var p = pathname || "";
    var q = search || "";
    for (var i = 0; i < AAD_PATH_PATTERNS.length; i++) {
      if (AAD_PATH_PATTERNS[i].test(p)) {
        score += 4;
        hits.push("URL path AAD: " + p.split("?")[0].slice(0, 60));
        break;
      }
    }
    if (AAD_QUERY_PATTERN.test(q) && /scope=|response_type=|response_mode=/i.test(q)) {
      score += 1;
      hits.push("query kiểu OAuth authorize");
    }
    return { score: score, hits: hits };
  }

  // ---------------------------------------------------------------------------
  // Đọc cả closed Shadow DOM từ isolated world, không sửa attachShadow của trang.
  // ---------------------------------------------------------------------------
  var MAX_ROOTS = 4000;

  function shadowRootOf(el) {
    try {
      if (typeof chrome !== "undefined" && chrome.dom && chrome.dom.openOrClosedShadowRoot) {
        return chrome.dom.openOrClosedShadowRoot(el);
      }
    } catch (e) {}
    return el.shadowRoot || null;
  }

  function collectRoots(startNode) {
    var roots = [];
    if (!startNode) return roots;
    var queue = [startNode];
    var seen = new Set(queue);
    function enqueueShadow(el) {
      var sr = shadowRootOf(el);
      if (sr && !seen.has(sr) && seen.size < MAX_ROOTS) {
        seen.add(sr);
        queue.push(sr);
      }
    }
    for (var q = 0; q < queue.length && roots.length < MAX_ROOTS; q++) {
      var r = queue[q];
      roots.push(r);
      if (r.nodeType === 1) enqueueShadow(r);
      var all;
      try { all = r.querySelectorAll ? r.querySelectorAll("*") : []; } catch (e) { all = []; }
      for (var i = 0; i < all.length; i++) {
        enqueueShadow(all[i]);
      }
    }
    return roots;
  }

  function deepQuery(roots, selector) {
    for (var i = 0; i < roots.length; i++) {
      try { var m = roots[i].querySelector(selector); if (m) return m; } catch (e) {}
    }
    return null;
  }

  function deepHtml(roots) {
    var parts = [], total = 0, CAP = 4 * 1024 * 1024;
    for (var i = 0; i < roots.length && total < CAP; i++) {
      var chunk = "";
      try { chunk = roots[i].innerHTML || ""; } catch (e) {}
      total += chunk.length;
      parts.push(chunk);
    }
    return parts.join("\n");
  }

  var CRED_SELECTOR =
    'input[name="passwd"], input[name="loginfmt"], #i0118, #i0116, input[type="password"]';

  // Ứng viên "ô nhập giả": không phải <input type=password> nhưng gõ được
  var SURROGATE_SELECTOR =
    '[contenteditable=""], [contenteditable="true"], [role="textbox"], ' +
    'input[type="text"], input[type="tel"], input:not([type]), input[type="email"]';

  var PW_KEYWORDS = /pass\s*word|mật\s*khẩu|matkhau|\bpwd\b|passphrase|mã\s*pin/i;

  // Ô có bị che ký tự kiểu password không? (-webkit-text-security là dấu hiệu
  // rất đặc trưng của ô password GIẢ — site thật dùng input[type=password]).
  function isMasked(el, win) {
    try {
      var v = "";
      if (win && win.getComputedStyle) {
        v = win.getComputedStyle(el).getPropertyValue("-webkit-text-security") || "";
      }
      if (!v && el.style) v = el.style.getPropertyValue("-webkit-text-security") || "";
      if (v && v !== "none") return true;
      // fallback: masking đặt inline qua thuộc tính style (phishing hay dùng)
      var raw = (el.getAttribute && el.getAttribute("style")) || "";
      return /-webkit-text-security\s*:\s*(disc|circle|square)/i.test(raw);
    } catch (e) { return false; }
  }

  // Element này có "ngữ nghĩa password" không? (nhãn/placeholder/aria/thuộc tính)
  function hasPwSemantics(el) {
    try {
      var bag = [
        el.getAttribute("aria-label"), el.getAttribute("placeholder"),
        el.getAttribute("name"), el.getAttribute("id"),
        el.getAttribute("autocomplete"), el.getAttribute("data-label")
      ].filter(Boolean).join(" ");
      if (/current-password|new-password/.test(el.getAttribute("autocomplete") || "")) return true;
      if (PW_KEYWORDS.test(bag)) return true;
      // nhãn ngay trước element
      var prev = el.previousElementSibling;
      if (prev && PW_KEYWORDS.test((prev.textContent || "").slice(0, 40))) return true;
      // <label for=id> ở bất kỳ đâu (tránh CSS.escape để không phụ thuộc môi trường)
      var doc = el.ownerDocument, id = el.getAttribute("id");
      if (id && doc && doc.getElementsByTagName) {
        var labels = doc.getElementsByTagName("label");
        for (var k = 0; k < labels.length; k++) {
          if (labels[k].getAttribute("for") === id && PW_KEYWORDS.test(labels[k].textContent || "")) return true;
        }
      }
    } catch (e) {}
    return false;
  }

  /**
   * Gate: có bề mặt nhập credential không? Thử light DOM trước (rẻ).
   * Nếu không có <input type=password> thật thì tìm SURROGATE (fix bypass
   * contenteditable / ô password giả bằng -webkit-text-security).
   * @return {found, roots, surrogate, surrogateScore, signals}
   */
  function findCredentialField(doc, win) {
    win = win || doc.defaultView || (typeof window !== "undefined" ? window : null);
    // 1) Ô thật — nhanh nhất
    try {
      if (doc.querySelector(CRED_SELECTOR)) return { found: true, roots: null, surrogate: false, surrogateScore: 0, signals: [] };
    } catch (e) {}
    var roots = collectRoots(doc.documentElement || doc);
    if (deepQuery(roots, CRED_SELECTOR)) return { found: true, roots: roots, surrogate: false, surrogateScore: 0, signals: [] };

    // 2) Ô GIẢ — quét có giới hạn
    var signals = [], score = 0, found = false, MAX = 400, seen = 0;
    for (var i = 0; i < roots.length && seen < MAX; i++) {
      var els;
      try { els = roots[i].querySelectorAll(SURROGATE_SELECTOR); } catch (e) { els = []; }
      for (var j = 0; j < els.length && seen < MAX; j++, seen++) {
        var el = els[j];
        if (isMasked(el, win)) {                       // ô password giả (che ký tự)
          found = true; score += 3;
          if (signals.indexOf("ô password giả (-webkit-text-security)") < 0) signals.push("ô password giả (-webkit-text-security)");
        } else if ((el.isContentEditable || el.getAttribute("role") === "textbox") && hasPwSemantics(el)) {
          found = true; score += 2;
          if (signals.indexOf("ô nhập giả contenteditable/role=textbox có nhãn password") < 0) signals.push("ô nhập giả contenteditable/role=textbox có nhãn password");
        }
      }
    }
    return { found: found, roots: roots, surrogate: found, surrogateScore: score, signals: signals };
  }

  /**
   * Chấm điểm vân tay DOM trang login Microsoft (Azure AD / Entra ID).
   * evilginx KHÔNG đổi tên các selector này (phải để JS gốc của MS chạy).
   */
  function scoreMicrosoftLogin(doc, roots, html) {
    var score = 0, hits = [];
    if (!roots) roots = collectRoots(doc.documentElement || doc);
    if (html == null) html = deepHtml(roots);

    var domChecks = [
      ['input[name="loginfmt"]', 3, "field username 'loginfmt'"],
      ["#i0116", 2, "username #i0116"],
      ['input[name="passwd"]', 3, "field password 'passwd'"],
      ["#i0118", 2, "password #i0118"],
      ["#idSIButton9", 2, "nút Sign in #idSIButton9"],
      ["#lightbox", 1, "container #lightbox"],
      ['input[name="urlMsaSignUp"]', 1, "hidden field MSA"]
    ];
    domChecks.forEach(function (c) {
      if (deepQuery(roots, c[0])) { score += c[1]; hits.push(c[2]); }
    });

    if (/\$Config\s*=\s*\{/.test(html) || /"sCtx"|"urlLogin"|"sFT"|"canaryUrl"/.test(html)) {
      score += 3; hits.push("$Config (AAD)");
    }
    if (/aadcdn\.ms(ft)?auth\.net|logincdn\.msauth\.net/.test(html)) {
      score += 2; hits.push("CDN msauth");
    }
    if (/ConvergedSignIn|ConvergedSignInPaginatedStrings|CXH|Login\.PostMsa/.test(html)) {
      score += 1; hits.push("Converged sign-in framework");
    }
    if (/Sign in to your account|Stay signed in\?|Đăng nhập vào tài khoản của bạn|Duy trì đăng nhập/i.test(html)) {
      score += 1; hits.push("chuỗi thương hiệu trang login");
    }
    return { score: score, hits: hits };
  }

  /**
   * Vân tay THƯƠNG HIỆU Microsoft — KHÔNG phụ thuộc tên field.
   * Mục tiêu: clone tĩnh đổi tên loginfmt/passwd vẫn bị bắt.
   * v3: SIẾT để giảm false positive — chỉ dùng class/chuỗi ĐẶC HỮU của trang AAD,
   * bỏ các class generic (table-cell, inner-container...) và chuỗi generic
   * ("Forgot my password", "Sign-in options") vốn xuất hiện đầy trên web hợp lệ.
   * TỔNG điểm brand bị CAP ở 4 -> brand KHÔNG bao giờ tự vượt ngưỡng, phải đi kèm
   * path AAD / tên field MS / BitB / surrogate / domain đáng ngờ.
   */
  var BRAND_CAP = 4;
  function scoreBrandFingerprint(roots, html) {
    var score = 0, hits = [];

    // Logo Microsoft: chỉ tính alt/aria (ngữ nghĩa rõ) hoặc SVG 4-ô-vuông đặc trưng.
    // KHÔNG dùng img[src*=microsoft] vì khớp nút "Sign in with Microsoft" hợp lệ.
    if (deepQuery(roots, 'img[alt="Microsoft" i], img[alt*="Microsoft account" i], [aria-label="Microsoft" i]')) {
      score += 2; hits.push("logo/nhãn Microsoft");
    } else if (/#f25022/i.test(html) && /#7fba00/i.test(html) && /#00a4ef/i.test(html) && /#ffb900/i.test(html) && /<svg/i.test(html)) {
      score += 2; hits.push("SVG logo Microsoft (4 màu ô vuông)");
    }

    // Class ĐẶC HỮU của convergence UI (AAD), không dùng chung chỗ khác
    var aadClasses = /ext-sign-in-box|ext-boilerplate-text|lightbox-cover|ext-header|ext-middle|ext-footer/gi;
    var m = html.match(aadClasses);
    if (m) {
      var uniq = {}; m.forEach(function (x) { uniq[x.toLowerCase()] = 1; });
      var keys = Object.keys(uniq);
      var n = Math.min(keys.length, 2);
      score += n; hits.push("class UI AAD (" + keys.slice(0, 2).join(",") + ")");
    }

    // Chuỗi ĐẶC HỮU (đi kèm nhau mới đặc trưng AAD), tối đa +1
    var boiler = [/Can't access your account\?/i, /Không thể truy cập tài khoản/i, /Stay signed in\?/i, /Duy trì đăng nhập/i];
    for (var i = 0; i < boiler.length; i++) {
      if (boiler[i].test(html)) { score += 1; hits.push("chuỗi đặc hữu trang login MS"); break; }
    }

    if (score > BRAND_CAP) score = BRAND_CAP;
    return { score: score, hits: hits };
  }

  /**
   * Browser-in-the-Browser: trang vẽ một "cửa sổ trình duyệt giả" với thanh địa
   * chỉ hiển thị URL Microsoft thật, trong khi host thật là của attacker.
   * Tín hiệu mạnh & ít FP: một element NGẮN hiển thị nguyên URL host tin cậy MS
   * như NỘI DUNG/giá trị (không phải href) trên trang host KHÔNG tin cậy.
   */
  var BITB_URL_RE = /^https?:\/\/(www\.)?(login\.microsoftonline\.com|login\.microsoft\.com|login\.live\.com|account\.microsoft\.com|microsoftonline\.com|microsoft\.com|office\.com|office365\.com|outlook\.com)(\/|$)/i;

  function scoreBitB(roots) {
    var hits = [], MAX = 600, seen = 0;
    for (var i = 0; i < roots.length && seen < MAX; i++) {
      var els;
      try { els = roots[i].querySelectorAll('input,span,div,p,code,bdi,a,label'); } catch (e) { els = []; }
      for (var j = 0; j < els.length && seen < MAX; j++, seen++) {
        var el = els[j];
        // giá trị hiển thị (input) hoặc text NGẮN (address-bar giả), không xét href
        var val = "";
        try {
          if (el.tagName === "INPUT") val = (el.value || el.getAttribute("value") || "").trim();
          else if (!el.children.length) val = (el.textContent || "").trim();
        } catch (e) {}
        if (val && val.length < 120 && BITB_URL_RE.test(val)) {
          return { score: 4, hits: ["Browser-in-the-Browser: thanh địa chỉ giả hiển thị '" + val.slice(0, 48) + "'"] };
        }
      }
    }
    return { score: 0, hits: hits };
  }

  /**
   * Đánh giá tổng thể.
   * @param loc  object có hostname, pathname, search (thường là window.location)
   * @return null nếu an toàn; {hostname, url, score, pathScore, hits, domainSignals, tier}
   */
  function evaluate(doc, loc, trustedList, threshold) {
    var hostname = loc.hostname;
    if (isTrustedHost(hostname, trustedList)) return null;

    // 1) Tín hiệu URL — rẻ nhất, có sớm nhất
    var up = scoreUrlPath(loc.pathname, loc.search);
    var pathStrong = up.score >= 4;

    // 2) Gate: phải có bề mặt nhập credential (thật hoặc GIẢ), TRỪ khi path AAD đã đặc hiệu
    var cred = findCredentialField(doc);
    if (!cred.found && !pathStrong) return null;

    // 3) Chấm điểm đầy đủ — serialize HTML MỘT lần, dùng chung cho các chiều
    var roots = cred.roots || collectRoots(doc.documentElement || doc);
    var html = deepHtml(roots);
    var fp = scoreMicrosoftLogin(doc, roots, html);   // vân tay evilginx (tên field, $Config)
    var brand = scoreBrandFingerprint(roots, html);   // vân tay thương hiệu (đã siết, cap 4)
    var bitb = scoreBitB(roots);                      // thanh địa chỉ giả
    var dom = domainRiskSignals(hostname);            // domain đáng ngờ (typosquat/punycode/PaaS)

    var total = fp.score + up.score + brand.score + bitb.score + dom.score + (cred.surrogateScore || 0);
    var hits = up.hits.concat(fp.hits, brand.hits, bitb.hits, cred.signals || []);

    // Tín hiệu độ tin cậy cao: BitB, ô password giả bị che ký tự -> strong ngay
    var highConfidence = bitb.score > 0 || (cred.signals || []).some(function (s) { return /text-security/.test(s); });

    if (total >= threshold || pathStrong) {
      return {
        hostname: hostname,
        url: loc.href || "",
        score: total,
        pathScore: up.score,
        hits: hits,
        domainSignals: dom.signals,
        tier: highConfidence || total >= threshold + 4 || (pathStrong && cred.found) ? "strong" : "medium"
      };
    }
    return null;
  }

  /**
   * Kiểm tra cấu hình policy: cảnh báo allowlist khai quá rộng (apex 2 nhãn,
   * hoặc eTLD phổ biến) vì sẽ biến allowlist thành lỗ hổng.
   */
  function validatePolicy(cfg) {
    var warnings = [];
    var BROAD = /^(com|net|org|vn|com\.vn|io|co|info|biz)$/i;
    ["orgIdpDomains", "trustedAuthDomains"].forEach(function (key) {
      (cfg[key] || []).forEach(function (d) {
        var h = normalizeHost(d);
        var labels = h.split(".").filter(Boolean);
        if (!h || labels.length < 2 || BROAD.test(h)) {
          warnings.push(key + ": '" + d + "' không hợp lệ hoặc quá rộng");
        } else if (labels.length === 2 || (labels.length === 3 && /^(com|net|org|edu|gov)$/i.test(labels[1]))) {
          warnings.push(key + ": '" + d + "' là apex — mọi subdomain (kể cả bị takeover) sẽ được tin. Khai host cụ thể (vd sso." + d + ").");
        }
      });
    });
    if (typeof cfg.detectionThreshold === "number" && cfg.detectionThreshold < 4) {
      warnings.push("detectionThreshold < 4 sẽ gây false positive cao");
    }
    return warnings;
  }

  return {
    DEFAULT_TRUSTED_DOMAINS: DEFAULT_TRUSTED_DOMAINS,
    isTrustedHost: isTrustedHost,
    domainRiskSignals: domainRiskSignals,
    scoreUrlPath: scoreUrlPath,
    collectRoots: collectRoots,
    findCredentialField: findCredentialField,
    scoreMicrosoftLogin: scoreMicrosoftLogin,
    scoreBrandFingerprint: scoreBrandFingerprint,
    scoreBitB: scoreBitB,
    evaluate: evaluate,
    validatePolicy: validatePolicy
  };
})();
