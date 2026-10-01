# AiTM Phishing Guard (v1.9.1)

Chrome extension (Manifest V3) phát hiện và cảnh báo trang đăng nhập Microsoft
giả mạo theo mô hình **Adversary-in-the-Middle (evilginx)**.

## 1. Nguyên lý phát hiện

evilginx là reverse-proxy: nó proxy **nguyên bản** trang `login.microsoftonline.com`
thật về cho nạn nhân, nên DOM trang giả **giống hệt** trang thật. Vì vậy không thể
phân biệt bằng giao diện. Tín hiệu phân biệt đáng tin cậy duy nhất là **domain**.

Luật cốt lõi (trong `src/detector.js`):

```
IF   host KHÔNG thuộc allowlist (MS chính chủ + IdP nội bộ)
AND  (  [URL path đặc trưng AAD: /common/oauth2/v2.0/authorize, /kmsi, /login.srf ...]
      OR [ô credential + vân tay DOM: loginfmt / passwd / $Config / idSIButton9 ...] )
=> PHISHING
```

Tín hiệu URL path (v1.1) độc lập DOM và có ngay từ khi tải trang: evilginx proxy
**nguyên path** của AAD lên host của attacker. Path có tenant-segment
(`common|organizations|consumers|<guid>`) là đặc hiệu của AAD — Keycloak/Okta/ADFS
không trùng, đã test không false positive.

Trang trên `login.microsoftonline.com` thật => domain hợp lệ => **không cảnh báo**.
Trang trên domain typosquat/homoglyph/punycode/subdomain lạ mà vẫn có vân tay login
=> **cảnh báo đỏ full màn hình**, chặn nhập credential + 2FA.

## 2. Cấu trúc

```
aitm-phishing-guard/
├── manifest.json               # MV3, Chrome 111+
├── src/hook-policy.js          # đăng ký hook theo managed policy; loại CAPTCHA và host tin cậy
├── src/detector.js             # allowlist + URL path AAD + vân tay DOM (deep shadow) + validatePolicy
├── src/content.js              # điều phối; report / warn (overlay) / block (interstitial)
├── src/devicecode.js           # v1.2: cảnh báo trên trang DEVICE CODE thật của Microsoft
├── src/exfil-hook.js           # v1.4 MAIN world: bắt HÀNH VI exfil (cross-origin post, Telegram/Discord, keystroke streaming)
├── src/exfil-content.js        # v1.4: chấm điểm hành vi + cảnh báo soft (heuristic tổng quát, ngoài O365)
├── src/background.js           # telemetry ký HMAC + định danh, offline queue, điều hướng block
├── src/config.js               # đặt server nhận log trước khi deploy; để trống = không gửi
├── src/settings.js             # chuẩn hóa endpoint từ source; metadata từ managed policy
├── src/telemetry.js            # hàng đợi log, HMAC, retry và loại query/fragment
├── src/access.js               # bản ghi chặn và ngoại lệ domain theo tab
├── blocked.html / blocked.js   # trang interstitial thay hoàn toàn trang phishing
├── policy/managed_schema.json  # schema cấu hình IT đẩy xuống
└── icons/
```

## 3. Test thử (load unpacked)

1. `chrome://extensions` → bật **Developer mode** → **Load unpacked** → chọn thư mục.
   Không có managed policy thì mặc định `blockMode=block`, `enabled=true`.
2. Dựng evilginx trong lab với phishlet o365/microsoft, truy cập link phishing →
   phải thấy cảnh báo đỏ. Truy cập `login.microsoftonline.com` thật → không cảnh báo.

## 4. Force-install (user không gỡ/tắt/sửa được)

### Windows – Group Policy / Registry
Dùng policy **ExtensionInstallForcelist** (force-install + chặn gỡ + chặn tắt):

```
HKLM\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist
  1 = "<EXTENSION_ID>;<UPDATE_URL>"
```

- Qua Chrome Web Store (private/unlisted): `UPDATE_URL = https://clients2.google.com/service/update2/crx`
- Self-host: trỏ tới `update.xml` nội bộ của tập đoàn.

### Intune
Settings Catalog → **Google Chrome > Extensions > Force-installed Apps and Extensions**
→ thêm `EXTENSION_ID;UPDATE_URL`.

### macOS / Linux
Đặt key tương ứng trong file plist (`com.google.Chrome`) hoặc
`/etc/opt/chrome/policies/managed/*.json`.

> Khi extension nằm trong ExtensionInstallForcelist: user **không thể** gỡ, tắt,
> hay chỉnh sửa code; nút remove/disable bị khóa và quản lý bởi "tổ chức của bạn".
> Cấu hình `chrome.storage.managed` là **read-only** với user, chỉ admin đẩy được.

## 5. Cấu hình do IT đẩy xuống (managed policy)

Khóa **3rdparty/extensions/<EXTENSION_ID>/policy** (Windows registry/GPO hoặc JSON):

```json
{
  "enabled": true,
  "blockMode": "report",
  "deviceCodeMode": "warn",
  "behaviorMode": "warn",
  "behaviorAllowlist": ["internal-analytics.vingroup.net"],
  "orgIdpDomains": ["adfs.vingroup.net", "sts.vingroup.net", "sso.vingroup.net"],
  "trustedAuthDomains": [],
  "detectionThreshold": 6,
  "safePortalUrl": "https://myapps.microsoft.com/",
  "telemetrySecret": "<random-32-bytes>",
  "deviceId": "%COMPUTERNAME%",
  "userId": "%USERNAME%",
  "helpdeskContact": "IT Helpdesk (ext 1234)"
}
```

| Khóa | Ghi chú |
|---|---|
| `enabled` | **Kill switch.** `false` = ngừng đăng ký hook; tải lại các tab sau khi policy đồng bộ để gỡ hook và dừng detector đã chạy. |
| `blockMode` | `report` (im lặng, chỉ telemetry) → `warn` (overlay, cho đóng) → `block` (interstitial). |
| `deviceCodeMode` | `warn` (mặc định: overlay đỏ + nút "Tôi hiểu rủi ro" để hiện trang nhập mã), `block` (không có nút chấp nhận), `off`. |
| `behaviorMode` | `warn` (mặc định: cảnh báo soft khi phát hiện hành vi exfil trên **bất kỳ site nào ngoài O365**), `off` (ngừng đăng ký hook; cần tải lại tab đang mở). Không có block cứng. |
| `orgIdpDomains` | Khai **host cụ thể**. Khai apex (`vingroup.net`) → extension gửi `aitm_config_warning`. |
| `safePortalUrl` | Nút "Đi tới cổng đăng nhập chính thức" đưa user về đây (không về `about:blank`). |
| `telemetrySecret` | Server verify `X-AiTM-Signature = sha256=HMAC_SHA256(secret, X-AiTM-Timestamp + "." + body)`; reject nếu lệch > 5 phút. |
| `deviceId` / `userId` | GPO Preferences hỗ trợ biến môi trường; Intune dùng device/user token. SOC cần cái này để IR reset đúng người. |

### Quy trình rollout khuyến nghị
1. **`report`** toàn fleet 2–4 tuần → đo false positive từ `aitm_phishing_detected` + `aitm_config_warning`, tune allowlist.
2. **`warn`** 1–2 tuần → đo tỷ lệ bấm "báo nhầm" (`aitm_false_positive_report`).
3. **`block`**. Giữ `enabled=false` sẵn làm nút khẩn cấp.

Sự kiện gửi về server (`aitm_phishing_detected`, `aitm_domain_blocked`,
`aitm_false_positive_report`, `aitm_config_warning`), ký HMAC khi có `telemetrySecret`,
queue offline trong `storage.local` và retry mỗi 15 phút:

```json
{
  "event": "aitm_phishing_detected",
  "eventId": "ef955e49-8dbe-46cb-9939-e4e3e198c056",
  "source": "aitm-phishing-guard",
  "extVersion": "1.9.1",
  "deviceId": "VN-LT-04213",
  "userId": "nam.hv",
  "data": {
    "url": "https://login.micros0ft-online.com/common/oauth2/v2.0/authorize",
    "hostname": "login.micros0ft-online.com",
    "score": 20, "pathScore": 5, "tier": "strong", "mode": "block",
    "signals": ["URL path AAD: /common/oauth2/v2.0/authorize", "field username 'loginfmt'", "$Config (AAD)"],
    "domainSignals": ["biến thể typosquat của login.microsoftonline.com"],
    "referrer": "", "isTopFrame": true, "ts": "2026-09-04T...", "ua": "..."
  }
}
```

### Cấu hình server trong source và báo nhầm để truy cập tiếp (v1.9.1)

Đặt địa chỉ nhận log trong **`src/config.js` trước khi đóng gói/deploy**:

```js
var AITM_CONFIG = Object.freeze({
  reportingEndpoint: "https://logs.example.com/api/aitm"
});
```

Có thể nhập domain trần (`logs.example.com` → `https://logs.example.com/api/aitm`)
hoặc URL đầy đủ với đường dẫn riêng. Giá trị mặc định trong repo là chuỗi rỗng.

1. **Để `reportingEndpoint: ""` để tắt gửi log:** không gửi sự kiện mới, không thêm
   log mới vào hàng đợi, không gửi log cũ đang chờ. Chặn phishing và nút báo nhầm /
   truy cập tiếp vẫn hoạt động. Cấu hình endpoint không hợp lệ cũng không gửi log.
2. **Không có trang Options, nút cấu hình hay API lưu endpoint cho user.** Địa chỉ
   trong `chrome.storage.local` từ bản cũ và `reportingEndpoint` trong managed policy
   đều bị bỏ qua. `telemetrySecret`, `deviceId`, `userId` vẫn lấy từ managed policy.
3. Sau khi chỉnh source, đóng gói/deploy bản mới (hoặc reload extension khi thử
   unpacked), rồi reload các tab. Server nhận **POST JSON**, trả HTTP **2xx** để xác
   nhận. HTTP chỉ được chấp nhận trên localhost để thử nghiệm; production dùng HTTPS.
   Server và chứng chỉ cần được triển khai riêng.
4. Trên trang bị chặn, user có thể bấm **Không phải phishing — truy cập tiếp**.
   Extension lưu ngoại lệ cho **đúng hostname, chỉ trong tab hiện tại**, ghi sự kiện
   rồi quay về URL ban đầu (giữ query/fragment để luồng đăng nhập tiếp tục).
   Không cho phép ngầm các subdomain hay tab khác. Đóng tab, khởi động lại trình duyệt
   hoặc reload extension sẽ xóa ngoại lệ. Nếu iframe bị chặn, quay lại trang cha và
   chỉ cho phép hostname của iframe đó. Ngoại lệ này dành cho detector DOM/URL;
   các cảnh báo hành vi exfil độc lập vẫn hoạt động.

| Sự kiện | Ý nghĩa và trường chính |
|---|---|
| `aitm_domain_blocked` | Tab đã được chuyển sang trang chặn; `data.hostname`, `data.blockId`, `data.action="blocked"`, điểm và dấu hiệu phát hiện. |
| `aitm_false_positive_report` | User báo nhầm; thao tác ở trang chặn có `data.action="allow_and_continue"`, `data.scope="tab"` và `data.blockId` trùng sự kiện chặn. Báo nhầm từ overlay warn chỉ gửi báo cáo. |
| `aitm_exfil_false_positive` | User báo nhầm cảnh báo hành vi; giữ cơ chế ghi nhớ 30 ngày của module này. |

Ví dụ `data` của sự kiện user truy cập tiếp:

```json
{
  "blockId": "804f21fb-f311-4b87-9442-2e20aec12880",
  "hostname": "login.example.com",
  "url": "https://login.example.com/common/oauth2/authorize",
  "action": "allow_and_continue",
  "scope": "tab",
  "fromInterstitial": true,
  "score": 7,
  "tier": "strong"
}
```

Log có `eventId` để server chống trùng khi retry. Mã `blockId` nối lần chặn với
quyết định của user. Từ v1.9.0, `source` là `aitm-phishing-guard`; cập nhật bộ lọc
SIEM nếu đang lọc tên cũ. Các trường URL trong log bỏ userinfo, query và fragment;
không gửi mật khẩu hay nội dung form. URL đầy đủ chỉ được giữ trong session của
extension để điều hướng lại, không đặt trong query của trang cảnh báo.

Hàng đợi tối đa 200 sự kiện, đầy thì bỏ sự kiện cũ nhất. Gửi lỗi hoặc quá 10 giây
thì giữ lại để retry; mỗi đợt tối đa 25 sự kiện. Ghi log mới không bị mất khi một
đợt gửi đang chạy. Khi bản deploy để trống endpoint, hàng đợi cũ được giữ và không gửi; khi deploy
bản có endpoint, log còn chờ sẽ gửi tới endpoint trong source của bản đó. Việc truy cập tiếp chỉ chờ lưu quyết định
và log cục bộ, không chờ server online. Cảnh báo hết hiệu lực không được dùng để
thêm ngoại lệ; yêu cầu từ content script của trang web cũng không được phép bỏ chặn.

Kiểm thử: `node tests/logging-access.test.cjs` cho cấu hình source, HMAC, queue và
quyền bỏ chặn. `node tests/browser-smoke.cjs /path/to/chromium` kiểm tra bản đóng gói
có endpoint cùng luồng chặn → báo nhầm → truy cập tiếp; thêm `--no-logs` để kiểm tra
bản để trống endpoint vẫn bảo vệ và không gửi/queue log. Mỗi lần chạy tạo bản sao
extension và profile tạm, giả lập request log trong service worker; không sửa
source thật và không gửi dữ liệu thử ra server bên ngoài.

## 6. Module device code (v1.2)

**Bối cảnh.** Device code phishing không dùng trang giả: kẻ gian gửi mã cho nạn nhân
nhập tại `microsoft.com/devicelogin` **thật**; Microsoft cấp token thẳng cho app của
attacker. Extension AiTM (mục 1) bỏ qua host tin cậy nên mù với vector này. Kiểm soát
chính là **Conditional Access chặn Device code flow** (tập đoàn đã bật); module này là
lớp awareness phủ nốt: overlay đỏ full trang trên `…/oauth2/deviceauth` và
`/devicelogin`, giải thích ngắn khi nào hợp lệ / khi nào lừa đảo, flag nếu người dùng
đến từ Outlook/Teams/Gmail/Zalo…, và nút **"Tôi hiểu rủi ro – tiếp tục nhập mã"**
(chỉ ở `deviceCodeMode=warn`). **Không ghi nhớ** — mỗi lần mở trang đều cảnh báo lại.

**Telemetry:** `aitm_devicecode_page_view`, `aitm_devicecode_risk_accepted`,
`aitm_devicecode_left`, `aitm_devicecode_user_report`. SOC nên đối chiếu
`risk_accepted` (có `userId`) với Entra sign-in log `authenticationProtocol = deviceCode`
để phát hiện tài khoản nằm ngoài scope CA hoặc CA bị lệch.

**Giới hạn:** người dùng đang ở trang thật, làm việc "hợp lệ" — đây là nudge hành vi,
không phải kiểm soát kỹ thuật. Microsoft đổi markup trang này khá thường xuyên; module
bám theo **URL path** (ổn định) thay vì selector, đã test không kích hoạt trên
`/oauth2/v2.0/authorize`. Cùng nhóm "trên domain thật" còn OAuth consent phishing —
xử lý bằng siết user consent + admin consent workflow, ngoài phạm vi extension.

## 6b. Phát hiện hành vi exfil ngoài O365 (v1.4)

O365 module dựa trên *ground truth* (biết domain/giao diện thật). Với **site bất kỳ**
không có ground truth đó, nên chuyển sang **chấm điểm HÀNH VI** — thứ attacker khó né
vì phishing kit buộc phải gửi dữ liệu ra ngoài.

`exfil-hook.js` (MAIN world, `document_start`) hook `fetch`/XHR/`sendBeacon`/`WebSocket`/
`Image.src`. Nguyên tắc v1.5 (sau khi sửa false positive kiểu analytics):

- **Bằng chứng thay vì từ khóa.** Chỉ khẳng định "gửi mật khẩu" khi request **chứa đúng
  giá trị password người dùng vừa gõ** (so cả bản raw / URL-encode / JSON-escape / base64).
  Pixel analytics (TikTok, GA, Facebook…) không bao giờ chứa giá trị đó nên không còn bị nhầm.
- **Cross-site (eTLD+1), không phải cross-origin.** `app.acme.com → api.acme.com` là hợp lệ.
- **Bỏ qua nhà cung cấp hợp lệ.** Allowlist tích hợp: IdP/auth (Auth0, Okta, Firebase,
  Cognito, Entra…), thanh toán (Stripe, PayPal, VNPay, Momo…), và analytics/session-replay
  (với analytics, chỉ cảnh báo nếu request **thực sự chứa password**). IT bổ sung qua
  `behaviorAllowlist`.
- **Chỉ chạy khi trang có ô password.** Không có thì không phát tín hiệu nào.
- **Kênh exfil** (Telegram/Discord/formspree/webhook.site…) vẫn là tín hiệu mạnh độc lập.
- **Keystroke streaming** chỉ tính khi đang gõ trong ô credential và lặp ≥4 lần.

Câu chữ cảnh báo bám theo **mức bằng chứng**: có giá trị password → "Trang này vừa gửi mật
khẩu bạn nhập ra máy chủ ngoài" (đỏ); chỉ tín hiệu yếu → "hành vi bất thường" (hổ phách).
Lý do gom theo **domain gốc**, tối đa 3 dòng (không liệt kê từng subhost). "Bỏ qua" tắt
cảnh báo cho site đó trong phiên.

**Riêng tư:** giá trị password chỉ được đọc trong bộ nhớ MAIN world để so khớp — KHÔNG gửi
đi đâu, KHÔNG log. Event `aitm:exfil` chỉ mang boolean + host đã tóm tắt.

**Nút cảnh báo:** hai nút rõ nghĩa — **"Đúng, đáng ngờ"** (user xác nhận: banner đổi sang
hướng dẫn xử lý, nhắc đổi mật khẩu nếu là trường hợp mạnh) và **"Báo nhầm"** (user khẳng
định trang hợp lệ: không cảnh báo lại host đó trong 30 ngày + gửi tín hiệu tune allowlist).

**Telemetry:** `aitm_exfil_behavior_detected` (tự động khi hiện, kèm `strong`/`sites`/`reasons`),
`aitm_exfil_user_confirmed` (user bấm "Đúng, đáng ngờ" — true-positive có phán xét),
`aitm_exfil_false_positive` (user bấm "Báo nhầm" — nguồn chính để tune `behaviorAllowlist`).

**Giới hạn:** body dạng Blob/ReadableStream không đọc đồng bộ được (bỏ qua để an toàn); trang
có thể lấy `fetch` nguyên bản từ iframe mới tạo để né hook. Tín hiệu hạ tầng (domain mới đăng
ký, CT) vẫn cần backend enrichment — hạng mục sau.

### v1.7 — rà soát & siết thuật toán

Sau đợt review nội bộ, các điều chỉnh:

1. **Bắt form POST truyền thống** (`<form action="https://evil/post.php">`) — điểm mù lớn nhất
   trước đây (chỉ hook fetch/XHR). Listener `submit` capture-phase; khi form gửi **đúng mật
   khẩu vừa nhập** cross-site tới host không hợp lệ → **soft-block** (`preventDefault`, mật
   khẩu CHƯA rời trang), banner có nút "Báo nhầm – vẫn gửi" để user tin cậy đi tiếp.
2. **Vệ sinh allowlist** — bỏ mọi apex PaaS đa-tenant mà attacker tự tạo subdomain
   (`amazonaws.com`, `cloudflare.com`, `firebaseapp.com`, `supabase.co`, `b2clogin.com`,
   `ciamlogin.com`). Chỉ giữ endpoint IdP thật; AWS thu hẹp về `cognito-idp.*.amazonaws.com`,
   Cloudflare về `challenges.cloudflare.com`. **B2C/CIAM phải khai theo tenant cụ thể trong
   `orgIdpDomains`.**
3. **Nhất quán "ô credential"** giữa detector và module exfil: cả hai nhận diện surrogate
   (contenteditable có nhãn password, ô che bằng `-webkit-text-security`) qua thuộc tính, và
   `credSeen` **sticky** cả vòng đời trang (không mất khi blur).
4. **Siết brand fingerprint** — bỏ class/chuỗi generic (`table-cell`, "Forgot my password"…)
   và `img[src*=microsoft]` (khớp nút SSO hợp lệ). Tổng điểm brand **cap ở 4**, không bao giờ
   tự vượt ngưỡng — phải đi kèm path AAD / tên field MS / BitB / surrogate / domain đáng ngờ.
5. **Cap tín hiệu yếu** (từ khóa body / identifier / websocket) tổng ở 3; regex body có biên
   (không khớp `passport`, `shipping`, `client_secret`).
6. **Throttle** `aitm-config-warning` 1 lần/ngày (trước đây mỗi lần tải trang).
7. **Chấm điểm domain** (typosquat/punycode/PaaS free) thay vì chỉ hiển thị — bù cho brand
   đã siết để clone đổi tên field trên domain giả vẫn bị bắt.
8. Module O365 chuyển sang `document_start` (path AAD có ngay, không đợi idle).

9. **(v1.7.1) Ghi nhớ "Báo nhầm" đúng cách.** Trước đây lưu `sessionStorage` — vừa mất khi
   đóng tab, vừa thuộc origin trang nên **trang phishing tự ghi được để tắt cảnh báo**. Nay lưu
   `chrome.storage.local` (chỉ extension đọc/ghi), **TTL 30 ngày**, cap 200 host, nhớ qua các
   lần truy cập. IT muốn vĩnh viễn → `behaviorAllowlist`. Đồng thời sửa hai lỗi trạng thái: sau "Báo nhầm" hoặc
   "Đúng, đáng ngờ → Đóng", form bị soft-block không còn bị chặn âm thầm không banner.
   **Chính sách ghi nhớ theo module (v1.7.2):**
   | Module | User "báo nhầm"/"chấp nhận" có được ghi nhớ? |
   |---|---|
   | O365 (AiTM) | **Từ v1.9.0:** báo nhầm trên trang chặn cho phép đúng hostname trong tab hiện tại; đóng tab sẽ xóa. Overlay warn chỉ gửi báo cáo. |
   | Device code | **Không.** Mỗi lần mở trang đều cảnh báo lại; "Tôi hiểu rủi ro" chỉ có hiệu lực cho lần tải đó. |
   | Hành vi exfil (site bất kỳ) | **Có, 30 ngày**, `chrome.storage.local`. Vì đây là heuristic không có ground truth, FP là chi phí cố định. |

Đánh đổi có chủ đích: clone **verbatim** (giữ loginfmt/passwd) vẫn bị bắt qua fingerprint;
custom kit **đổi sạch tên field trên domain trông vô hại** không còn bị DOM bắt một mình —
tầng chặn cho ca đó là **hành vi exfil** (mục 6b) và telemetry, đúng như giới hạn đã nêu.

### v1.7.3 — sửa hai false positive thực địa

1. **Tài liệu trên `*.live.com` bị báo phishing.** `DEFAULT_TRUSTED_DOMAINS` (detector) chỉ có
   `login.live.com` / `account.live.com`, trong khi `main-world.js` đã tin cả apex `live.com` →
   hai danh sách lệch nhau; OneDrive / Word Online / Outlook consumer (`onedrive.live.com`,
   `*.officeapps.live.com`, `outlook.live.com`) bị chấm điểm như host lạ. Nay hai danh sách
   **đồng bộ**, bổ sung các apex **Microsoft sở hữu toàn bộ** (`live.com`, `microsoft.com`,
   `microsoftonline.com`, `office.com`, `office.net`, `office365.com`, `outlook.com`,
   `hotmail.com`, `onedrive.com`, `1drv.ms`, `windowsazure.com`, `microsoftazuread-sso.com`).
   **Không** thêm apex đa-tenant (`sharepoint.com`, `azurewebsites.net`, `blob.core.windows.net`,
   `azurestaticapps.net`) vì attacker tự tạo được subdomain ở đó. Trên host tin cậy, cả
   `main-world.js` lẫn `exfil-hook.js` giờ **không hook gì** (footprint 0 trên Outlook/Teams/OneDrive).
2. **Cloudflare Turnstile / managed challenge "không thể verify".** v1.7.3 thử che
   wrapper bằng cách sửa `Function.prototype.toString`, nhưng chưa áp dụng
   `exclude_matches` và vẫn ép Shadow DOM đóng thành mở. Chưa có log thực địa chứng minh
   Cloudflare kiểm tra từng thuộc tính nào; các thay đổi này chỉ là nguyên nhân nghi ngờ.
   Cách tiếp cận đó đã được thay thế ở v1.8.0.

### v1.8.0 — giảm can thiệp vào trang và sửa lifecycle của hook

- **Loại CAPTCHA khỏi content scripts:** `challenges.cloudflare.com`, các đường dẫn
  reCAPTCHA và `*.hcaptcha.com`. Đây là loại trừ phạm vi injection, khác với
  `behaviorAllowlist` (chỉ bỏ qua đánh giá đích gửi dữ liệu). Không whitelist toàn bộ
  `cloudflare.com` hoặc mọi website dùng Cloudflare.
- **Bỏ `main-world.js`:** không sửa `Function.prototype.toString`, `attachShadow`,
  `pushState` hoặc `replaceState`. Detector dùng
  [chrome.dom.openOrClosedShadowRoot](https://developer.chrome.com/docs/extensions/reference/api/dom)
  để đọc Shadow DOM đóng từ isolated world. Trang vẫn thấy `host.shadowRoot === null`.
  SPA dùng Navigation API / popstate / hashchange; quét dự phòng mỗi 2 giây cũng bắt
  nội dung được thêm muộn trong Shadow DOM.
- **Hook hành vi theo policy:** background dùng `chrome.scripting` (thêm quyền
  `scripting`) đăng ký hook MAIN ở `document_start`, chỉ top frame. `enabled=false`
  hoặc `behaviorMode=off` gỡ đăng ký; host tin cậy tích hợp và `trustedAuthDomains` /
  `orgIdpDomains` được loại khỏi hook, dùng chung danh sách với detector.
  Không nhận lệnh tắt hook qua thuộc tính DOM của trang.
- **Policy áp dụng cho lần tải trang tiếp theo:** sau cập nhật extension hoặc policy,
  chờ background đồng bộ rồi reload các tab. Gỡ đăng ký script không hoàn tác script
  đã chạy. Đăng ký được giữ qua phiên; trang mở ngay lúc cài đặt/đồng bộ có thể chạy
  trước khi đăng ký hoàn tất. Khi đọc policy lỗi, background giữ đăng ký trước đó và
  ghi lỗi ở console service worker.
- **Form không bị chặn âm thầm:** chỉ soft-block khi listener cảnh báo đã nhận xử lý;
  listener chưa sẵn sàng, chế độ off hoặc host đã báo nhầm thì không giữ submit.
  Đọc `formaction` của nút submit và giữ nút đó khi người dùng cho phép gửi tiếp.
- **Sửa tính tương thích API:** giữ lỗi gọi WebSocket thiếu `new`, hỗ trợ subclass,
  chuyển tiếp nguyên các tham số; đọc đúng phạm vi `byteOffset` / `byteLength` của
  TypedArray để tránh báo nhầm do dữ liệu ngoài phần thực sự được gửi.

**Kiểm thử tự động:** chạy `node tests/compatibility.test.cjs` (Node.js 22+,
không cần cài dependency). Kiểm tra registration/policy, closed shadow roots,
WebSocket, request forwarding, typed-array slices và soft-block form.
Kiểm tra tích hợp bằng Chromium hỗ trợ load extension:
`node tests/browser-smoke.cjs /path/to/chromium`. Bài kiểm tra tạo profile tạm,
intercept request để trả trang giả lập và tự dọn profile; không giải CAPTCHA thật.

**Kiểm thử Cloudflare thực tế:** reload extension tại `chrome://extensions`, rồi
reload trang đang lỗi. So sánh cùng URL khi bật/tắt extension; ghi lại mã lỗi,
Ray ID và Console/Network nếu lỗi còn xảy ra. Không dùng `enabled=false` trên tab
chưa reload để làm phép so sánh. Xem
[hướng dẫn Cloudflare](https://developers.cloudflare.com/cloudflare-challenges/troubleshooting/challenge-solve-issues/).
Loại trừ iframe không bảo đảm Managed Challenge trên trang chính sẽ thành công:
hook hành vi vẫn chạy trên trang chính không tin cậy. Có thể dùng `behaviorMode=off`
và reload để cô lập tầng này, đồng thời giữ detector DOM/URL hoạt động.

## 7. Giới hạn & phòng thủ nhiều lớp (lưu ý kiến trúc)

Extension này là lớp **phát hiện/cảnh báo** mạnh với evilginx (vì evilginx không
đổi tên field DOM), nhưng **không phải biện pháp tuyệt đối**.

### Đã vá
- **v1.0** — open Shadow DOM (`collectRoots`/`deepQuery`); SPA render muộn (observer sống lâu).
- **v1.1** —
  - **closed shadowRoot**: từ v1.8.0 đọc bằng API extension, không ép thành open.
  - **pushState/replaceState**: từ v1.8.0 dùng Navigation API và polling 2s, không patch history.
  - **URL path AAD**: tín hiệu độc lập DOM, bắt được cả trước khi form render.
  - **Tamper overlay**: chế độ `block` điều hướng cả tab sang `blocked.html` của
    extension → JS trang phishing bị loại bỏ hoàn toàn, không còn cuộc đua re-inject.
    Đồng thời xử lý luôn trường hợp phishing nhúng trong iframe.
  - **Hiệu năng**: gate rẻ (1 `querySelector`) trước khi duyệt shadow/serialize HTML;
    host tin cậy không gắn observer.
  - **Allowlist thiếu** (b2clogin, ciamlogin, passwordreset, autologon SSO, mysignins…).

### Vẫn còn (cần lớp bù)
- **Né hook hành vi MAIN world**: trang có thể lấy API mạng nguyên bản từ iframe
  mới hoặc can thiệp kênh sự kiện DOM giữa hai world. Tầng heuristic này không phải
  ranh giới bảo mật tuyệt đối; cần phối hợp detector DOM/URL và bảo vệ mạng.
- **Kit tùy biến** đổi tên field/obfuscate/render bằng ảnh và không giữ path AAD
  (Tycoon 2FA, Greatness dùng template riêng) → cần đo detection rate với mẫu thực.
- **file:// attachment**: content script không chạy nếu tắt "Allow access to file
  URLs" → chặn HTML attachment ở mail gateway.
- **Subdomain takeover / allowlist quá rộng**: extension cảnh báo cấu hình apex,
  nhưng subdomain đã bị takeover trên host hợp lệ vẫn được tin. Rà định kỳ.
- **Chỉ brand Microsoft**; ruleset chưa tách thành file ký số fetch từ xa (mục
  9/10 trong review) — nâng cấp cho v1.2.

Khuyến nghị kết hợp (defense-in-depth) — đây mới là lớp chặn AiTM triệt để nhất:

1. **Phishing-resistant MFA**: FIDO2 / passkeys / Windows Hello / chứng thư.
   evilginx **không** đánh cắp được phiên với FIDO2 (origin-bound).
2. **Conditional Access + token protection / token binding**, đánh giá rủi ro
   đăng nhập (Entra ID Protection).
3. Chặn ở tầng mạng: **DNS/proxy blocklist** domain mới đăng ký, newly-registered
   domains, threat intel evilginx.
4. Giám sát SIEM: chính endpoint telemetry ở trên để dựng cảnh báo & săn lùng.
```
