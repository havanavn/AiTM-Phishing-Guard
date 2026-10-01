/* Cấu hình khi đóng gói/deploy; không có giao diện cho người dùng chỉnh sửa.
 * Để trống reportingEndpoint để tắt gửi log (kể cả log còn trong hàng đợi).
 * Ví dụ: "logs.example.com" -> https://logs.example.com/api/aitm
 * Hoặc:  "https://logs.example.com/security/events"
 */
var AITM_CONFIG = Object.freeze({
  reportingEndpoint: ""
});
