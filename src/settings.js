/* Background only. The destination comes exclusively from the packaged config. */
var AITMSettings = (function () {
  function endpoint(value) {
    var text = typeof value === "string" ? value.trim() : "";
    if (!text) return "";
    if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(text)) text = "https://" + text;
    var url;
    try { url = new URL(text); } catch (e) { throw new Error("Địa chỉ server không hợp lệ."); }
    var local = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
    if (url.protocol !== "https:" && !(local && url.protocol === "http:")) {
      throw new Error("Server nhận log phải dùng HTTPS (HTTP chỉ dùng cho localhost).");
    }
    if (url.username || url.password || url.hash) throw new Error("Không đặt tài khoản hoặc fragment trong địa chỉ server.");
    if (url.pathname === "/") url.pathname = "/api/aitm";
    return url.href;
  }
  async function load() {
    var destination = endpoint(AITM_CONFIG.reportingEndpoint);
    // No destination means no logging, independent of old local/managed settings.
    if (!destination) return { reportingEndpoint: "" };
    var managed = await chrome.storage.managed.get(["telemetrySecret", "deviceId", "userId"]).catch(function () { return {}; });
    return {
      reportingEndpoint: destination,
      telemetrySecret: managed.telemetrySecret || "",
      deviceId: managed.deviceId || null,
      userId: managed.userId || null
    };
  }
  return { endpoint: endpoint, load: load };
})();
