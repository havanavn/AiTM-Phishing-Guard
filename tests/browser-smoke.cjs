// Usage: node tests/browser-smoke.cjs /path/to/chromium [--no-logs]
// Uses a temporary profile and intercepted fixture pages; no live CAPTCHA solve.
const { spawn } = require('node:child_process');
const { mkdtempSync, rmSync, cpSync, mkdirSync, writeFileSync } = require('node:fs');
const { tmpdir } = require('node:os');
const path = require('node:path');
const assert = require('node:assert/strict');
const executable = process.argv[2];
if (!executable) throw new Error('Pass a Chromium executable that supports --load-extension');
const root = path.resolve(__dirname, '..');
const workspace = mkdtempSync(path.join(tmpdir(), 'aitm-smoke-'));
const profile = path.join(workspace, 'profile'), extension = path.join(workspace, 'extension');
const noLogs = process.argv.includes('--no-logs');
mkdirSync(extension);
for (const entry of ['manifest.json', 'blocked.html', 'blocked.js', 'src', 'policy', 'icons']) {
  cpSync(path.join(root, entry), path.join(extension, entry), {recursive:true});
}
// Exercise a packaged deployment config without changing the working tree.
writeFileSync(path.join(extension, 'src/config.js'), 'var AITM_CONFIG = Object.freeze(' +
  JSON.stringify({reportingEndpoint:noLogs ? '' : 'logs.example.test'}) + ');\n');
const browser = spawn(executable, [
  '--headless=new', '--no-sandbox', '--disable-gpu', '--disable-background-networking',
  '--no-first-run', '--remote-debugging-pipe', '--user-data-dir=' + profile,
  '--disable-extensions-except=' + extension, '--load-extension=' + extension, 'about:blank'
], { stdio: ['ignore', 'ignore', 'pipe', 'pipe', 'pipe'] });
let sequence = 0, buffer = '', stderr = '';
const pending = new Map(), listeners = [];
browser.stderr.on('data', data => { stderr = (stderr + data).slice(-4000); });
function connectionError(error) {
  for (const request of pending.values()) {
    clearTimeout(request.timeout);
    request.reject(new Error(error.message + '\n' + stderr));
  }
  pending.clear();
}
browser.on('error', connectionError);
browser.stdio[3].on('error', connectionError);
browser.stdio[4].on('error', connectionError);
function send(method, params = {}, sessionId) {
  return new Promise((resolve, reject) => {
    const id = ++sequence;
    const timeout = setTimeout(() => { pending.delete(id); reject(new Error(method + ' timed out\n' + stderr)); }, 15000);
    pending.set(id, { resolve, reject, timeout });
    browser.stdio[3].write(JSON.stringify({ id, method, params, sessionId }) + '\0');
  });
}
browser.stdio[4].on('data', data => {
  buffer += data.toString();
  let end;
  while ((end = buffer.indexOf('\0')) >= 0) {
    const message = JSON.parse(buffer.slice(0, end)); buffer = buffer.slice(end + 1);
    const request = pending.get(message.id);
    if (request) {
      clearTimeout(request.timeout); pending.delete(message.id);
      if (message.error) request.reject(new Error(JSON.stringify(message.error)));
      else request.resolve(message.result);
    } else for (const listener of listeners) listener(message);
  }
});
async function evaluate(session, expression) {
  const result = await send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true }, session);
  if (result.exceptionDetails) throw new Error(JSON.stringify(result.exceptionDetails));
  return result.result.value;
}
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
async function until(fn) {
  for (let i = 0; i < 100; i++) { const result = await fn(); if (result) return result; await sleep(100); }
  throw new Error('Timed out waiting for extension/page\n' + stderr);
}
const fixture = Buffer.from(`<html><body><div id="host"></div><script>
  document.getElementById('host').attachShadow({mode:'closed'}).innerHTML = '<input type="password">';
</script></body></html>`).toString('base64');
listeners.push(message => {
  if (message.method === 'Fetch.requestPaused') {
    if (message.params.request.url.startsWith('chrome-extension://')) {
      send('Fetch.continueRequest', {requestId:message.params.requestId}, message.sessionId).catch(console.error);
      return;
    }
    send('Fetch.fulfillRequest', { requestId: message.params.requestId, responseCode: 200,
      responseHeaders: [{ name: 'Content-Type', value: 'text/html' }], body: fixture }, message.sessionId)
      .catch(error => { console.error(error); process.exitCode = 1; });
  }
});
async function page(url) {
  const { targetId } = await send('Target.createTarget', { url: 'about:blank' });
  const { sessionId } = await send('Target.attachToTarget', { targetId, flatten: true });
  await send('Fetch.enable', { patterns: [{ urlPattern: '*' }] }, sessionId);
  await send('Page.navigate', { url }, sessionId);
  await until(() => evaluate(sessionId, 'document.readyState === "complete" && !!document.getElementById("host")'));
  return sessionId;
}
async function isolated(worker, url, code) {
  return evaluate(worker, `(async () => {
    const [tab] = await chrome.tabs.query({url: ${JSON.stringify(url)}});
    const [result] = await chrome.scripting.executeScript({target:{tabId:tab.id}, func: () => (${code})});
    return result.result;
  })()`);
}
(async () => {
  try {
    const worker = await until(async () => (await send('Target.getTargets')).targetInfos
      .find(t => t.type === 'service_worker' && t.url.endsWith('/src/background.js')));
    const { sessionId: workerSession } = await send('Target.attachToTarget', { targetId: worker.targetId, flatten: true });
    await until(() => evaluate(workerSession, 'typeof chrome !== "undefined" && !!chrome.scripting && chrome.scripting.getRegisteredContentScripts().then(s => s.length === 1)'));
    // Capture the HTTP POST contract without sending fixture logs to the Internet.
    await evaluate(workerSession, `globalThis.receivedLogs = []; globalThis.fetch = async (url, init) => {
      receivedLogs.push({url, body:JSON.parse(init.body), headers:init.headers}); return {ok:true};
    }`);
    await evaluate(workerSession, `chrome.storage.local.set({aitm_settings:{reportingEndpoint:'ignored.example.test'}})`);
    assert.equal(await evaluate(workerSession, 'AITMSettings.load().then(s => s.reportingEndpoint)'), noLogs ? '' : 'https://logs.example.test/api/aitm');
    assert.equal(await evaluate(workerSession, '!!chrome.runtime.getManifest().options_ui'), false);
    console.log('PASS: packaged source config controls logging; no user options or local override');
    const regularUrl = 'https://compat.example.test/';
    const regular = await page(regularUrl);
    assert.equal(await evaluate(regular, 'window.__aitmExfilHooked'), true);
    assert.equal(await evaluate(regular, 'document.getElementById("host").shadowRoot'), null);
    assert.equal(await evaluate(regular, 'Function.prototype.toString.toString().includes("[native code]")'), true);
    assert.equal(await isolated(workerSession, regularUrl, 'AITMDetector.findCredentialField(document).found'), true);
    console.log('PASS: real Chrome registration, closed shadow detection and unchanged page APIs');

    const formResult = await evaluate(regular, `(() => {
      const form = document.createElement('form');
      form.action = '/safe'; form.method = 'POST';
      form.innerHTML = '<input type="password" name="secret" value="test-only-value"><button formaction="https://collector.other.test/post">Send</button>';
      document.body.append(form);
      const allowed = form.dispatchEvent(new SubmitEvent('submit', {bubbles:true, cancelable:true, submitter:form.querySelector('button')}));
      return {allowed, warning:!!document.getElementById('aitm-exfil-guard-host')};
    })()`);
    assert.deepEqual(formResult, { allowed: false, warning: true });
    console.log('PASS: real cross-world acknowledgement blocks exfil form and displays warning');

    const trusted = await page('https://login.microsoftonline.com/fixture');
    assert.equal(await evaluate(trusted, 'typeof window.__aitmExfilHooked'), 'undefined');
    console.log('PASS: trusted authentication host receives no behavior hook');

    const captchaUrl = 'https://challenges.cloudflare.com/fixture';
    const captcha = await page(captchaUrl);
    assert.equal(await evaluate(captcha, 'typeof window.__aitmExfilHooked'), 'undefined');
    assert.equal(await isolated(workerSession, captchaUrl, 'typeof AITMDetector'), 'undefined');
    console.log('PASS: CAPTCHA document receives neither MAIN nor isolated content scripts');

    await evaluate(workerSession, 'chrome.scripting.unregisterContentScripts({ids:["aitm-exfil"]})');
    const disabledUrl = 'https://compat.example.test/disabled';
    const disabled = await page(disabledUrl);
    assert.equal(await evaluate(disabled, 'typeof window.__aitmExfilHooked'), 'undefined');
    assert.equal(await isolated(workerSession, disabledUrl, 'typeof AITMDetector'), 'object');
    console.log('PASS: unregistering behavior hooks retains isolated DOM detection on new pages');

    const blockedUrl = 'https://compat.example.test/common/oauth2/v2.0/authorize?secret=fixture-token#private';
    await evaluate(disabled, `history.pushState({}, "", ${JSON.stringify(blockedUrl)})`);
    await until(() => evaluate(disabled, 'location.protocol === "chrome-extension:" && location.pathname === "/blocked.html"'));
    console.log('PASS: SPA navigation to a phishing URL is blocked without a History hook');
    await until(() => evaluate(disabled, '!!document.getElementById("fp") && !document.getElementById("fp").disabled'));
    const blockedTab = await evaluate(disabled, 'chrome.tabs.getCurrent().then(t => t.id)');
    await evaluate(disabled, 'document.getElementById("fp").click()');
    try {
      await until(() => evaluate(disabled, 'location.href === ' + JSON.stringify(blockedUrl)));
    } catch (error) {
      console.error(await evaluate(disabled, '({url:location.href,status:document.getElementById("status")?.textContent,detail:document.getElementById("detail")?.textContent})'));
      throw error;
    }
    await sleep(2200);
    assert.equal(await evaluate(disabled, 'location.href'), blockedUrl);
    await evaluate(workerSession, 'flushQueue()');
    const logs = await evaluate(workerSession, 'receivedLogs');
    if (noLogs) {
      assert.equal(logs.length, 0);
      assert.equal(await evaluate(workerSession, 'chrome.storage.local.get(QUEUE_KEY).then(s => (s[QUEUE_KEY] || []).length)'), 0);
      console.log('PASS: empty source config sends/queues no logs; blocking and continue still work');
    } else {
      const blockedLog = logs.find(l => l.body.event === 'aitm_domain_blocked');
      const continueLog = logs.find(l => l.body.data.action === 'allow_and_continue');
      assert.ok(blockedLog && continueLog);
      assert.equal(blockedLog.url, 'https://logs.example.test/api/aitm');
      assert.equal(blockedLog.body.data.hostname, 'compat.example.test');
      assert.equal(blockedLog.body.data.blockId, continueLog.body.data.blockId);
      assert.equal(continueLog.body.data.scope, 'tab');
      assert.ok(!JSON.stringify(logs).includes('fixture-token'));
      console.log('PASS: report-and-continue restores URL; block/report logs use deployment endpoint and redact tokens');
    }

    await send('Page.navigate', {url:blockedUrl.replace('compat.example.test', 'child.compat.example.test')}, disabled);
    await until(() => evaluate(disabled, 'location.protocol === "chrome-extension:" && location.pathname === "/blocked.html"'));
    console.log('PASS: accepting a host does not bypass its subdomains');
    await send('Page.close', {}, disabled);
    await until(() => evaluate(workerSession, `chrome.storage.session.get('aitm_allow_${blockedTab}').then(s => !s['aitm_allow_${blockedTab}'])`));
    console.log('PASS: closing the tab removes its domain exception');
  } finally {
    browser.kill('SIGTERM');
    await new Promise(resolve => browser.exitCode !== null ? resolve() : browser.once('exit', resolve));
    for (const request of pending.values()) clearTimeout(request.timeout);
    rmSync(workspace, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
