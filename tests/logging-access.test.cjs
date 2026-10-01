const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const crypto = require('node:crypto');
const load = (ctx, file) => vm.runInContext(fs.readFileSync(path.join(__dirname, '..', 'src', file), 'utf8'), ctx);
function area(initial = {}) {
  const data = structuredClone(initial);
  return {
    data,
    get: async keys => keys == null ? structuredClone(data) : Object.fromEntries((Array.isArray(keys) ? keys : [keys]).filter(k => k in data).map(k => [k, structuredClone(data[k])])),
    set: async obj => Object.assign(data, structuredClone(obj)),
    remove: async keys => (Array.isArray(keys) ? keys : [keys]).forEach(k => delete data[k])
  };
}
function context(config = {}, local = {}, managed = {}) {
  const session = area(), records = new Map(), posts = [], tabRemoved = [];
  const chrome = {
    storage: { managed: area(managed), local: area(local), session },
    runtime: { getManifest: () => ({version:'1.9.1'}), getURL: p => 'chrome-extension://extension-id/' + p },
    alarms: { create() {} },
    tabs: {
      get: async id => { if (!records.has(id)) throw new Error('Tab gone'); return structuredClone(records.get(id)); },
      update: async (id, update) => { assert.ok(records.has(id)); Object.assign(records.get(id), update); },
      onRemoved: { addListener: f => tabRemoved.push(f) }
    }
  };
  const ctx = vm.createContext({chrome, URL, crypto:crypto.webcrypto, TextEncoder, AbortController, setTimeout, clearTimeout, console,
    fetch:async (url, init) => { posts.push({url, init}); return {ok:true}; }
  });
  load(ctx, 'config.js');
  ctx.AITM_CONFIG = Object.freeze({...ctx.AITM_CONFIG, ...config});
  load(ctx, 'settings.js'); load(ctx, 'telemetry.js'); load(ctx, 'access.js');
  return {ctx, chrome, records, posts, tabRemoved};
}

test('logging endpoint accepts domain/full URL and rejects unsafe URLs', () => {
  const {ctx} = context();
  assert.equal(ctx.AITMSettings.endpoint(' logs.example.test '), 'https://logs.example.test/api/aitm');
  assert.equal(ctx.AITMSettings.endpoint('https://logs.example.test/events'), 'https://logs.example.test/events');
  assert.equal(ctx.AITMSettings.endpoint('http://localhost:8765'), 'http://localhost:8765/api/aitm');
  assert.equal(ctx.AITMSettings.endpoint(''), '');
  for (const value of ['http://logs.example.test', 'https://user:pass@logs.example.test', 'https://logs.example.test/#token', 'file:///tmp/log']) {
    assert.throws(() => ctx.AITMSettings.endpoint(value));
  }
});

test('only source config determines the endpoint; legacy local and managed destinations are ignored', async () => {
  const legacyLocal = {aitm_settings:{reportingEndpoint:'local.example.test'}};
  const legacyManaged = {reportingEndpoint:'managed.example.test', userId:'test-user'};
  const disabled = context({}, legacyLocal, legacyManaged);
  assert.equal((await disabled.ctx.AITMSettings.load()).reportingEndpoint, '');
  const configured = context({reportingEndpoint:'source.example.test'}, legacyLocal, legacyManaged);
  const settings = await configured.ctx.AITMSettings.load();
  assert.equal(settings.reportingEndpoint, 'https://source.example.test/api/aitm');
  assert.equal(settings.userId, 'test-user');
});

test('deployment has no user settings page or toolbar configuration action', () => {
  const root = path.join(__dirname, '..');
  const manifest = JSON.parse(fs.readFileSync(path.join(root, 'manifest.json')));
  assert.equal(manifest.options_ui, undefined);
  assert.equal(manifest.options_page, undefined);
  assert.equal(manifest.action, undefined);
  assert.equal(fs.existsSync(path.join(root, 'options.html')), false);
  assert.equal(fs.existsSync(path.join(root, 'options.js')), false);
});

test('outbound logs use configured endpoint, valid HMAC and redact URL credentials/tokens', async () => {
  const {ctx,posts} = context({reportingEndpoint:'logs.example.test'}, {}, {telemetrySecret:'unit-test-secret'});
  await ctx.emit('aitm_domain_blocked', {hostname:'phish.test', url:'https://user:password@phish.test/path?code=secret#token'}, {tab:{url:'https://phish.test/?secret=1'}});
  await ctx.flushQueue();
  assert.equal(posts.length, 1);
  const {url,init} = posts[0];
  assert.equal(url, 'https://logs.example.test/api/aitm');
  assert.equal(init.method, 'POST'); assert.equal(init.credentials, 'omit'); assert.equal(init.redirect, 'error');
  const event = JSON.parse(init.body);
  assert.equal(event.data.url, 'https://phish.test/path');
  assert.equal(event.tabUrl, 'https://phish.test/');
  assert.equal(event.source, 'aitm-phishing-guard');
  assert.ok(event.eventId);
  const expected = crypto.createHmac('sha256', 'unit-test-secret').update(init.headers['X-AiTM-Timestamp'] + '.' + init.body).digest('hex');
  assert.equal(init.headers['X-AiTM-Signature'], 'sha256=' + expected);
});

test('offline events persist and concurrent enqueues survive an in-flight flush', async () => {
  const {ctx,chrome} = context({reportingEndpoint:'logs.example.test'});
  ctx.fetch = async () => ({ok:false});
  await Promise.all(Array.from({length:12}, (_,i) => ctx.emit('event', {index:i}, {})));
  await ctx.flushQueue();
  assert.equal(chrome.storage.local.data.aitm_tx_queue.length, 12);
  const firstIds = chrome.storage.local.data.aitm_tx_queue.map(e => e.eventId);
  let unblock;
  let started;
  const waitStarted = new Promise(resolve => started = resolve);
  ctx.fetch = () => { started(); return new Promise(resolve => unblock = resolve); };
  const running = ctx.flushQueue();
  await waitStarted;
  await ctx.emit('concurrent', {}, {});
  ctx.fetch = async () => ({ok:true});
  unblock({ok:true});
  await running;
  assert.equal(chrome.storage.local.data.aitm_tx_queue.length, 1);
  assert.equal(chrome.storage.local.data.aitm_tx_queue[0].event, 'concurrent');
  assert.equal(new Set(firstIds).size, 12);
  await ctx.flushQueue();
  assert.equal(chrome.storage.local.data.aitm_tx_queue.length, 0);
});

test('empty deployment config sends no queued/new events even when legacy endpoints exist', async () => {
  const {ctx,chrome,posts} = context({}, {
    aitm_tx_queue:[{eventId:'pending',event:'old'}],
    aitm_settings:{reportingEndpoint:'old.example.test'}
  }, {reportingEndpoint:'managed.example.test'});
  chrome.storage.managed.get = async () => { throw new Error('must not read storage without a destination'); };
  assert.equal((await ctx.emit('new', {}, {})).status, 'disabled');
  await ctx.flushQueue();
  assert.equal(chrome.storage.local.data.aitm_tx_queue.length, 1);
  assert.equal(posts.length, 0);
});

test('invalid source destination disables logging instead of queuing undeliverable events', async () => {
  const {ctx,chrome,posts} = context({reportingEndpoint:'http://insecure.example.test'});
  ctx.console = {error() {}};
  assert.equal((await ctx.emit('new', {}, {})).status, 'disabled');
  await ctx.flushQueue();
  assert.equal(chrome.storage.local.data.aitm_tx_queue, undefined);
  assert.equal(posts.length, 0);
});

async function blockedContext(frameId = 0) {
  const fixture = context({reportingEndpoint:'logs.example.test'});
  const {ctx,records} = fixture;
  records.set(7, {id:7,url:'https://portal.test/home'});
  const sender = {id:'extension-id',tab:{id:7,url:'https://portal.test/home'},frameId,
    url:'https://phish.test/common/oauth2/authorize?code=private#token'};
  if (frameId === 0) records.get(7).url = sender.url;
  await ctx.blockTab(sender, {hostname:'spoofed.test',url:'javascript:alert(1)',score:7,tier:'strong'});
  const record = fixture.chrome.storage.session.data.aitm_block_7;
  return {...fixture,sender,record,message:{tabId:7,blockId:record.id},pageSender:{url:records.get(7).url}};
}

test('block and continue correlate domain logs and allow only this exact host in this tab', async () => {
  const {ctx,chrome,records,posts,sender,record,message,pageSender} = await blockedContext();
  assert.equal(record.hostname, 'phish.test');
  assert.ok(!records.get(7).url.includes('private'));
  await ctx.continueBlocked(message, pageSender);
  assert.equal(records.get(7).url, sender.url);
  assert.equal(await ctx.domainAllowed(sender), true);
  assert.equal(await ctx.domainAllowed({...sender,tab:{id:8}}), false);
  assert.equal(await ctx.domainAllowed({...sender,url:'https://child.phish.test/'}), false);
  assert.equal(await ctx.domainAllowed({...sender,url:'https://phish.test.attacker.test/'}), false);
  assert.equal(chrome.storage.session.data.aitm_block_7, undefined);
  await ctx.flushQueue();
  const events = posts.map(p => JSON.parse(p.init.body));
  const blocked = events.find(e => e.event === 'aitm_domain_blocked');
  const continued = events.find(e => e.event === 'aitm_false_positive_report');
  assert.equal(blocked.data.blockId, continued.data.blockId);
  assert.equal(continued.data.action, 'allow_and_continue');
  assert.equal(continued.data.scope, 'tab');
});

test('continuing a blocked iframe restores the parent page, and closing removes the exception', async () => {
  const {ctx,chrome,records,message,pageSender,tabRemoved} = await blockedContext(2);
  await ctx.continueBlocked(message,pageSender);
  assert.equal(records.get(7).url, 'https://portal.test/home');
  tabRemoved[0](7);
  await ctx.tabActions.get(7);
  assert.equal(chrome.storage.session.data.aitm_allow_7, undefined);
});

test('web content, wrong tab, stale ID and stale page cannot grant an exception', async () => {
  const {ctx,chrome,records,message,pageSender,sender} = await blockedContext();
  await assert.rejects(ctx.continueBlocked(message,sender), /extension/);
  await assert.rejects(ctx.continueBlocked({...message,blockId:'wrong'},pageSender), /hết hiệu lực/);
  await assert.rejects(ctx.continueBlocked(message,{...pageSender,tab:{id:8}}), /Tab/);
  records.get(7).url = 'https://other.test/';
  await assert.rejects(ctx.continueBlocked(message,pageSender), /hết hiệu lực/);
  assert.equal(chrome.storage.session.data.aitm_allow_7, undefined);
});

test('extension sender and tab-bound record work when Chrome omits the internal tab URL', async () => {
  const {ctx,records,message,pageSender} = await blockedContext();
  delete records.get(7).url;
  assert.equal((await ctx.verifiedBlock(message,pageSender)).id, message.blockId);
});

test('SPA blocking restores current tab URL rather than the initial sender document URL', async () => {
  const {ctx,records,chrome} = context();
  records.set(7,{id:7,url:'https://phish.test/common/oauth2/authorize?state=preserve#fragment'});
  await ctx.blockTab({tab:{id:7},frameId:0,url:'https://phish.test/start'},{});
  assert.equal(chrome.storage.session.data.aitm_block_7.returnUrl, 'https://phish.test/common/oauth2/authorize?state=preserve#fragment');
});

test('duplicate block messages preserve the active record when the tab URL is hidden', async () => {
  const {ctx,records,chrome,sender,record} = await blockedContext();
  delete records.get(7).url;
  await ctx.blockTab(sender,{score:9});
  assert.equal(chrome.storage.session.data.aitm_block_7.id, record.id);
});
