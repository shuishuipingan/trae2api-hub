#!/usr/bin/env node
/**
 * test_oauth_dashboard.js — 浏览器 OAuth 登录面板的独立回归。
 *
 * 纯 Node + vm：不启动浏览器、不访问网络、不读取账号。
 * 覆盖：授权链接校验、回调地址校验、状态机、单定时器轮询、取消、
 *       401/过期/终态停止、有限重试、远程浏览器粘贴框、旧 501 兼容。
 * 运行：node test_oauth_dashboard.js
 */
'use strict';

const fs = require('fs');
const path = require('path');
const vm = require('vm');
const assert = require('assert');

const htmlPath = path.join(__dirname, 'dashboard.html');
const html = fs.readFileSync(htmlPath, 'utf8');
let passed = 0;
const failures = [];

function check(name, fn) {
  try {
    fn();
    passed += 1;
  } catch (err) {
    failures.push({ name, message: err && err.message || String(err) });
  }
}

async function checkAsync(name, fn) {
  try {
    await fn();
    passed += 1;
  } catch (err) {
    failures.push({ name, message: err && err.message || String(err) });
  }
}

function extract(startMarker, endMarker) {
  const start = html.indexOf(startMarker);
  const end = html.indexOf(endMarker, start + startMarker.length);
  if (start < 0 || end < 0) throw new Error('missing marker: ' + startMarker + ' / ' + endMarker);
  return html.slice(start, end);
}

const contractSrc = extract('/* BEGIN-OAUTH-CONTRACT', '/* END-OAUTH-CONTRACT */');
const runtimeSrc = extract('/* BEGIN-OAUTH-RUNTIME', '/* END-OAUTH-RUNTIME */');
const importSrc = extract('/* BEGIN-IMPORT-CONTRACT', '/* END-IMPORT-CONTRACT */');

/* ------------------------------------------------------------------ 静态面 */
check('OAuth 面板结构与入口存在', () => {
  ['oauthBlock', 'btnOauthStart', 'btnOauthCancel', 'btnOauthRetry', 'oauthLink',
   'oauthStatus', 'oauthRemaining', 'oauthVerification', 'oauthCallbackDetails',
   'oauthCallbackInput', 'oauthCallbackStatus', 'btnOauthCallback',
   'oauthRealmCn', 'oauthRealmIntl'].forEach(id => {
    const count = (html.match(new RegExp('id="' + id + '"', 'g')) || []).length;
    assert.strictEqual(count, 1, id + ' should appear exactly once, got ' + count);
  });
  assert.ok(html.includes('开始浏览器授权'), 'missing start button label');
  assert.ok(html.includes('浏览器不在网关机器？粘贴回调地址'), 'missing callback paste block');
});

check('授权链接为安全外链', () => {
  const anchor = html.slice(html.indexOf('id="oauthLink"'), html.indexOf('>打开授权页</a>') + 1);
  assert.ok(anchor.includes('target="_blank"'), 'authorization link must open a new tab');
  assert.ok(anchor.includes('rel="noopener noreferrer"'), 'authorization link must drop opener');
});

check('旧设备授权探测已移除，避免悬空回调监听', () => {
  assert.ok(!html.includes('probeLoginUnsupported(this)'), 'obsolete probe handler');
  assert.ok(!html.includes('设备授权登录（当前构建不支持）'), 'obsolete probe section');
});

check('OAuth 代码无 innerHTML / 日志 / 本地存储', () => {
  const block = contractSrc + runtimeSrc;
  assert.ok(!/\.innerHTML\b/.test(block), 'OAuth must not assign innerHTML');
  assert.ok(!/\bconsole\s*\./.test(block), 'OAuth must not log to console');
  assert.ok(!/localStorage|sessionStorage/.test(block), 'OAuth must not persist secrets locally');
  assert.ok(!/setInterval/.test(block), 'OAuth must not use setInterval');
});

check('预开空窗并清除 opener；仅一个轮询 timer', () => {
  assert.ok(runtimeSrc.includes("window.open('about:blank'"), 'must pre-open a blank popup');
  assert.ok(runtimeSrc.includes('popup.opener = null'), 'must clear popup.opener before navigation');
  assert.strictEqual((runtimeSrc.match(/setTimeout\(oauthTick/g) || []).length, 1,
    'exactly one polling timer entrypoint');
  assert.ok(runtimeSrc.includes('clearTimeout(OAUTH.timer)'), 'timer must be cancellable');
  assert.ok(runtimeSrc.includes('AbortController'), 'polling must be abortable');
});

check('端点只经统一前缀构造，不散落字面量', () => {
  assert.ok(contractSrc.includes("OAUTH_ENDPOINT = '/accounts/login/'"), 'missing endpoint base');
  assert.strictEqual((runtimeSrc.match(/fetch\(OAUTH_ENDPOINT \+ action/g) || []).length, 1,
    'all OAuth calls must go through oauthRequest');
  assert.ok(!runtimeSrc.includes('/accounts/login/poll'), 'poll endpoint must use the shared base');
  assert.ok(!runtimeSrc.includes('/accounts/login/cancel'), 'cancel endpoint must use the shared base');
});

check('所有内联脚本语法可编译', () => {
  const blocks = [...html.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/g)]
    .map(m => m[1]).filter(src => src.trim());
  assert.ok(blocks.length >= 2, 'expected inline scripts');
  blocks.forEach((src, index) => {
    try { new Function(src); }
    catch (err) { throw new Error('script block #' + index + ' syntax error: ' + err.message); }
  });
});

/* ------------------------------------------------------------------ vm 夹具 */
function makeElement(id) {
  return {
    id, textContent: '', value: '', hidden: false, disabled: false, open: false,
    href: '', checked: false, focused: false, scrolled: false, closed: false,
    style: {}, dataset: {}, attrs: {}, classList: { add() {}, remove() {}, toggle() {} },
    setAttribute(key, value) { this.attrs[key] = String(value); if (key === 'href') this.href = String(value); },
    removeAttribute(key) { delete this.attrs[key]; if (key === 'href') this.href = ''; },
    focus() { this.focused = true; },
    scrollIntoView() { this.scrolled = true; },
    close() { this.closed = true; }
  };
}

function makeHarness() {
  const timers = new Map();
  let nextTimerId = 1;
  const clock = { now: 1700000000000 };
  const RealDate = Date;
  function FakeDate(...args) { return new RealDate(...args); }
  FakeDate.now = () => clock.now;
  FakeDate.parse = RealDate.parse;
  FakeDate.UTC = RealDate.UTC;

  const elements = {};
  ['oauthBlock', 'btnOauthStart', 'btnOauthCancel', 'btnOauthRetry', 'oauthLink',
   'oauthStatus', 'oauthRemaining', 'oauthVerification', 'oauthCallbackDetails',
   'oauthCallbackInput', 'oauthCallbackStatus', 'btnOauthCallback',
   'oauthRealmCn', 'oauthRealmIntl'].forEach(id => { elements[id] = makeElement(id); });

  const state = {
    requests: [], popups: [], panelLoginCalls: 0, loadAccountsCalls: 0,
    responder: async () => makeResponse(200, {})
  };

  const sandbox = {
    console, URL, Promise, Object, Array, String, Number, Math, isFinite,
    encodeURIComponent, Date: FakeDate, AbortController,
    setTimeout(fn, ms) {
      const id = nextTimerId++;
      timers.set(id, { fn, at: clock.now + (Number(ms) || 0) });
      return id;
    },
    clearTimeout(id) { timers.delete(id); },
    document: { getElementById(id) { return elements[id] || null; } },
    location: { hostname: '127.0.0.1', origin: 'http://127.0.0.1:8791' },
    authHeaders(base) { return Object.assign({ 'X-Panel-Token': 'test-panel-token' }, base || {}); },
    panelNeedsLogin() { state.panelLoginCalls += 1; },
    loadAccounts() { state.loadAccountsCalls += 1; return Promise.resolve(); },
    fetch(url, init) { state.requests.push({ url, init }); return state.responder(url, init); }
  };
  sandbox.window = sandbox;
  sandbox.open = function () {
    const popup = {
      closed: false, opener: { leaked: true }, navigated: '',
      location: { replace(url) { popup.navigated = url; } },
      close() { popup.closed = true; }
    };
    state.popups.push(popup);
    return popup;
  };

  const ctx = vm.createContext(sandbox);
  vm.runInContext(importSrc, ctx);
  vm.runInContext(contractSrc, ctx);
  vm.runInContext(runtimeSrc, ctx);

  elements.oauthRealmIntl.checked = true;
  elements.oauthRealmCn.checked = false;

  async function advance(ms) {
    clock.now += Number(ms) || 0;
    const due = [...timers.entries()]
      .filter(([, timer]) => timer.at <= clock.now)
      .sort((a, b) => a[1].at - b[1].at);
    for (const [id, timer] of due) {
      if (!timers.has(id)) continue;
      timers.delete(id);
      await timer.fn();
    }
  }

  function resetResponder(fn) { state.responder = fn; }
  function requestsTo(action) {
    return state.requests.filter(r => r.url.indexOf('/accounts/login/' + action) === 0);
  }
  function lastRequest() { return state.requests[state.requests.length - 1]; }

  return { ctx, elements, state, timers, clock, advance, resetResponder, requestsTo, lastRequest };
}

function makeResponse(status, body) {
  return {
    status,
    ok: status >= 200 && status < 300,
    text: async () => (body === undefined ? '' : JSON.stringify(body))
  };
}

function startPayload(overrides) {
  const now = Math.floor(1700000000000 / 1000);
  return Object.assign({
    status: 'pending',
    state: 'state-abc',
    authorization_url: 'https://www.trae.ai/oauth/authorize?client_id=demo',
    verification_uri: 'https://www.trae.ai/device?code=ABCD-1234',
    redirect_uri: 'http://127.0.0.1:49152/authorize',
    expires_at: now + 300,
    interval: 2,
    realm: 'intl'
  }, overrides || {});
}

/* ------------------------------------------------------------------ 纯函数 */
check('纯函数契约可加载', () => {
  const h = makeHarness();
  const c = h.ctx.__oauthContract;
  ['oauthSafeAuthorizeUrl', 'oauthNormalizeExpiry', 'oauthRemainingSeconds',
   'oauthPollDelay', 'oauthBackoffMs', 'oauthIsTerminal', 'oauthParseStartResponse',
   'oauthValidateCallbackUrl', 'oauthStatusText'].forEach(name => {
    assert.strictEqual(typeof c[name], 'function', name + ' must be exported');
  });
});

check('授权链接只接受 https 官方域', () => {
  const c = makeHarness().ctx.__oauthContract;
  assert.strictEqual(c.oauthSafeAuthorizeUrl('https://www.trae.ai/oauth?x=1'),
    'https://www.trae.ai/oauth?x=1');
  assert.strictEqual(c.oauthSafeAuthorizeUrl('https://www.trae.cn/authorization'), 'https://www.trae.cn/authorization');
  assert.strictEqual(c.oauthSafeAuthorizeUrl('https://trae.com.cn/oauth'), '');
  assert.strictEqual(c.oauthSafeAuthorizeUrl('https://auth.traeapi.us/oauth'), '');
  [
    'http://www.trae.ai/oauth',
    'javascript:alert(1)',
    'data:text/html,<script>alert(1)</script>',
    'https://evil.example/oauth',
    'https://trae.ai.evil.example/oauth',
    'https://evil-trae.ai/oauth',
    'https://www.trae.ai@evil.example/oauth',
    'https://user:pass@www.trae.ai/oauth',
    ''
  ].forEach(url => assert.strictEqual(c.oauthSafeAuthorizeUrl(url), '', 'must reject: ' + url));
});

check('expires_at 归一化与剩余时间', () => {
  const c = makeHarness().ctx.__oauthContract;
  const now = 1700000000000;
  assert.strictEqual(c.oauthNormalizeExpiry(1700000300, now), 1700000300000);
  assert.strictEqual(c.oauthNormalizeExpiry(1700000300000, now), 1700000300000);
  assert.strictEqual(c.oauthNormalizeExpiry(120, now), now + 120000);
  assert.strictEqual(c.oauthNormalizeExpiry('2023-11-14T22:13:20Z', now), 1700000000000);
  assert.strictEqual(c.oauthNormalizeExpiry('not-a-date', now), 0);
  assert.strictEqual(c.oauthNormalizeExpiry(null, now), 0);
  assert.strictEqual(c.oauthRemainingSeconds(now + 1500, now), 2);
  assert.strictEqual(c.oauthRemainingSeconds(now - 1, now), 0);
  assert.strictEqual(c.oauthPollDelay(0), 2);
  assert.strictEqual(c.oauthPollDelay(7), 7);
  assert.strictEqual(c.oauthPollDelay(999), 60);
  assert.strictEqual(c.oauthBackoffMs(1), 1000);
  assert.strictEqual(c.oauthBackoffMs(9), 15000);
});

check('终态与可读状态文案', () => {
  const c = makeHarness().ctx.__oauthContract;
  ['success', 'failed', 'expired', 'cancelled', 'not_found'].forEach(s => {
    assert.ok(c.oauthIsTerminal(s), s + ' must be terminal');
    assert.ok(c.oauthStatusText(s).length > 0, s + ' needs readable text');
  });
  ['pending', 'exchanging', 'unknown'].forEach(s => assert.ok(!c.oauthIsTerminal(s)));
  assert.ok(c.oauthStatusText('failed', '后端通用错误').includes('后端通用错误'));
});

check('start 响应解析与旧 501 兼容', () => {
  const c = makeHarness().ctx.__oauthContract;
  const ok = c.oauthParseStartResponse(startPayload(), 1700000000000);
  assert.ok(ok.ok && ok.state === 'state-abc' && ok.interval === 2 && ok.realm === 'intl');
  const unsupported = c.oauthParseStartResponse({ status: 'unsupported', message: '不支持设备授权' }, 1700000000000);
  assert.ok(!unsupported.ok && unsupported.terminal && unsupported.message === '不支持设备授权');
  assert.ok(!c.oauthParseStartResponse({ authorization_url: 'https://www.trae.ai/x' }).ok);
  const failed = c.oauthParseStartResponse({ status: 'failed', message: '监听端口启动失败' }, 1700000000000);
  assert.ok(!failed.ok && failed.status === 'failed' && failed.message.includes('监听端口启动失败'));
  assert.ok(!c.oauthParseStartResponse({ state: 'x' }).ok);
  assert.strictEqual(c.oauthParseStartResponse({ state: 'x', authorization_url: 'https://www.trae.ai/x', interval: 999 }).interval, 60);
});

check('回调地址必须匹配网关 redirect_uri', () => {
  const c = makeHarness().ctx.__oauthContract;
  const redirect = 'http://127.0.0.1:49152/authorize';
  assert.ok(c.oauthValidateCallbackUrl('http://127.0.0.1:49152/authorize?code=abc&state=s', redirect, 's').ok);
  assert.strictEqual(c.oauthValidateCallbackUrl('http://127.0.0.1:49152/authorize?code=abc&state=other', redirect, 's').ok, false);
  assert.ok(c.oauthValidateCallbackUrl('http://localhost:49152/authorize?code=abc', 'http://localhost:49152/authorize').ok);
  [
    'javascript:alert(1)',
    'data:text/html,x',
    'http://127.0.0.1:9999/authorize?code=abc',
    'http://localhost:49152/authorize?code=abc',
    'http://192.168.1.2:49152/authorize?code=abc',
    'http://127.0.0.1:49152/other?code=abc',
    'https://evil.example/authorize?code=abc',
    ''
  ].forEach(url => {
    const verdict = c.oauthValidateCallbackUrl(url, redirect);
    assert.strictEqual(verdict.ok, false, 'must reject: ' + url);
    assert.ok(verdict.reason.length > 0);
  });
});

/* ------------------------------------------------------------------ 运行时 */
(async () => {
  await checkAsync('start：预开弹窗、清 opener、校验后导航并启动轮询', async () => {
    const h = makeHarness();
    h.resetResponder(async url => {
      assert.strictEqual(url, '/accounts/login/start');
      return makeResponse(200, startPayload());
    });
    await h.ctx.oauthStart(h.elements.btnOauthStart);
    const req = h.state.requests[0];
    assert.strictEqual(req.url, '/accounts/login/start');
    assert.deepStrictEqual(JSON.parse(req.init.body), { realm: 'intl' });
    assert.strictEqual(req.init.headers['X-Panel-Token'], 'test-panel-token');
    assert.strictEqual(h.state.popups.length, 1);
    assert.strictEqual(h.state.popups[0].opener, null);
    assert.strictEqual(h.state.popups[0].navigated, 'https://www.trae.ai/oauth/authorize?client_id=demo');
    assert.strictEqual(h.elements.oauthLink.href, 'https://www.trae.ai/oauth/authorize?client_id=demo');
    assert.strictEqual(h.elements.oauthLink.hidden, false);
    assert.strictEqual(h.elements.btnOauthCancel.hidden, false);
    assert.ok(h.elements.oauthStatus.textContent.includes('已打开授权页'));
    assert.strictEqual(h.timers.size, 1, 'exactly one polling timer should be scheduled');
    assert.strictEqual(h.ctx.OAUTH.state, 'state-abc');
    await h.advance(1000);
    assert.ok(h.elements.oauthRemaining.textContent.includes('剩余'), 'remaining time must be visible');
  });

  await checkAsync('区域选择：cn 传入 start 请求', async () => {
    const h = makeHarness();
    h.elements.oauthRealmCn.checked = true;
    h.elements.oauthRealmIntl.checked = false;
    h.resetResponder(async () => makeResponse(200, startPayload({ realm: 'cn' })));
    await h.ctx.oauthStart(h.elements.btnOauthStart);
    assert.deepStrictEqual(JSON.parse(h.state.requests[0].init.body), { realm: 'cn' });
    assert.strictEqual(h.ctx.OAUTH.realm, 'cn');
  });

  await checkAsync('关闭时忽略迟到的 start 响应', async () => {
    const h = makeHarness();
    let resolveStart = null;
    h.resetResponder(async () => new Promise(resolve => {
      resolveStart = () => resolve(makeResponse(200, startPayload()));
    }));
    const pending = h.ctx.oauthStart(h.elements.btnOauthStart);
    assert.strictEqual(h.state.requests.length, 1);
    h.ctx.oauthLeave();
    resolveStart();
    await pending;
    assert.strictEqual(h.ctx.OAUTH.active, false);
    assert.strictEqual(h.ctx.OAUTH.state, '');
    assert.strictEqual(h.timers.size, 0);
    assert.strictEqual(h.state.popups[0].closed, true);
  });

  await checkAsync('start：拒绝非官方/非 https 授权链接且不导航', async () => {
    const h = makeHarness();
    h.resetResponder(async () => makeResponse(200, startPayload({ authorization_url: 'javascript:alert(1)' })));
    await h.ctx.oauthStart(h.elements.btnOauthStart);
    assert.strictEqual(h.state.popups[0].navigated, '');
    assert.strictEqual(h.state.popups[0].closed, true);
    assert.ok(h.elements.oauthStatus.textContent.includes('拒绝打开'));
    assert.strictEqual(h.ctx.OAUTH.active, false);
    assert.strictEqual(h.timers.size, 0);
  });

  await checkAsync('start：旧 501 unsupported 可读且不轮询', async () => {
    const h = makeHarness();
    h.resetResponder(async () => makeResponse(501, { status: 'unsupported', message: '设备授权不可用，请导入凭证' }));
    await h.ctx.oauthStart(h.elements.btnOauthStart);
    assert.ok(h.elements.oauthStatus.textContent.includes('设备授权不可用'));
    assert.strictEqual(h.ctx.OAUTH.active, false);
    assert.strictEqual(h.timers.size, 0);
    assert.strictEqual(h.state.popups[0].closed, true);
  });

  await checkAsync('轮询：pending → exchanging → success 后停止并刷新账号', async () => {
    const h = makeHarness();
    let polls = 0;
    h.resetResponder(async url => {
      if (url === '/accounts/login/start') return makeResponse(200, startPayload());
      polls += 1;
      if (polls === 1) return makeResponse(200, { status: 'pending' });
      if (polls === 2) return makeResponse(200, { status: 'exchanging' });
      return makeResponse(200, { status: 'success', account: { nickname: 'demo-user' } });
    });
    await h.ctx.oauthStart(h.elements.btnOauthStart);
    await h.advance(2000);
    assert.ok(h.elements.oauthStatus.textContent.includes('等待浏览器'));
    await h.advance(2000);
    assert.ok(h.elements.oauthStatus.textContent.includes('正在换取账号'));
    await h.advance(2000);
    assert.ok(h.elements.oauthStatus.textContent.includes('登录成功'));
    assert.ok(h.elements.oauthStatus.textContent.includes('demo-user'));
    assert.strictEqual(h.state.loadAccountsCalls, 1);
    assert.strictEqual(h.ctx.OAUTH.active, false);
    assert.strictEqual(h.timers.size, 0);
    assert.strictEqual(h.state.popups[0].closed, true);
    assert.strictEqual(h.elements.btnOauthCancel.hidden, true);
  });

  await checkAsync('轮询：401 停轮询并触发面板登录', async () => {
    const h = makeHarness();
    h.resetResponder(async url => {
      if (url === '/accounts/login/start') return makeResponse(200, startPayload());
      return makeResponse(401, { message: 'panel required' });
    });
    await h.ctx.oauthStart(h.elements.btnOauthStart);
    await h.advance(2000);
    assert.strictEqual(h.state.panelLoginCalls, 1);
    assert.strictEqual(h.ctx.OAUTH.active, false);
    assert.strictEqual(h.timers.size, 0);
    assert.strictEqual(h.state.popups[0].closed, true);
  });

  await checkAsync('轮询：连续失败有上限，可手动重试', async () => {
    const h = makeHarness();
    h.resetResponder(async url => {
      if (url === '/accounts/login/start') return makeResponse(200, startPayload());
      throw new Error('network down');
    });
    await h.ctx.oauthStart(h.elements.btnOauthStart);
    for (let i = 0; i < 5; i += 1) {
      h.ctx.OAUTH.nextPollAt = 0;
      await h.ctx.oauthPollOnce();
    }
    assert.strictEqual(h.ctx.OAUTH.active, false);
    assert.strictEqual(h.ctx.OAUTH.failures, 5);
    assert.ok(h.elements.oauthStatus.textContent.includes('连续 5 次'));
    assert.strictEqual(h.elements.btnOauthRetry.hidden, false);
    assert.strictEqual(h.elements.btnOauthCancel.hidden, true);
    assert.strictEqual(h.timers.size, 0, 'failure budget must clear the polling timer');
    h.ctx.oauthRetryPoll();
    assert.strictEqual(h.ctx.OAUTH.active, true);
    assert.strictEqual(h.elements.btnOauthRetry.hidden, true);
    assert.ok(h.timers.size >= 1);
  });

  await checkAsync('轮询：expires_at 到期自动停止', async () => {
    const h = makeHarness();
    h.resetResponder(async url => {
      if (url === '/accounts/login/start') return makeResponse(200, startPayload({
        expires_at: Math.floor(h.clock.now / 1000) + 3
      }));
      return makeResponse(200, { status: 'pending' });
    });
    await h.ctx.oauthStart(h.elements.btnOauthStart);
    await h.advance(5000);
    assert.strictEqual(h.ctx.OAUTH.active, false);
    assert.ok(h.elements.oauthStatus.textContent.includes('已过期'));
    assert.strictEqual(h.state.popups[0].closed, true);
  });

  await checkAsync('取消：停止 timer、关闭弹窗并通知网关', async () => {
    const h = makeHarness();
    h.resetResponder(async url => {
      if (url === '/accounts/login/start') return makeResponse(200, startPayload());
      return makeResponse(200, { status: 'cancelled' });
    });
    await h.ctx.oauthStart(h.elements.btnOauthStart);
    await h.ctx.oauthCancel(h.elements.btnOauthCancel);
    const cancel = h.requestsTo('cancel')[0];
    assert.ok(cancel, 'cancel request missing');
    assert.deepStrictEqual(JSON.parse(cancel.init.body), { state: 'state-abc' });
    assert.strictEqual(h.ctx.OAUTH.active, false);
    assert.strictEqual(h.timers.size, 0);
    assert.strictEqual(h.state.popups[0].closed, true);
    assert.ok(h.elements.oauthStatus.textContent.includes('已取消'));
  });

  await checkAsync('回调粘贴：提交完整 URL，校验失败不发请求', async () => {
    const h = makeHarness();
    h.resetResponder(async url => {
      if (url === '/accounts/login/start') return makeResponse(200, startPayload());
      return makeResponse(200, { status: 'pending' });
    });
    await h.ctx.oauthStart(h.elements.btnOauthStart);
    h.elements.oauthCallbackInput.value = 'http://127.0.0.1:9999/authorize?code=abc';
    await h.ctx.oauthSubmitCallback(h.elements.btnOauthCallback);
    assert.strictEqual(h.requestsTo('callback').length, 0);
    assert.ok(h.elements.oauthCallbackStatus.textContent.includes('回调地址'));

    h.elements.oauthCallbackInput.value = 'http://127.0.0.1:49152/authorize?code=abc&state=state-abc';
    await h.ctx.oauthSubmitCallback(h.elements.btnOauthCallback);
    const callback = h.requestsTo('callback')[0];
    assert.ok(callback, 'callback request missing');
    const body = JSON.parse(callback.init.body);
    assert.strictEqual(body.callback_url, 'http://127.0.0.1:49152/authorize?code=abc&state=state-abc');
    assert.strictEqual(body.state, 'state-abc');
    assert.strictEqual(h.elements.oauthCallbackInput.value, '');
    assert.ok(h.elements.oauthCallbackStatus.textContent.includes('已提交'));
  });

  await checkAsync('轮询终态：failed / cancelled / not_found 都停止', async () => {
    for (const status of ['failed', 'cancelled', 'not_found']) {
      const h = makeHarness();
      h.resetResponder(async url => {
        if (url === '/accounts/login/start') return makeResponse(200, startPayload());
        return makeResponse(200, { status, message: status === 'failed' ? '后端通用失败' : '' });
      });
      await h.ctx.oauthStart(h.elements.btnOauthStart);
      await h.advance(2000);
      assert.strictEqual(h.ctx.OAUTH.active, false, status + ' must stop polling');
      assert.strictEqual(h.timers.size, 0, status + ' must clear timer');
      assert.strictEqual(h.state.popups[0].closed, true, status + ' must close popup');
      assert.ok(h.elements.oauthStatus.textContent.length > 0, status + ' needs readable text');
    }
  });

  await checkAsync('远程浏览器自动展开回调粘贴框', async () => {
    const h = makeHarness();
    h.ctx.location.hostname = '192.168.1.10';
    h.resetResponder(async url => {
      if (url === '/accounts/login/start') return makeResponse(200, startPayload());
      return makeResponse(200, { status: 'pending' });
    });
    await h.ctx.oauthStart(h.elements.btnOauthStart);
    assert.strictEqual(h.elements.oauthCallbackDetails.open, true);
  });

  await checkAsync('弹窗被拦截时保留显式链接', async () => {
    const h = makeHarness();
    h.ctx.open = function () { return null; };
    h.resetResponder(async url => {
      if (url === '/accounts/login/start') return makeResponse(200, startPayload());
      return makeResponse(200, { status: 'pending' });
    });
    await h.ctx.oauthStart(h.elements.btnOauthStart);
    assert.strictEqual(h.elements.oauthLink.hidden, false);
    assert.ok(h.elements.oauthStatus.textContent.includes('拦截'));
  });

  await checkAsync('关闭面板停止轮询并尽力取消会话', async () => {
    const h = makeHarness();
    h.resetResponder(async url => {
      if (url === '/accounts/login/start') return makeResponse(200, startPayload());
      return makeResponse(200, { status: 'pending' });
    });
    await h.ctx.oauthStart(h.elements.btnOauthStart);
    h.ctx.oauthLeave();
    await Promise.resolve();
    await Promise.resolve();
    assert.strictEqual(h.ctx.OAUTH.active, false);
    assert.strictEqual(h.timers.size, 0);
    assert.strictEqual(h.state.popups[0].closed, true);
    assert.ok(h.requestsTo('cancel').length >= 1, 'closing should ask the gateway to cancel');
  });

  await checkAsync('打开面板会重置残留状态', async () => {
    const h = makeHarness();
    h.ctx.oauthSetStatus('旧状态', 'warn');
    h.elements.btnOauthCancel.hidden = false;
    h.ctx.oauthReset();
    assert.strictEqual(h.elements.oauthStatus.textContent, '');
    assert.strictEqual(h.elements.btnOauthCancel.hidden, true);
    assert.strictEqual(h.elements.oauthRealmIntl.checked, true);
    assert.strictEqual(h.ctx.OAUTH.state, '');
  });

  console.log('');
  console.log('dashboard OAuth regression');
  console.log('  file    : ' + htmlPath);
  console.log('  checks  : ' + passed + ' passed, ' + failures.length + ' failed');
  if (failures.length) {
    failures.forEach(f => console.log('  FAIL    : ' + f.name + '\n             ' + f.message));
    process.exitCode = 1;
  } else {
    console.log('  result  : OK');
  }
})();
