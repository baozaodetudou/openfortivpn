import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { readFileSync } from 'node:fs';

const source = readFileSync(new URL('../web/remote-client.js', import.meta.url), 'utf8');
function client(fetch) {
  const elements = new Map();
  const element = selector => {
    if (!elements.has(selector)) {
      const classes = new Set(selector === '#app' || selector === '#editor' ? ['hidden'] : []);
      elements.set(selector, { value: '', textContent: '', innerHTML: '', classes,
        classList: { add: c => classes.add(c), remove: c => classes.delete(c), contains: c => classes.has(c) },
        focus() {}, addEventListener() {} });
    }
    return elements.get(selector);
  };
  const context = vm.createContext({ fetch, AbortController, DOMException, Headers, Error,
    document: { querySelector: element, querySelectorAll: () => [], addEventListener() {} },
    sessionStorage: { getItem: () => '', setItem() {}, removeItem() {} },
    setTimeout: () => 1, clearTimeout() {}, requestAnimationFrame() {},
    crypto: { randomUUID: () => 'profile' }, confirm: () => true });
  vm.runInContext(source + '\nglobalThis.client={api,refresh,login,logout,state,renderAuthentication};', context);
  context.client.state.token = 'synthetic-token';
  return { ...context.client, context, element };
}

test('OTP input survives polling but clears on attempt changes, closure and logout', () => {
  const c=client(async()=>({status:200,ok:true,json:async()=>({})}));
  c.state.selected='one';
  c.state.challenges=[{profileId:'one',attemptId:'attempt',requestId:'nonce',prompt:'<script>untrusted prompt</script>',maxResponseBytes:64}];
  c.renderAuthentication();
  assert.equal(c.element('#authentication-prompt').textContent,'<script>untrusted prompt</script>');
  assert.equal(c.element('#authentication-prompt').innerHTML,'');
  const input=c.element('#authentication-response'); input.value='synthetic-otp';
  c.renderAuthentication(); assert.equal(input.value,'synthetic-otp');
  c.state.challenges[0].attemptId='another-attempt';
  c.renderAuthentication(); assert.equal(input.value,'');
  input.value='synthetic-otp'; c.logout();
  assert.equal(input.value,''); assert.equal(c.state.authChallenge,null);
  assert.equal(c.state.challenges.length,0);
  assert.equal(c.element('#authentication').classes.has('hidden'),true);
});

test('401 rejects login and keeps the console hidden', async () => {
  const c = client(async () => ({status: 401, ok: false}));
  await assert.rejects(c.login(), /令牌无效/);
  assert.equal(c.state.token, '');
  assert.equal(c.element('#app').classes.has('hidden'), true);
  assert.equal(c.element('#login').classes.has('hidden'), false);
});

test('v1 and v2 error envelopes preserve the actual message', async () => {
  for (const body of [{message: 'precise'}, {error: 'precise'}, {error: {code:'BUSY',message:'precise'}}]) {
    const c = client(async () => ({status:409, ok:false, json:async()=>body}));
    await assert.rejects(c.api('/api/v1/profiles'), /precise/);
  }
});

test('failed refresh rejects and exposes offline state', async () => {
  const c = client(async () => { throw new Error('offline'); });
  await assert.rejects(c.refresh(), /offline/);
  assert.equal(c.state.online, false);
  assert.match(c.element('#connection-state').textContent, /离线/);
});

test('a response from a previous session cannot restore the console', async () => {
  let resolve;
  const c = client(() => new Promise(r => { resolve=r; }));
  const pending = c.login();
  c.logout();
  resolve({status:200, ok:true, json:async()=>({profiles:[],instances:[],logs:[],engine:{available:true}})});
  await assert.rejects(pending, {name:'AbortError'});
  assert.equal(c.state.snapshot, null);
  assert.equal(c.element('#app').classes.has('hidden'), true);
});

test('successful authorization alone opens the console', async () => {
  const c = client(async () => ({status:200, ok:true, json:async()=>({profiles:[],instances:[],logs:[],engine:{available:true,platform:'test'}})}));
  await c.login();
  assert.equal(c.state.online, true);
  assert.equal(c.element('#app').classes.has('hidden'), false);
});

test('logout during JSON decoding rejects a previously authorized response', async () => {
  let resolve;
  let started;
  const decoding = new Promise(r=>{started=r;});
  const c = client(async () => ({status:200,ok:true,json:()=>new Promise(r=>{resolve=r;started();})}));
  const pending = c.api('/api/v1/snapshot');
  await decoding;
  c.logout();
  resolve({profiles:[{profile:{id:'obsolete'}}]});
  await assert.rejects(pending,{name:'AbortError'});
  assert.equal(c.state.snapshot,null);
});
