import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
const require = createRequire(new URL('../app/package.json', import.meta.url));
const ts = require('typescript');
const modules = new Map();
function loadService(name) {
  if (modules.has(name)) return modules.get(name);
  const source = readFileSync(new URL(`../app/src/lib/services/${name}.ts`, import.meta.url), 'utf8');
  const context = vm.createContext({ exports: {}, Error, Map, Promise,
    require: name => loadService(name.replace('./', '')) });
  vm.runInContext(ts.transpileModule(source, { compilerOptions: {
    module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022,
  } }).outputText, context);
  modules.set(name, context.exports);
  return context.exports;
}
const { AppearanceController, NativeAppearanceQueue, clampUiScale } = loadService('appearance');
const { AutostartController, DesktopPreferencesController, SettingsOperationQueue } = loadService('desktop-settings');
const { RemoteSettingsController } = loadService('remote-settings');
const deferred = () => { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; };
const flush = async () => { for (let i = 0; i < 8; i++) await Promise.resolve(); };
const remoteStatus = (running = false, port = 18443) => ({ enabled: running, running, bindAddress: '127.0.0.1', port,
  url: `https://127.0.0.1:${port}`, certificateFingerprint: 'synthetic-fingerprint', tokenConfigured: running });

test('appearance normalizes untrusted storage and persists only whitelisted preferences', async () => {
  const stored = [], rendered = [];
  let state;
  const appearance = new AppearanceController({
    read: () => '{"theme":"unknown","accent":"blue","scale":148,"token":"synthetic-secret"}',
    write: value => stored.push(JSON.parse(value)), render: value => rendered.push(value),
  }, value => { state = value; });
  appearance.initialize();
  assert.equal(state.preferences.theme, 'system');
  assert.equal(state.preferences.accent, 'blue');
  assert.equal(state.preferences.scale, 150);
  assert.equal(stored.length, 0);
  appearance.update({ scale: 77 });
  assert.equal(state.preferences.scale, 80);
  assert.deepEqual(Object.keys(stored[0]).sort(), ['accent', 'scale', 'theme']);
  assert.equal(JSON.stringify(stored).includes('synthetic-secret'), false);
  assert.equal(clampUiScale(Number.NaN), 100);
  appearance.dispose();
  appearance.update({ theme: 'light' });
  assert.equal(rendered.length, 2);
});

test('native appearance commands stay ordered and coalesce changes while an older command is pending', async () => {
  const calls = [], zoom = [], theme = [];
  let state;
  const appearance = new AppearanceController({ read: () => null, write() {}, render() {}, native: {
    setZoom: scale => { calls.push(['zoom', scale]); const task = deferred(); zoom.push(task); return task.promise; },
    setTheme: value => { calls.push(['theme', value]); const task = deferred(); theme.push(task); return task.promise; },
  } }, value => { state = value; });
  appearance.initialize();
  await flush();
  assert.deepEqual(calls, [['zoom', 1]]);
  appearance.update({ scale: 110, theme: 'light' });
  appearance.update({ scale: 125, theme: 'dark' });
  assert.equal(state.preferences.scale, 125);
  assert.equal(calls.length, 1);
  zoom[0].resolve();
  await flush();
  assert.deepEqual(calls, [['zoom', 1], ['zoom', 1.25]]);
  zoom[1].resolve();
  await flush();
  assert.deepEqual(calls.at(-1), ['theme', 'dark']);
  appearance.update({ scale: 140, theme: 'light' });
  theme[0].resolve();
  await flush();
  assert.deepEqual(calls.at(-1), ['zoom', 1.4]);
  zoom[2].resolve();
  await flush();
  assert.deepEqual(calls.at(-1), ['theme', 'light']);
  theme[1].resolve();
  await appearance.whenIdle();
});

test('stale native errors cannot replace a newer preference and disposal stops queued native work', async () => {
  const zoom = deferred();
  let published = 0, themes = 0, state;
  const appearance = new AppearanceController({ read: () => null, write() {}, render() {}, native: {
    setZoom: () => zoom.promise, setTheme: async () => { themes++; },
  } }, value => { published++; state = value; });
  appearance.initialize();
  await flush();
  appearance.update({ theme: 'light', scale: 110 });
  appearance.dispose();
  const count = published;
  zoom.reject({ password: 'synthetic-secret' });
  await appearance.whenIdle();
  assert.equal(published, count);
  assert.equal(themes, 0);
  assert.equal(state.error, '');
});

test('native failure preserves storage failure and fallback error text does not stringify secret fields', async () => {
  let state;
  const appearance = new AppearanceController({ read: () => null,
    write() { throw new Error('storage unavailable'); }, render() {}, native: {
      setZoom: async () => { throw { password: 'synthetic-secret' }; },
      setTheme: async () => {},
    } }, value => { state = value; });
  appearance.update({ theme: 'dark' });
  await appearance.whenIdle();
  assert.equal(state.error, '无法保存外观设置：storage unavailable');
  appearance.update({ theme: 'light' });
  await appearance.whenIdle();
  assert.equal(state.error.includes('synthetic-secret'), false);
});

test('desktop preference writes invalidate older refreshes and preserve the other preference', async () => {
  const oldRead = deferred(), write = deferred();
  let state, reads = 0, payload;
  const settings = new DesktopPreferencesController((command, args) => {
    if (command === 'get_desktop_preferences') return ++reads === 1
      ? Promise.resolve({ closeToTray: true, startMinimized: true }) : oldRead.promise;
    payload = args;
    return write.promise;
  }, value => { state = value; });
  await settings.refresh();
  const refreshing = settings.refresh();
  await flush();
  const saving = settings.set('closeToTray', false);
  assert.equal(state.busy, true);
  oldRead.resolve({ closeToTray: true, startMinimized: false });
  await flush();
  assert.equal(payload.preferences.closeToTray, false);
  assert.equal(payload.preferences.startMinimized, true);
  write.resolve({ closeToTray: false, startMinimized: true });
  await saving;
  await refreshing;
  assert.equal(state.value.closeToTray, false);
  assert.equal(state.value.startMinimized, true);
  assert.equal(state.loading, false);
  assert.equal(state.busy, false);
});

test('desktop preferences rollback failed writes and ignore responses after disposal', async () => {
  let state, published = 0;
  const write = deferred();
  const settings = new DesktopPreferencesController(command => command === 'get_desktop_preferences'
    ? Promise.resolve({ closeToTray: true, startMinimized: false }) : write.promise,
  value => { state = value; published++; });
  await settings.refresh();
  const pending = settings.set('startMinimized', true);
  write.reject({ error: { message: 'disk full' }, password: 'synthetic-secret' });
  await pending;
  assert.equal(state.value.startMinimized, false);
  assert.equal(state.error, '无法保存后台运行设置：disk full');
  const read = deferred();
  const closing = new DesktopPreferencesController(() => read.promise, () => { published++; });
  const refresh = closing.refresh();
  closing.dispose();
  const count = published;
  read.resolve({ closeToTray: false, startMinimized: false });
  await refresh;
  assert.equal(published, count);
});

test('autostart verifies the native change and a stale read cannot undo the chosen state', async () => {
  const stale = deferred();
  let reads = 0, native = false, state;
  const calls = [];
  const settings = new AutostartController({
    isEnabled: () => ++reads === 2 ? stale.promise : Promise.resolve(native),
    enable: async () => { native = true; calls.push('enable'); },
    disable: async () => { native = false; calls.push('disable'); },
  }, value => { state = value; });
  await settings.refresh();
  const refreshing = settings.refresh();
  await flush();
  const saving = settings.update(true);
  stale.resolve(false);
  await saving;
  await refreshing;
  assert.equal(state.value, true);
  assert.deepEqual(calls, ['enable']);
  assert.equal(reads, 3);
});

test('autostart mismatch is reported and duplicate writes are not submitted while busy', async () => {
  let state, enables = 0, disables = 0;
  const enable = deferred();
  const settings = new AutostartController({ isEnabled: async () => false,
    enable: () => { enables++; return enable.promise; }, disable: async () => { disables++; },
  }, value => { state = value; });
  await settings.refresh();
  const pending = settings.update(true);
  await settings.update(false);
  enable.resolve();
  await pending;
  assert.equal(enables, 1);
  assert.equal(disables, 0);
  assert.equal(state.value, false);
  assert.equal(state.error.includes('系统未能更新'), true);
});

function makeRemote(invoke, extra = {}) {
  let state;
  const states = [];
  const controller = new RemoteSettingsController({ invoke, copy: async () => {}, loadOpener: async () => async () => {}, ...extra }, value => {
    state = value;
    states.push(value);
  });
  return { controller, states, get state() { return state; } };
}

test('remote snapshots cannot replace a newer event or the outcome of a pending mutation', async () => {
  const mutation = deferred();
  const remote = makeRemote(() => mutation.promise);
  const ticket = remote.controller.snapshotTicket();
  remote.controller.receiveStatus(remoteStatus(true, 19443));
  remote.controller.receiveSnapshot(ticket, remoteStatus(false));
  assert.equal(remote.state.status.port, 19443);
  remote.controller.open();
  const pending = remote.controller.configure({ enabled: true, bindAddress: ' 127.0.0.1 ', port: 20443 });
  const during = remote.controller.snapshotTicket();
  remote.controller.receiveSnapshot(during, remoteStatus(false));
  remote.controller.receiveStatus(remoteStatus(false, 21443));
  mutation.resolve({ status: remoteStatus(true, 20443), token: 'synthetic-token' });
  assert.equal(await pending, true);
  assert.equal(remote.state.status.port, 21443);
  assert.equal(remote.state.status.running, false);
  assert.equal(remote.state.token, 'synthetic-token');
  remote.controller.receiveSnapshot(during, remoteStatus(true));
  assert.equal(remote.state.status.port, 21443);
});

test('closing or reopening the remote modal prevents a late token reveal while status still settles', async () => {
  for (const reopen of [false, true]) {
    const mutation = deferred();
    const remote = makeRemote(() => mutation.promise);
    remote.controller.open();
    const pending = remote.controller.rotateToken();
    remote.controller.close();
    if (reopen) remote.controller.open();
    mutation.resolve({ status: remoteStatus(true), token: 'synthetic-token' });
    assert.equal(await pending, false);
    assert.equal(remote.state.token, '');
    assert.equal(remote.state.open, reopen);
    assert.equal(remote.state.busy, false);
    assert.equal(remote.state.status.running, true);
    assert.equal(remote.states.some(state => state.token === 'synthetic-token'), false);
  }
});

test('remote disposal clears a revealed token and suppresses pending failures or updates', async () => {
  const mutation = deferred();
  let invokeCount = 0;
  const remote = makeRemote(() => ++invokeCount === 1
    ? Promise.resolve({ status: remoteStatus(true), token: 'synthetic-token' }) : mutation.promise);
  remote.controller.open();
  await remote.controller.rotateToken();
  assert.equal(remote.state.token, 'synthetic-token');
  const pending = remote.controller.rotateToken();
  remote.controller.dispose();
  const count = remote.states.length;
  mutation.reject({ password: 'synthetic-secret' });
  assert.equal(await pending, false);
  remote.controller.receiveStatus(remoteStatus(false));
  remote.controller.open();
  await remote.controller.rotateToken();
  assert.equal(remote.states.length, count);
  assert.equal(remote.state.token, '');
  assert.equal(invokeCount, 2);
});

test('remote writes keep the v1 payload and auto-close only when no one-time token was returned', async () => {
  const calls = [];
  const remote = makeRemote(async (command, args) => {
    calls.push({ command, args });
    return { status: remoteStatus(false), token: null };
  });
  remote.controller.open();
  assert.equal(await remote.controller.configure({ enabled: false, bindAddress: ' 127.0.0.1 ', port: 18443 }), true);
  assert.equal(calls[0].command, 'configure_remote_access');
  assert.equal(calls[0].args.input.bindAddress, '127.0.0.1');
  assert.equal(calls[0].args.input.port, 18443);
  assert.equal(remote.state.open, false);
  assert.equal(await remote.controller.rotateToken(), false);
  assert.equal(calls.length, 1);
});

test('late clipboard and opener failures cannot change a closed modal and old tokens cannot be copied', async () => {
  const clipboard = deferred(), opener = deferred();
  let copies = 0;
  const remote = makeRemote(async () => ({ status: remoteStatus(true), token: 'synthetic-token' }), {
    copy: () => { copies++; return clipboard.promise; }, loadOpener: async () => () => opener.promise,
  });
  remote.controller.open();
  await remote.controller.rotateToken();
  assert.equal(await remote.controller.copyToken('obsolete-token'), false);
  const copying = remote.controller.copyToken('synthetic-token');
  const opening = remote.controller.openUrl();
  await flush();
  remote.controller.close();
  const count = remote.states.length;
  clipboard.reject(new Error('clipboard unavailable'));
  opener.reject(new Error('opener unavailable'));
  assert.equal(await copying, false);
  await opening;
  assert.equal(remote.states.length, count);
  assert.equal(remote.state.error, '');
  assert.equal(copies, 1);
});

test('a remounted page waits for an old native appearance command before applying its own intent', async () => {
  const queue = new NativeAppearanceQueue(), oldZoom = deferred(), calls = [];
  let oldAlive = true;
  const oldPage = new AppearanceController({ read: () => null, write() {}, render() {},
    native: queue.bind({ setZoom: scale => { calls.push(['oldZoom', scale]); return oldZoom.promise; },
      setTheme: async theme => { calls.push(['oldTheme', theme]); } }, () => oldAlive),
  }, () => {});
  oldPage.initialize();
  await flush();
  oldPage.update({ scale: 110, theme: 'dark' });
  oldAlive = false;
  oldPage.dispose();
  const nextPage = new AppearanceController({ read: () => null, write() {}, render() {},
    native: queue.bind({ setZoom: async scale => { calls.push(['newZoom', scale]); },
      setTheme: async theme => { calls.push(['newTheme', theme]); } }, () => true),
  }, () => {});
  nextPage.initialize();
  nextPage.update({ scale: 140, theme: 'light' });
  await flush();
  assert.deepEqual(calls, [['oldZoom', 1]]);
  oldZoom.resolve();
  await oldPage.whenIdle();
  await nextPage.whenIdle();
  assert.deepEqual(calls, [['oldZoom', 1], ['newZoom', 1.4], ['newTheme', 'light']]);
});

test('a remounted settings page reads the outcome of an already submitted old write', async () => {
  const operations = new SettingsOperationQueue(), write = deferred();
  let native = { closeToTray: true, startMinimized: true }, reads = 0, oldUpdates = 0, state;
  const invoke = async (command, args) => {
    if (command === 'get_desktop_preferences') { reads++; return { ...native }; }
    await write.promise;
    native = args.preferences;
    return { ...native };
  };
  const oldPage = new DesktopPreferencesController(invoke, () => { oldUpdates++; }, operations);
  await oldPage.refresh();
  const pending = oldPage.set('closeToTray', false);
  await flush();
  oldPage.dispose();
  const count = oldUpdates;
  const nextPage = new DesktopPreferencesController(invoke, value => { state = value; }, operations);
  const refreshing = nextPage.refresh();
  await flush();
  assert.equal(reads, 1);
  write.resolve();
  await pending;
  await refreshing;
  assert.equal(oldUpdates, count);
  assert.equal(state.value.closeToTray, false);
  assert.equal(reads, 2);
});

test('disposed settings writes still queued behind native work are skipped before submission', async () => {
  const operations = new SettingsOperationQueue(), barrier = deferred();
  let writes = 0, state;
  const invoke = async command => {
    if (command !== 'get_desktop_preferences') writes++;
    return { closeToTray: true, startMinimized: true };
  };
  const oldPage = new DesktopPreferencesController(invoke, () => {}, operations);
  await oldPage.refresh();
  const blocker = operations.run(() => barrier.promise);
  const pending = oldPage.set('startMinimized', false);
  oldPage.dispose();
  const nextPage = new DesktopPreferencesController(invoke, value => { state = value; }, operations);
  const refreshing = nextPage.refresh();
  barrier.resolve();
  await blocker;
  await pending;
  await refreshing;
  assert.equal(writes, 0);
  assert.equal(state.value.startMinimized, true);
});

test('an opener module loaded after modal close, reopen or disposal never launches the old request', async () => {
  for (const ending of ['close', 'reopen', 'dispose']) {
    const loading = deferred();
    let launches = 0;
    const remote = makeRemote(async () => ({ status: remoteStatus(true), token: null }), {
      loadOpener: () => loading.promise,
    });
    remote.controller.receiveStatus(remoteStatus(true));
    remote.controller.open();
    const opening = remote.controller.openUrl();
    if (ending === 'dispose') remote.controller.dispose();
    else { remote.controller.close(); if (ending === 'reopen') remote.controller.open(); }
    loading.resolve(async () => { launches++; });
    await opening;
    assert.equal(launches, 0);
  }
});

function loadPageFunction(name, globals) {
  const page = readFileSync(new URL('../app/src/routes/+page.svelte', import.meta.url), 'utf8');
  const script = page.slice(page.indexOf('>') + 1, page.indexOf('</script>'));
  const parsed = ts.createSourceFile('page.ts', script, ts.ScriptTarget.ES2022, true, ts.ScriptKind.TS);
  const declaration = parsed.statements.find(statement => ts.isFunctionDeclaration(statement) && statement.name?.text === name);
  assert.ok(declaration, `page function ${name} exists`);
  const code = `${declaration.getText(parsed)}\nexports.action = ${name};`;
  const context = vm.createContext({ exports: {}, Error, Promise, ...globals });
  vm.runInContext(ts.transpileModule(code, { compilerOptions: {
    module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022,
  } }).outputText, context);
  return context.exports.action;
}

test('the actual page does not launch a VPN after disposal while a privilege check is pending', async () => {
  const privilege = deferred(), calls = [];
  let alive = true;
  const start = loadPageFunction('startProfile', {
    snapshots: { alive: () => alive, changed: () => assert.fail('disposed state must not change') },
    latestInstanceForProfile: () => null, isActive: () => false, editProfile: () => {},
    showError: () => {}, showSuccess: () => {}, upsertInstance: () => {},
    invoke: command => { calls.push(command); return privilege.promise; }, busy: false,
  });
  const pending = start({ hasSecret: true, passwordStored: false, profile: { id: 'synthetic', useSudo: true } });
  alive = false;
  privilege.resolve({ required: true, ready: true, platform: 'synthetic' });
  await pending;
  assert.deepEqual(calls, ['privilege_status']);
  await start({ hasSecret: true, profile: { id: 'synthetic', useSudo: true } });
  assert.deepEqual(calls, ['privilege_status']);
});

test('the actual page does not connect a pending profile after a disposed helper-install response', async () => {
  const install = deferred();
  let alive = true, starts = 0;
  const unlock = loadPageFunction('unlockPrivileges', {
    snapshots: { alive: () => alive, changed: () => assert.fail('disposed state must not change') },
    administratorPassword: 'synthetic-admin-password', privilegeBusy: false, privilegeError: '',
    pendingPrivilegeProfileId: 'synthetic', profiles: [{ profile: { id: 'synthetic' } }],
    invoke: () => install.promise, startProfile: async () => { starts++; }, showSuccess: () => {},
    errorText: loadService('manager-state').errorText,
  });
  const pending = unlock({ preventDefault() {} });
  alive = false;
  install.resolve({ required: true, ready: true, platform: 'synthetic' });
  await pending;
  assert.equal(starts, 0);
});

test('the actual page does not copy an exported configuration returned after disposal', async () => {
  const exporting = deferred();
  let alive = true, copies = 0;
  const copy = loadPageFunction('copyConfig', {
    snapshots: { alive: () => alive }, invoke: () => exporting.promise,
    navigator: { clipboard: { writeText: async () => { copies++; } } },
    showSuccess: () => {}, showError: () => {},
  });
  const pending = copy({ profile: { id: 'synthetic' } });
  alive = false;
  exporting.resolve('synthetic password-free config');
  await pending;
  assert.equal(copies, 0);
});
